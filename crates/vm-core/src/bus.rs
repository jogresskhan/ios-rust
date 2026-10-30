//! Flat physical bus — QEMU's sysbus equivalent for the T8030 map.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use crate::{Device, DmaDevice};

/// Optional MMIO access log — M5 device-census instrumentation (task M5-C).
///
/// Off by default and behavior-identical: set `IOS_RUST_MMIO_LOG=<path>` to
/// append, one line per bus event, to `<path>`:
///
/// ```text
/// #map,<device>,<base hex>,<size hex>          (attach; RAM regions too)
/// #unimpl,<node>,<base hex>,<size hex>,<compat> (t8030 attach_from_adt)
/// <addr hex>,<size bytes>,<r|w>,<device|UNMAPPED> (every non-RAM access)
/// ```
///
/// RAM-backed regions (dram/srom/sram/seprom/boot-pause/nvram) are NOT
/// logged per-access — the census only cares about MMIO windows, and the
/// 8M-insn boot would otherwise emit ~25M fetch lines. Append-only; the
/// consumer is tools/re/reports/m5_mmio_census.py. The emulator never
/// parses the log back, so default behavior is byte-identical.
static MMIO_LOG: OnceLock<Option<Mutex<File>>> = OnceLock::new();

fn mmio_log_file() -> Option<&'static Mutex<File>> {
    MMIO_LOG
        .get_or_init(|| {
            let path = std::env::var_os("IOS_RUST_MMIO_LOG")?;
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .ok()
                .map(Mutex::new)
        })
        .as_ref()
}

/// Append one raw line to the MMIO log (no-op unless IOS_RUST_MMIO_LOG is
/// set). Public so the machine crate can annotate attach decisions the bus
/// never sees (unmodeled /arm-io nodes).
pub fn mmio_log_line(line: &str) {
    if let Some(f) = mmio_log_file() {
        if let Ok(mut f) = f.lock() {
            let _ = f.write_all(line.as_bytes());
            let _ = f.write_all(b"\n");
        }
    }
}

/// True when MMIO logging is enabled (cheap hot-path gate).
fn mmio_logging() -> bool {
    mmio_log_file().is_some()
}

/// Process-wide mirrors of the newest `Bus`'s unmapped-access counters.
/// The boot harness moves its `Bus` into the CPU's `MemAccess` box, so the
/// counters are read post-run through these accessors; `Bus::new` resets
/// them (one live machine per boot run — honest for the harness, harmless
/// for tests that never assert on them).
static UNMAPPED_READS: AtomicU64 = AtomicU64::new(0);
static UNMAPPED_WRITES: AtomicU64 = AtomicU64::new(0);

/// Unmapped reads (silent-zero) seen by the newest `Bus` since its creation.
pub fn unmapped_reads() -> u64 {
    UNMAPPED_READS.load(Ordering::Relaxed)
}

/// Unmapped writes (dropped) seen by the newest `Bus` since its creation.
pub fn unmapped_writes() -> u64 {
    UNMAPPED_WRITES.load(Ordering::Relaxed)
}

struct Region {
    base: u64,
    size: u64,
    device: Box<dyn Device>,
}

/// One flat physical address space. Devices attach at [base, base+size).
/// Reads/writes that miss every region read as 0 and drop writes
/// (QEMU "unimplemented-device" behavior).
pub struct Bus {
    regions: Vec<Region>,
    pub unmapped_read_zeros: u64,
    pub unmapped_reads: u64,
    pub unmapped_writes: u64,
}

impl Bus {
    pub fn new() -> Self {
        UNMAPPED_READS.store(0, Ordering::Relaxed);
        UNMAPPED_WRITES.store(0, Ordering::Relaxed);
        Bus {
            regions: Vec::new(),
            unmapped_read_zeros: 0,
            unmapped_reads: 0,
            unmapped_writes: 0,
        }
    }

    pub fn attach(&mut self, base: u64, size: u64, device: Box<dyn Device>) {
        assert!(size > 0, "region size must be > 0");
        if mmio_logging() {
            let name = device.name();
            mmio_log_line(&format!("#map,{name},{base:#x},{size:#x}"));
        }
        self.regions.push(Region { base, size, device });
        self.regions.sort_by_key(|r| r.base);
    }

    /// Region resolution — **B1 rule (M5 attach-spec §0)**: resolve overlapping
    /// windows by SMALLEST matching region wins; tie → the region attached
    /// later. The real ADT nests device pages inside larger windows (measured:
    /// pmgr window22 [0x23D100000+0x80000] ⊃ dockchannel-uart [0x23D10C000+0x1000]
    /// and pmp; mca-switch ⊃ mca0/mca1; SEPROM Ram ⊃ dart-sep …). The old
    /// `position()` = lowest-base-first silently shadowed the nested devices
    /// forever. Iteration is in (base, attach-order) order because `attach`
    /// does a stable sort by base, so `<=` implements "tie → last attached".
    fn find(&mut self, addr: u64) -> Option<usize> {
        let mut best: Option<usize> = None;
        for (i, r) in self.regions.iter().enumerate() {
            if addr >= r.base && addr < r.base + r.size {
                best = match best {
                    None => Some(i),
                    Some(b) => {
                        if r.size <= self.regions[b].size {
                            Some(i)
                        } else {
                            Some(b)
                        }
                    }
                };
            }
        }
        best
    }

    pub fn read(&mut self, addr: u64, size: u8) -> u64 {
        match self.find(addr) {
            Some(i) => {
                let r = &mut self.regions[i];
                let v = r.device.read(addr - r.base, size);
                if mmio_logging() && r.device.ram_mut().is_none() {
                    let name = r.device.name();
                    // M5-P: value appended (console-reconstruction aid — the
                    // FIPSPOST/panic print stream rides the UART FIFO writes).
                    mmio_log_line(&format!("{addr:#x},{size},r,{name},{v:#x}"));
                }
                v
            }
            None => {
                if mmio_logging() {
                    mmio_log_line(&format!("{addr:#x},{size},r,UNMAPPED"));
                }
                self.unmapped_reads += 1;
                UNMAPPED_READS.fetch_add(1, Ordering::Relaxed);
                self.unmapped_read_zeros
            }
        }
    }

    pub fn write(&mut self, addr: u64, size: u8, val: u64) {
        match self.find(addr) {
            Some(i) => {
                let r = &mut self.regions[i];
                if mmio_logging() && r.device.ram_mut().is_none() {
                    let name = r.device.name();
                    // M5-P: value appended (console-reconstruction aid).
                    mmio_log_line(&format!("{addr:#x},{size},w,{name},{val:#x}"));
                }
                let off = addr - r.base;
                r.device.write(off, size, val);
            }
            None => {
                if mmio_logging() {
                    mmio_log_line(&format!("{addr:#x},{size},w,UNMAPPED,{val:#x}"));
                }
                self.unmapped_writes += 1;
                UNMAPPED_WRITES.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Bulk read used by DMA and the CPU backend (RAM regions only).
    pub fn read_raw(&mut self, addr: u64, buf: &mut [u8]) {
        match self.find(addr) {
            Some(i) => {
                let r = &mut self.regions[i];
                if let Some(ram) = r.device.ram_mut() {
                    let off = (addr - r.base) as usize;
                    if off < ram.len() {
                        let end = (off + buf.len()).min(ram.len());
                        buf[..end - off].copy_from_slice(&ram[off..end]);
                        buf[end - off..].fill(0);
                    } else {
                        buf.fill(0);
                    }
                }
            }
            None => {
                self.unmapped_reads += 1;
                UNMAPPED_READS.fetch_add(1, Ordering::Relaxed);
                buf.fill(0);
            }
        }
    }

    pub fn write_raw(&mut self, addr: u64, data: &[u8]) {
        match self.find(addr) {
            Some(i) => {
                let r = &mut self.regions[i];
                if let Some(ram) = r.device.ram_mut() {
                    let off = (addr - r.base) as usize;
                    if off < ram.len() {
                        let end = (off + data.len()).min(ram.len());
                        ram[off..end].copy_from_slice(&data[..end - off]);
                    }
                }
            }
            None => {
                self.unmapped_writes += 1;
                UNMAPPED_WRITES.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn tick(&mut self, now_ns: u64) {
        for r in &mut self.regions {
            r.device.tick(now_ns);
        }
    }

    pub fn region_count(&self) -> usize {
        self.regions.len()
    }

    pub fn region_summary(&self) -> Vec<(String, u64, u64)> {
        self.regions
            .iter()
            .map(|r| (r.device.name().to_string(), r.base, r.size))
            .collect()
    }
}

impl Default for Bus {
    fn default() -> Self {
        Self::new()
    }
}

/// Plain RAM region (SROM/SRAM/DRAM bank).
pub struct Ram {
    label: &'static str,
    pub data: Vec<u8>,
}

impl Ram {
    pub fn new(label: &'static str, size: u64) -> Self {
        Ram {
            label,
            data: vec![0u8; size as usize],
        }
    }
    pub fn load_at(&mut self, addr: u64, img: &[u8]) {
        let off = addr as usize;
        let end = (off + img.len()).min(self.data.len());
        self.data[off..end].copy_from_slice(&img[..end - off]);
    }
}

impl Device for Ram {
    fn name(&self) -> &'static str {
        self.label
    }
    fn ram_mut(&mut self) -> Option<&mut Vec<u8>> {
        Some(&mut self.data)
    }
    fn read(&mut self, off: u64, size: u8) -> u64 {
        let o = off as usize;
        if o + 8 <= self.data.len() {
            let raw = u64::from_le_bytes(self.data[o..o + 8].try_into().unwrap());
            // honor the access width: sub-8 loads return exactly `size`
            // bytes (zero-extended) — a 32-bit LDR must not observe the
            // neighboring word.
            let bytes = (size as u32).clamp(1, 8) as u32;
            if bytes >= 8 {
                raw
            } else {
                raw & ((1u64 << (bytes * 8)) - 1)
            }
        } else {
            0
        }
    }
    fn write(&mut self, off: u64, size: u8, val: u64) {
        let o = off as usize;
        // honor the access width: a 32-bit STR must not clobber the
        // neighboring word.
        let bytes = (size as usize).clamp(1, 8);
        if o + bytes <= self.data.len() {
            self.data[o..o + bytes]
                .copy_from_slice(&val.to_le_bytes()[..bytes]);
        }
    }
}

// Silence unused-import warning for DmaDevice until DMA-capable devices land.
#[allow(dead_code)]
fn _dma_bound<T: DmaDevice>(_: &T) {}
