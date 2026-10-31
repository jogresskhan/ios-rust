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
                let off = addr - r.base;
                // lazy-aware bulk write: Ram commits its backing first;
                // eager RAM devices keep the historic truncating copy;
                // non-RAM devices keep the historic silent skip.
                r.device.write_ram_bulk(off, data);
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
///
/// **Lazy commit (the OOM fix, 2026-10-31):** the backing `Vec` starts
/// EMPTY and grows geometrically on first write/load — never an eager
/// `vec![0u8; size]`. Uncommitted bytes read as 0, which is exactly what
/// the old zero-filled Vec returned for untouched memory, so guest-visible
/// semantics are unchanged; a 4 GiB DRAM window now costs ~0 RSS until the
/// guest actually touches pages (the eager 4 GiB allocation aborted every
/// `cargo test`/boot run on a 4 GiB host before a single insn retired).
///
/// Direct mutation through `ram_mut()` must keep `data.len() <= size`.
pub struct Ram {
    label: &'static str,
    /// Full region size in bytes (the address window) — NOT the allocation.
    size: u64,
    /// Committed prefix of the region, zero-filled. `len() <= size`.
    pub data: Vec<u8>,
}

impl Ram {
    pub fn new(label: &'static str, size: u64) -> Self {
        Ram {
            label,
            size,
            data: Vec::new(),
        }
    }
    /// Grow the committed prefix to cover `end` bytes (clamped to the
    /// region size). Commits exactly what is needed plus geometric
    /// headroom for sequential writes — never past the region, never a
    /// power-of-two overshoot (a doubling past a 2 GiB-deep touch used to
    /// request the full 4 GiB).
    fn ensure(&mut self, end: usize) {
        if end <= self.data.len() {
            return;
        }
        let cap = self.size as usize;
        let want = end
            .max(self.data.len().saturating_mul(2))
            .max(64 * 1024);
        self.data.resize(want.min(cap), 0);
    }
    pub fn load_at(&mut self, addr: u64, img: &[u8]) {
        let off = addr as usize;
        // clamp to the REGION size (the old full-size Vec made this the
        // same thing); an entirely out-of-range load still panics like
        // before ([off..end] with end < off is an invalid slice).
        let end = (off + img.len()).min(self.size as usize);
        self.ensure(end);
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
    /// Lazy-aware bulk write: commit the prefix covering the write, clamped
    /// to the region, then copy (same truncation semantics as the historic
    /// full-size Vec, which clamped at len == size).
    fn write_ram_bulk(&mut self, off: u64, data: &[u8]) {
        let o = off as usize;
        if o >= self.size as usize {
            return;
        }
        let end = (o + data.len()).min(self.size as usize);
        self.ensure(end);
        self.data[o..end].copy_from_slice(&data[..end - o]);
    }
    fn read(&mut self, off: u64, size: u8) -> u64 {
        let o = off as usize;
        // The old full-size Vec read only when o+8 <= len(== region size)
        // and returned 0 otherwise — including the last-7-bytes-of-region
        // quirk. Preserve that exactly against the REGION size.
        if o + 8 > self.size as usize {
            return 0;
        }
        // honor the access width: sub-8 loads return exactly `size`
        // bytes (zero-extended) — a 32-bit LDR must not observe the
        // neighboring word.
        let bytes = (size as u32).clamp(1, 8) as u32;
        if o >= self.data.len() {
            // fully uncommitted = untouched = zero (same as the old Vec)
            return 0;
        }
        // assemble: committed prefix + implicit zeros for the uncommitted
        // tail of the 8-byte window — identical to reading the old
        // zero-filled Vec at this address.
        let have = (self.data.len() - o).min(8);
        let mut buf = [0u8; 8];
        buf[..have].copy_from_slice(&self.data[o..o + have]);
        let raw = u64::from_le_bytes(buf);
        if bytes >= 8 {
            raw
        } else {
            raw & ((1u64 << (bytes * 8)) - 1)
        }
    }
    fn write(&mut self, off: u64, size: u8, val: u64) {
        let o = off as usize;
        // honor the access width: a 32-bit STR must not clobber the
        // neighboring word.
        let bytes = (size as usize).clamp(1, 8);
        // the old Vec dropped writes whose bytes crossed the region end
        if o + bytes > self.size as usize {
            return;
        }
        self.ensure(o + bytes);
        self.data[o..o + bytes]
            .copy_from_slice(&val.to_le_bytes()[..bytes]);
    }
}

// Silence unused-import warning for DmaDevice until DMA-capable devices land.
#[allow(dead_code)]
fn _dma_bound<T: DmaDevice>(_: &T) {}

#[cfg(test)]
mod ram_lazy_tests {
    use super::*;

    /// THE OOM REGRESSION PIN: a 4 GiB DRAM window must not eagerly
    /// allocate (the old `vec![0u8; size]` aborted 4 GiB hosts before a
    /// single guest insn retired).
    #[test]
    fn ram_4g_window_costs_nothing_until_touched() {
        let r = Ram::new("dram", 4 << 30);
        assert!(r.data.is_empty(), "fresh Ram must not commit the window");
        assert_eq!(r.data.capacity(), 0);
    }

    /// Untouched memory reads 0 — same value the old zero-filled Vec gave.
    #[test]
    fn ram_uncommitted_reads_zero() {
        let mut r = Ram::new("dram", 1 << 20);
        assert_eq!(r.read(0x1000, 8), 0);
        assert_eq!(r.read(0xFF000, 4), 0);
        // and a write commits exactly a geometric prefix
        r.write(0x1000, 4, 0xDEAD_BEEF);
        assert_eq!(r.read(0x1000, 4), 0xDEAD_BEEF);
        assert!(r.data.len() >= 0x1004 && r.data.len() <= 0x20000);
        assert!(r.data.len() <= 1 << 20);
        // neighbors still zero, sub-word width honored
        assert_eq!(r.read(0x1004, 4), 0);
        assert_eq!(r.read(0x1000, 2), 0xBEEF);
        assert_eq!(r.read(0x1002, 2), 0xDEAD);
    }

    /// A wide read straddling the committed frontier assembles committed
    /// bytes + implicit zeros — byte-identical to the old zero-filled Vec.
    #[test]
    fn ram_straddled_read_matches_eager_zero_fill() {
        let mut r = Ram::new("dram", 1 << 20);
        r.write(0x100, 1, 0xAB);
        // committed prefix ends at 0x101; an 8-byte read at 0x100 sees
        // 0xAB followed by seven zeros
        assert_eq!(r.read(0x100, 8), 0xAB);
        r.write(0x104, 2, 0xCD_EF);
        // window 0x100..0x108 now = AB 00 00 00 EF CD 00 00 (LE)
        assert_eq!(r.read(0x100, 8), 0x0000_CDEF_0000_00AB);
    }

    /// Region-end quirks are preserved EXACTLY as the old full-size Vec:
    /// the last 8 bytes of the window read 0, writes crossing the end are
    /// dropped, and loads past the end truncate.
    #[test]
    fn ram_region_end_quirks_preserved() {
        let size = 0x10000u64;
        let mut r = Ram::new("sram", size);
        // read whose 8-byte window crosses the end → 0 (old behavior)
        assert_eq!(r.read(size - 4, 4), 0);
        // write crossing the end → dropped, nothing committed
        r.write(size - 2, 4, 0xFFFF_FFFF);
        assert!(r.data.is_empty());
        // load_at truncates at the region end
        let img = [0x11u8; 8];
        r.load_at(size - 2, &img);
        assert_eq!(r.data.len(), size as usize);
        assert_eq!(&r.data[(size - 2) as usize..], &[0x11, 0x11]);
        // a read fully inside still works after commit
        r.write(0, 8, 0x0102_0304_0506_0708);
        assert_eq!(r.read(0, 8), 0x0102_0304_0506_0708);
    }

    /// Small regions (FakeRam-style) still work: commit never exceeds size.
    #[test]
    fn ram_small_region_full_commit() {
        let mut r = Ram::new("sram", 0x100);
        r.write(0xF0, 8, 0x1234);
        assert_eq!(r.data.len(), 0x100);
        assert_eq!(r.read(0xF0, 8), 0x1234);
        // past-end read quirk holds
        assert_eq!(r.read(0xFC, 4), 0);
    }

    /// load_at into a fresh Ram commits lazily and round-trips. Offset is
    /// 64 MiB deep (the real kernel's LOAD_PA is 16 MiB in; a 2 GiB-deep
    /// touch would need a 2 GiB dense prefix — the documented cost of the
    /// flat model, which is still ≤ the old full-window commit).
    #[test]
    fn ram_load_at_roundtrip() {
        let mut r = Ram::new("dram", 4 << 30);
        let img: Vec<u8> = (0..255u8).collect();
        r.load_at(0x400_0000, &img); // 64 MiB in — no 4 GiB allocation needed
        assert!(r.data.len() >= 0x400_00FF);
        assert!(r.data.len() <= 0x800_0000); // headroom is geometric, bounded
        assert_eq!(&r.data[0x400_0000..0x400_00FF], &img[..]);
        assert_eq!(r.read(0x400_0000, 8), u64::from_le_bytes(img[..8].try_into().unwrap()));
        // untouched low memory still zero
        assert_eq!(r.read(0, 8), 0);
    }
}
