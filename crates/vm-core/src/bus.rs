//! Flat physical bus — QEMU's sysbus equivalent for the T8030 map.

use crate::{Device, DmaDevice};

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
        Bus {
            regions: Vec::new(),
            unmapped_read_zeros: 0,
            unmapped_reads: 0,
            unmapped_writes: 0,
        }
    }

    pub fn attach(&mut self, base: u64, size: u64, device: Box<dyn Device>) {
        assert!(size > 0, "region size must be > 0");
        self.regions.push(Region { base, size, device });
        self.regions.sort_by_key(|r| r.base);
    }

    fn find(&mut self, addr: u64) -> Option<usize> {
        self.regions
            .iter()
            .position(|r| addr >= r.base && addr < r.base + r.size)
    }

    pub fn read(&mut self, addr: u64, size: u8) -> u64 {
        match self.find(addr) {
            Some(i) => {
                let r = &mut self.regions[i];
                r.device.read(addr - r.base, size)
            }
            None => {
                self.unmapped_reads += 1;
                self.unmapped_read_zeros
            }
        }
    }

    pub fn write(&mut self, addr: u64, size: u8, val: u64) {
        match self.find(addr) {
            Some(i) => {
                let r = &mut self.regions[i];
                let off = addr - r.base;
                r.device.write(off, size, val);
            }
            None => {
                self.unmapped_writes += 1;
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
