//! sart — Apple SART IOMMU (port of Inferno hw/apple-silicon/sart.c).
//! Simple allocate/lock state machine used by ANS2 storage DMA.

use vm_core::Device;

pub const SART_CONFIG: u64 = 0x0400;
pub const SART_INDEX: u64 = 0x0404;
pub const SART_ADDR_LO: u64 = 0x0408;
pub const SART_ADDR_HI: u64 = 0x040C;
pub const SART_SIZE: u64 = 0x0410;
pub const SART_FLAGS: u64 = 0x0414;
pub const SART_STATUS: u64 = 0x0418;
pub const SART_REG_FMT: u64 = 0x041C;

const SART_MAX_ENTRIES: usize = 32;

#[derive(Clone, Debug, Default)]
pub struct SartEntry {
    pub addr: u64,
    pub size: u64,
    pub flags: u64,
    pub locked: bool,
}

pub struct Sart {
    pub entries: Vec<SartEntry>,
    pub index: u32,
    pub configured: bool,
    pub unknown_reads: u64,
}

impl Sart {
    pub fn new() -> Self {
        Sart {
            entries: vec![SartEntry::default(); SART_MAX_ENTRIES],
            index: 0,
            configured: false,
            unknown_reads: 0,
        }
    }

    /// Host-side helper: program an entry directly (machine setup for DRAM).
    pub fn program(&mut self, idx: usize, addr: u64, size: u64, flags: u64, locked: bool) {
        if idx < SART_MAX_ENTRIES {
            self.entries[idx] = SartEntry { addr, size, flags, locked };
        }
    }

    pub fn translate(&self, iova: u64) -> Option<u64> {
        for e in &self.entries {
            if !e.locked || e.size == 0 {
                continue;
            }
            if iova >= e.addr && iova < e.addr + e.size {
                return Some(iova); // identity window (SART is 1:1 with DRAM)
            }
        }
        None
    }

    pub fn regs_documented() -> &'static [(&'static str, u64)] {
        &[
            ("CONFIG", SART_CONFIG),
            ("INDEX", SART_INDEX),
            ("ADDR_LO", SART_ADDR_LO),
            ("ADDR_HI", SART_ADDR_HI),
            ("SIZE", SART_SIZE),
            ("FLAGS", SART_FLAGS),
            ("STATUS", SART_STATUS),
            ("REG_FMT", SART_REG_FMT),
        ]
    }
}

impl Default for Sart {
    fn default() -> Self {
        Self::new()
    }
}

impl Device for Sart {
    fn name(&self) -> &'static str {
        "sart"
    }
    fn read(&mut self, off: u64, _size: u8) -> u64 {
        match off {
            SART_CONFIG => self.configured as u64,
            SART_INDEX => self.index as u64,
            SART_ADDR_LO => self.entries[self.index as usize].addr as u32 as u64,
            SART_ADDR_HI => self.entries[self.index as usize].addr >> 32,
            SART_SIZE => self.entries[self.index as usize].size,
            SART_FLAGS => self.entries[self.index as usize].flags,
            SART_STATUS => 1, // idle/done
            SART_REG_FMT => 0x1F,
            _ => {
                self.unknown_reads += 1;
                0
            }
        }
    }
    fn write(&mut self, off: u64, _size: u8, val: u64) {
        let i = self.index as usize;
        match off {
            SART_CONFIG => self.configured = val & 1 == 1,
            SART_INDEX => {
                if (val as usize) < SART_MAX_ENTRIES {
                    self.index = val as u32;
                }
            }
            SART_ADDR_LO => self.entries[i].addr = (self.entries[i].addr & !0xFFFF_FFFF) | (val & 0xFFFF_FFFF),
            SART_ADDR_HI => self.entries[i].addr = (self.entries[i].addr & 0xFFFF_FFFF) | (val << 32),
            SART_SIZE => self.entries[i].size = val,
            SART_FLAGS => self.entries[i].flags = val,
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identity_window() {
        let mut s = Sart::new();
        s.program(0, 0x800_0000_0000, 0x1000_0000, 0, true);
        assert_eq!(s.translate(0x800_0000_0100), Some(0x800_0000_0100));
        assert_eq!(s.translate(0x900_0000_0000), None);
    }
}
