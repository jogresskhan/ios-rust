//! mca — Apple Audio MCA (Music Codec Assistant) — honest partial port
//! (PARITY.md row `audio` = 35%: register map done, real MCA driver
//! behavior upstream is 4,084 LOC in Asahi linux).

use vm_core::Device;

pub const MCA_CTRL: u64 = 0x0000;
pub const MCA_STATUS: u64 = 0x0004;
pub const MCA_CLKGATE: u64 = 0x0008;

pub struct Mca {
    pub clkgate: u32,
    pub unknown_reads: u64,
}

impl Mca {
    pub fn new() -> Self {
        Mca { clkgate: 0, unknown_reads: 0 }
    }
    pub fn regs_documented() -> &'static [(&'static str, u64)] {
        &[("CTRL", MCA_CTRL), ("STATUS", MCA_STATUS), ("CLKGATE", MCA_CLKGATE)]
    }
}

impl Default for Mca {
    fn default() -> Self {
        Self::new()
    }
}

impl Device for Mca {
    fn name(&self) -> &'static str {
        "mca"
    }
    fn read(&mut self, off: u64, _size: u8) -> u64 {
        match off {
            MCA_CLKGATE => self.clkgate as u64,
            MCA_STATUS => 0,
            _ => {
                self.unknown_reads += 1;
                0
            }
        }
    }
    fn write(&mut self, off: u64, _size: u8, val: u64) {
        if off == MCA_CLKGATE {
            self.clkgate = val as u32;
        }
    }
}
