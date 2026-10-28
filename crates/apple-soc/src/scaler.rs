//! scaler — Apple display Scaler/Dither (port of t8030_create_scaler
//! region): register map stub — compositing happens in the ADP path.

use vm_core::Device;

pub const SCALER_CTRL: u64 = 0x0000;

pub struct Scaler {
    pub unknown_reads: u64,
}

impl Scaler {
    pub fn new() -> Self {
        Scaler { unknown_reads: 0 }
    }
    pub fn regs_documented() -> &'static [(&'static str, u64)] {
        &[("CTRL", SCALER_CTRL)]
    }
}

impl Default for Scaler {
    fn default() -> Self {
        Self::new()
    }
}

impl Device for Scaler {
    fn name(&self) -> &'static str {
        "scaler"
    }
    fn read(&mut self, off: u64, _size: u8) -> u64 {
        self.unknown_reads += 1;
        let _ = off;
        0
    }
    fn write(&mut self, _off: u64, _size: u8, _val: u64) {}
}
