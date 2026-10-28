//! pmgr — Apple PMGR (power/clock manager), T8030 layout.
//! Port of Inferno hw/misc/apple-silicon/t8030-config.c.inc pmgr region
//! + apple_pmgr*.c psreg behavior: per-device clock gates + power states.

use vm_core::Device;

pub const PMGR_PSREG_BASE: u64 = 0x0000; // per-device power state regs, 0x1000 stride
pub const PMGR_PERF_CPU_BASE: u64 = 0x34800; // perf MIDF/MTUF registers
pub const PMGR_UNK_E4000: u64 = 0x3D2E4000; // referenced in t8030.c (pmgr_unk_e4000)

const PS_STATE_OFF: u32 = 0x0;
const PS_STATE_ON: u32 = 0xF;

pub struct Pmgr {
    /// psreg idx → state (0xF = on). Devices read their gate before MMIO.
    pub ps: std::collections::BTreeMap<u64, u32>,
    pub unknown_reads: u64,
    pub unknown_writes: u64,
}

impl Pmgr {
    pub fn new() -> Self {
        Pmgr { ps: std::collections::BTreeMap::new(), unknown_reads: 0, unknown_writes: 0 }
    }

    pub fn power_on(&mut self, psreg: u64) {
        self.ps.insert(psreg, PS_STATE_ON);
    }

    pub fn power_off(&mut self, psreg: u64) {
        self.ps.insert(psreg, PS_STATE_OFF);
    }

    pub fn is_on(&self, psreg: u64) -> bool {
        self.ps.get(&psreg).copied().unwrap_or(PS_STATE_ON) == PS_STATE_ON
    }

    pub fn regs_documented() -> &'static [(&'static str, u64)] {
        &[
            ("PSREG(n)", PMGR_PSREG_BASE),
            ("PERF_CPU", PMGR_PERF_CPU_BASE),
            ("UNK_E4000", PMGR_UNK_E4000),
        ]
    }
}

impl Default for Pmgr {
    fn default() -> Self {
        Self::new()
    }
}

impl Device for Pmgr {
    fn name(&self) -> &'static str {
        "pmgr"
    }
    fn read(&mut self, off: u64, _size: u8) -> u64 {
        if off < 0x34000 {
            let idx = off & !0xF;
            Ok128(self.ps.get(&idx).copied().unwrap_or(PS_STATE_ON) as u64)
        } else {
            self.unknown_reads += 1;
            0
        }
    }
    fn write(&mut self, off: u64, _size: u8, val: u64) {
        if off < 0x34000 {
            let idx = off & !0xF;
            self.ps.insert(idx, (val & 0xF) as u32);
        } else {
            self.unknown_writes += 1;
        }
    }
}

fn Ok128(v: u64) -> u64 {
    // power-state regs read back as (state<<4)|sw-progress bits
    (v & 0xF) | (v << 4 & 0xF0)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn gate_roundtrip() {
        let mut p = Pmgr::new();
        p.write(0x1000, 4, 0xF);
        assert!(p.is_on(0x1000));
        p.write(0x1000, 4, 0x0);
        assert!(!p.is_on(0x1000));
    }
}
