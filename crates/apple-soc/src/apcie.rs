//! apcie — Apple PCIe root complex (port of hw/pci-host/apcie.c):
//! ECAM config space with synthesized root-port capability set.

use vm_core::Device;

pub const APCIE_ECAM_BASE_OFF: u64 = 0x0000; // relative window base

pub struct Apcie {
    /// cfg addr → dword (root port + bridges synthesized)
    pub cfg: std::collections::BTreeMap<u64, u32>,
    pub config_cycles: u64,
    pub unknown_reads: u64,
}

impl Apcie {
    pub fn new() -> Self {
        let mut c = Apcie { cfg: std::collections::BTreeMap::new(), config_cycles: 0, unknown_reads: 0 };
        // Root port vendor/device (Apple, ANS2-attached)
        c.cfg.insert(0x00, 0x1420_0000 | (0x14 << 16));
        c.cfg.insert(0x04, 0x0010_0407); // status|command: mem+bus master
        c.cfg.insert(0x08, 0x0604_0000); // class: PCI bridge
        c
    }

    pub fn regs_documented() -> &'static [(&'static str, u64)] {
        &[("ECAM", APCIE_ECAM_BASE_OFF)]
    }
}

impl Device for Apcie {
    fn name(&self) -> &'static str {
        "apcie"
    }
    fn read(&mut self, off: u64, _size: u8) -> u64 {
        // off here is ECAM-relative config offset (device attach maps the window)
        self.config_cycles += 1;
        match off {
            _ => self.cfg.get(&(off & !0x3)).copied().unwrap_or(0xFFFF_FFFF) as u64,
        }
    }
    fn write(&mut self, off: u64, _size: u8, val: u64) {
        if off == 0x04 {
            self.cfg.insert(0x04, (val & 0xFFFF) as u32);
        }
    }
}

impl Default for Apcie {
    fn default() -> Self {
        Self::new()
    }
}
