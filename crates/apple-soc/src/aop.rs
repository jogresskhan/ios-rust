//! aop — Apple AOP (Always-On Processor) shim (port of hw/misc/
//! apple-silicon/aop.c): RTKit-based IOP with sensor/buttons mailboxes.

use vm_core::Device;

pub const AOP_BASE_STAT: u64 = 0x0000;

pub struct Aop {
    pub rtkit: crate::rtkit::RtkitDevice,
    pub unknown_reads: u64,
}

impl Aop {
    pub fn new() -> Self {
        Aop { rtkit: crate::rtkit::RtkitDevice::new("rtkit-aop"), unknown_reads: 0 }
    }
    pub fn regs_documented() -> &'static [(&'static str, u64)] {
        &[("STAT", AOP_BASE_STAT), ("MAILBOX", 0x1000)]
    }
}

impl Default for Aop {
    fn default() -> Self {
        Self::new()
    }
}

impl Device for Aop {
    fn name(&self) -> &'static str {
        "aop"
    }
    fn read(&mut self, off: u64, size: u8) -> u64 {
        if off == 0x1000 {
            // mailbox read isn't modeled as reg read (device polls via recv())
            return 0;
        }
        self.rtkit.read(off, size)
    }
    fn write(&mut self, off: u64, size: u8, val: u64) {
        self.rtkit.write(off, size, val);
    }
}
