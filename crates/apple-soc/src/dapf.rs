//! dapf — Apple DART address-filter shim (attach-spec §5.2).
//!
//! `/arm-io/dapf-disp0` (`230708000+1000`), `/arm-io/dapf-aop`
//! (`24AC04000+1000`) and the two ownerless DISD-tagged apcie pages
//! (`601008000+4000`, `602008000+4000` from `/defaults/pmap-io-ranges`) are
//! DART-family SID filters — NOT a display pipe (`adp-v4` mis-model) and NOT
//! an ASC coprocessor (`aop` mis-model). A DAPF gates which PA ranges a DART
//! stream may reach.
//!
//! Boot-minimal model: `0x0` (TCR) = store-on-write / read-back (default 0).
//! TCR bit7 TRANSLATE_ENABLE=0 ⇒ bypass ⇒ no faults — the boot-safe answer.
//! Every other offset RAZ (read 0, write drop, counted). A post-stop run that
//! shows TCR=translate-enabled + readback upgrades this to the full DART shim.

use vm_core::Device;

pub const DAPF_TCR: u64 = 0x0;

#[derive(Default)]
pub struct Dapf {
    tcr: u32,
    pub unknown_reads: u64,
    pub unknown_writes: u64,
}

impl Dapf {
    pub fn new() -> Self {
        Dapf::default()
    }
    /// Translate-enable flag of the stored TCR (host diagnostics).
    pub fn translate_enabled(&self) -> bool {
        self.tcr & 0x80 != 0
    }
}

impl Device for Dapf {
    fn name(&self) -> &'static str {
        "dapf"
    }
    fn read(&mut self, off: u64, _size: u8) -> u64 {
        match off {
            DAPF_TCR => self.tcr as u64,
            _ => {
                self.unknown_reads += 1;
                0
            }
        }
    }
    fn write(&mut self, off: u64, _size: u8, val: u64) {
        match off {
            DAPF_TCR => self.tcr = (val & 0xFFFF_FFFF) as u32,
            _ => self.unknown_writes += 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tcr_scratch_default_bypass() {
        let mut d = Dapf::new();
        assert!(!d.translate_enabled()); // default TCR=0 ⇒ bypass
        d.write(DAPF_TCR, 4, 0x80);
        assert!(d.translate_enabled());
        assert_eq!(d.read(DAPF_TCR, 4), 0x80);
        assert_eq!(d.read(0x1234, 4), 0); // RAZ elsewhere
    }
}
