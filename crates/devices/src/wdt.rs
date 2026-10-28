//! Apple Watchdog / timers — port of `hw/watchdog/apple_wdt.c` (torvalds/linux
//! apple_wdt semantics; Inferno model). Controls WDT_CTRL/WDT_TMR; the guest
//! xnu pongo-adjacent path kicks it via 0x23D2B0018 on T8030-class rigs.

use crate::bus::{MMIODevice, W4};

pub const REG_WDT_CTRL: u64 = 0x8;
pub const REG_WDT_TMR: u64 = 0xC;

#[derive(Debug, Default)]
pub struct Wdt {
    ctrl: u32,
    tmr: u32,
    pub reset_requested: bool,
}

impl MMIODevice for Wdt {
    fn name(&self) -> &'static str {
        "apple-wdt"
    }
    fn size(&self) -> u64 {
        0x100
    }
    fn read(&mut self, offset: u64, _width: u32) -> u64 {
        match offset {
            REG_WDT_CTRL => self.ctrl as u64,
            REG_WDT_TMR => self.tmr as u64,
            _ => 0,
        }
    }
    fn write(&mut self, offset: u64, value: u64, _width: u32) {
        match offset {
            REG_WDT_CTRL => {
                self.ctrl = value as u32;
                // bit 2 = ARM+reset (per apple_wdt driver WDT_CTRL_RESET_EN)
                if self.ctrl & 0b100 != 0 {
                    self.reset_requested = true;
                }
            }
            REG_WDT_TMR => self.tmr = value as u32,
            _ => {}
        }
    }
}

pub const PARITY_PCT: u8 = 60; // simple model, semantics verified vs driver

impl crate::bus::Device for Wdt {
    fn mmio(&mut self) -> &mut dyn MMIODevice {
        self
    }
    fn parity_pct(&self) -> u8 {
        PARITY_PCT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reset_flag() {
        let mut w = Wdt::default();
        w.write(REG_WDT_TMR, 100, W4);
        w.write(REG_WDT_CTRL, 0b100, W4);
        assert!(w.reset_requested);
    }
}
