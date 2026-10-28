//! wdt — Apple watchdog (port of Inferno hw/watchdog/apple_wdt.c).
//! Timeout raises a reset request the machine observes on tick.

use vm_core::Device;

pub const WDT_RST: u64 = 0x0000;   // 0x1 = kick
pub const WDT_CTRL: u64 = 0x0008;  // bit0 enable
pub const WDT_CNT: u64 = 0x0010;
pub const WDT_PERIOD: u64 = 0x001C;

pub struct AppleWdt {
    pub enabled: bool,
    pub period_ns: u64,
    countdown_ns: u64,
    pub reset_requested: bool,
    pub unknown_reads: u64,
}

impl AppleWdt {
    pub fn new() -> Self {
        AppleWdt { enabled: false, period_ns: 0, countdown_ns: 0, reset_requested: false, unknown_reads: 0 }
    }

    pub fn regs_documented() -> &'static [(&'static str, u64)] {
        &[("RST", WDT_RST), ("CTRL", WDT_CTRL), ("CNT", WDT_CNT), ("PERIOD", WDT_PERIOD)]
    }
}

impl Default for AppleWdt {
    fn default() -> Self {
        Self::new()
    }
}

impl Device for AppleWdt {
    fn name(&self) -> &'static str {
        "apple-wdt"
    }
    fn read(&mut self, off: u64, _size: u8) -> u64 {
        match off {
            WDT_CTRL => self.enabled as u64,
            WDT_CNT => self.countdown_ns / 1_000_000,
            WDT_PERIOD => self.period_ns / 1_000_000,
            _ => {
                self.unknown_reads += 1;
                0
            }
        }
    }
    fn write(&mut self, off: u64, _size: u8, val: u64) {
        match off {
            WDT_RST => {
                if val == 1 {
                    self.countdown_ns = self.period_ns;
                }
            }
            WDT_CTRL => self.enabled = val & 1 == 1,
            WDT_PERIOD => self.period_ns = val * 1_000_000,
            _ => {}
        }
    }
    fn tick(&mut self, _now_ns: u64) {
        if self.enabled && self.period_ns > 0 {
            if self.countdown_ns == 0 {
                self.countdown_ns = self.period_ns;
            }
            self.countdown_ns = self.countdown_ns.saturating_sub(1_000_000);
            if self.countdown_ns == 0 {
                self.reset_requested = true;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn expires_and_resets() {
        let mut w = AppleWdt::new();
        w.write(WDT_PERIOD, 4, 2); // 2ms
        w.write(WDT_CTRL, 4, 1);
        for _ in 0..5 {
            w.tick(0);
        }
        assert!(w.reset_requested);
    }
}
