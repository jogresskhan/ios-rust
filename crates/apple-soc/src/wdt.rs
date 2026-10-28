//! apple-wdt — Apple Watchdog Timer, T8030.
//!
//! Faithful Rust port of ChefKiss Inferno `hw/watchdog/apple_wdt.c`
//! (AGPL-3.0, © 2024-2026 Visual Ehrmanntraut). Register offsets,
//! timer-complement semantics (TMR registers store `clock - value`), the
//! IRQ-ack bit behavior and the reset path are all preserved.
//!
//! The C wires `watchdog_perform_action()` (QEMU system reset) plus the
//! legacy device reset; here a watchdog expiry latches
//! [`AppleWdt::reset_pending`] (and clears the register file) for the
//! machine to consume.
//!
//! The C exposes *two* MMIO regions (`.reg` 0x44 bytes and a 4-byte
//! `.scratch` RAM). The vm-core bus attaches one region per device, so
//! the scratch register is served at relative offset 0x800 (documented
//! mapping decision; the machine places the device region accordingly).

use vm_core::Device;

pub const REG_CHIP_WDOG_TMR: u64 = 0x0;
pub const REG_CHIP_WDOG_RST_CNT: u64 = 0x4;
pub const REG_CHIP_WDOG_INTR_CNT: u64 = 0x8;
pub const REG_CHIP_WDOG_CTL: u64 = 0xC;
pub const REG_SYS_WDOG_TMR: u64 = 0x10;
pub const REG_SYS_WDOG_RST_CNT: u64 = 0x14;
pub const REG_SYS_WDOG_CTL: u64 = 0x1C;

pub const REG_SIZE: u64 = 0x44;

pub const WDOG_CTL_EN_IRQ: u32 = 1 << 0;
pub const WDOG_CTL_ACK_IRQ: u32 = 1 << 1;
pub const WDOG_CTL_EN_RESET: u32 = 1 << 2;

pub const WDOG_CNTFRQ_HZ: u64 = 24_000_000;

/// Relative offset serving the C's second MMIO region (scratch RAM).
pub const SCRATCH_OFFSET: u64 = 0x800;

const WORDS: usize = (REG_SIZE / 4) as usize;

/// Apple watchdog (T8030 `wdt` node: two regions, reg + scratch).
#[derive(Debug)]
pub struct AppleWdt {
    reg: [u32; WORDS],
    cntfrq_hz: u64,
    cnt_period_ns: u64,
    /// Virtual clock captured by [`Device::tick`].
    now_ns: u64,
    /// IRQ line (C `irqs[0]`).
    pub irq_level: bool,
    /// Latched when a chip/system watchdog reset fires
    /// (`watchdog_perform_action` equivalent).
    pub reset_pending: bool,
    /// C `s->scratch` (own MMIO region in QEMU; offset 0x800 here).
    pub scratch: u32,
    pub unknown_reads: u64,
    pub unknown_writes: u64,
}

fn wdog_cntfrq_period_ns(cntfrq_hz: u64) -> u64 {
    if 1_000_000_000u64 > cntfrq_hz {
        1_000_000_000 / cntfrq_hz
    } else {
        1
    }
}

impl AppleWdt {
    pub fn new() -> Self {
        let cntfrq_hz = WDOG_CNTFRQ_HZ;
        let mut w = AppleWdt {
            reg: [0; WORDS],
            cntfrq_hz,
            cnt_period_ns: wdog_cntfrq_period_ns(cntfrq_hz),
            now_ns: 0,
            irq_level: false,
            reset_pending: false,
            scratch: 0,
            unknown_reads: 0,
            unknown_writes: 0,
        };
        w.apple_wdt_reset();
        w
    }

    /// `apple_wdt_reset` (legacy reset zeroes the whole register file).
    pub fn apple_wdt_reset(&mut self) {
        self.reg = [0; WORDS];
        self.irq_level = false;
    }

    fn wdt_get_clock(&self) -> u32 {
        (self.now_ns / self.cnt_period_ns) as u32
    }

    fn wdt_get_chip_timer(&self) -> u32 {
        self.wdt_get_clock().wrapping_sub(self.reg[0])
    }

    fn wdt_get_sys_timer(&self) -> u32 {
        self.wdt_get_clock().wrapping_sub(self.reg[4])
    }

    /// `wdt_set_irq`.
    fn set_irq(&mut self, level: bool) {
        self.irq_level = level;
    }

    /// `wdt_update` — evaluate IRQ/reset conditions; called after every
    /// register write and on tick (the C re-arms a "now" timer after
    /// writes and a real deadline timer otherwise).
    pub fn wdt_update(&mut self) {
        let mut expiry: u64 = 0xffff_ffff;
        let chip_tmr = self.wdt_get_chip_timer();
        let sys_tmr = self.wdt_get_sys_timer();

        if self.reg[3] & WDOG_CTL_EN_RESET != 0 {
            // reg.chip_control
            if chip_tmr >= self.reg[1] {
                // reg.chip_reset_counter → watchdog_perform_action()
                self.reset_pending = true;
                self.apple_wdt_reset();
                return;
            } else {
                let d = (self.reg[1] - chip_tmr) as u64;
                expiry = expiry.min(d);
            }
        }

        if self.reg[7] & WDOG_CTL_EN_RESET != 0 {
            // reg.sys_control
            if sys_tmr >= self.reg[5] {
                // reg.sys_reset_counter → watchdog_perform_action()
                self.reset_pending = true;
                self.apple_wdt_reset();
                return;
            } else {
                let d = (self.reg[5] - sys_tmr) as u64;
                expiry = expiry.min(d);
            }
        }

        if self.reg[3] & WDOG_CTL_EN_IRQ != 0 {
            if chip_tmr >= self.reg[2] {
                // reg.chip_interrupt_counter
                if self.reg[3] & WDOG_CTL_ACK_IRQ == 0 {
                    self.reg[3] |= WDOG_CTL_ACK_IRQ;
                    self.set_irq(true);
                }
            } else {
                let d = (self.reg[2] - chip_tmr) as u64;
                expiry = expiry.min(d);
            }
        }

        let _ = expiry * self.cnt_period_ns; // next deadline (host timer)
    }

    /// Clear [`AppleWdt::reset_pending`] after the machine applied it.
    pub fn ack_reset(&mut self) {
        self.reset_pending = false;
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

    fn read(&mut self, addr: u64, _size: u8) -> u64 {
        if addr >= SCRATCH_OFFSET {
            if addr == SCRATCH_OFFSET {
                return self.scratch as u64;
            }
            self.unknown_reads += 1;
            return 0;
        }
        if addr >= REG_SIZE {
            self.unknown_reads += 1; // C: LOG_UNIMP "Bad offset"
            return 0;
        }

        let mut val = self.reg[(addr >> 2) as usize];
        match addr {
            REG_CHIP_WDOG_TMR => val = self.wdt_get_chip_timer(),
            REG_SYS_WDOG_TMR => val = self.wdt_get_sys_timer(),
            _ => {}
        }
        val as u64
    }

    fn write(&mut self, addr: u64, _size: u8, data: u64) {
        if addr >= SCRATCH_OFFSET {
            if addr == SCRATCH_OFFSET {
                self.scratch = data as u32;
            } else {
                self.unknown_writes += 1;
            }
            return;
        }
        if addr >= REG_SIZE {
            self.unknown_writes += 1;
            return;
        }

        let index = (addr >> 2) as usize;
        let mut val = data as u32;

        match addr {
            REG_CHIP_WDOG_TMR | REG_SYS_WDOG_TMR => {
                // Store the complement so reads yield elapsed ticks.
                val = self.wdt_get_clock().wrapping_sub(val);
            }
            REG_CHIP_WDOG_CTL => {
                if val & WDOG_CTL_ACK_IRQ != 0 {
                    self.set_irq(false);
                }
                val &= !WDOG_CTL_ACK_IRQ;
            }
            _ => {}
        }

        self.reg[index] = val;
        // C: timer_mod_ns(now) → evaluate immediately.
        self.wdt_update();
    }

    fn tick(&mut self, now_ns: u64) {
        self.now_ns = now_ns;
        self.wdt_update();
    }
}

pub fn regs_documented() -> &'static [(&'static str, u64)] {
    &[
        ("REG_CHIP_WDOG_TMR", REG_CHIP_WDOG_TMR),
        ("REG_CHIP_WDOG_RST_CNT", REG_CHIP_WDOG_RST_CNT),
        ("REG_CHIP_WDOG_INTR_CNT", REG_CHIP_WDOG_INTR_CNT),
        ("REG_CHIP_WDOG_CTL", REG_CHIP_WDOG_CTL),
        ("REG_SYS_WDOG_TMR", REG_SYS_WDOG_TMR),
        ("REG_SYS_WDOG_RST_CNT", REG_SYS_WDOG_RST_CNT),
        ("REG_SYS_WDOG_CTL", REG_SYS_WDOG_CTL),
        (".scratch (mapped at 0x800)", SCRATCH_OFFSET),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timer_readback_is_elapsed() {
        let mut w = AppleWdt::new();
        // Write "load" value 100 at clock 0 → stored 0-100; at clock 250
        // the read returns 250 - (0-100) mod 2^32 = 350.
        w.write(REG_CHIP_WDOG_TMR, 4, 100);
        w.tick(250 * w.cnt_period_ns);
        assert_eq!(w.read(REG_CHIP_WDOG_TMR, 4), 350);
    }

    #[test]
    fn irq_fires_on_interrupt_counter_and_acks() {
        let mut w = AppleWdt::new();
        w.write(REG_CHIP_WDOG_RST_CNT, 4, 0xFFFF_0000); // far away
        w.write(REG_CHIP_WDOG_INTR_CNT, 4, 100);
        w.write(REG_CHIP_WDOG_CTL, 4, WDOG_CTL_EN_IRQ as u64);
        w.tick(101 * w.cnt_period_ns);
        assert!(w.irq_level);
        // The hardware latches the ACK bit itself when the IRQ fires.
        assert_eq!(
            w.read(REG_CHIP_WDOG_CTL, 4) as u32 & WDOG_CTL_ACK_IRQ,
            WDOG_CTL_ACK_IRQ
        );
        // ACK via write-back on the control register (the C stores the
        // written value minus the ACK bit). The guest must also re-arm
        // the interrupt counter, otherwise wdt_update (called after the
        // write, like the C's timer_mod_ns(now)) re-fires immediately.
        w.write(REG_CHIP_WDOG_INTR_CNT, 4, 300);
        w.write(REG_CHIP_WDOG_CTL, 4, (WDOG_CTL_EN_IRQ | WDOG_CTL_ACK_IRQ) as u64);
        assert!(!w.irq_level);
        w.tick(200 * w.cnt_period_ns);
        assert!(!w.irq_level);
        w.tick(301 * w.cnt_period_ns);
        assert!(w.irq_level, "IRQ re-fires at the new interrupt counter");
    }

    #[test]
    fn reset_counter_fires_reset_pending() {
        let mut w = AppleWdt::new();
        w.write(REG_CHIP_WDOG_RST_CNT, 4, 50);
        w.write(REG_CHIP_WDOG_CTL, 4, WDOG_CTL_EN_RESET as u64);
        w.tick(51 * w.cnt_period_ns);
        assert!(w.reset_pending);
        assert!(w.irq_level == false);
        w.ack_reset();
        assert!(!w.reset_pending);
    }

    #[test]
    fn scratch_region_roundtrip() {
        let mut w = AppleWdt::new();
        w.write(SCRATCH_OFFSET, 4, 0xDEAD_BEEF);
        assert_eq!(w.read(SCRATCH_OFFSET, 4), 0xDEAD_BEEF);
    }
}
