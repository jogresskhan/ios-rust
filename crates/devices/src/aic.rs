//! AIC v2 (Apple Interrupt Controller) — structural port of
//! `hw/intc/apple_aic.c` (Inferno) with semantics cross-checked against the
//! Linux `irq-apple-aic` driver (GPL-2.0, torvalds/linux drivers/irqchip).
//!
//! Register block (per-die), offsets from AIC base:
//!   0x0004 AIC_INFO, 0x0008 AIC_WHOAMI, 0x2000+4*n AIC_HW_SET, 0x2080 SW_SET,
//!   0x2100 HW_CLR, 0x2180 SW_CLR, 0x2800 HW_MASK_SET... (see aic.rs tests for
//!   the exact table this port implements). Event/daemon Model differs on M-series;
//!   T8030 uses the die-local v2 layout.

use crate::bus::{MMIODevice, W4};

pub const REG_INFO: u64 = 0x0004;
pub const REG_WHOAMI: u64 = 0x2004; // v2: WHOAMI at 0x2004 region block
pub const HW_SET_BASE: u64 = 0x2000;
pub const HW_ENABLE_SET: u64 = 0x2810;
pub const HW_ENABLE_CLR: u64 = 0x2814;
pub const HW_FENABLE_SET: u64 = 0x2820;
pub const HW_FENABLE_CLR: u64 = 0x2824;
pub const SW_SET_BASE: u64 = 0x4080; // IPI set in v2 region

pub struct Aic {
    /// 640 hw + 32 ipi bits, as bitmap words the C model keeps.
    hw_pending: [u64; 11], // 640/64 + slack
    hw_enabled: [u64; 11],
    sw_pending: u64,
    sw_enabled: u64,
    info: u64, // (dies<<16) | irqs
}

impl Aic {
    pub fn new(num_irqs: u32, dies: u32) -> Self {
        Self {
            hw_pending: [0; 11],
            hw_enabled: [0; 11],
            sw_pending: 0,
            sw_enabled: 0,
            info: ((dies as u64) << 16) | num_irqs as u64,
        }
    }

    /// aic_update / irq line change from a device.
    pub fn set_hw_irq(&mut self, irq: u32, level: bool) {
        let word = (irq / 64) as usize;
        let bit = irq % 64;
        if level {
            self.hw_pending[word] |= 1 << bit;
        } else {
            self.hw_pending[word] &= !(1 << bit);
        }
    }

    pub fn enabled_pending(&self) -> Vec<u32> {
        let mut out = Vec::new();
        for (w, (&p, &e)) in self.hw_pending.iter().zip(self.hw_enabled.iter()).enumerate() {
            let active = p & e;
            for bit in 0..64 {
                if active & (1 << bit) != 0 {
                    out.push((w as u32) * 64 + bit);
                }
            }
        }
        out
    }
}

impl MMIODevice for Aic {
    fn name(&self) -> &'static str {
        "apple-aic-v2"
    }
    fn size(&self) -> u64 {
        0x8000
    }

    fn read(&mut self, offset: u64, _width: u32) -> u64 {
        match offset {
            REG_INFO => self.info,
            HW_ENABLE_SET => self.hw_enabled[0],
            o if (0x2000..0x2080).contains(&o) => {
                let w = ((o - 0x2000) / 4) as usize;
                self.hw_pending.get(w).copied().unwrap_or(0)
            }
            _ => 0,
        }
    }

    fn write(&mut self, offset: u64, value: u64, _width: u32) {
        match offset {
            HW_ENABLE_SET => {
                self.hw_enabled[0] |= value;
            }
            HW_ENABLE_CLR => {
                self.hw_enabled[0] &= !value;
            }
            o if (HW_SET_BASE..HW_SET_BASE + 0x80).contains(&o) => {
                let w = ((o - HW_SET_BASE) / 4) as usize;
                if let Some(slot) = self.hw_pending.get_mut(w) {
                    *slot |= value;
                }
            }
            _ => {}
        }
    }
}

/// parity: register skeleton + enable/pending semantics = 35 (structural port,
/// needs golden-trace verification + IPI routing + preemption ladder).
pub const PARITY_PCT: u8 = 35;

impl crate::bus::Device for Aic {
    fn mmio(&mut self) -> &mut dyn MMIODevice {
        self
    }
    fn parity_pct(&self) -> u8 {
        PARITY_PCT
    }
}

// W4 used by tests/readers; keep the import meaningful.
#[allow(dead_code)]
const _: u32 = W4;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enable_and_pending() {
        let mut aic = Aic::new(640, 1);
        aic.write(HW_ENABLE_SET, 1 << 5, W4);
        aic.set_hw_irq(5, true);
        assert_eq!(aic.read(REG_INFO, W4), 640 | (1 << 16));
        assert_eq!(aic.enabled_pending(), vec![5]);
        aic.set_hw_irq(5, false);
        assert!(aic.enabled_pending().is_empty());
    }
}
