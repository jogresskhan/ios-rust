//! aic — Apple Interrupt Controller (AIC v2) — port of Inferno
//! `hw/intc/apple_aic.c`. Register map is exact; arbitration modeled for
//! one visible CPU (the machine runs one guest core in the Rust port).

use vm_core::Device;

pub const REG_AIC_REV: u64 = 0x0000;
pub const REG_AIC_CAP0: u64 = 0x0004;
pub const REG_AIC_CAP1: u64 = 0x0008;
pub const REG_AIC_RST: u64 = 0x000C;
pub const REG_AIC_GLB_CFG: u64 = 0x0010;
pub const REG_AIC_WHOAMI: u64 = 0x2000;
pub const REG_AIC_IACK: u64 = 0x2004;
// BITSET/BITCLR banks for ENABLE/PEND per group of 32 IRQs.
pub const REG_AIC_INTERRUPT_ENABLE: u64 = 0x4100;
pub const REG_AIC_INTERRUPT_PEND: u64 = 0x4180;
pub const REG_AIC_SW_SET: u64 = 0x4D00;
pub const REG_AIC_SW_CLR: u64 = 0x4D80;

const MAX_IRQ: usize = 640;

pub struct Aic {
    pub num_irqs: u32,
    enabled: [u64; MAX_IRQ / 64],
    pending_hw: [u64; MAX_IRQ / 64],
    pending_sw: [u64; MAX_IRQ / 64],
    pub unknown_reads: u64,
    pub unknown_writes: u64,
}

impl Aic {
    pub fn new(num_irqs: u32) -> Self {
        Aic {
            num_irqs: num_irqs.min(640),
            enabled: [0; MAX_IRQ / 64],
            pending_hw: [0; MAX_IRQ / 64],
            pending_sw: [0; MAX_IRQ / 64],
            unknown_reads: 0,
            unknown_writes: 0,
        }
    }

    /// Device-side IRQ line assertion (QEMU: apple_aic_set_sw / hw irq).
    pub fn set_irq(&mut self, num: u32, level: bool) {
        let (w, b) = ((num / 64) as usize, num % 64);
        if level {
            self.pending_hw[w] |= 1 << b;
        } else {
            self.pending_hw[w] &= !(1 << b);
        }
    }

    pub fn any_pending(&self) -> bool {
        (0..(self.num_irqs / 64) as usize)
            .any(|w| (self.pending_hw[w] | self.pending_sw[w]) & self.enabled[w] != 0)
    }

    fn read_bank(&self, base_off: u64, off: u64) -> u64 {
        let idx = ((off - base_off) / 4) as usize;
        let w = (idx / 2) as usize;
        match w {
            _ if idx % 2 == 0 && w < MAX_IRQ / 64 => match base_off {
                REG_AIC_INTERRUPT_ENABLE => self.enabled[w],
                REG_AIC_INTERRUPT_PEND => self.pending_hw[w] | self.pending_sw[w],
                REG_AIC_SW_SET => self.pending_sw[w],
                _ => 0,
            },
            _ => 0,
        }
    }

    fn write_bank(&mut self, base_off: u64, off: u64, val: u64) {
        let idx = ((off - base_off) / 4) as usize;
        let w = (idx / 2) as usize;
        if w >= MAX_IRQ / 64 {
            return;
        }
        match base_off {
            REG_AIC_INTERRUPT_ENABLE => {
                if idx % 2 == 0 {
                    self.enabled[w] |= val;
                } else {
                    self.enabled[w] &= !val;
                }
            }
            REG_AIC_SW_SET => {
                if idx % 2 == 0 {
                    self.pending_sw[w] |= val;
                } else {
                    self.pending_sw[w] &= !val;
                }
            }
            REG_AIC_SW_CLR => {
                if idx % 2 == 0 {
                    self.pending_sw[w] &= !val;
                }
            }
            _ => {}
        }
    }

    pub fn regs_documented() -> &'static [(&'static str, u64)] {
        &[
            ("REV", REG_AIC_REV),
            ("CAP0", REG_AIC_CAP0),
            ("CAP1", REG_AIC_CAP1),
            ("RST", REG_AIC_RST),
            ("GLB_CFG", REG_AIC_GLB_CFG),
            ("WHOAMI", REG_AIC_WHOAMI),
            ("IACK", REG_AIC_IACK),
            ("ENABLE_SET", REG_AIC_INTERRUPT_ENABLE),
            ("PEND", REG_AIC_INTERRUPT_PEND),
            ("SW_SET", REG_AIC_SW_SET),
            ("SW_CLR", REG_AIC_SW_CLR),
        ]
    }
}

impl Device for Aic {
    fn name(&self) -> &'static str {
        "aic"
    }
    fn read(&mut self, off: u64, _size: u8) -> u64 {
        match off {
            REG_AIC_REV => 0x1, // aic,1
            REG_AIC_CAP0 => self.num_irqs.min(640),
            REG_AIC_CAP1 => 0x0,
            REG_AIC_WHOAMI => 0x0, // CPU0
            REG_AIC_IACK => {
                for w in 0..(self.num_irqs / 64) as usize {
                    let pend = (self.pending_hw[w] | self.pending_sw[w]) & self.enabled[w];
                    if pend != 0 {
                        let b = pend.trailing_zeros();
                        let irq = (w * 64) as u32 + b;
                        // ack: clear SW, HW stays until device deasserts
                        self.pending_sw[w] &= !(1 << b);
                        return irq as u64;
                    }
                }
                0xFFFF_FFFF // spurious
            }
            off if (REG_AIC_INTERRUPT_ENABLE..REG_AIC_INTERRUPT_ENABLE + 0x100).contains(&off) => {
                self.read_bank(REG_AIC_INTERRUPT_ENABLE, off)
            }
            off if (REG_AIC_INTERRUPT_PEND..REG_AIC_INTERRUPT_PEND + 0x100).contains(&off) => {
                self.read_bank(REG_AIC_INTERRUPT_PEND, off)
            }
            off if (REG_AIC_SW_SET..REG_AIC_SW_SET + 0x100).contains(&off) => {
                self.read_bank(REG_AIC_SW_SET, off)
            }
            _ => {
                self.unknown_reads += 1;
                0
            }
        }
    }
    fn write(&mut self, off: u64, _size: u8, val: u64) {
        match off {
            REG_AIC_RST => {
                self.enabled = [0; MAX_IRQ / 64];
                self.pending_hw = [0; MAX_IRQ / 64];
                self.pending_sw = [0; MAX_IRQ / 64];
            }
            off if (REG_AIC_INTERRUPT_ENABLE..REG_AIC_INTERRUPT_ENABLE + 0x100).contains(&off) => {
                self.write_bank(REG_AIC_INTERRUPT_ENABLE, off, val)
            }
            off if (REG_AIC_SW_SET..REG_AIC_SW_SET + 0x100).contains(&off) => {
                self.write_bank(REG_AIC_SW_SET, off, val)
            }
            off if (REG_AIC_SW_CLR..REG_AIC_SW_CLR + 0x100).contains(&off) => {
                self.write_bank(REG_AIC_SW_CLR, off, val)
            }
            _ => self.unknown_writes += 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn enable_iack_order() {
        let mut a = Aic::new(640);
        a.set_irq(5, true);
        a.write(REG_AIC_INTERRUPT_ENABLE + 4, 4, 1 << 5); // enable SET word for irq5
        assert_eq!(a.read(REG_AIC_IACK, 4), 5);
        assert_eq!(a.read(REG_AIC_IACK, 4), 0xFFFF_FFFF); // acked
    }
}
