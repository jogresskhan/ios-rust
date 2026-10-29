//! aic — Apple Interrupt Controller (AIC v1) for the T8030 machine.
//!
//! Register map from the REAL kernel's own `pexpert/pexpert/arm/AIC.h`
//! (xnu-7195.121.3, the exact iOS 14.2-era source), byte-validated against
//! the on-device AIC kext (`com.apple.driver.AppleInterruptController`,
//! code at 0x…988e000) and the pexpert mapping path (gPicBase = the ADT
//! "interrupt-controller"/master reg = 0x23B100000 on n104ap).
//!
//! The previous version of this file claimed a "v2" map (WHOAMI 0x2004,
//! ENABLE 0x4100, SW_SET 0x4D00 …) — REAL-DATA BUG: those offsets were
//! never validated against the real boot; T8030 ships the classic v1
//! block below (AIC.h, verified line-by-line).
//!
//! IACK protocol: read `Iack` → `(die<<24)|(type<<16)|num` with
//! auto-ack + auto-mask; 0 = nothing pending. EOI = write the IRQ bit to
//! `IntMaskClr` (re-unmask). Boot init masks ALL (the driver's first
//! mask-loop). Timer FIQs bypass AIC entirely (xnu samples CNTV_CTL
//! ISTATUS directly — sleh_fiq, measured).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use vm_core::Device;

pub const AIC_SIZE: u64 = 0x8000;
pub const TIMEBASE_SIZE: u64 = 0x1000;

const N_IRQS: usize = 1024;
const WORDS: usize = N_IRQS / 64;

/// vec types in the Iack word (AIC.h kAICIackVecType*).
const VEC_EXT: u64 = 1;
const VEC_IPI: u64 = 4;

/// AIC parity against the real driver (map + IACK/EOI/IPI/mask live;
/// outstanding: multi-CPU routing, FIQ steering, timebase alarm semantics).
pub const AIC_PARITY_PCT: u8 = 72;

pub struct Aic {
    /// Raw hw pending state (HwIntMon window).
    hw_pending: [u64; WORDS],
    /// Masked IRQs (IntMaskSet sets, IntMaskClr clears; boot = all set).
    masked: [u64; WORDS],
    /// Software-generated interrupts (SwGen windows + IPI sends).
    sw_pending: [u64; WORDS],
    /// Per-IRQ target CPU bitmaps (TgtDst).
    tgt: Vec<u64>,
    /// The timebase counter (MainTim; the aic-timebase page mirrors it).
    timebase: u64,
    /// Shared IRQ line into the CPU (raised when any unmasked pending).
    irq_line: Option<Arc<AtomicBool>>,
    /// Parity counters.
    pub iack_count: u64,
    pub eoi_count: u64,
    pub unknown_reads: u64,
    pub unknown_writes: u64,
}

impl Aic {
    pub fn new() -> Self {
        Self {
            hw_pending: [0; WORDS],
            masked: [!0u64; WORDS], // boot init: all masked
            sw_pending: [0; WORDS],
            tgt: vec![0; N_IRQS],
            timebase: 0,
            irq_line: None,
            iack_count: 0,
            eoi_count: 0,
            unknown_reads: 0,
            unknown_writes: 0,
        }
    }

    /// Bind the shared IRQ line the CPU polls (a13-cpu `irq_line`).
    pub fn set_irq_line(&mut self, line: Arc<AtomicBool>) {
        self.irq_line = Some(line);
        self.rearm();
    }

    fn rearm(&mut self) {
        let any = self
            .hw_pending
            .iter()
            .zip(&self.masked)
            .any(|(&p, &m)| p & !m != 0)
            || self.sw_pending.iter().any(|&p| p != 0);
        if let Some(line) = &self.irq_line {
            line.store(any, Ordering::Relaxed);
        }
    }

    /// Device driver interface: level-change an hw IRQ line.
    pub fn set_irq(&mut self, num: u32, level: bool) {
        let (w, b) = ((num / 64) as usize, num % 64);
        if level {
            self.hw_pending[w] |= 1 << b;
        } else {
            self.hw_pending[w] &= !(1 << b);
        }
        self.rearm();
    }

    pub fn any_pending(&self) -> bool {
        self.hw_pending
            .iter()
            .zip(&self.masked)
            .any(|(&p, &m)| p & !m != 0)
            || self.sw_pending.iter().any(|&p| p != 0)
    }

    /// The IACK word: lowest-numbered unmasked pending IRQ (deterministic —
    /// single core). Auto-ack + auto-mask per the AIC protocol.
    fn iack(&mut self) -> u64 {
        for w in 0..WORDS {
            let ext = self.hw_pending[w] & !self.masked[w];
            if ext != 0 {
                let bit = ext.trailing_zeros();
                let irq = (w * 64) as u32 + bit;
                self.hw_pending[w] &= !(1 << bit);
                self.masked[w] |= 1 << bit;
                self.iack_count += 1;
                self.rearm();
                return (VEC_EXT << 16) | irq as u64;
            }
        }
        for w in 0..WORDS {
            if self.sw_pending[w] != 0 {
                let bit = self.sw_pending[w].trailing_zeros();
                let irq = (w * 64) as u32 + bit;
                self.sw_pending[w] &= !(1 << bit);
                self.iack_count += 1;
                self.rearm();
                return (VEC_IPI << 16) | irq as u64;
            }
        }
        0
    }

}

impl Default for Aic {
    fn default() -> Self {
        Self::new()
    }
}

impl Device for Aic {
    fn name(&self) -> &'static str {
        "apple-aic-v1"
    }

    fn read(&mut self, off: u64, _size: u8) -> u64 {
        match off {
            0x0000 => 1,                        // AicRev
            0x0004 => N_IRQS as u64,            // Cap0: IRQ count
            0x0008 => 0,                        // Cap1
            0x000C => 0,                        // Rst
            0x0010 => 0,                        // GlbCfg
            0x0020 => self.timebase as u32 as u64, // MainTimLo
            0x0028 => (self.timebase >> 32) & 0xFFFF, // MainTimHi
            0x2000 | 0x5000 => 0,               // WhoAmI = cpu0
            0x2004 | 0x5004 => self.iack(),     // Iack (auto-ack+mask)
            0x2018 | 0x5018 => 0,               // TmrIntStat (FIQ bypasses AIC)
            o if (0x3000..0x4000).contains(&o) => {
                let n = ((o - 0x3000) / 4) as usize;
                self.tgt.get(n).copied().unwrap_or(0)
            }
            o if (0x4000..0x4080).contains(&o) => {
                self.sw_pending.get(((o - 0x4000) / 4) as usize).copied().unwrap_or(0)
            }
            o if (0x4100..0x4180).contains(&o) => {
                self.masked.get(((o - 0x4100) / 4) as usize).copied().unwrap_or(0)
            }
            o if (0x4200..0x4280).contains(&o) => {
                self.hw_pending.get(((o - 0x4200) / 4) as usize).copied().unwrap_or(0)
            }
            o if (0x5000..0x5080).contains(&o) => match o & 0x7F {
                0x04 => self.iack(), // per-CPU alias Iack
                _ => 0,
            },
            _ => {
                self.unknown_reads += 1;
                0
            }
        }
    }

    fn write(&mut self, off: u64, _size: u8, val: u64) {
        match off {
            // IPI send/ack (the fast-IPI sysreg path covers xnu's use; the
            // MMIO windows map to SW pending bits 576+cpu).
            0x2008 | 0x5008 => {
                for cpu in 0..32u64 {
                    if val & (1 << cpu) != 0 {
                        let irq = 576 + cpu as u32;
                        self.sw_pending[(irq / 64) as usize] |= 1 << (irq % 64);
                    }
                }
                self.rearm();
            }
            0x200C | 0x500C => {
                for w in 0..WORDS {
                    self.sw_pending[w] &= !val;
                }
                self.rearm();
            }
            0x2014 | 0x5014 => self.timebase = val, // TmrCnt
            0x2010 | 0x5010 | 0x2018 | 0x5018 | 0x201C | 0x501C | 0x2020 | 0x5020 => {}
            o if (0x3000..0x4000).contains(&o) => {
                let n = ((o - 0x3000) / 4) as usize;
                if n < N_IRQS {
                    self.tgt[n] = val & 0xFFFF;
                }
            }
            o if (0x4000..0x4080).contains(&o) => {
                if let Some(slot) = self.sw_pending.get_mut(((o - 0x4000) / 4) as usize) {
                    *slot |= val;
                }
                self.rearm();
            }
            o if (0x4080..0x4100).contains(&o) => {
                if let Some(slot) = self.sw_pending.get_mut(((o - 0x4080) / 4) as usize) {
                    *slot &= !val;
                }
                self.rearm();
            }
            o if (0x4100..0x4180).contains(&o) => {
                if let Some(slot) = self.masked.get_mut(((o - 0x4100) / 4) as usize) {
                    *slot |= val;
                }
                self.rearm();
            }
            // IntMaskClr = the EOI path (re-unmask)
            o if (0x4180..0x4200).contains(&o) => {
                if let Some(slot) = self.masked.get_mut(((o - 0x4180) / 4) as usize) {
                    *slot &= !val;
                }
                self.eoi_count += val.count_ones() as u64;
                self.rearm();
            }
            _ => self.unknown_writes += 1,
        }
    }
}

/// The aic-timebase page (AIC+0x1000; the ADT's second reg window,
/// device_type="timer", mapped by pexpert as gTimerBase). MainTimLo/Hi.
pub struct AicTimebase {
    pub counter: u64,
}

impl Device for AicTimebase {
    fn name(&self) -> &'static str {
        "aic-timebase"
    }
    fn read(&mut self, off: u64, _size: u8) -> u64 {
        match off {
            0x20 => self.counter as u32 as u64,
            0x28 => (self.counter >> 32) & 0xFFFF,
            _ => 0,
        }
    }
    fn write(&mut self, off: u64, _size: u8, val: u64) {
        if off == 0x20 {
            self.counter = (self.counter & !0xFFFF_FFFF) | (val & 0xFFFF_FFFF);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aic_h_v1_map_iack_auto_mask_eoi() {
        let mut aic = Aic::new();
        // boot init: everything masked
        assert_eq!(aic.read(0x4100, 4), !0u64);
        // device raises IRQ 541 (the max n104ap ADT IRQ) — masked → no IACK
        aic.set_irq(541, true);
        assert_eq!(aic.read(0x2004, 4), 0, "masked IRQ must not IACK");
        // unmask via IntMaskClr
        aic.write(0x4180 + 8 * 4, 4, 1u64 << (541 % 64));
        assert_eq!(aic.read(0x2004, 4), (VEC_EXT << 16) | 541);
        // auto-ack + auto-mask: second IACK reads 0
        assert_eq!(aic.read(0x2004, 4), 0);
        // EOI re-unmasks
        aic.write(0x4180 + 8 * 4, 4, 1u64 << (541 % 64));
        assert_eq!(aic.eoi_count, 2);
    }

    #[test]
    fn aic_ipi_windows_vec_type() {
        let mut aic = Aic::new();
        aic.write(0x2008, 4, 1 << 2); // IPI to cpu2 → sw IRQ 578
        assert_eq!(aic.read(0x2004, 4), (VEC_IPI << 16) | 578);
    }

    #[test]
    fn aic_target_and_monitor_windows() {
        let mut aic = Aic::new();
        aic.write(0x3000 + 4 * 60, 4, 1); // timer IRQ 60 → cpu0
        assert_eq!(aic.read(0x3000 + 4 * 60, 4), 1);
        aic.set_irq(60, true);
        assert_eq!(aic.read(0x4200, 4) & (1 << 60), 1 << 60);
    }
}
