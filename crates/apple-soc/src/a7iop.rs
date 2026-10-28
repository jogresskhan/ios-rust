//! a7iop — Apple A7IOP core (port of hw/misc/apple-silicon/a7iop/
//! {core,regs-v2,regs-v4}.c): the RTKit companion-processor block with the
//! CPU start/status control and the v2 (A7–A11) vs v4 ("AKF", T8020+)
//! register tables around the A7IOP mailbox. AOP/SMC/SEP-style devices
//! instantiate this with their role name and map their mailbox windows.
//!
//! Upstream maps the paired mailbox objects at 0xB80/0x4000 (v2) or
//! 0x4100/0x8100 (v4); both windows route into the single collapsed
//! [`A7IopMailbox`] (see a7iop_mailbox.rs).

use vm_core::Device;
pub use crate::a7iop_mailbox::{A7IopMailbox, A7IopVersion};

// ---- CPU control (a7iop/core.h, a7iop/private.h) ----
pub const CPU_CTRL_RUN: u32 = 1 << 4;
pub const SEP_BOOT_MONITOR_RUN: u32 = 1 << 16;
pub const CPU_STATUS_IDLE: u32 = 0x1;
pub const AKF_STRIDE: u64 = 0x4000;

// ---- shared core registers (both variants) ----
pub const REG_CPU_CTRL: u64 = 0x44;
pub const REG_CPU_STATUS: u64 = 0x48;

// ---- v2 register map (a7iop/regs-v2.c) ----
pub const V2_AXI_BASE_LO: u64 = 0x8;
pub const V2_AXI_BASE_HI: u64 = 0x10;
pub const V2_AXI_START_LO: u64 = 0x18;
pub const V2_AXI_START_HI: u64 = 0x20;
pub const V2_AXI_END_LO: u64 = 0x28;
pub const V2_AXI_END_HI: u64 = 0x30;
pub const V2_REMAP_0: u64 = 0x38;
pub const V2_REMAP_1: u64 = 0x3C;
pub const V2_KIC_GLB_CFG: u64 = 0x80C;
pub const KIC_GLB_CFG_TIMER_EN: u32 = 1 << 1;
pub const V2_KIC_MAILBOX_EXT_SET: u64 = 0xC00;
pub const V2_KIC_MAILBOX_EXT_CLR: u64 = 0xC04;
pub const V2_IDLE_STATUS: u64 = 0x4040;
pub const V2_KIC_TMR_CFG1: u64 = 0xC000;
pub const KIC_TMR_CFG_FSL_TIMER: u32 = 0 << 4;
pub const KIC_TMR_CFG_FSL_SW: u32 = 1 << 4;
pub const KIC_TMR_CFG_FSL_EXTERNAL: u32 = 2 << 4;
pub const KIC_TMR_CFG_SMD_FIQ: u32 = 0 << 3;
pub const KIC_TMR_CFG_SMD_IRQ: u32 = 1 << 3;
pub const KIC_TMR_CFG_EMD_IRQ: u32 = 1 << 2;
pub const KIC_TMR_CFG_IMD_FIQ: u32 = 0 << 1;
pub const KIC_TMR_CFG_IMD_IRQ: u32 = 1 << 1;
pub const KIC_TMR_CFG_EN: u32 = 1 << 0;
pub const KIC_TMR_CFG_NMI: u32 =
    KIC_TMR_CFG_FSL_SW | KIC_TMR_CFG_SMD_FIQ | KIC_TMR_CFG_IMD_FIQ | KIC_TMR_CFG_EN;
pub const V2_KIC_TMR_CFG2: u64 = 0xC004;
pub const V2_KIC_TMR_ISR: u64 = 0xC018;
pub const V2_KIC_TMR_STATE_SET1: u64 = 0xC020;
pub const KIC_TMR_STATE_SET_SGT: u32 = 1 << 0;
pub const V2_KIC_TMR_STATE_SET2: u64 = 0xC024;
pub const V2_KIC_GLB_TIME_BASE_LO: u64 = 0xC030;
pub const V2_KIC_GLB_TIME_BASE_HI: u64 = 0xC038;
/// C: `IOP_MAILBOX_REG_BASE` — the iop mailbox window on the outer regs.
pub const V2_IOP_MAILBOX_REG_BASE: u64 = 0xB80;

// ---- v4 ("AKF") register map (a7iop/regs-v4.c) ----
pub const V4_AXI_CTRL: u64 = 0x38;
pub const AXI_CTRL_RUN: u32 = 1 << 0;
pub const V4_UNKNOWN_40: u64 = 0x40;
pub const V4_UNKNOWN_4C: u64 = 0x4C;
pub const V4_KIC_GLB_CFG: u64 = 0x80C;
/// "akf: READ IRQ %x"
pub const V4_INTERRUPT_STATUS: u64 = 0x81C;
pub const V4_SEP_AKF_DISABLE_INTERRUPT_BASE: u64 = 0xA00;
pub const V4_SEP_AKF_ENABLE_INTERRUPT_BASE: u64 = 0xA80;
pub const V4_KIC_TMR0_EN: u64 = 0xC00;
pub const V4_KIC_TMR1_EN: u64 = 0xC04;
pub const V4_KIC_TMR0_INT_MASK_SET: u64 = 0xC10;
pub const V4_KIC_TMR1_INT_MASK_SET: u64 = 0xC14;
pub const V4_KIC_TMR0_INT_MASK_CLR: u64 = 0xC18;
pub const V4_KIC_TMR1_INT_MASK_CLR: u64 = 0xC1C;
pub const V4_IDLE_STATUS: u64 = 0x8000;
pub const V4_KIC_TMR_CFG1: u64 = 0x10000;
pub const KIC_TMR_CFG_EMD_FIQ: u32 = 0 << 2;
pub const V4_KIC_TMR_CFG2: u64 = 0x10004;
pub const V4_KIC_TMR_STATE_SET1: u64 = 0x10020;
pub const V4_KIC_TMR_STATE_SET2: u64 = 0x10024;
pub const V4_KIC_GLB_TIME_BASE_LO: u64 = 0x10030;
pub const V4_KIC_GLB_TIME_BASE_HI: u64 = 0x10038;
pub const AKF_MAILBOX_OFF: u64 = 0x100;
/// iop mailbox window (C: AKF_STRIDE + AKF_MAILBOX_OFF).
pub const V4_IOP_MAILBOX_BASE: u64 = AKF_STRIDE + AKF_MAILBOX_OFF;
/// ap mailbox window (C: AKF_STRIDE * 2 + AKF_MAILBOX_OFF).
pub const V4_AP_MAILBOX_BASE: u64 = AKF_STRIDE * 2 + AKF_MAILBOX_OFF;

use crate::a7iop_mailbox::{MBOX_V2_SIZE, MBOX_V4_SIZE};

pub struct A7Iop {
    pub role: &'static str,
    pub variant: A7IopVersion,
    pub mmio_size: u64,
    pub mailbox: A7IopMailbox,
    pub cpu_status: u32,
    pub cpu_ctrl: u32,
    /// Set by cpu_start (C: ops->start callback).
    pub started: bool,
    /// C: ops->start invocations (machine glue polls instead of QEMU BHs).
    pub start_requests: u64,
    /// C: ops->wakeup invocations.
    pub wake_requests: u64,
    pub guest_errors: u64,
    pub unknown_reads: u64,
    pub unknown_writes: u64,
}

impl A7Iop {
    pub fn new(role: &'static str, variant: A7IopVersion, mmio_size: u64) -> Self {
        let mut s = A7Iop {
            role,
            variant,
            mmio_size,
            mailbox: A7IopMailbox::new(role, variant),
            cpu_status: 0,
            cpu_ctrl: 0,
            started: false,
            start_requests: 0,
            wake_requests: 0,
            guest_errors: 0,
            unknown_reads: 0,
            unknown_writes: 0,
        };
        s.reset();
        s
    }

    /// C: `apple_a7iop_reset` — CPU starts idle.
    pub fn reset(&mut self) {
        self.cpu_status = CPU_STATUS_IDLE;
    }

    /// C: `apple_a7iop_cpu_start` — clear IDLE and request a start/wake
    /// unless the core is already awake (SEP skips the check via
    /// SEP_BOOT_MONITOR_RUN).
    pub fn cpu_start(&mut self, wake: bool) {
        if (self.cpu_ctrl & SEP_BOOT_MONITOR_RUN) == 0
            && (self.cpu_status & CPU_STATUS_IDLE) == 0
        {
            // Already awake - do nothing.
            return;
        }
        self.cpu_status &= !CPU_STATUS_IDLE;
        // C: s->ops->start / s->ops->wakeup.
        if wake {
            self.wake_requests += 1;
        } else {
            self.started = true;
            self.start_requests += 1;
        }
    }

    /// C: `apple_a7iop_set_cpu_ctrl` — RUN bits trigger cpu_start.
    pub fn set_cpu_ctrl(&mut self, value: u32) {
        self.cpu_ctrl = value;
        if (value & (CPU_CTRL_RUN | SEP_BOOT_MONITOR_RUN)) != 0 {
            self.cpu_start(false);
        }
    }

    /// Route an outer offset into the mailbox window; returns the
    /// mailbox-relative offset (C: memory_region_add_subregion_overlap).
    fn route_mailbox(&self, off: u64) -> Option<u64> {
        match self.variant {
            A7IopVersion::V2 => {
                let iop = V2_IOP_MAILBOX_REG_BASE..V2_IOP_MAILBOX_REG_BASE + MBOX_V2_SIZE;
                let ap = AKF_STRIDE..AKF_STRIDE + MBOX_V2_SIZE;
                if iop.contains(&off) {
                    Some(off - V2_IOP_MAILBOX_REG_BASE)
                } else if ap.contains(&off) {
                    Some(off - AKF_STRIDE)
                } else {
                    None
                }
            }
            A7IopVersion::V4 => {
                let iop = V4_IOP_MAILBOX_BASE..V4_IOP_MAILBOX_BASE + MBOX_V4_SIZE;
                let ap = V4_AP_MAILBOX_BASE..V4_AP_MAILBOX_BASE + MBOX_V4_SIZE;
                if iop.contains(&off) {
                    Some(off - V4_IOP_MAILBOX_BASE)
                } else if ap.contains(&off) {
                    Some(off - V4_AP_MAILBOX_BASE)
                } else {
                    None
                }
            }
        }
    }

    // ---- v2 core regs (C: apple_a7iop_v2_reg_*) ----

    fn read_v2(&mut self, off: u64) -> u64 {
        match off {
            REG_CPU_CTRL => self.cpu_ctrl as u64,
            REG_CPU_STATUS => self.cpu_status as u64,
            _ => {
                self.unknown_reads += 1;
                0
            }
        }
    }

    fn write_v2(&mut self, off: u64, val: u64) {
        match off {
            REG_CPU_CTRL => self.set_cpu_ctrl(val as u32),
            REG_CPU_STATUS => self.cpu_status = val as u32,
            _ => {
                self.unknown_writes += 1;
            }
        }
    }

    // ---- v4 core regs (C: apple_a7iop_v4_reg_*) ----

    fn read_v4(&mut self, off: u64) -> u64 {
        match off {
            REG_CPU_CTRL => self.cpu_ctrl as u64,
            REG_CPU_STATUS => self.cpu_status as u64,
            // TODO upstream: response not interrupt available, but something
            // with REG_V3_CPU_CTRL?
            V4_UNKNOWN_4C => 1,
            off if (V4_SEP_AKF_DISABLE_INTERRUPT_BASE
                ..V4_SEP_AKF_DISABLE_INTERRUPT_BASE + 0x10)
                .contains(&off) =>
            {
                // Shows disabled as 0b1, not enabled!
                let g = ((off - V4_SEP_AKF_DISABLE_INTERRUPT_BASE) >> 2) as usize;
                (!self.mailbox.interrupts_enabled[g]) as u64
            }
            off if (V4_SEP_AKF_ENABLE_INTERRUPT_BASE
                ..V4_SEP_AKF_ENABLE_INTERRUPT_BASE + 0x10)
                .contains(&off) =>
            {
                let g = ((off - V4_SEP_AKF_ENABLE_INTERRUPT_BASE) >> 2) as usize;
                (!self.mailbox.interrupts_enabled[g]) as u64
            }
            V4_KIC_GLB_CFG => self.mailbox.glb_cfg as u64,
            V4_INTERRUPT_STATUS => self.mailbox.read_interrupt_status() as u64,
            V4_KIC_TMR0_EN => self.mailbox.timer0_enabled as u64,
            V4_KIC_TMR1_EN => self.mailbox.timer1_enabled as u64,
            V4_KIC_TMR0_INT_MASK_SET | V4_KIC_TMR0_INT_MASK_CLR => {
                self.mailbox.timer0_masked as u64
            }
            V4_KIC_TMR1_INT_MASK_SET | V4_KIC_TMR1_INT_MASK_CLR => {
                self.mailbox.timer1_masked as u64
            }
            _ => {
                self.unknown_reads += 1;
                0
            }
        }
    }

    fn write_v4(&mut self, off: u64, val: u64) {
        match off {
            REG_CPU_CTRL => self.set_cpu_ctrl(val as u32),
            off if (V4_SEP_AKF_DISABLE_INTERRUPT_BASE
                ..V4_SEP_AKF_DISABLE_INTERRUPT_BASE + 0x10)
                .contains(&off) =>
            {
                let g = ((off - V4_SEP_AKF_DISABLE_INTERRUPT_BASE) >> 2) as usize;
                self.mailbox.interrupts_enabled[g] &= !(val as u32);
                self.mailbox.update_irq();
            }
            off if (V4_SEP_AKF_ENABLE_INTERRUPT_BASE
                ..V4_SEP_AKF_ENABLE_INTERRUPT_BASE + 0x10)
                .contains(&off) =>
            {
                let g = ((off - V4_SEP_AKF_ENABLE_INTERRUPT_BASE) >> 2) as usize;
                self.mailbox.interrupts_enabled[g] |= val as u32;
                self.mailbox.update_irq();
            }
            V4_KIC_GLB_CFG => {
                self.mailbox.glb_cfg = val as u32;
                self.mailbox.update_irq();
            }
            V4_KIC_TMR0_EN => {
                self.mailbox.timer0_enabled = val as u32;
                self.mailbox.update_irq();
            }
            V4_KIC_TMR1_EN => {
                self.mailbox.timer1_enabled = val as u32;
                self.mailbox.update_irq();
            }
            V4_KIC_TMR0_INT_MASK_SET => {
                self.mailbox.timer0_masked |= val as u32;
                self.mailbox.update_irq();
            }
            V4_KIC_TMR0_INT_MASK_CLR => {
                self.mailbox.timer0_masked &= !(val as u32);
                self.mailbox.update_irq();
            }
            V4_KIC_TMR1_INT_MASK_SET => {
                self.mailbox.timer1_masked |= val as u32;
                self.mailbox.update_irq();
            }
            V4_KIC_TMR1_INT_MASK_CLR => {
                self.mailbox.timer1_masked &= !(val as u32);
                self.mailbox.update_irq();
            }
            _ => {
                self.unknown_writes += 1;
            }
        }
    }

    pub fn regs_documented() -> &'static [(&'static str, u64)] {
        &[
            ("CPU_CTRL", REG_CPU_CTRL),
            ("CPU_STATUS", REG_CPU_STATUS),
            ("V2_IOP_MAILBOX", V2_IOP_MAILBOX_REG_BASE),
            ("V2_AP_MAILBOX", AKF_STRIDE),
            ("V4_INTERRUPT_STATUS", V4_INTERRUPT_STATUS),
            ("V4_SEP_AKF_ENABLE_INTERRUPT", V4_SEP_AKF_ENABLE_INTERRUPT_BASE),
            ("V4_IOP_MAILBOX", V4_IOP_MAILBOX_BASE),
            ("V4_AP_MAILBOX", V4_AP_MAILBOX_BASE),
        ]
    }
}

impl Default for A7Iop {
    fn default() -> Self {
        Self::new("aop", A7IopVersion::V4, 0x14000)
    }
}

impl Device for A7Iop {
    fn name(&self) -> &'static str {
        self.role
    }
    fn read(&mut self, off: u64, size: u8) -> u64 {
        if let Some(moff) = self.route_mailbox(off) {
            return self.mailbox.read(moff, size);
        }
        match self.variant {
            A7IopVersion::V2 => self.read_v2(off),
            A7IopVersion::V4 => self.read_v4(off),
        }
    }
    fn write(&mut self, off: u64, size: u8, val: u64) {
        if let Some(moff) = self.route_mailbox(off) {
            self.mailbox.write(moff, size, val);
            return;
        }
        match self.variant {
            A7IopVersion::V2 => self.write_v2(off, val),
            A7IopVersion::V4 => self.write_v4(off, val),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::a7iop_mailbox::{
        AP_EMPTY, CTRL_COUNT_SHIFT, IRQ_IOP_NONEMPTY, IRQ_SEP_TIMER0, REG_KIC_TMR_EN_MASK,
    };

    #[test]
    fn v2_cpu_start_then_already_awake() {
        let mut iop = A7Iop::new("aop", A7IopVersion::V2, 0xC040);
        assert_eq!(iop.read(REG_CPU_STATUS, 4), CPU_STATUS_IDLE as u64);
        // RUN write starts the coprocessor and clears IDLE.
        iop.write(REG_CPU_CTRL, 4, CPU_CTRL_RUN as u64);
        assert_eq!(iop.start_requests, 1);
        assert_eq!(iop.cpu_ctrl, CPU_CTRL_RUN);
        assert_eq!(iop.read(REG_CPU_STATUS, 4), 0);
        // Second RUN write: already awake → no new start request.
        iop.write(REG_CPU_CTRL, 4, CPU_CTRL_RUN as u64);
        assert_eq!(iop.start_requests, 1);
        // SEP_BOOT_MONITOR_RUN bypasses the awake check.
        iop.write(REG_CPU_CTRL, 4, SEP_BOOT_MONITOR_RUN as u64);
        assert_eq!(iop.start_requests, 2);
        // Unknown core registers count as unimplemented (v2 table).
        let _ = iop.read(V2_KIC_GLB_CFG, 4);
        assert_eq!(iop.unknown_reads, 1);
    }

    #[test]
    fn v4_mailbox_windows_roundtrip() {
        let mut iop = A7Iop::new("smc", A7IopVersion::V4, 0x14040);
        // AP writes a 4-word message into the AP window's IOP_SEND bank.
        for (i, w) in [0x10u64, 0x02, 0xAA, 0xBB].iter().enumerate() {
            iop.write(V4_AP_MAILBOX_BASE + crate::a7iop_mailbox::MBOX_V4_IOP_SEND0 + (i as u64) * 4, 4, *w);
        }
        assert_eq!(iop.mailbox.iop_count, 1);
        // The IOP drains it through its own window.
        for (i, w) in [0x10u64, 0x02, 0xAA].iter().enumerate() {
            assert_eq!(
                iop.read(V4_IOP_MAILBOX_BASE + crate::a7iop_mailbox::MBOX_V4_IOP_RECV0 + (i as u64) * 4, 4),
                *w
            );
        }
        assert_eq!(
            iop.read(V4_IOP_MAILBOX_BASE + crate::a7iop_mailbox::MBOX_V4_IOP_RECV3, 4),
            1 << CTRL_COUNT_SHIFT
        );
        assert_eq!(iop.mailbox.iop_count, 0);
        // v4 core table knows the KIC timer registers (no unknown count).
        iop.write(V4_KIC_TMR0_EN, 4, REG_KIC_TMR_EN_MASK as u64);
        assert_eq!(iop.read(V4_KIC_TMR0_EN, 4), REG_KIC_TMR_EN_MASK as u64);
        assert_eq!(iop.unknown_writes, 0);
    }

    #[test]
    fn v4_akf_interrupt_groups_and_status() {
        let mut iop = A7Iop::new("sep", A7IopVersion::V4, 0x14040);
        // Enable interrupt 2 of group 0 via the AKF enable base.
        iop.write(V4_SEP_AKF_ENABLE_INTERRUPT_BASE, 4, 1 << 2);
        assert_eq!(iop.mailbox.interrupts_enabled[0], 1 << 2);
        // Disable base reads inverted ("shows disabled as 0b1").
        assert_eq!(iop.read(V4_SEP_AKF_DISABLE_INTERRUPT_BASE, 4), !(1u32 << 2) as u64);
        assert_eq!(iop.read(V4_SEP_AKF_ENABLE_INTERRUPT_BASE + 4, 4), !0u32 as u64);
        // Disable it again through the disable base.
        iop.write(V4_SEP_AKF_DISABLE_INTERRUPT_BASE, 4, 1 << 2);
        assert_eq!(iop.mailbox.interrupts_enabled[0], 0);
        // INTERRUPT_STATUS read latches FIFO/doorbell states first.
        iop.write(
            V4_IOP_MAILBOX_BASE + crate::a7iop_mailbox::MBOX_V4_IOP_SEND0,
            4,
            1,
        );
        iop.write(
            V4_IOP_MAILBOX_BASE + crate::a7iop_mailbox::MBOX_V4_IOP_SEND3,
            4,
            2,
        );
        assert_eq!(iop.read(V4_INTERRUPT_STATUS, 4), IRQ_IOP_NONEMPTY as u64);
        assert_eq!(iop.mailbox.iop_count, 1); // the message was not received
        // To reach the status-queue pop path, mask every FIFO latch first
        // (IOP_NONEMPTY was masked by the read above; mask AP_EMPTY too).
        iop.mailbox.set_int_mask(AP_EMPTY);
        // Timer IRQ path: SEP GPIO push → gated by timer0 enable + sepd.
        iop.mailbox.sepd_enabled = 1;
        iop.mailbox.sep_timer0_irq(true);
        iop.write(V4_KIC_TMR0_EN, 4, REG_KIC_TMR_EN_MASK as u64);
        assert_eq!(iop.read(V4_INTERRUPT_STATUS, 4), IRQ_SEP_TIMER0 as u64);
        // The status read masks timer0 (C: timer0_masked |= INT_MASK_MASK).
        assert_eq!(
            iop.mailbox.timer0_masked & crate::a7iop_mailbox::REG_KIC_TMR_INT_MASK_MASK,
            crate::a7iop_mailbox::REG_KIC_TMR_INT_MASK_MASK
        );
    }
}

