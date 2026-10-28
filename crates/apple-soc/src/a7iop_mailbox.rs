//! a7iop_mailbox — Apple A7IOP mailbox (port of hw/misc/apple-silicon/
//! a7iop/mailbox/{core,regs-v2,regs-v4}.c): FIFO-paired doorbell mailbox
//! used by the RTKit companion processors (AOP/SMC/SEP/… hang off it).
//! Ports BOTH register layouts — v2 (A7–A11 "KIC" era, 2×u64 messages) and
//! v4 (T8020+ "AKF", 4×u32 messages) — selected by [`A7IopVersion`], plus
//! the interrupt-status queue and SEP timer GPIO inputs.
//!
//! Upstream keeps two cross-linked QEMU objects per role ("<role>-iop" and
//! "<role>-ap") sharing their FIFOs; this port collapses the pair into one
//! struct with an IOP-channel and an AP-channel (same observable behavior,
//! minus the duplicated per-object mask latches). The v4 SEND path upstream
//! also calls `apple_smc_mailbox_capture_provenance()` — an
//! [INFERNO-RTKIT-ORIGIN] debug-instrumentation hook with no guest-visible
//! effect — which this port intentionally omits.

use std::collections::VecDeque;
use vm_core::Device;

pub const MAX_MESSAGE_COUNT: u32 = 15;

// ---- control register bits (mailbox/core.c) ----
pub const CTRL_ENABLE: u32 = 1 << 0;
pub const CTRL_FULL: u32 = 1 << 16;
pub const CTRL_EMPTY: u32 = 1 << 17;
pub const CTRL_OVERFLOW: u32 = 1 << 18;
pub const CTRL_UNDERFLOW: u32 = 1 << 19;
pub const CTRL_COUNT_SHIFT: u32 = 20;
pub const CTRL_COUNT_MASK: u32 = MAX_MESSAGE_COUNT << CTRL_COUNT_SHIFT;

pub const fn ctrl_count(v: u32) -> u32 {
    (v << CTRL_COUNT_SHIFT) & CTRL_COUNT_MASK
}

// ---- int-mask bits (a7iop/mailbox/core.h) ----
pub const IOP_EMPTY: u32 = 1 << 0;
pub const IOP_NONEMPTY: u32 = 1 << 4;
pub const AP_EMPTY: u32 = 1 << 8;
pub const AP_NONEMPTY: u32 = 1 << 12;
// Applicable since t8020/A12. The following are guessed upstream.
pub const MAILBOX_MASKBIT_UNKN0_EMPTY: u32 = 1 << 16;
pub const MAILBOX_MASKBIT_UNKN0_NONEMPTY: u32 = 1 << 18;
pub const MAILBOX_MASKBIT_UNKN1_EMPTY: u32 = 1 << 20;
pub const MAILBOX_MASKBIT_UNKN1_NONEMPTY: u32 = 1 << 22;
pub const MAILBOX_MASKBIT_UNKN2_EMPTY: u32 = 1 << 24;
pub const MAILBOX_MASKBIT_UNKN2_NONEMPTY: u32 = 1 << 26;
pub const MAILBOX_MASKBIT_UNKN3_EMPTY: u32 = 1 << 28;
pub const MAILBOX_MASKBIT_UNKN3_NONEMPTY: u32 = 1 << 30;

// ---- interrupt status codes (a7iop/mailbox/core.h) ----
pub const IRQ_IOP_NONEMPTY: u32 = 0x40000;
pub const IRQ_IOP_EMPTY: u32 = 0x40001;
pub const IRQ_AP_NONEMPTY: u32 = 0x40002;
pub const IRQ_AP_EMPTY: u32 = 0x40003;
// Applicable since t8020/A12 (guessed upstream).
pub const IRQ_MAILBOX_UNKN0_NONEMPTY: u32 = 0x40004;
pub const IRQ_MAILBOX_UNKN0_EMPTY: u32 = 0x40005;
pub const IRQ_MAILBOX_UNKN1_NONEMPTY: u32 = 0x40006;
pub const IRQ_MAILBOX_UNKN1_EMPTY: u32 = 0x40007;
pub const IRQ_MAILBOX_UNKN2_NONEMPTY: u32 = 0x40008;
pub const IRQ_MAILBOX_UNKN2_EMPTY: u32 = 0x40009;
pub const IRQ_MAILBOX_UNKN3_NONEMPTY: u32 = 0x4000A;
pub const IRQ_MAILBOX_UNKN3_EMPTY: u32 = 0x4000B;
// Timer0: phys, Timer1: virt (sepOS >= 16).
pub const IRQ_SEP_TIMER0: u32 = 0x70001;
pub const IRQ_SEP_TIMER1: u32 = 0x70009;
pub const INTERRUPT_SEP_MANUAL_TIMER: u32 = 0x10008;

pub const KIC_GLB_CFG_EXT_INT_EN: u32 = 1 << 0;
pub const KIC_GLB_CFG_TIMEBASE_EN: u32 = 1 << 1;
pub const REG_KIC_TMR_EN_MASK: u32 = (1 << 3) | (1 << 2) | (1 << 1);
pub const REG_KIC_TMR_INT_MASK_MASK: u32 = 1 << 1;

// ---- IRQ line indices (a7iop/base.h enum) ----
pub const APPLE_A7IOP_IRQ_IOP_NONEMPTY: usize = 0;
pub const APPLE_A7IOP_IRQ_IOP_EMPTY: usize = 1;
pub const APPLE_A7IOP_IRQ_AP_NONEMPTY: usize = 2;
pub const APPLE_A7IOP_IRQ_AP_EMPTY: usize = 3;
pub const APPLE_A7IOP_IRQ_MAX: usize = 4;

// ---- v2 mailbox register map (mailbox/regs-v2.c) ----
pub const MBOX_V2_INT_MASK_SET: u64 = 0x00;
pub const MBOX_V2_INT_MASK_CLR: u64 = 0x04;
pub const MBOX_V2_IOP_CTRL: u64 = 0x08;
pub const MBOX_V2_IOP_SEND0: u64 = 0x10;
pub const MBOX_V2_IOP_SEND1: u64 = 0x14;
pub const MBOX_V2_IOP_RECV0: u64 = 0x18;
pub const MBOX_V2_IOP_RECV1: u64 = 0x1C;
pub const MBOX_V2_AP_CTRL: u64 = 0x20;
pub const MBOX_V2_AP_SEND0: u64 = 0x30;
pub const MBOX_V2_AP_SEND1: u64 = 0x34;
pub const MBOX_V2_AP_RECV0: u64 = 0x38;
pub const MBOX_V2_AP_RECV1: u64 = 0x3C;
pub const MBOX_V2_SIZE: u64 = MBOX_V2_AP_RECV1 + 4;

// ---- v4 ("AKF") mailbox register map (mailbox/regs-v4.c) ----
pub const MBOX_V4_INT_MASK_SET: u64 = 0x0;
pub const MBOX_V4_INT_MASK_CLR: u64 = 0x4;
pub const MBOX_V4_IOP_CTRL: u64 = 0x8;
pub const MBOX_V4_AP_CTRL: u64 = 0xC;
pub const MBOX_V4_IOP_SEND0: u64 = 0x700;
pub const MBOX_V4_IOP_SEND1: u64 = 0x704;
pub const MBOX_V4_IOP_SEND2: u64 = 0x708;
pub const MBOX_V4_IOP_SEND3: u64 = 0x70C;
pub const MBOX_V4_IOP_RECV0: u64 = 0x710;
pub const MBOX_V4_IOP_RECV1: u64 = 0x714;
pub const MBOX_V4_IOP_RECV2: u64 = 0x718;
pub const MBOX_V4_IOP_RECV3: u64 = 0x71C;
pub const MBOX_V4_AP_SEND0: u64 = 0x720;
pub const MBOX_V4_AP_SEND1: u64 = 0x724;
pub const MBOX_V4_AP_SEND2: u64 = 0x728;
pub const MBOX_V4_AP_SEND3: u64 = 0x72C;
pub const MBOX_V4_AP_RECV0: u64 = 0x730;
pub const MBOX_V4_AP_RECV1: u64 = 0x734;
pub const MBOX_V4_AP_RECV2: u64 = 0x738;
pub const MBOX_V4_AP_RECV3: u64 = 0x73C;
pub const MBOX_V4_SIZE: u64 = MBOX_V4_AP_RECV3 + 4;

/// C: `AppleA7IOPVersion`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum A7IopVersion {
    V2,
    V4,
}

/// C: `AppleA7IOPMessage` — a 16-byte message (two u64 slots).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct A7IopMessage {
    pub data: [u8; 16],
}

impl A7IopMessage {
    pub fn from_u64_pair(lo: u64, hi: u64) -> Self {
        let mut m = A7IopMessage { data: [0; 16] };
        m.data[..8].copy_from_slice(&lo.to_le_bytes());
        m.data[8..].copy_from_slice(&hi.to_le_bytes());
        m
    }
    pub fn to_u64_pair(&self) -> (u64, u64) {
        let mut lo = [0u8; 8];
        let mut hi = [0u8; 8];
        lo.copy_from_slice(&self.data[..8]);
        hi.copy_from_slice(&self.data[8..]);
        (u64::from_le_bytes(lo), u64::from_le_bytes(hi))
    }
    /// C: `stl_le_p(msg->data + 0xC, CTRL_COUNT(s->count))` on dequeue.
    fn set_count(&mut self, count: u32) {
        self.data[12..16].copy_from_slice(&ctrl_count(count).to_le_bytes());
    }
}

/// C: `AppleA7IOPMailbox` (the "<role>-iop"/"<role>-ap" pair collapsed).
pub struct A7IopMailbox {
    pub role: &'static str,
    pub variant: A7IopVersion,
    /// Messages queued for the IOP CPU (C: the inbox reached via
    /// `s->iop_mailbox`).
    pub iop_inbox: VecDeque<A7IopMessage>,
    /// Messages queued for the AP CPU (C: `s->ap_mailbox->inbox`).
    pub ap_inbox: VecDeque<A7IopMessage>,
    /// C: `interrupt_status` queue (`AppleA7IOPInterruptStatusMessage`).
    pub interrupt_status: VecDeque<u32>,
    pub iop_count: u32,
    pub ap_count: u32,
    pub iop_dir_en: bool,
    pub ap_dir_en: bool,
    pub iop_underflow: bool,
    pub ap_underflow: bool,
    pub int_mask: u32,
    pub iop_recv_reg: [u8; 16],
    pub ap_recv_reg: [u8; 16],
    pub iop_send_reg: [u8; 16],
    pub ap_send_reg: [u8; 16],
    pub interrupts_enabled: [u32; 4],
    // Latched IRQ states (C: iop_nonempty/iop_empty/ap_nonempty/ap_empty).
    pub iop_nonempty: bool,
    pub iop_empty: bool,
    pub ap_nonempty: bool,
    pub ap_empty: bool,
    pub glb_cfg: u32,
    pub timer0_enabled: u32,
    pub timer1_enabled: u32,
    pub timer0_masked: u32,
    pub timer1_masked: u32,
    /// Set by the SEP device glue (C: `s->mailbox->sepd_enabled = data == 0xff`).
    pub sepd_enabled: u32,
    /// C: `sep_cpu_irq` GPIO (raised while role == "SEP-iop").
    pub sep_cpu_irq: bool,
    /// C: `irqs[APPLE_A7IOP_IRQ_MAX]` output lines.
    pub irqs: [bool; APPLE_A7IOP_IRQ_MAX],
    /// C: `qemu_bh_schedule(handle_messages_bh)` counter — the owning IOP
    /// device polls this to drain the inbox.
    pub bh_scheduled: u64,
    pub guest_errors: u64,
    pub unknown_reads: u64,
    pub unknown_writes: u64,
}

impl A7IopMailbox {
    pub fn new(role: &'static str, variant: A7IopVersion) -> Self {
        let mut s = A7IopMailbox {
            role,
            variant,
            iop_inbox: VecDeque::new(),
            ap_inbox: VecDeque::new(),
            interrupt_status: VecDeque::new(),
            iop_count: 0,
            ap_count: 0,
            iop_dir_en: false,
            ap_dir_en: false,
            iop_underflow: false,
            ap_underflow: false,
            int_mask: 0,
            iop_recv_reg: [0; 16],
            ap_recv_reg: [0; 16],
            iop_send_reg: [0; 16],
            ap_send_reg: [0; 16],
            interrupts_enabled: [0; 4],
            iop_nonempty: false,
            iop_empty: false,
            ap_nonempty: false,
            ap_empty: false,
            glb_cfg: 0,
            timer0_enabled: 0,
            timer1_enabled: 0,
            timer0_masked: 0,
            timer1_masked: 0,
            sepd_enabled: 0,
            sep_cpu_irq: false,
            irqs: [false; APPLE_A7IOP_IRQ_MAX],
            bh_scheduled: 0,
            guest_errors: 0,
            unknown_reads: 0,
            unknown_writes: 0,
        };
        s.reset();
        s
    }

    /// C: `apple_a7iop_mailbox_reset`. Note upstream does NOT clear
    /// `int_mask` here — mirrored.
    pub fn reset(&mut self) {
        self.iop_count = 0;
        self.ap_count = 0;
        self.iop_dir_en = true;
        self.ap_dir_en = true;
        self.iop_underflow = false;
        self.ap_underflow = false;
        self.iop_recv_reg = [0; 16];
        self.ap_recv_reg = [0; 16];
        self.iop_send_reg = [0; 16];
        self.ap_send_reg = [0; 16];
        self.iop_inbox.clear();
        self.ap_inbox.clear();
        self.interrupt_status.clear();
        self.interrupts_enabled = [0; 4];
        self.iop_nonempty = false;
        self.iop_empty = false;
        self.ap_nonempty = false;
        self.ap_empty = false;
        self.glb_cfg = 0;
        self.timer0_enabled = 0;
        self.timer1_enabled = 0;
        self.timer0_masked = 0;
        self.timer1_masked = 0;
        self.sepd_enabled = 0;
        self.update_irq_status();
    }

    // ---- IRQ computation (C: update_irq_status / update_irq) ----

    /// C: `apple_a7iop_mailbox_update_irq_status`.
    pub fn update_irq_status(&mut self) {
        let iop_empty = self.iop_inbox.is_empty();
        let ap_empty = self.ap_inbox.is_empty();
        let iop_underflow = self.iop_underflow;
        let ap_underflow = self.ap_underflow;
        let iop_nonempty_unmasked = (self.int_mask & IOP_NONEMPTY) == 0;
        let iop_empty_unmasked = (self.int_mask & IOP_EMPTY) == 0;
        let ap_nonempty_unmasked = (self.int_mask & AP_NONEMPTY) == 0;
        let ap_empty_unmasked = (self.int_mask & AP_EMPTY) == 0;

        self.irqs[APPLE_A7IOP_IRQ_IOP_NONEMPTY] =
            (iop_nonempty_unmasked && !iop_empty) || iop_underflow;
        self.irqs[APPLE_A7IOP_IRQ_IOP_EMPTY] = iop_empty_unmasked && iop_empty;
        self.irqs[APPLE_A7IOP_IRQ_AP_NONEMPTY] =
            (ap_nonempty_unmasked && !ap_empty) || ap_underflow;
        self.irqs[APPLE_A7IOP_IRQ_AP_EMPTY] = ap_empty_unmasked && ap_empty;

        self.iop_nonempty = self.irqs[APPLE_A7IOP_IRQ_IOP_NONEMPTY];
        self.iop_empty = self.irqs[APPLE_A7IOP_IRQ_IOP_EMPTY];
        self.ap_nonempty = self.irqs[APPLE_A7IOP_IRQ_AP_NONEMPTY];
        self.ap_empty = self.irqs[APPLE_A7IOP_IRQ_AP_EMPTY];
    }

    /// C: `apple_a7iop_mailbox_update_irq`. The upstream "<role>-ap"
    /// recursion into its "<role>-iop" partner collapses to nothing here
    /// (same object).
    pub fn update_irq(&mut self) {
        self.update_irq_status();
        let sep_cpu_irq_raised = self.iop_nonempty
            || self.iop_empty
            || self.ap_nonempty
            || self.ap_empty
            || !self.interrupt_status_all_masked();
        if self.role == "SEP-iop" {
            self.sep_cpu_irq = sep_cpu_irq_raised;
        }
    }

    // ---- message channels ----

    /// C: `apple_a7iop_mailbox_is_empty` (IOP-channel view).
    pub fn is_empty(&self) -> bool {
        self.iop_underflow || self.iop_inbox.is_empty()
    }

    /// C: `apple_a7iop_inbox_peek` (IOP-channel view).
    pub fn inbox_peek(&self) -> Option<&A7IopMessage> {
        self.iop_inbox.front()
    }

    fn fifo_ctrl(count: u32, underflow: bool, empty: bool) -> u32 {
        if underflow {
            return CTRL_UNDERFLOW;
        }
        (if count >= MAX_MESSAGE_COUNT { CTRL_FULL } else { 0 })
            | (if empty { CTRL_EMPTY } else { 0 })
            | ctrl_count(count.min(MAX_MESSAGE_COUNT))
    }

    pub fn get_iop_ctrl(&self) -> u32 {
        (if self.iop_dir_en { CTRL_ENABLE } else { 0 })
            | Self::fifo_ctrl(self.iop_count, self.iop_underflow, self.iop_inbox.is_empty())
    }

    pub fn set_iop_ctrl(&mut self, value: u32) {
        self.iop_dir_en = (value & CTRL_ENABLE) != 0;
    }

    pub fn get_ap_ctrl(&self) -> u32 {
        (if self.ap_dir_en { CTRL_ENABLE } else { 0 })
            | Self::fifo_ctrl(self.ap_count, self.ap_underflow, self.ap_inbox.is_empty())
    }

    pub fn set_ap_ctrl(&mut self, value: u32) {
        self.ap_dir_en = (value & CTRL_ENABLE) != 0;
    }

    /// C: `apple_a7iop_mailbox_send` into the IOP channel
    /// (direction-gated by `apple_a7iop_mailbox_send_iop`).
    pub fn send_iop(&mut self, msg: A7IopMessage) {
        if !self.iop_dir_en {
            self.guest_errors += 1; // "%s: IOP direction not enabled."
            return;
        }
        self.iop_inbox.push_back(msg);
        self.iop_count += 1;
        self.update_irq();
        self.bh_scheduled += 1; // qemu_bh_schedule(handle_messages_bh)
    }

    /// C: `apple_a7iop_mailbox_send` into the AP channel.
    pub fn send_ap(&mut self, msg: A7IopMessage) {
        if !self.ap_dir_en {
            self.guest_errors += 1;
            return;
        }
        self.ap_inbox.push_back(msg);
        self.ap_count += 1;
        self.update_irq();
        self.bh_scheduled += 1;
    }

    /// C: `apple_a7iop_mailbox_recv` — shared FIFO pop with underflow
    /// latching and the CTRL_COUNT stamp into data[0xC..0x10].
    fn recv_channel(
        inbox: &mut VecDeque<A7IopMessage>,
        count: &mut u32,
        underflow: &mut bool,
    ) -> Option<A7IopMessage> {
        if *underflow {
            return None;
        }
        match inbox.pop_front() {
            None => {
                *underflow = true; // "%s: %s underflowed."
                None
            }
            Some(mut msg) => {
                msg.set_count(*count);
                *count -= 1;
                Some(msg)
            }
        }
    }

    /// C: `apple_a7iop_mailbox_recv_iop`.
    pub fn recv_iop(&mut self) -> Option<A7IopMessage> {
        if !self.iop_dir_en {
            self.guest_errors += 1;
            return None;
        }
        let msg = Self::recv_channel(
            &mut self.iop_inbox,
            &mut self.iop_count,
            &mut self.iop_underflow,
        );
        self.update_irq();
        msg
    }

    /// C: `apple_a7iop_mailbox_recv_ap`.
    pub fn recv_ap(&mut self) -> Option<A7IopMessage> {
        if !self.ap_dir_en {
            self.guest_errors += 1;
            return None;
        }
        let msg = Self::recv_channel(
            &mut self.ap_inbox,
            &mut self.ap_count,
            &mut self.ap_underflow,
        );
        self.update_irq();
        msg
    }

    // ---- interrupt mask + status queue ----

    pub fn get_int_mask(&self) -> u32 {
        self.int_mask
    }

    pub fn set_int_mask(&mut self, value: u32) {
        self.int_mask |= value;
        self.update_irq();
    }

    pub fn clear_int_mask(&mut self, value: u32) {
        self.int_mask &= !value;
        self.update_irq();
    }

    /// C: `is_interrupt_enabled` — note the `sepd_enabled` gate, an upstream
    /// SEP workaround that disables every status interrupt while zero.
    pub fn is_interrupt_enabled(&self, status: u32) -> bool {
        if self.sepd_enabled == 0 {
            return false;
        }
        if (status & 0xF0000) == 0x10000 && (self.glb_cfg & KIC_GLB_CFG_EXT_INT_EN) != 0 {
            let interrupt = (status & 0x7F) as usize;
            let group = interrupt / 32;
            self.interrupts_enabled[group] & (1 << (interrupt % 32)) != 0
        } else if status == IRQ_IOP_NONEMPTY {
            self.iop_nonempty
        } else if status == IRQ_IOP_EMPTY {
            self.iop_empty
        } else if status == IRQ_AP_NONEMPTY {
            self.ap_nonempty
        } else if status == IRQ_AP_EMPTY {
            self.ap_empty
        } else if status == IRQ_SEP_TIMER0 {
            (self.timer0_enabled & REG_KIC_TMR_EN_MASK) == REG_KIC_TMR_EN_MASK
                && (self.timer0_masked & REG_KIC_TMR_INT_MASK_MASK) == 0
        } else if status == IRQ_SEP_TIMER1 {
            (self.timer1_enabled & REG_KIC_TMR_EN_MASK) == REG_KIC_TMR_EN_MASK
                && (self.timer1_masked & REG_KIC_TMR_INT_MASK_MASK) == 0
        } else {
            true
        }
    }

    /// C: `apple_mbox_interrupt_status_empty`.
    fn interrupt_status_all_masked(&self) -> bool {
        self.interrupt_status
            .iter()
            .all(|&s| !self.is_interrupt_enabled(s))
    }

    /// C: `apple_a7iop_interrupt_status_push` — deduplicates.
    pub fn interrupt_status_push(&mut self, status: u32) {
        if self.interrupt_status.contains(&status) {
            self.update_irq();
            return;
        }
        // DON'T TEST FOR interrupts_enabled DURING PUSH!! (upstream comment)
        self.interrupt_status.push_back(status);
        self.update_irq();
    }

    /// C: `apple_a7iop_interrupt_status_pop` — order 0x4…, 0x7…, 0x1…
    /// with the upstream preference rule.
    pub fn interrupt_status_pop(&mut self) -> u32 {
        let mut preferred: Option<usize> = None;
        let mut group_preferred: u32 = 0;
        for (i, &status) in self.interrupt_status.iter().enumerate() {
            let group = (status >> 16) & 0x7;
            if self.is_interrupt_enabled(status) {
                let take = match preferred {
                    None => true,
                    Some(p) => {
                        (group == group_preferred && status < self.interrupt_status[p])
                            || (group != group_preferred && group == 0x7)
                    }
                };
                if take {
                    preferred = Some(i);
                    group_preferred = group;
                }
            }
        }
        let ret = preferred.map(|i| self.interrupt_status.remove(i).unwrap()).unwrap_or(0);
        self.update_irq();
        ret
    }

    /// C: `apple_a7iop_mailbox_read_interrupt_status` — the v4
    /// REG_INTERRUPT_STATUS read with its mask-latching side effects.
    pub fn read_interrupt_status(&mut self) -> u32 {
        let status;
        if self.iop_nonempty {
            status = IRQ_IOP_NONEMPTY;
            self.int_mask |= IOP_NONEMPTY;
        } else if self.iop_empty {
            status = IRQ_IOP_EMPTY;
            self.int_mask |= IOP_EMPTY;
        } else if self.ap_nonempty {
            status = IRQ_AP_NONEMPTY;
            self.int_mask |= AP_NONEMPTY;
        } else if self.ap_empty {
            status = IRQ_AP_EMPTY;
            self.int_mask |= AP_EMPTY;
        } else {
            status = self.interrupt_status_pop();
            if status != 0 {
                if (status & 0xf0000) == 0x10000 {
                    let interrupt = (status & 0x7F) as usize;
                    self.interrupts_enabled[interrupt / 32] &= !(1 << (interrupt % 32));
                } else {
                    match status {
                        IRQ_IOP_NONEMPTY => self.int_mask |= IOP_NONEMPTY,
                        IRQ_IOP_EMPTY => self.int_mask |= IOP_EMPTY,
                        IRQ_AP_NONEMPTY => self.int_mask |= AP_NONEMPTY,
                        IRQ_AP_EMPTY => self.int_mask |= AP_EMPTY,
                        IRQ_MAILBOX_UNKN0_NONEMPTY => {
                            self.int_mask |= MAILBOX_MASKBIT_UNKN0_NONEMPTY
                        }
                        IRQ_MAILBOX_UNKN0_EMPTY => {
                            self.int_mask |= MAILBOX_MASKBIT_UNKN0_EMPTY
                        }
                        IRQ_MAILBOX_UNKN1_NONEMPTY => {
                            self.int_mask |= MAILBOX_MASKBIT_UNKN1_NONEMPTY
                        }
                        IRQ_MAILBOX_UNKN1_EMPTY => {
                            self.int_mask |= MAILBOX_MASKBIT_UNKN1_EMPTY
                        }
                        IRQ_MAILBOX_UNKN2_NONEMPTY => {
                            self.int_mask |= MAILBOX_MASKBIT_UNKN2_NONEMPTY
                        }
                        IRQ_MAILBOX_UNKN2_EMPTY => {
                            self.int_mask |= MAILBOX_MASKBIT_UNKN2_EMPTY
                        }
                        IRQ_MAILBOX_UNKN3_NONEMPTY => {
                            self.int_mask |= MAILBOX_MASKBIT_UNKN3_NONEMPTY
                        }
                        IRQ_MAILBOX_UNKN3_EMPTY => {
                            self.int_mask |= MAILBOX_MASKBIT_UNKN3_EMPTY
                        }
                        IRQ_SEP_TIMER0 => {
                            self.timer0_masked |= REG_KIC_TMR_INT_MASK_MASK
                        }
                        IRQ_SEP_TIMER1 => {
                            self.timer1_masked |= REG_KIC_TMR_INT_MASK_MASK
                        }
                        _ => {}
                    }
                }
            }
        }
        self.update_irq();
        status
    }

    // ---- SEP timer GPIO inputs (C: apple_a7iop_gpio_timer0/1) ----

    pub fn sep_timer0_irq(&mut self, level: bool) {
        if !level {
            return;
        }
        // DON'T also do the checks here, only do them in interrupt_status_pop.
        self.interrupt_status_push(IRQ_SEP_TIMER0);
    }

    pub fn sep_timer1_irq(&mut self, level: bool) {
        if !level {
            return;
        }
        self.interrupt_status_push(IRQ_SEP_TIMER1);
    }

    // ---- v2 register interface (C: apple_a7iop_v2_mailbox_reg_* ) ----

    fn read_v2(&mut self, off: u64, size: u8) -> u64 {
        match off {
            MBOX_V2_INT_MASK_SET | MBOX_V2_INT_MASK_CLR => self.get_int_mask() as u64,
            MBOX_V2_IOP_CTRL => self.get_iop_ctrl() as u64,
            MBOX_V2_AP_CTRL => self.get_ap_ctrl() as u64,
            MBOX_V2_IOP_RECV0 | MBOX_V2_IOP_RECV1 => {
                self.read_recv(off, size, MBOX_V2_IOP_RECV0, true)
            }
            MBOX_V2_AP_RECV0 | MBOX_V2_AP_RECV1 => {
                self.read_recv(off, size, MBOX_V2_AP_RECV0, false)
            }
            _ => {
                self.unknown_reads += 1;
                0
            }
        }
    }

    fn write_v2(&mut self, off: u64, size: u8, val: u64) {
        match off {
            MBOX_V2_INT_MASK_SET => self.set_int_mask(val as u32),
            MBOX_V2_INT_MASK_CLR => self.clear_int_mask(val as u32),
            MBOX_V2_IOP_CTRL => self.set_iop_ctrl(val as u32),
            MBOX_V2_AP_CTRL => self.set_ap_ctrl(val as u32),
            MBOX_V2_IOP_SEND0 | MBOX_V2_IOP_SEND1 => {
                self.write_send(off, size, val, MBOX_V2_IOP_SEND0, MBOX_V2_IOP_SEND1, true)
            }
            MBOX_V2_AP_SEND0 | MBOX_V2_AP_SEND1 => {
                self.write_send(off, size, val, MBOX_V2_AP_SEND0, MBOX_V2_AP_SEND1, false)
            }
            _ => {
                self.unknown_writes += 1;
            }
        }
    }

    // ---- v4 register interface (C: apple_a7iop_v4_mailbox_reg_* ) ----

    fn read_v4(&mut self, off: u64, size: u8) -> u64 {
        match off {
            MBOX_V4_INT_MASK_SET | MBOX_V4_INT_MASK_CLR => self.get_int_mask() as u64,
            MBOX_V4_IOP_CTRL => self.get_iop_ctrl() as u64,
            MBOX_V4_AP_CTRL => self.get_ap_ctrl() as u64,
            MBOX_V4_IOP_RECV0
            | MBOX_V4_IOP_RECV1
            | MBOX_V4_IOP_RECV2
            | MBOX_V4_IOP_RECV3 => self.read_recv(off, size, MBOX_V4_IOP_RECV0, true),
            MBOX_V4_AP_RECV0
            | MBOX_V4_AP_RECV1
            | MBOX_V4_AP_RECV2
            | MBOX_V4_AP_RECV3 => self.read_recv(off, size, MBOX_V4_AP_RECV0, false),
            _ => {
                self.unknown_reads += 1;
                0
            }
        }
    }

    fn write_v4(&mut self, off: u64, size: u8, val: u64) {
        match off {
            MBOX_V4_INT_MASK_SET => self.set_int_mask(val as u32),
            MBOX_V4_INT_MASK_CLR => self.clear_int_mask(val as u32),
            MBOX_V4_IOP_CTRL => self.set_iop_ctrl(val as u32),
            MBOX_V4_AP_CTRL => self.set_ap_ctrl(val as u32),
            MBOX_V4_IOP_SEND0
            | MBOX_V4_IOP_SEND1
            | MBOX_V4_IOP_SEND2
            | MBOX_V4_IOP_SEND3 => {
                self.write_send(off, size, val, MBOX_V4_IOP_SEND0, MBOX_V4_IOP_SEND3, true)
            }
            MBOX_V4_AP_SEND0
            | MBOX_V4_AP_SEND1
            | MBOX_V4_AP_SEND2
            | MBOX_V4_AP_SEND3 => {
                self.write_send(off, size, val, MBOX_V4_AP_SEND0, MBOX_V4_AP_SEND3, false)
            }
            _ => {
                self.unknown_writes += 1;
            }
        }
    }

    /// C: the SEND0..N write path — bytes land in the send register at
    /// `off - send_base`; covering the last register enqueues the message.
    fn write_send(&mut self, off: u64, size: u8, val: u64, send_base: u64, send_last: u64, iop_dir: bool) {
        let slot = (off - send_base) as usize;
        let bytes = val.to_le_bytes();
        {
            let reg: &mut [u8; 16] = if iop_dir {
                &mut self.iop_send_reg
            } else {
                &mut self.ap_send_reg
            };
            for i in 0..size as usize {
                if slot + i < 16 {
                    reg[slot + i] = bytes[i];
                }
            }
        }
        if off + size as u64 - 4 == send_last {
            let msg = if iop_dir {
                A7IopMessage { data: self.iop_send_reg }
            } else {
                A7IopMessage { data: self.ap_send_reg }
            };
            if iop_dir {
                self.send_iop(msg);
            } else {
                self.send_ap(msg);
            }
        }
    }

    /// C: the RECV0..N read path — RECV0 pops a message (or zeroes the
    /// latch), then `size` bytes are returned from the latch register.
    fn read_recv(&mut self, off: u64, size: u8, recv_base: u64, iop_dir: bool) -> u64 {
        if off == recv_base {
            let msg = if iop_dir { self.recv_iop() } else { self.recv_ap() };
            let reg = if iop_dir {
                &mut self.iop_recv_reg
            } else {
                &mut self.ap_recv_reg
            };
            match msg {
                Some(m) => *reg = m.data,
                None => *reg = [0u8; 16],
            }
        }
        let slot = (off - recv_base) as usize;
        let reg: &[u8; 16] = if iop_dir { &self.iop_recv_reg } else { &self.ap_recv_reg };
        let mut out = 0u64;
        for i in 0..size as usize {
            if slot + i < 16 {
                out |= (reg[slot + i] as u64) << (8 * i);
            }
        }
        out
    }

    pub fn regs_documented() -> &'static [(&'static str, u64)] {
        &[
            ("V2_INT_MASK_SET", MBOX_V2_INT_MASK_SET),
            ("V2_IOP_CTRL", MBOX_V2_IOP_CTRL),
            ("V2_IOP_SEND0", MBOX_V2_IOP_SEND0),
            ("V2_AP_RECV1", MBOX_V2_AP_RECV1),
            ("V4_INT_MASK_SET", MBOX_V4_INT_MASK_SET),
            ("V4_IOP_CTRL", MBOX_V4_IOP_CTRL),
            ("V4_IOP_SEND0", MBOX_V4_IOP_SEND0),
            ("V4_AP_RECV3", MBOX_V4_AP_RECV3),
        ]
    }
}

impl Default for A7IopMailbox {
    fn default() -> Self {
        Self::new("a7iop", A7IopVersion::V4)
    }
}

impl Device for A7IopMailbox {
    fn name(&self) -> &'static str {
        "a7iop-mailbox"
    }
    fn read(&mut self, off: u64, size: u8) -> u64 {
        match self.variant {
            A7IopVersion::V2 => self.read_v2(off, size),
            A7IopVersion::V4 => self.read_v4(off, size),
        }
    }
    fn write(&mut self, off: u64, size: u8, val: u64) {
        match self.variant {
            A7IopVersion::V2 => self.write_v2(off, size, val),
            A7IopVersion::V4 => self.write_v4(off, size, val),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v2_send_recv_roundtrip_with_count_stamp() {
        let mut m = A7IopMailbox::new("aop-iop", A7IopVersion::V2);
        assert!(m.iop_dir_en && m.ap_dir_en); // reset enables both directions
        // IOP doorbell: two u32 halves form the 16-byte message (2 u64 slots).
        m.write(MBOX_V2_IOP_SEND0, 4, 0x11223344);
        assert_eq!(m.iop_count, 0); // not sent until SEND1 is covered
        m.write(MBOX_V2_IOP_SEND1, 4, 0x55667788);
        assert_eq!(m.iop_count, 1);
        assert_eq!(m.bh_scheduled, 1);
        // CTRL: enabled + count 1.
        assert_eq!(
            m.read(MBOX_V2_IOP_CTRL, 4),
            (CTRL_ENABLE | ctrl_count(1)) as u64
        );
        // Dequeue: RECV0 pops; both halves of the 64-bit slot come back
        // verbatim. (The CTRL_COUNT stamp lands in data[12..16], which the
        // v2 2-register window does not expose — v4's RECV3 does.)
        assert_eq!(m.read(MBOX_V2_IOP_RECV0, 4), 0x11223344);
        assert_eq!(m.read(MBOX_V2_IOP_RECV1, 4), 0x55667788);
        assert_eq!(m.iop_count, 0);
        // Second read underflows: CTRL shows UNDERFLOW, further reads zero.
        assert_eq!(m.read(MBOX_V2_IOP_RECV0, 4), 0);
        assert!(m.iop_underflow);
        assert_eq!(m.read(MBOX_V2_IOP_CTRL, 4), (CTRL_ENABLE | CTRL_UNDERFLOW) as u64);
    }

    #[test]
    fn v4_message_latch_and_channel_separation() {
        let mut m = A7IopMailbox::new("smc-ap", A7IopVersion::V4);
        // AP→IOP message through the v4 SEND0..3 window.
        m.write(MBOX_V4_IOP_SEND0, 4, 0x00000010);
        m.write(MBOX_V4_IOP_SEND1, 4, 0x00000002);
        m.write(MBOX_V4_IOP_SEND2, 4, 0xDEADBEEF);
        m.write(MBOX_V4_IOP_SEND3, 4, 0xCAFEBABE);
        assert_eq!(m.iop_count, 1);
        assert_eq!(m.ap_count, 0);
        assert_eq!(m.read(MBOX_V4_IOP_RECV0, 4), 0x00000010);
        assert_eq!(m.read(MBOX_V4_IOP_RECV1, 4), 0x00000002);
        assert_eq!(m.read(MBOX_V4_IOP_RECV2, 4), 0xDEADBEEF);
        assert_eq!(m.read(MBOX_V4_IOP_RECV3, 4), ctrl_count(1) as u64);
        // Popping an empty IOP channel zeroes the recv latch...
        assert_eq!(m.read(MBOX_V4_IOP_RECV0, 4), 0);
        // ...while the AP channel stays independent (empty → CTRL_EMPTY).
        assert_eq!(m.read(MBOX_V4_AP_CTRL, 4), (CTRL_ENABLE | CTRL_EMPTY) as u64);
        // IRQ lines: after the underflowing read the IOP_EMPTY latch is set
        // and the IOP_NONEMPTY line is raised by the underflow
        // (C: (unmasked && !empty) || iop_underflow).
        assert!(m.irqs[APPLE_A7IOP_IRQ_IOP_EMPTY]);
        assert!(m.irqs[APPLE_A7IOP_IRQ_IOP_NONEMPTY]);
        assert!(m.iop_underflow);
        assert!(m.irqs[APPLE_A7IOP_IRQ_AP_EMPTY]);
        assert!(!m.irqs[APPLE_A7IOP_IRQ_AP_NONEMPTY]);
    }

    #[test]
    fn int_mask_and_direction_gating() {
        let mut m = A7IopMailbox::new("aop-iop", A7IopVersion::V2);
        m.write(MBOX_V2_IOP_CTRL, 4, 0); // disable IOP direction
        m.write(MBOX_V2_IOP_SEND0, 4, 1);
        m.write(MBOX_V2_IOP_SEND1, 4, 2);
        assert_eq!(m.iop_count, 0); // send dropped, direction not enabled
        assert_eq!(m.guest_errors, 1);
        m.write(MBOX_V2_IOP_CTRL, 4, CTRL_ENABLE as u64);
        // INT_MASK_SET/CLR roundtrip drives the IRQ lines.
        m.write(MBOX_V2_INT_MASK_SET, 4, IOP_NONEMPTY as u64);
        assert_eq!(m.read(MBOX_V2_INT_MASK_CLR, 4), IOP_NONEMPTY as u64);
        m.write(MBOX_V2_IOP_SEND0, 4, 1);
        m.write(MBOX_V2_IOP_SEND1, 4, 2);
        assert!(m.iop_inbox.len() == 1);
        // IOP_NONEMPTY masked → nonempty IRQ line low.
        assert!(!m.irqs[APPLE_A7IOP_IRQ_IOP_NONEMPTY]);
        m.write(MBOX_V2_INT_MASK_CLR, 4, IOP_NONEMPTY as u64);
        assert!(m.irqs[APPLE_A7IOP_IRQ_IOP_NONEMPTY]);
    }

    #[test]
    fn interrupt_status_gating_and_pop_order() {
        let mut m = A7IopMailbox::new("SEP-iop", A7IopVersion::V4);
        // Upstream SEP glue sets sepd_enabled before any status IRQ flows.
        assert!(!m.is_interrupt_enabled(IRQ_SEP_TIMER0));
        m.sepd_enabled = 1;
        m.glb_cfg = KIC_GLB_CFG_EXT_INT_EN;
        m.interrupts_enabled[0] = (1 << 2) | (1 << 4); // interrupts 2 and 4, group 0
        m.interrupt_status_push(0x10004);
        m.interrupt_status_push(0x10002);
        assert!(m.sep_cpu_irq); // "SEP-iop" role latch
        // Same group → lowest status first.
        assert_eq!(m.interrupt_status_pop(), 0x10002);
        assert_eq!(m.interrupt_status_pop(), 0x10004);
        assert_eq!(m.interrupt_status_pop(), 0);
        // SEP timer GPIO path + timer enable gating.
        m.timer0_enabled = REG_KIC_TMR_EN_MASK;
        m.sep_timer0_irq(true);
        assert_eq!(m.interrupt_status_pop(), IRQ_SEP_TIMER0);
        assert_eq!(
            m.timer0_masked & REG_KIC_TMR_INT_MASK_MASK,
            0,
            "pop does not mask; read_interrupt_status does"
        );
        // A grouped interrupt read via read_interrupt_status clears its
        // enable bit (C: interrupts_enabled[group] &= ~BIT(...)). Mask the
        // (empty) FIFO latches first so the read reaches the pop path.
        m.set_int_mask(IOP_EMPTY | AP_EMPTY);
        m.interrupt_status_push(0x10002);
        assert_eq!(m.read_interrupt_status(), 0x10002);
        assert_eq!(m.interrupts_enabled[0] & (1 << 2), 0);
        // Duplicate pushes collapse (C dedupes in interrupt_status_push).
        m.interrupt_status_push(IRQ_SEP_TIMER1);
        m.interrupt_status_push(IRQ_SEP_TIMER1);
        assert_eq!(m.interrupt_status.len(), 1);
    }
}
