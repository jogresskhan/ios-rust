//! Apple RTKit — the IOP firmware protocol shared by ANS2, AOP (and SEP).
//!
//! Port of ChefKiss Inferno `hw/misc/apple-silicon/a7iop/rtkit.c` (the
//! management-EP boot handshake + EP mapper) and the A7IOP v4 mailbox
//! register block from `a7iop/mailbox/regs-v4.c`.
//!
//! Mailbox messages are 16 bytes (128-bit) on the v4 mailbox:
//! `[0..8] msg: u64 | [8..12] endpoint: u32 | [12..16] flags: u32`.
//!
//! Self-containment note (parity gap "iop-mailbox DMA"): the coprocessor
//! firmware image is *not* executed; RTKit is simulated from the IOP side
//! exactly like upstream (`apple_rtkit_iop_start` → HELLO → HELLO_ACK →
//! ROLLCALL → boot_done). Messages the guest sends to user endpoints are
//! queued into [`Rtkit::user_msgs`] for the owning device to drain.
//!
//! License: AGPL-3.0-or-later (derived work).

use std::collections::VecDeque;

use vm_core::Device;

// ---------------------------------------------------------------------------
// RTKit protocol constants (rtkit.c)
// ---------------------------------------------------------------------------

pub const EP_MANAGEMENT: u8 = 0;
pub const EP_CRASHLOG: u8 = 1;
pub const EP_USER_START: u8 = 32;

/// RTKIT_MIN_VERSION / RTKIT_MAX_VERSION (rtkit.c lines 104-106).
pub const RTKIT_MIN_VERSION: u16 = 3;
pub const RTKIT_MAX_VERSION_PRE_IOS14: u16 = 10;
pub const RTKIT_MAX_VERSION: u16 = 12;

/// EP0 boot states (rtkit.c lines 68-72).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ep0State {
    Idle,
    WaitHello,
    WaitRollcall,
    Done,
}

// Management-EP message types (MSG_*).
pub const MSG_HELLO: u64 = 1;
pub const MSG_HELLO_ACK: u64 = 2;
pub const MSG_TYPE_PING: u64 = 3;
pub const MSG_TYPE_PING_ACK: u64 = 4;
pub const MSG_TYPE_SET_EP_STATUS: u64 = 5;
pub const MSG_TYPE_REQ_POWER: u64 = 6;
pub const MSG_TYPE_POWER_ACK: u64 = 7;
pub const MSG_TYPE_ROLLCALL: u64 = 8;
pub const MSG_TYPE_POWER_NAP: u64 = 10;
pub const MSG_TYPE_AP_POWER: u64 = 11;

/// Management message: `type` in bits 52..56, payload in the low bits.
pub const fn mgmt_msg(ty: u64, payload: u64) -> u64 {
    (ty << 52) | (payload & 0xF_FFFF_FFFF_FFFF)
}
/// Extract the management message type.
pub const fn mgmt_type(msg: u64) -> u64 {
    (msg >> 52) & 0xF
}

/// PSTATE values (rtkit.c).
pub const PSTATE_PWRGATE: u64 = 0x0;
pub const PSTATE_SLEEP: u64 = 0x201;
pub const PSTATE_OFF: u64 = 0x202;
pub const PSTATE_ON: u64 = 0x220;

// ---------------------------------------------------------------------------
// A7IOP v4 mailbox registers (a7iop/mailbox/regs-v4.c)
// ---------------------------------------------------------------------------

pub const REG_INT_MASK_SET: u64 = 0x0;
pub const REG_INT_MASK_CLR: u64 = 0x4;
pub const REG_IOP_CTRL: u64 = 0x8;
pub const REG_AP_CTRL: u64 = 0xC;
pub const REG_IOP_SEND0: u64 = 0x700;
pub const REG_IOP_RECV0: u64 = 0x710;
pub const REG_AP_SEND0: u64 = 0x720;
pub const REG_AP_RECV0: u64 = 0x730;

/// Mailbox ring capacity (MAX_MESSAGE_COUNT, mailbox/core.c).
pub const MBOX_MAX_MESSAGES: usize = 15;

// CTRL register fields (mailbox/core.c lines 34-40).
pub const CTRL_ENABLE: u32 = 1 << 0;
pub const CTRL_FULL: u32 = 1 << 16;
pub const CTRL_EMPTY: u32 = 1 << 17;
pub const CTRL_OVERFLOW: u32 = 1 << 18;
pub const CTRL_UNDERFLOW: u32 = 1 << 19;
pub const CTRL_COUNT_SHIFT: u32 = 20;

/// A 16-byte mailbox message.
pub type MboxMessage = [u8; 16];

/// Assemble a 16-byte RTKit message.
pub fn rtkit_msg(endpoint: u8, msg: u64) -> MboxMessage {
    let mut m = [0u8; 16];
    m[0..8].copy_from_slice(&msg.to_le_bytes());
    m[8..12].copy_from_slice(&(endpoint as u32).to_le_bytes());
    // flags = 0
    m
}

/// Decode the endpoint field of a mailbox message.
pub fn msg_endpoint(m: &MboxMessage) -> u32 {
    u32::from_le_bytes(m[8..12].try_into().unwrap())
}

/// Decode the payload field of a mailbox message.
pub fn msg_payload(m: &MboxMessage) -> u64 {
    u64::from_le_bytes(m[0..8].try_into().unwrap())
}

// ---------------------------------------------------------------------------
// The RTKit device core
// ---------------------------------------------------------------------------

/// Simulated IOP side of the RTKit protocol + the A7IOP v4 mailbox reg block.
///
/// The owning device (ANS2 / AOP / SEP) embeds this and maps its single MMIO
/// region (the "rtkit" reg entry — `reg[1]` size in upstream terms) onto
/// [`Rtkit::read`] / [`Rtkit::write`].
pub struct Rtkit {
    pub role: &'static str,
    pub mmio_size: u64,

    int_mask: u32,
    iop_ctrl: u32,
    ap_ctrl: u32,

    /// IOP → AP direction: messages waiting for the guest.
    ap_ring: VecDeque<MboxMessage>,
    /// Latch for the 4-word AP_RECV read sequence.
    recv_latch: MboxMessage,
    /// Staging for the 4-word AP_SEND write sequence.
    send_stage: MboxMessage,
    send_words: u8,

    ep0: Ep0State,
    protocol_version: u16,

    /// Registered user EPs, indexed 0..(256 - EP_USER_START).
    user_eps: Vec<bool>,
    /// Rollcall v11 blocks still to deliver.
    rollcall: VecDeque<MboxMessage>,

    /// Messages delivered to user EPs (`ep` already mapped to 0..N).
    /// The owning device drains this in `write()`/`tick()`.
    pub user_msgs: Vec<(u8, u64)>,

    /// IOP started (AP enabled the mailbox).
    pub started: bool,
    /// EP0 handshake finished; user EPs are live.
    pub boot_done: bool,

    // parity-census counters
    pub msgs_from_ap: u64,
    pub msgs_to_ap: u64,
    pub unknown_eps: u64,
}

impl Rtkit {
    pub fn new(role: &'static str, mmio_size: u64) -> Self {
        Rtkit {
            role,
            mmio_size,
            int_mask: 0,
            iop_ctrl: 0,
            ap_ctrl: 0,
            ap_ring: VecDeque::new(),
            recv_latch: [0; 16],
            send_stage: [0; 16],
            send_words: 0,
            ep0: Ep0State::Idle,
            protocol_version: 0,
            user_eps: vec![false; 256 - EP_USER_START as usize],
            rollcall: VecDeque::new(),
            user_msgs: Vec::new(),
            started: false,
            boot_done: false,
            msgs_from_ap: 0,
            msgs_to_ap: 0,
            unknown_eps: 0,
        }
    }

    /// Register a user EP (index 0..N, wire EP number is index+EP_USER_START).
    /// Mirrors `apple_rtkit_register_user_ep`.
    pub fn register_user_ep(&mut self, index: u8) {
        assert!((index as usize) < self.user_eps.len());
        self.user_eps[index as usize] = true;
    }

    /// `apple_rtkit_send_msg`: enqueue a message for the guest (IOP → AP).
    pub fn send_to_ap(&mut self, endpoint: u8, msg: u64) {
        if self.ap_ring.len() >= MBOX_MAX_MESSAGES {
            // ring full: drop, exactly like the hardware overflow behaviour
            return;
        }
        self.ap_ring.push_back(rtkit_msg(endpoint, msg));
        self.msgs_to_ap += 1;
    }

    /// `apple_rtkit_send_user_msg`: user EP index gets +EP_USER_START.
    pub fn send_user_msg(&mut self, index: u8, msg: u64) {
        self.send_to_ap(index + EP_USER_START, msg);
    }

    /// `apple_rtkit_mgmt_send_hello` — kick off (or restart) the handshake.
    pub fn start(&mut self) {
        self.started = true;
        // HELLO { min, max } packed in the low 32 bits.
        let payload =
            (RTKIT_MAX_VERSION as u64) << 16 | RTKIT_MIN_VERSION as u64;
        self.send_to_ap(EP_MANAGEMENT, mgmt_msg(MSG_HELLO, payload));
        self.ep0 = Ep0State::WaitHello;
    }

    /// `apple_rtkit_mgmt_rollcall_v10/v11`.
    fn send_rollcall(&mut self) {
        // Build the EP mask over registered EPs. We use the v10 layout
        // (single 52-bit mask) when protocol_version <= 10, v11 blocks else.
        if self.protocol_version <= 10 {
            let mut mask: u64 = 0;
            for (ep, _) in self.registered_eps() {
                mask |= 1u64 << ep;
            }
            self.send_to_ap(EP_MANAGEMENT, mgmt_msg(MSG_TYPE_ROLLCALL, mask));
        } else {
            // v11: blocks of 32 EPs. Payload layout (union AppleRTKitMessage):
            // mask: u32 (bits 0..32), block: 6 bits (32..38), end: 1 bit (51).
            let eps = self.registered_eps();
            let mut block = 0u64;
            let mut mask = 0u64;
            for (ep, _) in &eps {
                let b = ep / EP_USER_START as u64;
                if b != block && mask != 0 {
                    let m =
                        (mask & 0xFFFF_FFFF) | (block << 32); // end = 0
                    self.rollcall
                        .push_back(rtkit_msg(EP_MANAGEMENT, mgmt_msg(MSG_TYPE_ROLLCALL, m)));
                    mask = 0;
                }
                block = b;
                mask |= 1 << (ep % EP_USER_START as u64);
            }
            let last = (mask & 0xFFFF_FFFF) | (block << 32) | (1 << 51);
            self.rollcall.push_back(rtkit_msg(EP_MANAGEMENT, mgmt_msg(MSG_TYPE_ROLLCALL, last)));
            if let Some(first) = self.rollcall.pop_front() {
                self.ap_ring.push_back(first);
                self.msgs_to_ap += 1;
            }
        }
        self.ep0 = Ep0State::WaitRollcall;
    }

    fn registered_eps(&self) -> Vec<(u64, bool)> {
        let mut v = Vec::new();
        v.push((EP_MANAGEMENT as u64, false));
        v.push((EP_CRASHLOG as u64, false));
        for (i, en) in self.user_eps.iter().enumerate() {
            if *en {
                v.push(((EP_USER_START as usize + i) as u64, true));
            }
        }
        v
    }

    /// Handle a message that arrived from the AP.
    fn handle_msg(&mut self, endpoint: u8, msg: u64) {
        self.msgs_from_ap += 1;
        if endpoint == EP_MANAGEMENT {
            self.handle_mgmt(msg);
        } else if endpoint == EP_CRASHLOG {
            // registered but has no handler upstream
        } else if endpoint >= EP_USER_START
            && self
                .user_eps
                .get(endpoint as usize - EP_USER_START as usize)
                .copied()
                .unwrap_or(false)
        {
            let idx = endpoint - EP_USER_START;
            self.user_msgs.push((idx, msg));
        } else {
            self.unknown_eps += 1;
        }
    }

    /// `apple_rtkit_mgmt_handle_msg`.
    fn handle_mgmt(&mut self, msg: u64) {
        match mgmt_type(msg) {
            MSG_HELLO_ACK => {
                if self.ep0 != Ep0State::WaitHello {
                    return;
                }
                let min_version = (msg & 0xFFFF) as u16;
                let max_version = ((msg >> 16) & 0xFFFF) as u16;
                // iOS <= 13 renegotiation (rtkit.c lines 292-300)
                if min_version == 0xFFFF && max_version == 0xBAD {
                    let payload = (RTKIT_MAX_VERSION_PRE_IOS14 as u64) << 16
                        | RTKIT_MIN_VERSION as u64;
                    self.send_to_ap(
                        EP_MANAGEMENT,
                        mgmt_msg(MSG_HELLO, payload),
                    );
                    return;
                }
                self.protocol_version = max_version;
                self.send_rollcall();
            }
            MSG_TYPE_PING => {
                // echo seg/timestamp, reply PING_ACK
                self.send_to_ap(
                    EP_MANAGEMENT,
                    mgmt_msg(MSG_TYPE_PING_ACK, msg & 0xF_FFFF_FFFF),
                );
            }
            MSG_TYPE_AP_POWER => {
                // echo the power state back (upstream: same type reply)
                self.send_to_ap(
                    EP_MANAGEMENT,
                    mgmt_msg(MSG_TYPE_AP_POWER, msg & 0xF_FFFF),
                );
            }
            MSG_TYPE_REQ_POWER => {
                let pstate = msg & 0xFFF;
                // PSTATE_ON would cpu_start the coprocessor; PSTATE_SLEEP/OFF
                // set IDLE — all bookkeeping only in the simulation.
                self.send_to_ap(
                    EP_MANAGEMENT,
                    mgmt_msg(MSG_TYPE_POWER_ACK, pstate),
                );
            }
            MSG_TYPE_ROLLCALL => {
                if self.ep0 != Ep0State::WaitRollcall {
                    return;
                }
                if self.rollcall.is_empty() {
                    // finished: POWER_ACK { 32 }
                    self.send_to_ap(
                        EP_MANAGEMENT,
                        mgmt_msg(MSG_TYPE_POWER_ACK, 32),
                    );
                    self.ep0 = Ep0State::Done;
                    self.boot_done = true;
                } else if let Some(next) = self.rollcall.pop_front() {
                    self.ap_ring.push_back(next);
                    self.msgs_to_ap += 1;
                }
            }
            _ => {}
        }
    }

    /// AP_CTRL register view (enable + ring status of the IOP→AP direction).
    fn ap_ctrl_view(&self) -> u32 {
        let mut v = self.ap_ctrl;
        if self.ap_ring.len() >= MBOX_MAX_MESSAGES {
            v |= CTRL_FULL;
        } else {
            v &= !CTRL_FULL;
        }
        if self.ap_ring.is_empty() {
            v |= CTRL_EMPTY;
        } else {
            v &= !CTRL_EMPTY;
        }
        v |= (self.ap_ring.len() as u32) << CTRL_COUNT_SHIFT;
        v
    }

    pub fn read(&mut self, off: u64, size: u8) -> u64 {
        let _ = size;
        match off {
            REG_INT_MASK_SET => self.int_mask,
            REG_INT_MASK_CLR => !self.int_mask & 0xFFFF_FFFF,
            REG_IOP_CTRL => self.iop_ctrl,
            REG_AP_CTRL => self.ap_ctrl_view(),
            off if (REG_AP_SEND0..REG_AP_RECV0).contains(&off) => {
                // AP send ring: reads-as-zero from the AP side
                0
            }
            off if (REG_AP_RECV0..REG_AP_RECV0 + 16).contains(&off) => {
                let word = ((off - REG_AP_RECV0) / 4) as usize;
                if word == 0 {
                    // popping word 0 latches the next message
                    self.recv_latch = self
                        .ap_ring
                        .pop_front()
                        .unwrap_or([0u8; 16]);
                }
                u32::from_le_bytes(
                    self.recv_latch[word * 4..word * 4 + 4].try_into().unwrap(),
                ) as u64
            }
            off if (REG_IOP_SEND0..REG_AP_SEND0).contains(&off) => 0,
            _ => 0,
        }
    }

    pub fn write(&mut self, off: u64, size: u8, val: u64) {
        let _ = size;
        match off {
            REG_INT_MASK_SET => self.int_mask |= val as u32,
            REG_INT_MASK_CLR => self.int_mask &= !(val as u32),
            REG_IOP_CTRL => self.iop_ctrl = val as u32,
            REG_AP_CTRL => {
                let was = self.ap_ctrl & CTRL_ENABLE;
                self.ap_ctrl = val as u32;
                if was == 0 && val & CTRL_ENABLE as u64 != 0 && !self.started {
                    // AP enabled the mailbox: IOP boots and sends HELLO.
                    self.start();
                }
            }
            off if (REG_AP_SEND0..REG_AP_RECV0).contains(&off) => {
                let word = ((off - REG_AP_SEND0) / 4) as usize;
                self.send_stage[word * 4..word * 4 + 4]
                    .copy_from_slice(&(val as u32).to_le_bytes());
                self.send_words += 1;
                if self.send_words == 4 {
                    self.send_words = 0;
                    let m = self.send_stage;
                    self.handle_msg(
                        msg_endpoint(&m) as u8,
                        msg_payload(&m),
                    );
                }
            }
            _ => {}
        }
    }

    /// Extend the region up to `mmio_size` (unmapped sub-ranges RAZ/WI).
    pub fn covers(&self, off: u64) -> bool {
        off < self.mmio_size
    }
}

impl Device for Rtkit {
    fn name(&self) -> &'static str {
        "rtkit"
    }
    fn read(&mut self, off: u64, size: u8) -> u64 {
        Rtkit::read(self, off, size)
    }
    fn write(&mut self, off: u64, size: u8, val: u64) {
        Rtkit::write(self, off, size, val)
    }
}

impl Rtkit {
    /// Parity census: documented mailbox/protocol items.
    pub fn regs_documented() -> &'static [(&'static str, u64)] {
        &[
            ("REG_INT_MASK_SET", REG_INT_MASK_SET),
            ("REG_INT_MASK_CLR", REG_INT_MASK_CLR),
            ("REG_IOP_CTRL", REG_IOP_CTRL),
            ("REG_AP_CTRL", REG_AP_CTRL),
            ("REG_IOP_SEND0", REG_IOP_SEND0),
            ("REG_IOP_RECV0", REG_IOP_RECV0),
            ("REG_AP_SEND0", REG_AP_SEND0),
            ("REG_AP_RECV0", REG_AP_RECV0),
            ("EP_MANAGEMENT", EP_MANAGEMENT as u64),
            ("EP_CRASHLOG", EP_CRASHLOG as u64),
            ("EP_USER_START", EP_USER_START as u64),
            ("MSG_HELLO", MSG_HELLO),
            ("MSG_HELLO_ACK", MSG_HELLO_ACK),
            ("MSG_TYPE_PING", MSG_TYPE_PING),
            ("MSG_TYPE_PING_ACK", MSG_TYPE_PING_ACK),
            ("MSG_TYPE_REQ_POWER", MSG_TYPE_REQ_POWER),
            ("MSG_TYPE_POWER_ACK", MSG_TYPE_POWER_ACK),
            ("MSG_TYPE_ROLLCALL", MSG_TYPE_ROLLCALL),
            ("MSG_TYPE_AP_POWER", MSG_TYPE_AP_POWER),
            ("RTKIT_MIN_VERSION", RTKIT_MIN_VERSION as u64),
            ("RTKIT_MAX_VERSION", RTKIT_MAX_VERSION as u64),
        ]
    }
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Drive the full EP0 handshake as the guest (AP) side would.
    fn handshake(rtk: &mut Rtkit) {
        rtk.register_user_ep(0);
        // AP enables the mailbox → IOP sends HELLO
        rtk.write(REG_AP_CTRL, 4, CTRL_ENABLE as u64);
        assert!(rtk.started);
        let hello = recv_msg(rtk);
        assert_eq!(msg_endpoint(&hello), EP_MANAGEMENT as u32);
        let payload = msg_payload(&hello);
        assert_eq!(mgmt_type(payload), MSG_HELLO);
        assert_eq!(payload & 0xFFFF, RTKIT_MIN_VERSION as u64);

        // AP replies HELLO_ACK { min: 3, max: 12 }
        send_msg(
            rtk,
            &rtkit_msg(
                EP_MANAGEMENT,
                mgmt_msg(
                    MSG_HELLO_ACK,
                    (RTKIT_MAX_VERSION as u64) << 16 | RTKIT_MIN_VERSION as u64,
                ),
            ),
        );
        assert_eq!(rtk.ep0, Ep0State::WaitRollcall);

        // IOP sent rollcall (v11: protocol 12) — read it.
        let rc = recv_msg(rtk);
        assert_eq!(msg_endpoint(&rc), EP_MANAGEMENT as u32);
        assert_eq!(mgmt_type(msg_payload(&rc)), MSG_TYPE_ROLLCALL);

        // AP replies ROLLCALL → boot done
        send_msg(rtk, &rtkit_msg(EP_MANAGEMENT, mgmt_msg(MSG_TYPE_ROLLCALL, 0)));
        assert!(rtk.boot_done);
    }

    /// Drain one 16-byte message from the AP_RECV ring (4 word reads).
    fn recv_msg(rtk: &mut Rtkit) -> MboxMessage {
        let mut m = [0u8; 16];
        for w in 0..4 {
            let v = rtk.read(REG_AP_RECV0 + w * 4, 4) as u32;
            m[w * 4..w * 4 + 4].copy_from_slice(&v.to_le_bytes());
        }
        m
    }

    /// Push one 16-byte message into the AP_SEND ring (4 word writes).
    fn send_msg(rtk: &mut Rtkit, m: &MboxMessage) {
        for w in 0..4 {
            let v = u32::from_le_bytes(m[w * 4..w * 4 + 4].try_into().unwrap());
            rtk.write(REG_AP_SEND0 + w * 4, 4, v as u64);
        }
    }

    #[test]
    fn ep0_boot_handshake() {
        let mut rtk = Rtkit::new("ANS2", 0x4000);
        handshake(&mut rtk);
        assert_eq!(rtk.protocol_version, RTKIT_MAX_VERSION);
        assert_eq!(rtk.ep0, Ep0State::Done);
    }

    #[test]
    fn user_ep_routing() {
        let mut rtk = Rtkit::new("AOP", 0x4000);
        handshake(&mut rtk);
        // guest sends a message to user EP 0 (wire EP 32)
        send_msg(&mut rtk, &rtkit_msg(EP_USER_START, 0xDEAD_BEEF));
        assert_eq!(rtk.user_msgs, vec![(0u8, 0xDEAD_BEEF_u64)]);
    }

    #[test]
    fn ring_full_drops() {
        let mut rtk = Rtkit::new("T", 0x4000);
        for i in 0..MBOX_MAX_MESSAGES + 4 {
            rtk.send_to_ap(EP_CRASHLOG, i as u64);
        }
        assert_eq!(rtk.ap_ring.len(), MBOX_MAX_MESSAGES);
    }
}
