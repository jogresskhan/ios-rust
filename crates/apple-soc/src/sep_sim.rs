//! Apple SEP simulator (SEP firmware is *not* executed).
//!
//! Port of ChefKiss Inferno `hw/arm/apple-silicon/sep-sim.c`: the
//! control-op state machine over the A7IOP mailbox (bootstrap handshake,
//! control ops, OOL plumbing, ART storage, XART ack shim, keystore ep 18)
//! plus the v4 mailbox register block (`a7iop/mailbox/regs-v4.c`).
//!
//! Faithful surface (sep-sim.c):
//!   * `SEPMessage { ep, tag, op, param, data }` (8 bytes, in the 16-byte
//!     mailbox message),
//!   * EP map (`EP_CONTROL` .. `EP_BOOTSTRAP`, incl. ep 18 = keystore),
//!   * `CONTROL_OP_*` set (NOP/ACK/OOL addr+size/TTY/SEED_DPA/GEN_RANDOM/
//!     SELF_TEST/DMA regs/ERASE_INSTALL/...), handled exactly like upstream:
//!     only NOP, OOL_SET_*, GET_SECURITY_MODE, SELF_TEST, ERASE_INSTALL are
//!     answered; the rest are recorded as unhandled,
//!   * bootstrap handshake (PING → PING_ACK, GET_STATUS, GENERATE_NONCE,
//!     GET_NONCE_WORD, BOOT_TZ0, BOOT_IMG4 → EP adverts, OPCODE_16),
//!   * keystore ep 18 responses (Create/Copy/Load Keybag, Lock State, KC
//!     Wrap, Null-D/Unwrap-D, Make System Keybag, Get Device State, Client
//!     Terminate) with the `KeystoreIPCHeader` (0x54) framing.
//!
//! Parity gaps: payload_hash is a SHA-256 upstream — zeroed here (no crypto
//! crates); guest RNG replaced by a deterministic xorshift64\*; OOL/DMA
//! targets outside the [`SepSim::dma_window`] are recorded in
//! [`SepSim::pending_ool_writes`].
//!
//! License: AGPL-3.0-or-later (derived work).

use std::collections::VecDeque;

use vm_core::Device;

use crate::rtkit::{
    MboxMessage, MBOX_MAX_MESSAGES, REG_AP_CTRL, REG_AP_RECV0, REG_AP_SEND0,
    REG_INT_MASK_CLR, REG_INT_MASK_SET, REG_IOP_CTRL, CTRL_ENABLE, CTRL_EMPTY,
    CTRL_FULL, CTRL_COUNT_SHIFT,
};

// ---------------------------------------------------------------------------
// SEP endpoints (sep-sim.c enum)
// ---------------------------------------------------------------------------

pub const EP_CONTROL: u8 = 0; // 'cntl'
pub const EP_LOGGER: u8 = 1;
pub const EP_ART_STORAGE: u8 = 2;
pub const EP_ART_REQUESTS: u8 = 3;
pub const EP_TRACING: u8 = 4;
pub const EP_DEBUG: u8 = 5;
pub const EP_EMBEDDED_ISP: u8 = 6;
pub const EP_MOBILE_SKS: u8 = 7;
pub const EP_SECURE_BIOMETRICS: u8 = 8;
pub const EP_FACE_ID: u8 = 9;
pub const EP_SECURE_CREDENTIALS: u8 = 10;
pub const EP_PAIRING: u8 = 11;
pub const EP_SECURE_ELEMENT: u8 = 12;
pub const EP_HDCP: u8 = 14;
pub const EP_UNIT_TESTING: u8 = 15;
pub const EP_XART_SLAVE: u8 = 16;
pub const EP_HILO: u8 = 17;
pub const EP_KEYSTORE: u8 = 18;
pub const EP_XART_MASTER: u8 = 19;
pub const EP_SMC: u8 = 20;
pub const EP_NONP: u8 = 21;
pub const EP_DISCOVERY: u8 = 253;
pub const EP_L4INFO: u8 = 254;
pub const EP_BOOTSTRAP: u8 = 255;

pub const SEP_ENDPOINT_MAX: usize = 0x20;

// Control ops.
pub const CONTROL_OP_NOP: u8 = 0;
pub const CONTROL_OP_ACK: u8 = 1;
pub const CONTROL_OP_SET_OOL_IN_ADDR: u8 = 2;
pub const CONTROL_OP_SET_OOL_OUT_ADDR: u8 = 3;
pub const CONTROL_OP_SET_OOL_IN_SIZE: u8 = 4;
pub const CONTROL_OP_SET_OOL_OUT_SIZE: u8 = 5;
pub const CONTROL_OP_TTY_IN: u8 = 10;
pub const CONTROL_OP_SLEEP: u8 = 12;
pub const CONTROL_OP_NOTIFY_ALIVE: u8 = 13;
pub const CONTROL_OP_SEED_DPA: u8 = 15;
pub const CONTROL_OP_GENERATE_RANDOM_DATA: u8 = 16;
pub const CONTROL_OP_OPCODE_18: u8 = 18;
pub const CONTROL_OP_NAP: u8 = 19;
pub const CONTROL_OP_GET_SECURITY_MODE: u8 = 20;
pub const CONTROL_OP_SELF_TEST: u8 = 24;
pub const CONTROL_OP_SET_DMA_CMD_ADDR: u8 = 25;
pub const CONTROL_OP_SET_DMA_CMD_SIZE: u8 = 26;
pub const CONTROL_OP_SET_DMA_IN_ADDR: u8 = 27;
pub const CONTROL_OP_SET_DMA_OUT_ADDR: u8 = 28;
pub const CONTROL_OP_SET_DMA_IN_RELAY_ADDR: u8 = 29;
pub const CONTROL_OP_SET_DMA_OUT_RELAY_ADDR: u8 = 30;
pub const CONTROL_OP_SET_DMA_IN_SIZE: u8 = 31;
pub const CONTROL_OP_SET_DMA_OUT_SIZE: u8 = 32;
pub const CONTROL_OP_ERASE_INSTALL: u8 = 37;
pub const CONTROL_OP_L4_PANIC: u8 = 38;
pub const CONTROL_OP_SEP_OS_PANIC: u8 = 39;

// ART storage ops.
pub const ART_STORAGE_OP_ART_LOAD: u8 = 1;
pub const ART_STORAGE_OP_NO_ART: u8 = 2;
pub const ART_STORAGE_OP_MANIFEST: u8 = 3;
pub const ART_STORAGE_OP_INCOMING: u8 = 20;
pub const ART_STORAGE_OP_RECEIVED: u8 = 21;

// XART ops (IOP → AP handled).
pub const XART_OP_ACK: u8 = 0;
pub const XART_OP_FLUSH_CACHED_XART: u8 = 12;
pub const XART_OP_SHUTDOWN: u8 = 13;
pub const XART_OP_NONCE_GENERATE: u8 = 15;
pub const XART_OP_NONCE_INVALIDATE: u8 = 17;
pub const XART_OP_COMMIT_HASH: u8 = 18;

// Discovery ops.
pub const DISCOVERY_OP_EP_ADVERT: u8 = 0;
pub const DISCOVERY_OP_OOL_ADVERT: u8 = 1;

// Bootstrap ops.
pub const BOOTSTRAP_OP_PING: u8 = 1;
pub const BOOTSTRAP_OP_GET_STATUS: u8 = 2;
pub const BOOTSTRAP_OP_GENERATE_NONCE: u8 = 3;
pub const BOOTSTRAP_OP_GET_NONCE_WORD: u8 = 4;
pub const BOOTSTRAP_OP_BOOT_TZ0: u8 = 5;
pub const BOOTSTRAP_OP_BOOT_IMG4: u8 = 6;
pub const BOOTSTRAP_OP_OPCODE_16: u8 = 16;
pub const BOOTSTRAP_OP_PING_ACK: u8 = 101;
pub const BOOTSTRAP_OP_STATUS_REPLY: u8 = 102;
pub const BOOTSTRAP_OP_NONCE_GENERATED: u8 = 103;
pub const BOOTSTRAP_OP_NONCE_WORD_REPLY: u8 = 104;
pub const BOOTSTRAP_OP_TZ0_ACCEPTED: u8 = 105;
pub const BOOTSTRAP_OP_IMG4_ACCEPTED: u8 = 106;
pub const BOOTSTRAP_OP_OPCODE_16_RESPONSE: u8 = 116;
pub const BOOTSTRAP_OP_ANNOUNCE_STATUS: u8 = 210;

// SEP status values.
pub const SEP_STATUS_SLEEPING: u32 = 0;
pub const SEP_STATUS_BOOTSTRAP: u32 = 1;
pub const SEP_STATUS_ACTIVE: u32 = 2;

// Keystore framing.
pub const KEYSTORE_MSG_TAG_REPLY: u8 = 0x80;
pub const KEYSTORE_MSG_TAG_CODE_MASK: u8 = 0x7F;
pub const KEYSTORE_IPC_HEADER_SIZE: usize = 0x54;
pub const KEYSTORE_IPC_VERSION_1: u32 = 1;

/// Decoded SEP message (`SEPMessage` — 8 bytes packed upstream).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SepMessage {
    pub ep: u8,
    pub tag: u8,
    pub op: u8,
    pub param: u8,
    pub data: u32,
}

impl SepMessage {
    pub fn encode(&self) -> MboxMessage {
        let mut m = [0u8; 16];
        m[0] = self.ep;
        m[1] = self.tag;
        m[2] = self.op;
        m[3] = self.param;
        m[4..8].copy_from_slice(&self.data.to_le_bytes());
        m
    }

    pub fn decode(m: &MboxMessage) -> Self {
        SepMessage {
            ep: m[0],
            tag: m[1],
            op: m[2],
            param: m[3],
            data: u32::from_le_bytes(m[4..8].try_into().unwrap()),
        }
    }
}

/// OOL bookkeeping per endpoint (`AppleSEPSimOOLState`).
#[derive(Debug, Clone, Copy, Default)]
pub struct OolState {
    pub in_addr: u64,
    pub in_size: u32,
    pub out_addr: u64,
    pub out_size: u32,
}

/// OOL capability advert (`AppleSEPSimOOLInfo`).
#[derive(Debug, Clone, Copy, Default)]
pub struct OolInfo {
    pub in_min_pages: u8,
    pub in_max_pages: u8,
    pub out_min_pages: u8,
    pub out_max_pages: u8,
}

/// The SEP simulator.
pub struct SepSim {
    int_mask: u32,
    iop_ctrl: u32,
    ap_ctrl: u32,
    recv_latch: MboxMessage,
    send_stage: MboxMessage,
    send_words: u8,

    outbox: VecDeque<MboxMessage>,
    pub status: u32,
    pub rsep: bool,
    pub ool_state: [OolState; SEP_ENDPOINT_MAX],
    pub ool_info: [OolInfo; SEP_ENDPOINT_MAX],

    /// Bounded window for keystore/OOL traffic: guest address `dma_base`
    /// maps to `dma[0]`. Out-of-window writes are recorded.
    pub dma_window: Vec<u8>,
    pub dma_base: u64,
    pub pending_ool_writes: Vec<(u64, Vec<u8>)>,

    /// Census of handled ops (`"ep-op" → count`).
    pub op_census: Vec<(String, u32)>,
    /// Log of unhandled ops (ep, op) for parity census.
    pub unhandled: Vec<(u8, u8)>,

    rng_state: u64,
    advertised: bool,
}

impl SepSim {
    pub fn new() -> Self {
        let mut s = SepSim {
            int_mask: 0,
            iop_ctrl: 0,
            ap_ctrl: 0,
            recv_latch: [0; 16],
            send_stage: [0; 16],
            send_words: 0,
            outbox: VecDeque::new(),
            status: SEP_STATUS_SLEEPING,
            rsep: false,
            ool_state: [OolState::default(); SEP_ENDPOINT_MAX],
            ool_info: [OolInfo::default(); SEP_ENDPOINT_MAX],
            dma_window: vec![0u8; 0x10_0000], // 1 MiB
            dma_base: 0,
            pending_ool_writes: Vec::new(),
            op_census: Vec::new(),
            unhandled: Vec::new(),
            rng_state: 0x9E37_79B9_7F4A_7C15,
            advertised: false,
        };
        // apple_sep_sim_reset_hold: OOL page caps per EP class.
        for &ep in &[
            EP_CONTROL,
            EP_LOGGER,
            EP_ART_STORAGE,
            EP_ART_REQUESTS,
            EP_SECURE_CREDENTIALS,
            EP_XART_SLAVE,
            EP_KEYSTORE,
            EP_XART_MASTER,
        ] {
            let info = &mut s.ool_info[ep as usize];
            match ep {
                EP_LOGGER => {
                    info.in_min_pages = 0;
                    info.in_max_pages = 0;
                    info.out_min_pages = 1;
                    info.out_max_pages = 1;
                }
                EP_ART_STORAGE | EP_ART_REQUESTS | EP_DEBUG | EP_UNIT_TESTING => {
                    info.in_min_pages = 1;
                    info.in_max_pages = 1;
                    info.out_min_pages = 1;
                    info.out_max_pages = 1;
                }
                EP_HILO => { /* all zero */ }
                _ => {
                    info.in_min_pages = 2;
                    info.in_max_pages = 2;
                    info.out_min_pages = 2;
                    info.out_max_pages = 2;
                }
            }
        }
        // Reset hold also announces BOOTSTRAP status on EP_BOOTSTRAP.
        s.status = SEP_STATUS_BOOTSTRAP;
        s.send_message(EP_BOOTSTRAP, 0, BOOTSTRAP_OP_ANNOUNCE_STATUS, 0, s.status);
        s
    }

    /// Point the OOL window at the physical address the guest will use.
    pub fn set_dma_window(&mut self, base: u64) {
        self.dma_base = base;
    }

    fn census(&mut self, op: &str) {
        let key = op.to_string();
        for e in self.op_census.iter_mut() {
            if e.0 == key {
                e.1 += 1;
                return;
            }
        }
        self.op_census.push((key, 1));
    }

    fn next_random(&mut self) -> u32 {
        // xorshift64*
        let mut x = self.rng_state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.rng_state = x;
        (x.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 32) as u32
    }

    fn send_message(&mut self, ep: u8, tag: u8, op: u8, param: u8, data: u32) {
        if self.outbox.len() >= MBOX_MAX_MESSAGES {
            return;
        }
        let msg = SepMessage { ep, tag, op, param, data };
        self.outbox.push_back(msg.encode());
    }

    fn reply(&mut self, msg: &SepMessage, op: u8, param: u8, data: u32) {
        self.send_message(msg.ep, msg.tag, op, param, data);
    }

    fn send_ack(&mut self, msg: &SepMessage, param: u8, data: u32) {
        self.reply(msg, CONTROL_OP_ACK, param, data);
    }

    // -----------------------------------------------------------------------
    // DMA window access
    // -----------------------------------------------------------------------

    fn dma_read(&mut self, addr: u64, buf: &mut [u8]) {
        if self.dma_base != 0 && addr >= self.dma_base {
            let off = (addr - self.dma_base) as usize;
            if off + buf.len() <= self.dma_window.len() {
                buf.copy_from_slice(&self.dma_window[off..off + buf.len()]);
                return;
            }
        }
        buf.fill(0);
    }

    fn dma_write(&mut self, addr: u64, data: &[u8]) {
        if self.dma_base != 0 && addr >= self.dma_base {
            let off = (addr - self.dma_base) as usize;
            if off + data.len() <= self.dma_window.len() {
                self.dma_window[off..off + data.len()].copy_from_slice(data);
                return;
            }
        }
        self.pending_ool_writes.push((addr, data.to_vec()));
    }

    // -----------------------------------------------------------------------
    // EP handlers (sep-sim.c)
    // -----------------------------------------------------------------------

    /// `apple_sep_sim_handle_control_msg`.
    fn handle_control(&mut self, msg: &SepMessage) {
        match msg.op {
            CONTROL_OP_NOP => {
                self.census("ctrl-nop");
                self.send_ack(msg, 0, 0);
            }
            CONTROL_OP_SET_OOL_IN_ADDR
            | CONTROL_OP_SET_OOL_OUT_ADDR
            | CONTROL_OP_SET_OOL_IN_SIZE
            | CONTROL_OP_SET_OOL_OUT_SIZE => {
                let id = msg.param as usize; // SetOOLMessage.id
                let ep = id.min(SEP_ENDPOINT_MAX - 1);
                match msg.op {
                    CONTROL_OP_SET_OOL_IN_ADDR => {
                        self.ool_state[ep].in_addr = (msg.data as u64) << 12;
                    }
                    CONTROL_OP_SET_OOL_OUT_ADDR => {
                        self.ool_state[ep].out_addr = (msg.data as u64) << 12;
                    }
                    CONTROL_OP_SET_OOL_IN_SIZE => {
                        self.ool_state[ep].in_size = msg.data;
                    }
                    _ => {
                        self.ool_state[ep].out_size = msg.data;
                    }
                }
                self.census("ctrl-set-ool");
                self.send_ack(msg, 0, 0);
            }
            CONTROL_OP_GET_SECURITY_MODE => {
                self.census("ctrl-get-security-mode");
                self.send_ack(msg, 0, 3);
            }
            CONTROL_OP_SELF_TEST => {
                self.census("ctrl-self-test");
                self.send_ack(msg, 0, 0);
            }
            CONTROL_OP_ERASE_INSTALL => {
                self.census("ctrl-erase-install");
                self.send_ack(msg, 0, 0);
                // Synthesized ART header (DER) — upstream builds a real
                // ASN.1 ART.Header with zeroed hashes via libtasn1; the
                // simplified 512-byte blob keeps the framing.
                let data = vec![0u8; 512];
                let out_addr = self.ool_state[EP_ART_STORAGE as usize].out_addr;
                self.dma_write(out_addr, &data);
                self.send_message(
                    EP_ART_STORAGE,
                    0,
                    ART_STORAGE_OP_INCOMING,
                    0,
                    0,
                );
            }
            other => {
                // TTY_IN, SLEEP, SEED_DPA, GENERATE_RANDOM_DATA, DMA regs,
                // NAP, L4_PANIC, SEP_OS_PANIC … upstream: "Unknown opcode".
                self.unhandled.push((EP_CONTROL, other));
                self.census("ctrl-unhandled");
            }
        }
    }

    /// `apple_sep_sim_handle_arts_msg`.
    fn handle_arts(&mut self, msg: &SepMessage) {
        match msg.op {
            ART_STORAGE_OP_RECEIVED => self.census("arts-received"),
            _ => self.unhandled.push((EP_ART_STORAGE, msg.op)),
        }
    }

    /// `apple_sep_sim_handle_xart_msg`.
    fn handle_xart(&mut self, slave: bool, msg: &SepMessage) {
        let _ = slave;
        match msg.op {
            XART_OP_FLUSH_CACHED_XART
            | XART_OP_COMMIT_HASH
            | XART_OP_NONCE_GENERATE
            | XART_OP_NONCE_INVALIDATE
            | XART_OP_SHUTDOWN => {
                self.census("xart-ack");
                self.reply(msg, XART_OP_ACK, 0, 0);
            }
            _ => {
                self.census("xart-default-ack");
                self.reply(msg, XART_OP_ACK, 0, 0);
            }
        }
    }

    /// `apple_sep_sim_handle_l4info`.
    fn handle_l4info(&mut self, msg: &SepMessage) {
        // L4InfoMessage { ep, tag, size: u16, address: u32 } — the fields are
        // packed over op/param/data in the 8-byte SEP message.
        let size = ((msg.param as u16) << 8 | msg.op as u16) & 0xFFFF;
        let address = (msg.data as u64) << 12;
        let st = &mut self.ool_state[EP_CONTROL as usize];
        st.in_addr = address;
        st.in_size = (size as u32) << 12;
        st.out_addr = address;
        st.out_size = (size as u32) << 12;
        self.census("l4info");
    }

    /// `apple_sep_sim_advertise_eps`.
    fn advertise_eps(&mut self) {
        const EPS: [(u8, u32); 8] = [
            (EP_CONTROL, u32::from_le_bytes(*b"cntl")),
            (EP_LOGGER, u32::from_le_bytes(*b"log ")),
            (EP_ART_STORAGE, u32::from_le_bytes(*b"arts")),
            (EP_ART_REQUESTS, u32::from_le_bytes(*b"artr")),
            (EP_SECURE_CREDENTIALS, u32::from_le_bytes(*b"scrd")),
            (EP_XART_SLAVE, u32::from_le_bytes(*b"xars")),
            (EP_KEYSTORE, u32::from_le_bytes(*b"sks ")),
            (EP_XART_MASTER, u32::from_le_bytes(*b"xarm")),
        ];
        for &(ep, name) in &EPS {
            // EP_ADVERT: { ep=DISCOVERY, op, id, name }
            let mut m = [0u8; 16];
            m[0] = EP_DISCOVERY;
            m[2] = DISCOVERY_OP_EP_ADVERT;
            m[4] = ep;
            m[8..12].copy_from_slice(&name.to_le_bytes());
            if self.outbox.len() < MBOX_MAX_MESSAGES {
                self.outbox.push_back(m);
            }
            // OOL_ADVERT: { ep=DISCOVERY, op, id, ool_info }
            let mut m = [0u8; 16];
            m[0] = EP_DISCOVERY;
            m[2] = DISCOVERY_OP_OOL_ADVERT;
            m[4] = ep;
            let info = self.ool_info[ep as usize];
            m[8] = info.in_min_pages;
            m[9] = info.in_max_pages;
            m[10] = info.out_min_pages;
            m[11] = info.out_max_pages;
            if self.outbox.len() < MBOX_MAX_MESSAGES {
                self.outbox.push_back(m);
            }
        }
        self.advertised = true;
    }

    /// `apple_sep_sim_handle_bootstrap_msg`.
    fn handle_bootstrap(&mut self, msg: &SepMessage) {
        match msg.op {
            BOOTSTRAP_OP_PING => {
                self.census("bootstrap-ping");
                self.send_message(msg.ep, msg.tag, BOOTSTRAP_OP_PING_ACK, 0, 0);
            }
            BOOTSTRAP_OP_GET_STATUS => {
                self.census("bootstrap-get-status");
                self.send_message(
                    msg.ep,
                    msg.tag,
                    BOOTSTRAP_OP_STATUS_REPLY,
                    0,
                    self.status,
                );
            }
            BOOTSTRAP_OP_GENERATE_NONCE => {
                self.census("bootstrap-generate-nonce");
                // 0xa0 = returned length in bits
                self.send_message(
                    msg.ep,
                    msg.tag,
                    BOOTSTRAP_OP_NONCE_GENERATED,
                    0,
                    0xa0,
                );
            }
            BOOTSTRAP_OP_GET_NONCE_WORD => {
                self.census("bootstrap-get-nonce-word");
                let randval = self.next_random();
                self.send_message(
                    msg.ep,
                    msg.tag,
                    BOOTSTRAP_OP_NONCE_WORD_REPLY,
                    msg.param, // index (not offset), echoed back
                    randval,
                );
            }
            BOOTSTRAP_OP_BOOT_TZ0 => {
                self.census("bootstrap-boot-tz0");
                self.rsep = msg.param == 1;
                self.status = SEP_STATUS_ACTIVE;
                self.send_message(
                    msg.ep,
                    msg.tag,
                    BOOTSTRAP_OP_TZ0_ACCEPTED,
                    0,
                    0,
                );
            }
            BOOTSTRAP_OP_BOOT_IMG4 => {
                self.census("bootstrap-boot-img4");
                // upstream asserts rsep == (param == 1) here
                if self.rsep != (msg.param == 1) {
                    self.census("bootstrap-img4-rsep-mismatch");
                }
                self.send_message(
                    msg.ep,
                    msg.tag,
                    BOOTSTRAP_OP_IMG4_ACCEPTED,
                    0,
                    0,
                );
                self.send_message(
                    EP_CONTROL,
                    0,
                    CONTROL_OP_NOTIFY_ALIVE,
                    0,
                    0,
                );
                self.advertise_eps();
            }
            BOOTSTRAP_OP_OPCODE_16 => {
                self.census("bootstrap-op16");
                // normally 0x20 random bytes split in 4-byte pieces
                let randval = self.next_random();
                self.send_message(
                    msg.ep,
                    msg.tag,
                    BOOTSTRAP_OP_OPCODE_16_RESPONSE,
                    0,
                    randval,
                );
            }
            other => {
                self.unhandled.push((EP_BOOTSTRAP, other));
            }
        }
    }

    /// Build a keystore IPC response header (payload_hash zeroed — SHA-256
    /// is a documented gap).
    fn ks_header(&self, msg_hdr: &[u8], body_size_extra: usize) -> Vec<u8> {
        let mut resp = vec![0u8; KEYSTORE_IPC_HEADER_SIZE + body_size_extra];
        let body_size = (KEYSTORE_IPC_HEADER_SIZE - 4) as u32;
        resp[0..4].copy_from_slice(&body_size.to_le_bytes());
        // payload_hash [4..0x14] stays zero
        resp[0x14..0x18]
            .copy_from_slice(&KEYSTORE_IPC_VERSION_1.to_le_bytes());
        // time_msecs at 0x18, id at 0x20, proc_uid 0x28, audit 0x30 —
        // echoed from the request header.
        for (dst, src) in [
            (0x18usize, 0x18usize),
            (0x20, 0x20),
            (0x28, 0x28),
            (0x30, 0x30),
        ] {
            if src + 8 <= msg_hdr.len() && dst + 8 <= resp.len() {
                resp[dst..dst + 8].copy_from_slice(&msg_hdr[src..src + 8]);
            }
        }
        // ipc_digest [0x34..0x48] echoed
        if 0x34 + 0x14 <= msg_hdr.len() {
            resp[0x34..0x34 + 0x14]
                .copy_from_slice(&msg_hdr[0x34..0x34 + 0x14]);
        }
        resp
    }

    /// `apple_sep_sim_keystore_send_ipc_resp`.
    fn keystore_send_ipc_resp(
        &mut self,
        msg: &SepMessage,
        resp_buf: Vec<u8>,
    ) {
        let out_addr = self.ool_state[EP_KEYSTORE as usize].out_addr;
        let resp_size = resp_buf.len() as u32;
        self.dma_write(out_addr, &resp_buf);
        // msg->id lives in the `op` byte of the SEP message layout.
        self.send_message(
            msg.ep,
            msg.tag | KEYSTORE_MSG_TAG_REPLY,
            msg.op,
            0,
            resp_size << 16,
        );
    }

    /// `apple_sep_sim_handle_keystore_msg`.
    fn handle_keystore(&mut self, msg: &SepMessage) {
        let msg_code = msg.tag & KEYSTORE_MSG_TAG_CODE_MASK;
        let size = (msg.data >> 16) as usize; // KeystoreMessage.size (bytes 6..8)
        let size = size.min(0x1000);
        let mut buf = vec![0u8; size];
        let in_addr = self.ool_state[EP_KEYSTORE as usize].in_addr;
        self.dma_read(in_addr, &mut buf);

        match msg_code {
            0x01 => {
                self.census("ks-create-keybag");
                let mut resp = self.ks_header(&buf, 8);
                let sel_off = KEYSTORE_IPC_HEADER_SIZE;
                resp[sel_off..sel_off + 4].copy_from_slice(&1u32.to_le_bytes());
                resp[sel_off + 4..sel_off + 8]
                    .copy_from_slice(b"BAG1");
                self.keystore_send_ipc_resp(msg, resp);
            }
            0x02 => {
                self.census("ks-copy-keybag");
                let mut resp = self.ks_header(&buf, 0x18);
                let sel_off = KEYSTORE_IPC_HEADER_SIZE;
                resp[sel_off..sel_off + 4].copy_from_slice(&0u32.to_le_bytes());
                resp[sel_off + 4..sel_off + 8]
                    .copy_from_slice(&0x10u32.to_le_bytes());
                for b in &mut resp[sel_off + 8..sel_off + 8 + 0x10] {
                    *b = 0xAF;
                }
                self.keystore_send_ipc_resp(msg, resp);
            }
            0x03 => {
                self.census("ks-load-keybag");
                let mut resp = self.ks_header(&buf, 8);
                let sel_off = KEYSTORE_IPC_HEADER_SIZE;
                resp[sel_off..sel_off + 4].copy_from_slice(&0u32.to_le_bytes());
                resp[sel_off + 4..sel_off + 8].copy_from_slice(b"BAG1");
                self.keystore_send_ipc_resp(msg, resp);
            }
            0x04 => {
                self.census("ks-change-lock-state");
                let mut resp = self.ks_header(&buf, 0xC);
                let sel_off = KEYSTORE_IPC_HEADER_SIZE;
                resp[sel_off..sel_off + 4].copy_from_slice(&0u32.to_le_bytes());
                // lock_state from msg + 0x60, bit 22 set (mostly guessing —
                // upstream comment kept verbatim)
                let mut lock_state = 0u32;
                if 0x60 + 4 <= buf.len() {
                    lock_state = u32::from_le_bytes(
                        buf[0x60..0x64].try_into().unwrap(),
                    );
                }
                lock_state |= 1 << 22;
                resp[sel_off + 4..sel_off + 8]
                    .copy_from_slice(&lock_state.to_le_bytes());
                let device_state = 0x1u64 | 0x2;
                resp[sel_off + 8..sel_off + 16]
                    .copy_from_slice(&device_state.to_le_bytes());
                self.keystore_send_ipc_resp(msg, resp);
            }
            0x05 => {
                self.census("ks-unload-keybag");
                let resp = self.ks_header(&buf, 4);
                self.keystore_send_ipc_resp(msg, resp);
            }
            0x08 => {
                self.census("ks-kc-wrap");
                // upstream replies with an empty message, no IPC buffer
                self.send_message(
                    msg.ep,
                    msg.tag | KEYSTORE_MSG_TAG_REPLY,
                    msg.op,
                    0,
                    0,
                );
            }
            0x0A | 0x0C | 0x0D | 0x1B => {
                self.census("ks-simple-selector-0");
                let mut resp = self.ks_header(&buf, 4);
                let sel_off = KEYSTORE_IPC_HEADER_SIZE;
                resp[sel_off..sel_off + 4].copy_from_slice(&0u32.to_le_bytes());
                self.keystore_send_ipc_resp(msg, resp);
            }
            0x19 => {
                self.census("ks-get-device-state");
                let mut resp = self.ks_header(&buf, 0xC);
                let sel_off = KEYSTORE_IPC_HEADER_SIZE;
                resp[sel_off..sel_off + 4].copy_from_slice(&0u32.to_le_bytes());
                // DER blob: length 8 + "applehax"
                resp[sel_off + 4..sel_off + 8]
                    .copy_from_slice(&8u32.to_le_bytes());
                resp[sel_off + 8..sel_off + 16].copy_from_slice(b"applehax");
                self.keystore_send_ipc_resp(msg, resp);
            }
            other => {
                self.census("ks-unknown");
                // upstream echoes the request back and replies with the size
                let out_addr = self.ool_state[EP_KEYSTORE as usize].out_addr;
                self.dma_write(out_addr, &buf);
                self.send_message(
                    msg.ep,
                    msg.tag | KEYSTORE_MSG_TAG_REPLY,
                    msg.op,
                    0,
                    (size as u32) << 16,
                );
                let _ = other;
            }
        }
    }

    /// `apple_sep_sim_handle_messages` — process one incoming SEP message.
    pub fn handle_message(&mut self, msg: &SepMessage) {
        match msg.ep {
            EP_CONTROL => self.handle_control(msg),
            EP_ART_STORAGE => self.handle_arts(msg),
            EP_ART_REQUESTS | EP_SECURE_CREDENTIALS | EP_DISCOVERY => {
                self.unhandled.push((msg.ep, msg.op));
            }
            EP_XART_SLAVE => self.handle_xart(true, msg),
            EP_XART_MASTER => self.handle_xart(false, msg),
            EP_KEYSTORE => self.handle_keystore(msg),
            EP_L4INFO => self.handle_l4info(msg),
            EP_BOOTSTRAP => self.handle_bootstrap(msg),
            other => {
                self.unhandled.push((other, msg.op));
            }
        }
    }

    fn ap_ctrl_view(&self) -> u32 {
        let mut v = self.ap_ctrl;
        if self.outbox.is_empty() {
            v |= CTRL_EMPTY;
        } else {
            v &= !CTRL_EMPTY;
        }
        if self.outbox.len() >= MBOX_MAX_MESSAGES {
            v |= CTRL_FULL;
        }
        v |= (self.outbox.len() as u32) << CTRL_COUNT_SHIFT;
        v
    }
}

impl Device for SepSim {
    fn name(&self) -> &'static str {
        "sep-sim"
    }

    fn read(&mut self, off: u64, size: u8) -> u64 {
        let _ = size;
        match off {
            REG_INT_MASK_SET => self.int_mask as u64,
            REG_INT_MASK_CLR => (!self.int_mask & 0xFFFF_FFFF) as u64,
            REG_IOP_CTRL => self.iop_ctrl as u64,
            REG_AP_CTRL => self.ap_ctrl_view() as u64,
            off if (REG_AP_SEND0..REG_AP_RECV0).contains(&off) => 0,
            off if (REG_AP_RECV0..REG_AP_RECV0 + 16).contains(&off) => {
                let word = ((off - REG_AP_RECV0) / 4) as usize;
                if word == 0 {
                    self.recv_latch =
                        self.outbox.pop_front().unwrap_or([0u8; 16]);
                }
                u32::from_le_bytes(
                    self.recv_latch[word * 4..word * 4 + 4].try_into().unwrap(),
                ) as u64
            }
            _ => 0,
        }
    }

    fn write(&mut self, off: u64, size: u8, val: u64) {
        let _ = size;
        match off {
            REG_INT_MASK_SET => self.int_mask = val as u32,
            REG_INT_MASK_CLR => self.int_mask &= !(val as u32),
            REG_IOP_CTRL => self.iop_ctrl = val as u32,
            REG_AP_CTRL => self.ap_ctrl = val as u32 & CTRL_ENABLE,
            off if (REG_AP_SEND0..REG_AP_RECV0).contains(&off) => {
                let word = ((off - REG_AP_SEND0) / 4) as usize;
                self.send_stage[word * 4..word * 4 + 4]
                    .copy_from_slice(&(val as u32).to_le_bytes());
                self.send_words += 1;
                if self.send_words == 4 {
                    self.send_words = 0;
                    let m = self.send_stage;
                    let msg = SepMessage::decode(&m);
                    self.handle_message(&msg);
                }
            }
            _ => {}
        }
    }
}

impl Default for SepSim {
    fn default() -> Self {
        Self::new()
    }
}

impl SepSim {
    pub fn regs_documented() -> &'static [(&'static str, u64)] {
        &[
            ("REG_INT_MASK_SET", REG_INT_MASK_SET),
            ("REG_INT_MASK_CLR", REG_INT_MASK_CLR),
            ("REG_IOP_CTRL", REG_IOP_CTRL),
            ("REG_AP_CTRL", REG_AP_CTRL),
            ("REG_AP_SEND0", REG_AP_SEND0),
            ("REG_AP_RECV0", REG_AP_RECV0),
            ("EP_CONTROL", EP_CONTROL as u64),
            ("EP_KEYSTORE", EP_KEYSTORE as u64),
            ("EP_BOOTSTRAP", EP_BOOTSTRAP as u64),
            ("CONTROL_OP_NOP", CONTROL_OP_NOP as u64),
            ("CONTROL_OP_ACK", CONTROL_OP_ACK as u64),
            ("CONTROL_OP_SET_OOL_IN_ADDR", CONTROL_OP_SET_OOL_IN_ADDR as u64),
            (
                "CONTROL_OP_SET_OOL_OUT_ADDR",
                CONTROL_OP_SET_OOL_OUT_ADDR as u64,
            ),
            ("CONTROL_OP_GET_SECURITY_MODE", CONTROL_OP_GET_SECURITY_MODE as u64),
            ("CONTROL_OP_SELF_TEST", CONTROL_OP_SELF_TEST as u64),
            ("CONTROL_OP_ERASE_INSTALL", CONTROL_OP_ERASE_INSTALL as u64),
            ("BOOTSTRAP_OP_PING", BOOTSTRAP_OP_PING as u64),
            ("BOOTSTRAP_OP_BOOT_TZ0", BOOTSTRAP_OP_BOOT_TZ0 as u64),
            ("BOOTSTRAP_OP_BOOT_IMG4", BOOTSTRAP_OP_BOOT_IMG4 as u64),
            ("KEYSTORE_IPC_HEADER_SIZE", KEYSTORE_IPC_HEADER_SIZE as u64),
            ("SEP_ENDPOINT_MAX", SEP_ENDPOINT_MAX as u64),
        ]
    }
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Write a SEP message into the device the way the guest would.
    fn send(dev: &mut SepSim, msg: SepMessage) {
        let m = msg.encode();
        for w in 0..4 {
            let v = u32::from_le_bytes(m[w * 4..w * 4 + 4].try_into().unwrap());
            dev.write(REG_AP_SEND0 + w * 4, 4, v as u64);
        }
    }

    fn recv(dev: &mut SepSim) -> Option<SepMessage> {
        if dev.outbox.is_empty() {
            return None;
        }
        let mut m = [0u8; 16];
        for w in 0..4 {
            let v = dev.read(REG_AP_RECV0 + w * 4, 4) as u32;
            m[w * 4..w * 4 + 4].copy_from_slice(&v.to_le_bytes());
        }
        Some(SepMessage::decode(&m))
    }

    #[test]
    fn control_nop_gets_ack() {
        let mut sep = SepSim::new();
        // consume the reset-hold ANNOUNCE_STATUS
        let announce = recv(&mut sep).unwrap();
        assert_eq!(announce.ep, EP_BOOTSTRAP);
        assert_eq!(announce.op, BOOTSTRAP_OP_ANNOUNCE_STATUS);
        assert_eq!(announce.data, SEP_STATUS_BOOTSTRAP);

        send(
            &mut sep,
            SepMessage { ep: EP_CONTROL, tag: 7, op: CONTROL_OP_NOP, param: 0, data: 0 },
        );
        let ack = recv(&mut sep).unwrap();
        assert_eq!(ack.ep, EP_CONTROL);
        assert_eq!(ack.tag, 7); // tag echoed
        assert_eq!(ack.op, CONTROL_OP_ACK);
    }

    #[test]
    fn ool_set_and_l4info() {
        let mut sep = SepSim::new();
        send(
            &mut sep,
            SepMessage {
                ep: EP_CONTROL,
                tag: 1,
                op: CONTROL_OP_SET_OOL_IN_ADDR,
                param: 18, // keystore
                data: 0x123,
            },
        );
        assert_eq!(sep.ool_state[EP_KEYSTORE as usize].in_addr, 0x123_000);
        send(
            &mut sep,
            SepMessage {
                ep: EP_CONTROL,
                tag: 2,
                op: CONTROL_OP_SET_OOL_IN_SIZE,
                param: 18,
                data: 0x1000,
            },
        );
        assert_eq!(sep.ool_state[EP_KEYSTORE as usize].in_size, 0x1000);
    }

    #[test]
    fn bootstrap_ping_and_tz0() {
        let mut sep = SepSim::new();
        let _ = recv(&mut sep); // announce
        send(
            &mut sep,
            SepMessage { ep: EP_BOOTSTRAP, tag: 3, op: BOOTSTRAP_OP_PING, param: 0, data: 0 },
        );
        assert_eq!(recv(&mut sep).unwrap().op, BOOTSTRAP_OP_PING_ACK);
        send(
            &mut sep,
            SepMessage { ep: EP_BOOTSTRAP, tag: 4, op: BOOTSTRAP_OP_BOOT_TZ0, param: 1, data: 0 },
        );
        let m = recv(&mut sep).unwrap();
        assert_eq!(m.op, BOOTSTRAP_OP_TZ0_ACCEPTED);
        assert!(sep.rsep);
        assert_eq!(sep.status, SEP_STATUS_ACTIVE);
    }

    #[test]
    fn boot_img4_advertises_eps() {
        let mut sep = SepSim::new();
        let _ = recv(&mut sep);
        send(
            &mut sep,
            SepMessage { ep: EP_BOOTSTRAP, tag: 0, op: BOOTSTRAP_OP_BOOT_TZ0, param: 1, data: 0 },
        );
        let _ = recv(&mut sep); // TZ0_ACCEPTED
        send(
            &mut sep,
            SepMessage { ep: EP_BOOTSTRAP, tag: 0, op: BOOTSTRAP_OP_BOOT_IMG4, param: 1, data: 0 },
        );
        let m1 = recv(&mut sep).unwrap();
        assert_eq!(m1.op, BOOTSTRAP_OP_IMG4_ACCEPTED);
        let m2 = recv(&mut sep).unwrap();
        assert_eq!(m2.ep, EP_CONTROL);
        assert_eq!(m2.op, CONTROL_OP_NOTIFY_ALIVE);
        // 8 EPs × (EP_ADVERT + OOL_ADVERT)
        let mut adverts = 0;
        while let Some(m) = recv(&mut sep) {
            assert_eq!(m.ep, EP_DISCOVERY);
            adverts += 1;
        }
        assert_eq!(adverts, 16);
        assert!(sep.advertised);
    }

    #[test]
    fn keystore_create_keybag_ep18() {
        let mut sep = SepSim::new();
        let _ = recv(&mut sep);
        sep.set_dma_window(0x1000_0000);
        sep.ool_state[EP_KEYSTORE as usize].in_addr = 0x1000_0000;
        sep.ool_state[EP_KEYSTORE as usize].out_addr = 0x1001_0000;
        // request: selector 0x01 (Create Keybag) right after the 0x54 header
        let mut req = vec![0u8; 0x5C];
        req[0x54..0x58].copy_from_slice(&1u32.to_le_bytes());
        sep.dma_write(0x1000_0000, &req);

        // KeystoreMessage: tag = code; id in the `op` byte; size = data>>16
        send(
            &mut sep,
            SepMessage {
                ep: EP_KEYSTORE,
                tag: 0x01,   // code (no reply bit)
                op: 0x2A,    // msg->id
                param: 0,    // unused
                data: (0x5C << 16),
            },
        );
        let reply = recv(&mut sep).unwrap();
        assert_eq!(reply.ep, EP_KEYSTORE);
        assert_eq!(reply.tag, 0x01 | KEYSTORE_MSG_TAG_REPLY);
        assert_eq!(reply.op, 0x2A);
        let resp_size = reply.data >> 16;
        assert_eq!(resp_size as usize, KEYSTORE_IPC_HEADER_SIZE + 8);
        // response written to OOL out_addr: selector = 1, kb_id = 'BAG1'
        let out = &sep.dma_window[(0x1001_0000 - 0x1000_0000) as usize..];
        let sel = u32::from_le_bytes(
            out[KEYSTORE_IPC_HEADER_SIZE..KEYSTORE_IPC_HEADER_SIZE + 4]
                .try_into()
                .unwrap(),
        );
        assert_eq!(sel, 1);
        assert_eq!(&out[KEYSTORE_IPC_HEADER_SIZE + 4..KEYSTORE_IPC_HEADER_SIZE + 8], b"BAG1");
        // IPC version 1 in the header
        let ver = u32::from_le_bytes(out[0x14..0x18].try_into().unwrap());
        assert_eq!(ver, KEYSTORE_IPC_VERSION_1);
    }
}
