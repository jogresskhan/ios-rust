//! sep_sim — SEP simulator (port of Inferno hw/arm/apple-silicon/
//! sep-sim.c + sep-sim.h): the message-level service model that rides on
//! the A7IOP mailbox. This port covers everything the C model implements:
//! the SEP wire message format, the endpoint table (EP_CONTROL .. EP_
//! BOOTSTRAP), the control-op surface (OOL addr/size setup, security mode,
//! self test, erase install), the bootstrap boot-flow state machine
//! (PING → BOOT_TZ0 → BOOT_IMG4 → EP adverts), XART acks, L4INFO, the
//! ART-storage stub and the keystore IPC reply set (create/copy/load/
//! unlock/unload keybag, KC wrap, D-key, device state, client terminate).
//!
//! The legacy control-op MMIO surface ([`SepOp`], `SEP_*` offsets) is kept
//! for backward compatibility.

use vm_core::Device;

pub const SEP_MAILBOX_EP: u32 = 18; // == EP_KEYSTORE upstream ('sks ')

// Legacy control-op MMIO offsets (pre-port surface, kept for compat)
pub const SEP_STATUS: u64 = 0x0000;
pub const SEP_CTRL_OP: u64 = 0x0004;
pub const SEP_CTRL_ARG0: u64 = 0x0008;
pub const SEP_CTRL_ARG1: u64 = 0x000C;
pub const SEP_CTRL_ARG2: u64 = 0x0010;
pub const SEP_TTY_IN: u64 = 0x0020;
pub const SEP_TTY_OUT: u64 = 0x0024;

// ---------------------------------------------------------------------------
// Upstream model (sep-sim.h / sep-sim.c)
// ---------------------------------------------------------------------------
pub const SEP_ENDPOINT_MAX: usize = 0x20;

pub const SEP_STATUS_SLEEPING: u32 = 0;
pub const SEP_STATUS_BOOTSTRAP: u32 = 1;
pub const SEP_STATUS_ACTIVE: u32 = 2;

/// Wire format of every mailbox message (`SEPMessage`, 8 bytes packed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SepMessage {
    pub ep: u8,
    pub tag: u8,
    pub op: u8,
    pub param: u8,
    pub data: u32,
}

impl SepMessage {
    pub const fn new(ep: u8, tag: u8, op: u8, param: u8, data: u32) -> Self {
        SepMessage { ep, tag, op, param, data }
    }
    /// `apple_sep_sim_message_reply`: same ep/tag, new op/param/data.
    pub fn reply(&self, op: u8, param: u8, data: u32) -> SepMessage {
        SepMessage { ep: self.ep, tag: self.tag, op, param, data }
    }
}

/// Endpoint IDs (sep-sim.c enum; names are the 4CCs iOS matches on).
pub mod ep {
    pub const CONTROL: u8 = 0; // 'cntl'
    pub const LOGGER: u8 = 1; // 'log '
    pub const ART_STORAGE: u8 = 2; // 'arts'
    pub const ART_REQUESTS: u8 = 3; // 'artr'
    pub const TRACING: u8 = 4; // 'trac'
    pub const DEBUG: u8 = 5; // 'debu'
    pub const EMBEDDED_ISP: u8 = 6; // 'eisp'
    pub const MOBILE_SKS: u8 = 7; // 'msks'
    pub const SECURE_BIOMETRICS: u8 = 8; // 'sbio'
    pub const FACE_ID: u8 = 9; // 'sprl'
    pub const SECURE_CREDENTIALS: u8 = 10; // 'scrd'
    pub const PAIRING: u8 = 11;
    pub const SECURE_ELEMENT: u8 = 12; // 'sse '
    pub const HDCP: u8 = 14; // 'hdcp'
    pub const UNIT_TESTING: u8 = 15; // 'unit'
    pub const XART_SLAVE: u8 = 16; // 'xars'
    pub const HILO: u8 = 17; // 'hilo'
    pub const KEYSTORE: u8 = 18; // 'sks '
    pub const XART_MASTER: u8 = 19; // 'xarm'
    pub const SMC: u8 = 20; // 'smc ' (also hibernation 'hibe')
    pub const NONP: u8 = 21; // 'nonp'
    pub const CYRS: u8 = 22; // 'cyrs'
    pub const SKDL: u8 = 23; // 'skdl'
    pub const STAC: u8 = 24; // 'stac'
    pub const SIDV: u8 = 25; // 'sidv'
    pub const DISCOVERY: u8 = 253;
    pub const L4INFO: u8 = 254;
    pub const BOOTSTRAP: u8 = 255;

    /// `apple_sep_sim_eps` / `apple_sep_sim_endpoint_names`
    pub const ADVERTISED: [(u8, u32); 8] = [
        (CONTROL, 0x636E_746C), // 'cntl'
        (LOGGER, 0x6C6F_6720), // 'log '
        (ART_STORAGE, 0x6172_7473), // 'arts'
        (ART_REQUESTS, 0x6172_7472), // 'artr'
        (SECURE_CREDENTIALS, 0x7363_7264), // 'scrd'
        (XART_SLAVE, 0x7861_7273), // 'xars'
        (KEYSTORE, 0x736B_7320), // 'sks '
        (XART_MASTER, 0x7861_726D), // 'xarm'
    ];
}

/// EP_CONTROL opcodes (sep-sim.c).
pub mod control_op {
    pub const NOP: u8 = 0;
    pub const ACK: u8 = 1;
    pub const SET_OOL_IN_ADDR: u8 = 2;
    pub const SET_OOL_OUT_ADDR: u8 = 3;
    pub const SET_OOL_IN_SIZE: u8 = 4;
    pub const SET_OOL_OUT_SIZE: u8 = 5;
    pub const TTY_IN: u8 = 10;
    pub const SLEEP: u8 = 12;
    pub const NOTIFY_ALIVE: u8 = 13;
    pub const SEED_DPA: u8 = 15;
    pub const GENERATE_RANDOM_DATA: u8 = 16;
    pub const OPCODE_18: u8 = 18;
    pub const NAP: u8 = 19;
    pub const GET_SECURITY_MODE: u8 = 20;
    pub const SELF_TEST: u8 = 24;
    pub const SET_DMA_CMD_ADDR: u8 = 25;
    pub const SET_DMA_CMD_SIZE: u8 = 26;
    pub const SET_DMA_IN_ADDR: u8 = 27;
    pub const SET_DMA_OUT_ADDR: u8 = 28;
    pub const SET_DMA_IN_RELAY_ADDR: u8 = 29;
    pub const SET_DMA_OUT_RELAY_ADDR: u8 = 30;
    pub const SET_DMA_IN_SIZE: u8 = 31;
    pub const SET_DMA_OUT_SIZE: u8 = 32;
    pub const ERASE_INSTALL: u8 = 37;
    pub const L4_PANIC: u8 = 38;
    pub const SEP_OS_PANIC: u8 = 39;
}

/// EP_BOOTSTRAP opcodes incl. the 1xx reply codes (sep-sim.c).
pub mod bootstrap_op {
    pub const PING: u8 = 1;
    pub const GET_STATUS: u8 = 2;
    pub const GENERATE_NONCE: u8 = 3;
    pub const GET_NONCE_WORD: u8 = 4;
    pub const BOOT_TZ0: u8 = 5;
    pub const BOOT_IMG4: u8 = 6;
    pub const LOAD_SEP_ART: u8 = 7;
    pub const OPCODE_9: u8 = 9;
    pub const NOTIFY_OS_ACTIVE_ASYNC: u8 = 13;
    pub const OPCODE_14: u8 = 14;
    pub const SEND_DPA: u8 = 15;
    pub const OPCODE_16: u8 = 16;
    pub const INTEGRITY_TREE_SIZE: u8 = 17;
    pub const NOTIFY_OS_ACTIVE: u8 = 21;
    pub const OPCODE_30: u8 = 30;
    pub const OPCODE_31: u8 = 31;
    pub const OPCODE_35: u8 = 35;
    pub const BOOT_TMM_MANIFEST: u8 = 36;
    pub const BOOT_PATCH: u8 = 37;

    pub const PING_ACK: u8 = 101;
    pub const STATUS_REPLY: u8 = 102;
    pub const NONCE_GENERATED: u8 = 103;
    pub const NONCE_WORD_REPLY: u8 = 104;
    pub const TZ0_ACCEPTED: u8 = 105;
    pub const IMG4_ACCEPTED: u8 = 106;
    pub const ART_ACCEPTED: u8 = 107;
    pub const RESUMED_FROM_RAM: u8 = 108;
    pub const OPCODE_9_RESPONSE: u8 = 109;
    pub const OPCODE_14_RESPONSE: u8 = 114;
    pub const DPA_SENT: u8 = 115;
    pub const OPCODE_16_RESPONSE: u8 = 116;
    pub const INTEGRITY_TREE_SIZE_RESPONSE: u8 = 117;
    pub const LOG_RAW: u8 = 201;
    pub const LOG_PRINTABLE: u8 = 202;
    pub const ANNOUNCE_STATUS: u8 = 210;
    pub const TIMEBASE_UPDATE: u8 = 254;
    pub const PANIC: u8 = 255;
}

/// XART opcodes (slave = IOP→AP side the sim serves).
pub mod xart_op {
    pub const ACK: u8 = 0;
    pub const GET_XART: u8 = 0;
    pub const SET_XART: u8 = 1;
    pub const LYNX_AUTHENTICATE: u8 = 9;
    pub const LYNX_GET_CPSN: u8 = 10;
    pub const LYNX_GET_PUBLIC_KEY: u8 = 11;
    pub const GET_LOCKER_RECORD: u8 = 5;
    pub const ADD_LOCKER_RECORD: u8 = 6;
    pub const DELETE_LOCKER_RECORD: u8 = 7;
    pub const FLUSH_CACHED_XART: u8 = 12;
    pub const SHUTDOWN: u8 = 13;
    pub const POWERED_UP: u8 = 14;
    pub const NONCE_GENERATE: u8 = 15;
    pub const NONCE_READ: u8 = 16;
    pub const NONCE_INVALIDATE: u8 = 17;
    pub const COMMIT_HASH: u8 = 18;
}

pub mod art_storage_op {
    pub const ART_LOAD: u8 = 1;
    pub const NO_ART: u8 = 2;
    pub const MANIFEST: u8 = 3;
    pub const INCOMING: u8 = 20;
    pub const RECEIVED: u8 = 21;
}

pub mod art_requests_op {
    pub const NEW_NONCE: u8 = 20;
    pub const INVALIDATE_NONCE: u8 = 21;
    pub const COMMIT_HASH: u8 = 22;
    pub const COUNTER_SELF_TEST: u8 = 30;
    pub const PURGE_SYSTEM_TOKEN: u8 = 40;
}

pub mod debug_op {
    pub const COPY_FROM_OBJECT: u8 = 0;
    pub const COPY_TO_OBJECT: u8 = 1;
    pub const OBJECT_INFO: u8 = 2;
    pub const CREATE_OBJECT: u8 = 3;
    pub const SHARE_OBJECT: u8 = 4;
    pub const DUMP_TRNG_DATA: u8 = 5;
    pub const PROCESS_INFO: u8 = 6;
    pub const DUMP_COVERAGE: u8 = 7;
}

pub mod discovery_op {
    pub const EP_ADVERT: u8 = 0;
    pub const OOL_ADVERT: u8 = 1;
}

// Keystore message constants (sep-sim.c)
pub const KEYSTORE_MSG_TAG_REPLY: u8 = 0x80;
pub const KEYSTORE_MSG_TAG_CODE_MASK: u8 = 0x7F;
pub const KEYSTORE_IPC_HEADER_SIZE: u32 = 0x54;
pub const KEYSTORE_IPC_VERSION_1: u32 = 1;
pub const KEYSTORE_IPC_FLAG_ENCRYPTED: u32 = 1 << 0;
pub const KEYSTORE_IPC_FLAG_EXTENDED: u32 = 1 << 1;

/// Per-endpoint OOL capability advertisement (`AppleSEPSimOOLInfo`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OolInfo {
    pub in_min_pages: u8,
    pub in_max_pages: u8,
    pub out_min_pages: u8,
    pub out_max_pages: u8,
}

/// Per-endpoint OOL buffer state (`AppleSEPSimOOLState`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OolState {
    pub in_addr: u64,
    pub in_size: u32,
    pub out_addr: u64,
    pub out_size: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SepOp {
    Nop,
    Ack,
    Ool,
    Tty,
    SeedDpa,
    GenRandom,
    SelfTest,
    Dma,
    EraseInstall,
    Keystore,
    Unknown(u8),
}

impl SepOp {
    pub fn from_code(c: u8) -> Self {
        match c {
            0 => SepOp::Nop,
            1 => SepOp::Ack,
            2 => SepOp::Ool,
            3 => SepOp::Tty,
            4 => SepOp::SeedDpa,
            5 => SepOp::GenRandom,
            6 => SepOp::SelfTest,
            7 => SepOp::Dma,
            8 => SepOp::EraseInstall,
            9 => SepOp::Keystore,
            other => SepOp::Unknown(other),
        }
    }
    pub fn code(&self) -> u8 {
        match self {
            SepOp::Nop => 0,
            SepOp::Ack => 1,
            SepOp::Ool => 2,
            SepOp::Tty => 3,
            SepOp::SeedDpa => 4,
            SepOp::GenRandom => 5,
            SepOp::SelfTest => 6,
            SepOp::Dma => 7,
            SepOp::EraseInstall => 8,
            SepOp::Keystore => 9,
            SepOp::Unknown(c) => *c,
        }
    }
}

pub struct SepSim {
    // legacy fields
    pub status: u32,
    pub last_op: SepOp,
    pub args: [u32; 3],
    pub tty_in: Vec<u8>,
    pub tty_out: Vec<u8>,
    /// deterministic PRNG state (SEP host test mode)
    pub rng_state: u64,
    pub dpa_seed: [u8; 32],
    pub ops_processed: u64,
    pub unknown_reads: u64,

    // upstream model
    pub rsep: bool,
    pub ool_info: [OolInfo; SEP_ENDPOINT_MAX],
    pub ool_state: [OolState; SEP_ENDPOINT_MAX],
    /// messages the sim sent toward the AP mailbox (read side)
    pub outbox: Vec<SepMessage>,
    /// last keystore reply payload (what would be DMA'd to the OOL out buf)
    pub keystore_resp: Vec<u8>,
    pub keystore_codes_seen: Vec<u8>,
    pub unknown_msgs: u64,
    /// scratch of the last OOL write the sim performed (addr, bytes)
    pub last_dma_write: Option<(u64, Vec<u8>)>,
    /// optional DMA hook for keystore request fetch (machine injects)
    pub dma_read: Option<Box<dyn FnMut(u64, &mut [u8]) + Send>>,
}

impl SepSim {
    pub fn new() -> Self {
        SepSim {
            status: 1, // ready (== SEP_STATUS_BOOTSTRAP after reset_hold)
            last_op: SepOp::Nop,
            args: [0; 3],
            tty_in: Vec::new(),
            tty_out: Vec::new(),
            rng_state: 0x9E3779B97F4A7C15,
            dpa_seed: [0; 32],
            ops_processed: 0,
            unknown_reads: 0,
            rsep: false,
            ool_info: [OolInfo::default(); SEP_ENDPOINT_MAX],
            ool_state: [OolState::default(); SEP_ENDPOINT_MAX],
            outbox: Vec::new(),
            keystore_resp: Vec::new(),
            keystore_codes_seen: Vec::new(),
            unknown_msgs: 0,
            last_dma_write: None,
            dma_read: None,
        }
    }

    fn next_rand(&mut self) -> u64 {
        // xorshift64* — deterministic for tests
        let mut x = self.rng_state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.rng_state = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }

    /// `apple_sep_sim_send_message` toward the AP.
    pub fn send(&mut self, msg: SepMessage) {
        self.outbox.push(msg);
    }

    fn reply(&mut self, msg: &SepMessage, op: u8, param: u8, data: u32) {
        self.send(msg.reply(op, param, data));
    }

    fn control_ack(&mut self, msg: &SepMessage, param: u8, data: u32) {
        self.reply(msg, control_op::ACK, param, data);
    }

    /// `apple_sep_sim_reset_hold`: OOL capability defaults + bootstrap
    /// announce. Mailbox direction-enable bits are the A7IOP's job here.
    pub fn reset_hold(&mut self) {
        for &(ep, _) in ep::ADVERTISED.iter() {
            let info = &mut self.ool_info[ep as usize];
            match ep {
                ep::LOGGER => {
                    *info = OolInfo { in_min_pages: 0, in_max_pages: 0, out_min_pages: 1, out_max_pages: 1 };
                }
                ep::ART_STORAGE | ep::ART_REQUESTS | ep::DEBUG | ep::UNIT_TESTING => {
                    *info = OolInfo { in_min_pages: 1, in_max_pages: 1, out_min_pages: 1, out_max_pages: 1 };
                }
                ep::HILO => {
                    *info = OolInfo::default(); // 0/0/0/0
                }
                _ => {
                    *info = OolInfo { in_min_pages: 2, in_max_pages: 2, out_min_pages: 2, out_max_pages: 2 };
                }
            }
        }
        self.status = SEP_STATUS_BOOTSTRAP;
        self.send(SepMessage::new(
            ep::BOOTSTRAP,
            0,
            bootstrap_op::ANNOUNCE_STATUS,
            0,
            self.status,
        ));
    }

    /// `apple_sep_sim_advertise_eps`: one EP + one OOL advert per service.
    pub fn advertise_eps(&mut self) {
        for &(id, name) in ep::ADVERTISED.iter() {
            self.send(SepMessage::new(
                ep::DISCOVERY,
                0,
                discovery_op::EP_ADVERT,
                id,
                name,
            ));
            // OOLAdvertisementMessage packs the OOLInfo in the 32-bit data
            let info = self.ool_info[id as usize];
            let packed = ((info.in_min_pages as u32) << 24)
                | ((info.in_max_pages as u32) << 16)
                | ((info.out_min_pages as u32) << 8)
                | (info.out_max_pages as u32);
            self.send(SepMessage::new(
                ep::DISCOVERY,
                0,
                discovery_op::OOL_ADVERT,
                id,
                packed,
            ));
        }
    }

    /// `apple_sep_sim_handle_messages` main dispatch.
    pub fn handle_message(&mut self, msg: SepMessage) {
        self.ops_processed += 1;
        match msg.ep {
            ep::CONTROL => self.handle_control(&msg),
            ep::ART_STORAGE => self.handle_art_storage(&msg),
            ep::ART_REQUESTS | ep::SECURE_CREDENTIALS | ep::DISCOVERY => {
                self.unknown_msgs += 1; // upstream: logged, no reply
            }
            ep::XART_SLAVE => self.handle_xart(&msg, true),
            ep::XART_MASTER => self.handle_xart(&msg, false),
            ep::KEYSTORE => self.handle_keystore(&msg),
            ep::L4INFO => self.handle_l4info(&msg),
            ep::BOOTSTRAP => self.handle_bootstrap(&msg),
            _ => {
                self.unknown_msgs += 1; // "UNKNOWN_%d_OP_%d"
            }
        }
    }

    fn handle_control(&mut self, msg: &SepMessage) {
        match msg.op {
            control_op::NOP => self.control_ack(msg, 0, 0),
            control_op::SET_OOL_IN_ADDR => {
                let id = msg.param as usize;
                if id < SEP_ENDPOINT_MAX {
                    self.ool_state[id].in_addr = (msg.data as u64) << 12;
                }
                self.control_ack(msg, 0, 0);
            }
            control_op::SET_OOL_OUT_ADDR => {
                let id = msg.param as usize;
                if id < SEP_ENDPOINT_MAX {
                    self.ool_state[id].out_addr = (msg.data as u64) << 12;
                }
                self.control_ack(msg, 0, 0);
            }
            control_op::SET_OOL_IN_SIZE => {
                let id = msg.param as usize;
                if id < SEP_ENDPOINT_MAX {
                    self.ool_state[id].in_size = msg.data;
                }
                self.control_ack(msg, 0, 0);
            }
            control_op::SET_OOL_OUT_SIZE => {
                let id = msg.param as usize;
                if id < SEP_ENDPOINT_MAX {
                    self.ool_state[id].out_size = msg.data;
                }
                self.control_ack(msg, 0, 0);
            }
            control_op::GET_SECURITY_MODE => self.control_ack(msg, 0, 3),
            control_op::SELF_TEST => self.control_ack(msg, 0, 0),
            control_op::TTY_IN => self.tty_in.push(msg.data as u8),
            control_op::ERASE_INSTALL => {
                self.control_ack(msg, 0, 0);
                // Synthesize the zeroed ART.Header the C model DER-encodes
                // (version 0, counter 0, 20B manifest hash, 20B sleep hash,
                // empty nonce, 32B InfoHMAC) — 0x51 bytes total.
                let art = vec![0u8; 0x51];
                let out = self.ool_state[ep::ART_STORAGE as usize].out_addr;
                self.last_dma_write = Some((out, art));
                self.send(SepMessage::new(
                    ep::ART_STORAGE,
                    0,
                    art_storage_op::INCOMING,
                    0,
                    0,
                ));
            }
            _ => {
                self.unknown_msgs += 1;
            }
        }
    }

    fn handle_art_storage(&mut self, msg: &SepMessage) {
        match msg.op {
            art_storage_op::RECEIVED => {} // logged upstream
            _ => self.unknown_msgs += 1,
        }
    }

    fn handle_xart(&mut self, msg: &SepMessage, _slave: bool) {
        // every handled op (and unknown ones) get an ACK upstream
        self.reply(msg, xart_op::ACK, 0, 0);
    }

    fn handle_l4info(&mut self, msg: &SepMessage) {
        let size = ((msg.param as u16) << 8) | msg.op as u16;
        let addr = (msg.data as u64) << 12;
        let c = &mut self.ool_state[ep::CONTROL as usize];
        c.in_addr = addr;
        c.in_size = (size as u32) << 12;
        c.out_addr = addr;
        c.out_size = (size as u32) << 12;
    }

    fn handle_bootstrap(&mut self, msg: &SepMessage) {
        match msg.op {
            bootstrap_op::PING => {
                // needed for S8000 and T8015
                self.send(SepMessage::new(
                    ep::BOOTSTRAP,
                    msg.tag,
                    bootstrap_op::PING_ACK,
                    0,
                    0,
                ));
            }
            bootstrap_op::GET_STATUS => {
                self.send(SepMessage::new(
                    ep::BOOTSTRAP,
                    msg.tag,
                    bootstrap_op::STATUS_REPLY,
                    0,
                    self.status,
                ));
            }
            bootstrap_op::GENERATE_NONCE => {
                // 0xa0 is the returned length in bits
                self.send(SepMessage::new(
                    ep::BOOTSTRAP,
                    msg.tag,
                    bootstrap_op::NONCE_GENERATED,
                    0,
                    0xa0,
                ));
            }
            bootstrap_op::GET_NONCE_WORD => {
                // param is the index (not offset), and must be echoed
                let randval = self.next_rand() as u32;
                self.send(SepMessage::new(
                    ep::BOOTSTRAP,
                    msg.tag,
                    bootstrap_op::NONCE_WORD_REPLY,
                    msg.param,
                    randval,
                ));
            }
            bootstrap_op::BOOT_TZ0 => {
                self.rsep = msg.param == 1;
                self.status = SEP_STATUS_ACTIVE;
                self.send(SepMessage::new(
                    ep::BOOTSTRAP,
                    msg.tag,
                    bootstrap_op::TZ0_ACCEPTED,
                    0,
                    0,
                ));
            }
            bootstrap_op::BOOT_IMG4 => {
                // upstream asserts rsep matches; the sim just proceeds
                self.send(SepMessage::new(
                    ep::BOOTSTRAP,
                    msg.tag,
                    bootstrap_op::IMG4_ACCEPTED,
                    0,
                    0,
                ));
                self.send(SepMessage::new(
                    ep::CONTROL,
                    0,
                    control_op::NOTIFY_ALIVE,
                    0,
                    0,
                ));
                self.advertise_eps();
            }
            bootstrap_op::OPCODE_16 => {
                // normally returns 0x20 random bytes split in 4-byte pieces
                let randval = self.next_rand() as u32;
                self.send(SepMessage::new(
                    ep::BOOTSTRAP,
                    msg.tag,
                    bootstrap_op::OPCODE_16_RESPONSE,
                    0,
                    randval,
                ));
            }
            _ => {
                self.unknown_msgs += 1;
            }
        }
    }

    /// `apple_sep_sim_handle_keystore_msg`: builds the IPC response body per
    /// selector code. The SHA-256 payload-hash of the real header is left
    /// zeroed (no hash oracle in this port) — everything else matches.
    fn handle_keystore(&mut self, msg: &SepMessage) {
        let code = msg.tag & KEYSTORE_MSG_TAG_CODE_MASK;
        let id = msg.op;
        let size = (msg.data & 0xFFFF) as u32;
        self.keystore_codes_seen.push(code);

        // request header (dma read of the OOL in buffer happens via hook)
        let req = if let Some(rd) = self.dma_read.as_mut() {
            let in_addr = self.ool_state[ep::KEYSTORE as usize].in_addr;
            let mut buf = vec![0u8; size as usize];
            if size > 0 {
                rd(in_addr, &mut buf);
            }
            buf
        } else {
            vec![0u8; 0]
        };
        // echo header fields the C model copies
        let copy_hdr = |resp: &mut Vec<u8>, req: &[u8]| {
            if req.len() >= KEYSTORE_IPC_HEADER_SIZE as usize {
                let hdr_len = KEYSTORE_IPC_HEADER_SIZE as usize;
                for i in 0x14..hdr_len {
                    if i < resp.len() {
                        resp[i] = req[i];
                    }
                }
            }
        };

        let mut resp: Vec<u8>;
        match code {
            0x01 => {
                // Create Keybag: selector 1 + keybag id 'BAG1'
                resp = vec![0; (KEYSTORE_IPC_HEADER_SIZE + 8) as usize];
                copy_hdr(&mut resp, &req);
                let b = KEYSTORE_IPC_HEADER_SIZE as usize;
                resp[b..b + 4].copy_from_slice(&1u32.to_le_bytes());
                resp[b + 4..b + 8].copy_from_slice(&u32::from_le_bytes(*b"BAG1").to_le_bytes());
            }
            0x02 => {
                // Copy Keybag: selector 0 + 0x10-byte 0xAF payload blob
                resp = vec![0; (KEYSTORE_IPC_HEADER_SIZE + 4 + 4 + 0x10) as usize];
                copy_hdr(&mut resp, &req);
                let b = KEYSTORE_IPC_HEADER_SIZE as usize;
                resp[b..b + 4].copy_from_slice(&0u32.to_le_bytes());
                resp[b + 4..b + 8].copy_from_slice(&0x10u32.to_le_bytes());
                for byte in resp[b + 8..].iter_mut() {
                    *byte = 0xAF;
                }
            }
            0x03 => {
                // Load Keybag: selector 0 + keybag handle 'BAG1'
                resp = vec![0; (KEYSTORE_IPC_HEADER_SIZE + 8) as usize];
                copy_hdr(&mut resp, &req);
                let b = KEYSTORE_IPC_HEADER_SIZE as usize;
                resp[b..b + 4].copy_from_slice(&0u32.to_le_bytes());
                resp[b + 4..b + 8].copy_from_slice(&u32::from_le_bytes(*b"BAG1").to_le_bytes());
            }
            0x04 => {
                // Change Lock State: selector 0 + lock_state | (1<<22) + 0x3
                resp = vec![0; (KEYSTORE_IPC_HEADER_SIZE + 4 + 4 + 8) as usize];
                copy_hdr(&mut resp, &req);
                let b = KEYSTORE_IPC_HEADER_SIZE as usize;
                resp[b..b + 4].copy_from_slice(&0u32.to_le_bytes());
                let mut lock_state = 0u32;
                if req.len() >= 0x64 {
                    lock_state = u32::from_le_bytes(
                        req[0x60..0x64].try_into().unwrap(),
                    );
                }
                lock_state |= 1 << 22;
                resp[b + 4..b + 8].copy_from_slice(&lock_state.to_le_bytes());
                resp[b + 8..b + 16].copy_from_slice(&(0x1u64 | 0x2).to_le_bytes());
            }
            0x05 | 0x0A | 0x0C | 0x0D => {
                // Unload Keybag / Null D Key / Unwrap D Key / Make System
                // Keybag: selector 0 only
                resp = vec![0; (KEYSTORE_IPC_HEADER_SIZE + 4) as usize];
                copy_hdr(&mut resp, &req);
                let b = KEYSTORE_IPC_HEADER_SIZE as usize;
                resp[b..b + 4].copy_from_slice(&0u32.to_le_bytes());
            }
            0x08 => {
                // KC Wrap: bare reply (tag |= 0x80), no payload write
                self.send(SepMessage::new(
                    msg.ep,
                    msg.tag | KEYSTORE_MSG_TAG_REPLY,
                    id,
                    0,
                    0,
                ));
                self.keystore_resp = Vec::new();
                return;
            }
            0x19 => {
                // Get Device State: selector 0 + 8-byte "applehax" DER blob
                resp = vec![0; (KEYSTORE_IPC_HEADER_SIZE + 4 + 4 + 8) as usize];
                copy_hdr(&mut resp, &req);
                let b = KEYSTORE_IPC_HEADER_SIZE as usize;
                resp[b..b + 4].copy_from_slice(&0u32.to_le_bytes());
                resp[b + 4..b + 8].copy_from_slice(&8u32.to_le_bytes());
                resp[b + 8..b + 16].copy_from_slice(b"applehax");
            }
            0x1B => {
                // Client Terminate: selector 0
                resp = vec![0; (KEYSTORE_IPC_HEADER_SIZE + 4) as usize];
                copy_hdr(&mut resp, &req);
                let b = KEYSTORE_IPC_HEADER_SIZE as usize;
                resp[b..b + 4].copy_from_slice(&0u32.to_le_bytes());
            }
            _ => {
                // Unknown: echo the request buffer back, reply with size
                self.last_dma_write = Some((
                    self.ool_state[ep::KEYSTORE as usize].out_addr,
                    req.clone(),
                ));
                self.reply(msg, id, 0, size << 16);
                self.keystore_resp = req;
                return;
            }
        }

        let resp_size = resp.len() as u32;
        let out = self.ool_state[ep::KEYSTORE as usize].out_addr;
        self.last_dma_write = Some((out, resp.clone()));
        self.keystore_resp = resp;
        // reply: tag |= 0x80, op = id, data = resp_size << 16
        self.send(SepMessage::new(
            msg.ep,
            msg.tag | KEYSTORE_MSG_TAG_REPLY,
            id,
            0,
            resp_size << 16,
        ));
    }

    /// Legacy census submit (kept; drives the old MMIO control-op surface).
    pub fn submit(&mut self, op: SepOp, args: [u32; 3]) -> u32 {
        self.last_op = op;
        self.args = args;
        match op {
            SepOp::Nop | SepOp::Ack => 0,
            SepOp::GenRandom => {
                let mut words = [0u64; 4];
                for w in &mut words {
                    *w = self.next_rand();
                }
                for (dst, src) in self.dpa_seed.chunks_exact_mut(8).zip(words.iter()) {
                    dst.copy_from_slice(&src.to_le_bytes());
                }
                0
            }
            SepOp::SeedDpa => 0,
            SepOp::SelfTest => 0, // pass
            SepOp::Dma => 0,
            SepOp::EraseInstall => 0,
            SepOp::Keystore => 0x1, // locked (research-scope)
            SepOp::Tty => 0,
            SepOp::Ool => 0,
            SepOp::Unknown(_) => 0x2,
        }
    }

    pub fn regs_documented() -> &'static [(&'static str, u64)] {
        &[
            ("STATUS", SEP_STATUS),
            ("CTRL_OP", SEP_CTRL_OP),
            ("ARG0", SEP_CTRL_ARG0),
            ("ARG1", SEP_CTRL_ARG1),
            ("ARG2", SEP_CTRL_ARG2),
            ("TTY_IN", SEP_TTY_IN),
            ("TTY_OUT", SEP_TTY_OUT),
        ]
    }
}

impl Default for SepSim {
    fn default() -> Self {
        Self::new()
    }
}

impl Device for SepSim {
    fn name(&self) -> &'static str {
        "sep-sim"
    }
    fn read(&mut self, off: u64, _size: u8) -> u64 {
        match off {
            SEP_STATUS => self.status as u64,
            SEP_CTRL_OP => self.last_op.code() as u64,
            SEP_CTRL_ARG0 => self.args[0] as u64,
            SEP_CTRL_ARG1 => self.args[1] as u64,
            SEP_CTRL_ARG2 => self.args[2] as u64,
            SEP_TTY_OUT => self.tty_out.pop().unwrap_or(0) as u64,
            _ => {
                self.unknown_reads += 1;
                0
            }
        }
    }
    fn write(&mut self, off: u64, _size: u8, val: u64) {
        match off {
            SEP_CTRL_OP => {
                let op = SepOp::from_code(val as u8);
                self.status = self.submit(op, self.args);
            }
            SEP_CTRL_ARG0 => self.args[0] = val as u32,
            SEP_CTRL_ARG1 => self.args[1] = val as u32,
            SEP_CTRL_ARG2 => self.args[2] = val as u32,
            SEP_TTY_IN => self.tty_in.push(val as u8),
            _ => {}
        }
    }
}

// (DMA scratch lives in the struct: `last_dma_write`, `dma_read`)

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_ops() {
        let mut s = SepSim::new();
        assert_eq!(s.submit(SepOp::SelfTest, [0; 3]), 0);
        assert_eq!(s.submit(SepOp::GenRandom, [0; 3]), 0);
        assert!(s.dpa_seed.iter().any(|&b| b != 0));
        assert_eq!(s.submit(SepOp::Keystore, [0; 3]), 0x1);
        assert_eq!(s.submit(SepOp::Unknown(0x77), [0; 3]), 0x2);
    }

    #[test]
    fn bootstrap_boot_flow_matches_c_model() {
        let mut s = SepSim::new();
        s.reset_hold();
        assert_eq!(s.status, SEP_STATUS_BOOTSTRAP);
        assert_eq!(s.outbox.len(), 1);
        assert_eq!(s.outbox[0].op, bootstrap_op::ANNOUNCE_STATUS);
        // PING → PING_ACK
        s.outbox.clear();
        s.handle_message(SepMessage::new(ep::BOOTSTRAP, 0x42, bootstrap_op::PING, 0, 0));
        assert_eq!(s.outbox.len(), 1);
        assert_eq!(s.outbox[0].op, bootstrap_op::PING_ACK);
        assert_eq!(s.outbox[0].tag, 0x42);
        // GET_STATUS → STATUS_REPLY with current status
        s.outbox.clear();
        s.handle_message(SepMessage::new(ep::BOOTSTRAP, 0, bootstrap_op::GET_STATUS, 0, 0));
        assert_eq!(s.outbox[0].op, bootstrap_op::STATUS_REPLY);
        assert_eq!(s.outbox[0].data, SEP_STATUS_BOOTSTRAP);
        // GET_NONCE_WORD echoes the word index
        s.outbox.clear();
        s.handle_message(SepMessage::new(ep::BOOTSTRAP, 0, bootstrap_op::GET_NONCE_WORD, 7, 0));
        assert_eq!(s.outbox[0].op, bootstrap_op::NONCE_WORD_REPLY);
        assert_eq!(s.outbox[0].param, 7);
        assert_ne!(s.outbox[0].data, 0);
        // BOOT_TZ0 with param 1 → rsep firmware, ACTIVE
        s.outbox.clear();
        s.handle_message(SepMessage::new(ep::BOOTSTRAP, 0, bootstrap_op::BOOT_TZ0, 1, 0));
        assert!(s.rsep);
        assert_eq!(s.status, SEP_STATUS_ACTIVE);
        assert_eq!(s.outbox[0].op, bootstrap_op::TZ0_ACCEPTED);
        // BOOT_IMG4 → IMG4_ACCEPTED + NOTIFY_ALIVE + 8 EP + 8 OOL adverts
        s.outbox.clear();
        s.handle_message(SepMessage::new(ep::BOOTSTRAP, 0, bootstrap_op::BOOT_IMG4, 1, 0));
        assert_eq!(s.outbox[0].op, bootstrap_op::IMG4_ACCEPTED);
        assert_eq!(s.outbox[1].ep, ep::CONTROL);
        assert_eq!(s.outbox[1].op, control_op::NOTIFY_ALIVE);
        let adverts = &s.outbox[2..];
        assert_eq!(adverts.len(), 16);
        for (i, m) in adverts.iter().enumerate() {
            assert_eq!(m.ep, ep::DISCOVERY);
            let expect_op = if i % 2 == 0 { discovery_op::EP_ADVERT } else { discovery_op::OOL_ADVERT };
            assert_eq!(m.op, expect_op);
        }
        // first EP advert is 'cntl'
        assert_eq!(adverts[0].param, ep::CONTROL);
        assert_eq!(adverts[0].data, 0x636E_746C);
        // keystore advert carries the 2/2/2/2 page capability
        let ks_ool = adverts
            .iter()
            .find(|m| m.op == discovery_op::OOL_ADVERT && m.param == ep::KEYSTORE)
            .unwrap();
        assert_eq!(ks_ool.data, 0x02020202);
    }

    #[test]
    fn control_ool_and_l4info() {
        let mut s = SepSim::new();
        // SET_OOL_IN_ADDR ep 2 ('arts'), page-aligned shift << 12
        s.handle_message(SepMessage::new(
            ep::CONTROL,
            1,
            control_op::SET_OOL_IN_ADDR,
            2,
            0x1000,
        ));
        assert_eq!(s.ool_state[2].in_addr, 0x1000 << 12);
        assert_eq!(s.outbox.last().unwrap().op, control_op::ACK);
        // SET_OOL_OUT_SIZE
        s.handle_message(SepMessage::new(
            ep::CONTROL,
            2,
            control_op::SET_OOL_OUT_SIZE,
            2,
            0x2000,
        ));
        assert_eq!(s.ool_state[2].out_size, 0x2000);
        // GET_SECURITY_MODE → ack data 3
        s.outbox.clear();
        s.handle_message(SepMessage::new(
            ep::CONTROL,
            3,
            control_op::GET_SECURITY_MODE,
            0,
            0,
        ));
        assert_eq!(s.outbox[0].op, control_op::ACK);
        assert_eq!(s.outbox[0].data, 3);
        // L4INFO sets the CONTROL endpoint OOL window
        let size_words = 4u16; // param=high byte, op=low byte
        s.handle_message(SepMessage::new(
            ep::L4INFO,
            0,
            (size_words & 0xFF) as u8,
            (size_words >> 8) as u8,
            0x8000,
        ));
        let c = s.ool_state[ep::CONTROL as usize];
        assert_eq!(c.in_addr, 0x8000 << 12);
        assert_eq!(c.in_size, (size_words as u32) << 12);
        assert_eq!(c.out_addr, c.in_addr);
        // ERASE_INSTALL acks + pushes ART INCOMING with a payload
        s.outbox.clear();
        s.ool_state[ep::ART_STORAGE as usize].out_addr = 0x5000 << 12;
        s.handle_message(SepMessage::new(
            ep::CONTROL,
            4,
            control_op::ERASE_INSTALL,
            0,
            0,
        ));
        assert_eq!(s.outbox[0].op, control_op::ACK);
        assert_eq!(s.outbox[1].ep, ep::ART_STORAGE);
        assert_eq!(s.outbox[1].op, art_storage_op::INCOMING);
        let (addr, art) = s.last_dma_write.clone().unwrap();
        assert_eq!(addr, 0x5000 << 12);
        assert_eq!(art.len(), 0x51);
        assert!(art.iter().all(|&b| b == 0));
    }

    #[test]
    fn keystore_replies_match_c_model() {
        let mut s = SepSim::new();
        let hdr_len = KEYSTORE_IPC_HEADER_SIZE as usize;
        // build a request buffer: IPC header + selector 1
        let mut req = vec![0u8; hdr_len + 4];
        req[0x14..0x18].copy_from_slice(&KEYSTORE_IPC_VERSION_1.to_le_bytes());
        req[hdr_len..hdr_len + 4].copy_from_slice(&1u32.to_le_bytes());
        {
            let req_arc = std::sync::Arc::new(std::sync::Mutex::new(req.clone()));
            let r2 = req_arc.clone();
            s.dma_read = Some(Box::new(move |a, buf| {
                let _ = a;
                let m = r2.lock().unwrap();
                let n = buf.len().min(m.len());
                buf[..n].copy_from_slice(&m[..n]);
            }));
        }
        s.ool_state[ep::KEYSTORE as usize].in_addr = 0x9000 << 12;
        s.ool_state[ep::KEYSTORE as usize].out_addr = 0xA000 << 12;
        // Create Keybag (0x01): tag carries the code, op carries the id
        s.handle_message(SepMessage::new(
            ep::KEYSTORE,
            0x01, // code 1, not a reply
            0x55, // id
            0,
            (req.len() as u32) & 0xFFFF,
        ));
        let reply = s.outbox.last().unwrap();
        assert_eq!(reply.tag, 0x01 | KEYSTORE_MSG_TAG_REPLY);
        assert_eq!(reply.op, 0x55);
        assert_eq!(reply.data, ((hdr_len + 8) as u32) << 16);
        let resp = s.keystore_resp.clone();
        assert_eq!(resp.len(), hdr_len + 8);
        // selector 1
        assert_eq!(&resp[hdr_len..hdr_len + 4], &1u32.to_le_bytes());
        // keybag id 'BAG1'
        assert_eq!(&resp[hdr_len + 4..hdr_len + 8], b"BAG1");
        // IPC version echoed from the request header
        assert_eq!(
            &resp[0x14..0x18],
            &KEYSTORE_IPC_VERSION_1.to_le_bytes()
        );
        // Get Device State (0x19) returns "applehax"
        s.handle_message(SepMessage::new(ep::KEYSTORE, 0x19, 0x55, 0, 0x60));
        let resp = s.keystore_resp.clone();
        assert!(resp.windows(8).any(|w| w == b"applehax"));
        // KC Wrap (0x08) sends a bare reply with no payload
        s.outbox.clear();
        s.handle_message(SepMessage::new(ep::KEYSTORE, 0x08, 0x55, 0, 0));
        assert_eq!(s.outbox.last().unwrap().tag, 0x08 | KEYSTORE_MSG_TAG_REPLY);
        assert_eq!(s.keystore_resp.len(), 0);
        // Unknown code echoes the request back with size reply
        s.outbox.clear();
        s.handle_message(SepMessage::new(ep::KEYSTORE, 0x77, 0x55, 0, (req.len() as u32) & 0xFFFF));
        assert_eq!(s.keystore_resp, req);
        assert_eq!(s.outbox.last().unwrap().data, (req.len() as u32) << 16);
    }

    #[test]
    fn xart_ops_always_ack() {
        let mut s = SepSim::new();
        for op in [xart_op::FLUSH_CACHED_XART, xart_op::COMMIT_HASH,
            xart_op::NONCE_GENERATE, xart_op::NONCE_INVALIDATE,
            xart_op::SHUTDOWN, 0x99] {
            s.outbox.clear();
            s.handle_message(SepMessage::new(ep::XART_SLAVE, 9, op, 0, 0));
            assert_eq!(s.outbox.len(), 1);
            assert_eq!(s.outbox[0].op, xart_op::ACK);
            assert_eq!(s.outbox[0].tag, 9);
        }
        // master endpoint behaves the same
        s.outbox.clear();
        s.handle_message(SepMessage::new(ep::XART_MASTER, 9, xart_op::SHUTDOWN, 0, 0));
        assert_eq!(s.outbox[0].op, xart_op::ACK);
    }
}
