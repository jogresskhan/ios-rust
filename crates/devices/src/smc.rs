//! Apple SMC (System Management Controller) — T8030 key-protocol model.
//!
//! Provenance: the upstream line is LGPL-2.1 — Alexander Graf's QEMU
//! `applesmc`-adjacent SMC IOP work, carried into ChefKiss Inferno's
//! `hw/misc/apple-silicon/smc.c` (cloned to /home/z/research/inferno) on top
//! of the A7IOP/RTKit mailbox. **The LGPL-2.1 upstream marker is
//! intentional and retained**: this module is a structural port of the
//! key-protocol semantics under the workspace's GPL-2.0-or-later license.
//!
//! Wire format (smc.c, exact):
//!   KeyMessage  { cmd, tag_and_id, length, payload_length, key(4B LE) }
//!   KeyResponse { status, tag_and_id, length, unk3, response[4] }
//! dispatched over the RTKit user endpoint 0 (`kSMCKeyEndpoint`); every
//! command produces exactly one response, queued here (upstream
//! `apple_rtkit_send_user_msg`).
//!
//! Command codes / result codes / key attributes / types are 1:1 from
//! smc.h. Default keys are the upstream `apple_smc_create` table ('#KEY'
//! count, 'CLKH', 'RGEN', 'MBSE' (susp/offw/rest/waka/slpa), 'LGPB',
//! 'LGPE', 'NESN', 'AC-N', 'B0AP', 'AC-W', 'CHAI') plus OSK0/OSK1 as
//! explicitly-marked 32-byte placeholders (macOS-SMC shape; the iPhone
//! SMC does not expose them upstream — they exist here so the
//! AppleSMCPlatform key path has somewhere to land).
//!
//! The mailbox register block (STATUS/CMD_RESULT/CMD/RSP_DATA/KEY) follows
//! the MMIO shape the workspace's apple-soc model and Graf's design use;
//! the RTKit transport itself lives in the aop/a7iop models. Writes of
//! keys stage their bytes in `sram` (upstream `s->sram`); reads of keys
//! larger than 4 bytes land back in `sram` (upstream
//! `key_entry->info.size <= 4 ? resp.response : s->sram`).

use crate::bus::MMIODevice;
use std::collections::VecDeque;

// ---------------------------------------------------------------------------
// Commands (smc.h SMCCommand)
// ---------------------------------------------------------------------------
pub const SMC_NO_COMMAND: u8 = 0x0;
pub const SMC_READ_KEY: u8 = 0x10;
pub const SMC_WRITE_KEY: u8 = 0x11;
pub const SMC_GET_KEY_BY_INDEX: u8 = 0x12;
pub const SMC_GET_KEY_INFO: u8 = 0x13;
pub const SMC_NOTIFICATION: u8 = 0x14;
pub const SMC_GET_SRAM_ADDR: u8 = 0x17;
pub const SMC_READ_KEY_PAYLOAD: u8 = 0x20;

// ---------------------------------------------------------------------------
// Results (smc.h SMCResult)
// ---------------------------------------------------------------------------
pub const SMC_RESULT_SUCCESS: u8 = 0;
pub const SMC_RESULT_ERROR: u8 = 1;
pub const SMC_RESULT_COMM_COLLISION: u8 = 0x80;
pub const SMC_RESULT_SPURIOUS_DATA: u8 = 0x81;
pub const SMC_RESULT_BAD_COMMAND: u8 = 0x82;
pub const SMC_RESULT_BAD_PARAMETER: u8 = 0x83;
pub const SMC_RESULT_KEY_NOT_FOUND: u8 = 0x84;
pub const SMC_RESULT_KEY_NOT_READABLE: u8 = 0x85;
pub const SMC_RESULT_KEY_NOT_WRITABLE: u8 = 0x86;
pub const SMC_RESULT_KEY_SIZE_MISMATCH: u8 = 0x87;
pub const SMC_RESULT_BAD_ARGUMENT_ERROR: u8 = 0x89;
pub const SMC_RESULT_KEY_INDEX_RANGE_ERROR: u8 = 0xB8;

// ---------------------------------------------------------------------------
// Key attributes / types (smc.h)
// ---------------------------------------------------------------------------
pub const SMC_ATTR_LE: u8 = 1 << 2;
pub const SMC_ATTR_FUNC: u8 = 1 << 4;
pub const SMC_ATTR_W: u8 = 1 << 6;
pub const SMC_ATTR_R: u8 = 1 << 7;
pub const SMC_ATTR_RW: u8 = SMC_ATTR_R | SMC_ATTR_W;
pub const SMC_ATTR_RW_LE: u8 = SMC_ATTR_RW | SMC_ATTR_LE;
pub const SMC_ATTR_R_LE: u8 = SMC_ATTR_R | SMC_ATTR_LE;
pub const SMC_ATTR_W_LE: u8 = SMC_ATTR_W | SMC_ATTR_LE;

pub const SMC_KEY_TYPE_FLAG: u32 = u32::from_be_bytes(*b"flag");
pub const SMC_KEY_TYPE_HEX: u32 = u32::from_be_bytes(*b"hex_");
pub const SMC_KEY_TYPE_SINT8: u32 = u32::from_be_bytes(*b"si8 ");
pub const SMC_KEY_TYPE_SINT32: u32 = u32::from_be_bytes(*b"si32");
pub const SMC_KEY_TYPE_UINT8: u32 = u32::from_be_bytes(*b"ui8 ");
pub const SMC_KEY_TYPE_UINT32: u32 = u32::from_be_bytes(*b"ui32");
pub const SMC_KEY_TYPE_CLH: u32 = u32::from_be_bytes(*b"{clh");
pub const SMC_KEY_TYPE_IOFLT: u32 = u32::from_be_bytes(*b"ioft");

pub const KSMC_KEY_ENDPOINT: u8 = 0;

// ---------------------------------------------------------------------------
// Mailbox registers (workspace MMIO shape, matches apple-soc/smc.rs)
// ---------------------------------------------------------------------------
pub const SMC_STATUS: u64 = 0x0000;
pub const SMC_CMD_RESULT: u64 = 0x0004;
pub const SMC_CMD: u64 = 0x0008;
pub const SMC_RSP_DATA: u64 = 0x000C;
pub const SMC_KEY: u64 = 0x0010;

const SMC_STATUS_BUSY: u32 = 1 << 0;
const SMC_STATUS_READY: u32 = 1 << 4;

/// Wire request (smc.c `KeyMessage`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyMessage {
    pub cmd: u8,
    pub tag_and_id: u8,
    pub length: u8,
    pub payload_length: u8,
    pub key: [u8; 4],
}

impl KeyMessage {
    pub fn key_u32(&self) -> u32 {
        u32::from_le_bytes(self.key)
    }
}

/// Wire response (smc.c `KeyResponse`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KeyResponse {
    pub status: u8,
    pub tag_and_id: u8,
    pub length: u8,
    pub unk3: u8,
    pub response: [u8; 4],
}

impl KeyResponse {
    pub fn raw(&self) -> u64 {
        let mut b = [0u8; 8];
        b[0] = self.status;
        b[1] = self.tag_and_id;
        b[2] = self.length;
        b[3] = self.unk3;
        b[4..8].copy_from_slice(&self.response);
        u64::from_le_bytes(b)
    }

    pub fn from_raw(v: u64) -> Self {
        let b = v.to_le_bytes();
        KeyResponse {
            status: b[0],
            tag_and_id: b[1],
            length: b[2],
            unk3: b[3],
            response: [b[4], b[5], b[6], b[7]],
        }
    }

    /// HID button notification (smc.c `apple_smc_send_hid_button`):
    /// status=SMC_NOTIFICATION, {state, button, HID_EVENT_NOTIFY_BUTTON,
    /// EVENT_HID_EVENT_NOTIFY}.
    pub fn hid_notification(state: u8, button: u8) -> Self {
        KeyResponse {
            status: SMC_NOTIFICATION,
            response: [state, button, 1, 0x71],
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone)]
pub struct SmcKey {
    pub key: [u8; 4],
    pub size: u8,
    pub typ: u32,
    pub attr: u8,
    pub data: Vec<u8>,
    /// func-backed keys ('#KEY' count, 'MBSE') instead of stored data.
    pub func: SmcKeyFunc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SmcKeyFunc {
    #[default]
    None,
    KeyCount,
    Mbse,
}

/// Apple SMC model: key store + mailbox command dispatch + respond queue.
pub struct Smc {
    keys: Vec<SmcKey>,
    /// SRAM staging window (upstream `s->sram`, machine-mapped; tests and
    /// the host side poke it directly, exactly like the guest's SRAM MMIO).
    pub sram: Vec<u8>,
    pub sram_addr: u64,
    is_booted: bool,
    cur_key: [u8; 4],
    result: u32,
    rsp_byte: u8,
    status: u32,
    /// KeyResponses waiting for the AP side (upstream RTKit user-EP queue).
    pub respond_queue: VecDeque<KeyResponse>,
    /// MBSE 'rest' latch (upstream: `qemu_system_reset_request`).
    pub reset_requested: bool,
    /// MBSE 'susp'/'offw' latch (upstream: `qemu_system_shutdown_request`).
    pub shutdown_requested: bool,
    /// HID/event notifications pushed toward the AP.
    pub notifications: Vec<KeyResponse>,
    pub unknown_reads: u64,
}

impl Default for Smc {
    fn default() -> Self {
        Self::new()
    }
}

impl Smc {
    pub fn new() -> Self {
        let mut s = Smc {
            keys: Vec::new(),
            sram: vec![0; 0x1000],
            sram_addr: 0,
            is_booted: true,
            cur_key: [0; 4],
            result: 0,
            rsp_byte: 0,
            status: SMC_STATUS_READY,
            respond_queue: VecDeque::new(),
            reset_requested: false,
            shutdown_requested: false,
            notifications: Vec::new(),
            unknown_reads: 0,
        };
        // apple_smc_create default table (values from smc.c)
        s.add_func_key(*b"#KEY", 4, SMC_KEY_TYPE_UINT32, 0, SmcKeyFunc::KeyCount);
        s.add_key(
            *b"CLKH",
            8,
            SMC_KEY_TYPE_CLH,
            SMC_ATTR_RW_LE,
            &[0x40, 0x19, 0x01, 0x00, 0x80, 0x70, 0x00, 0x00],
        );
        s.add_key(*b"RGEN", 1, SMC_KEY_TYPE_UINT8, SMC_ATTR_R, &[3]);
        s.add_func_key(*b"MBSE", 4, SMC_KEY_TYPE_HEX, SMC_ATTR_LE, SmcKeyFunc::Mbse);
        s.add_key(*b"LGPB", 1, SMC_KEY_TYPE_FLAG, SMC_ATTR_RW, &[0]);
        s.add_key(*b"LGPE", 1, SMC_KEY_TYPE_FLAG, SMC_ATTR_RW, &[0]);
        s.add_key(*b"NESN", 4, SMC_KEY_TYPE_HEX, SMC_ATTR_W_LE, &[0; 4]);
        s.add_key(*b"AC-N", 1, SMC_KEY_TYPE_UINT8, SMC_ATTR_R, &[1]);
        s.add_key(*b"B0AP", 4, SMC_KEY_TYPE_SINT32, SMC_ATTR_R_LE, &[0; 4]);
        s.add_key(*b"AC-W", 1, SMC_KEY_TYPE_SINT8, SMC_ATTR_R, &[1]);
        s.add_key(*b"CHAI", 4, SMC_KEY_TYPE_UINT32, SMC_ATTR_R_LE, &[0; 4]);
        // OSK0/OSK1: 32-byte placeholders (see module doc) — writable, not
        // readable upstream-style, so the guest can stage but never trust.
        s.add_key(*b"OSK0", 32, SMC_KEY_TYPE_HEX, SMC_ATTR_W_LE, &[0; 32]);
        s.add_key(*b"OSK1", 32, SMC_KEY_TYPE_HEX, SMC_ATTR_W_LE, &[0; 32]);
        s
    }

    pub fn add_key(&mut self, key: [u8; 4], size: u8, typ: u32, attr: u8, data: &[u8]) {
        self.keys.push(SmcKey {
            key,
            size,
            typ,
            attr,
            data: data.to_vec(),
            func: SmcKeyFunc::None,
        });
    }

    /// apple_smc_add_key_func: ORs SMC_ATTR_FUNC + R (reader) / W (writer).
    pub fn add_func_key(&mut self, key: [u8; 4], size: u8, typ: u32, attr: u8, func: SmcKeyFunc) {
        let mut attr = attr | SMC_ATTR_FUNC;
        match func {
            SmcKeyFunc::KeyCount => attr |= SMC_ATTR_R,
            SmcKeyFunc::Mbse => attr |= SMC_ATTR_W,
            SmcKeyFunc::None => {}
        }
        self.keys.push(SmcKey {
            key,
            size,
            typ,
            attr,
            data: vec![0; size as usize],
            func,
        });
    }

    pub fn key(&self, key: &[u8; 4]) -> Option<&SmcKey> {
        self.keys.iter().find(|k| &k.key == key)
    }

    pub fn key_count(&self) -> u32 {
        self.keys.len() as u32
    }

    /// RTKit boot-done latch (upstream `apple_smc_boot_done`).
    pub fn set_booted(&mut self, booted: bool) {
        self.is_booted = booted;
    }

    /// HID button event (upstream `apple_smc_send_hid_button`).
    pub fn send_hid_button(&mut self, button: u8, state: bool) {
        if !self.is_booted {
            return;
        }
        self.notifications
            .push(KeyResponse::hid_notification(state as u8, button));
    }

    /// Full protocol dispatch (upstream `apple_smc_handle_key_endpoint`).
    pub fn dispatch(&mut self, msg: KeyMessage) -> KeyResponse {
        let mut resp =
            KeyResponse { tag_and_id: msg.tag_and_id, ..Default::default() };
        self.status = SMC_STATUS_BUSY | SMC_STATUS_READY;
        match msg.cmd {
            SMC_GET_SRAM_ADDR => {
                resp.response = (self.sram_addr as u32).to_le_bytes();
                resp.status = SMC_RESULT_SUCCESS;
            }
            SMC_READ_KEY | SMC_READ_KEY_PAYLOAD => {
                let key = msg.key;
                match self.keys.iter().find(|k| &k.key == &key) {
                    None => resp.status = SMC_RESULT_KEY_NOT_FOUND,
                    Some(k) if k.attr & SMC_ATTR_R == 0 => {
                        resp.status = SMC_RESULT_KEY_NOT_READABLE;
                    }
                    Some(k) => {
                        if msg.length < k.size {
                            resp.status = SMC_RESULT_KEY_SIZE_MISMATCH;
                        } else {
                            resp.status = SMC_RESULT_SUCCESS;
                            resp.length = k.size;
                            if k.func == SmcKeyFunc::KeyCount {
                                // smc_key_count_read: stl_be_p(data, count)
                                resp.response = self.key_count().to_be_bytes();
                            } else if k.func == SmcKeyFunc::Mbse {
                                // readable-but-func: responds with the last
                                // staged value (upstream MBSE is LE/wfunc)
                                let v =
                                    u32::from_le_bytes(self.sram[..4].try_into().unwrap());
                                resp.response = v.to_le_bytes();
                            } else if k.size as usize <= 4 {
                                for (i, b) in k.data.iter().take(4).enumerate() {
                                    resp.response[i] = *b;
                                }
                            } else {
                                // >4-byte reads land in SRAM (upstream)
                                let n = (k.size as usize).min(self.sram.len());
                                self.sram[..n].copy_from_slice(&k.data[..n]);
                            }
                        }
                    }
                }
            }
            SMC_WRITE_KEY => {
                let key = msg.key;
                // peek first (immutable), mutate after the match
                let found = self
                    .keys
                    .iter()
                    .find(|k| &k.key == &key)
                    .map(|k| (k.attr & SMC_ATTR_W != 0, k.size, k.func));
                match found {
                    None => resp.status = SMC_RESULT_KEY_NOT_FOUND,
                    Some((false, _, _)) => {
                        resp.status = SMC_RESULT_KEY_NOT_WRITABLE;
                    }
                    Some((true, size, func)) => {
                        if size != msg.length {
                            resp.status = SMC_RESULT_KEY_SIZE_MISMATCH;
                        } else {
                            resp.status = SMC_RESULT_SUCCESS;
                            resp.length = size;
                            if func == SmcKeyFunc::Mbse {
                                // apple_smc_mbse_write: susp/offw → shutdown,
                                // rest → reset, waka/slpa → plain ack
                                let v = u32::from_le_bytes(
                                    self.sram[..4].try_into().unwrap(),
                                );
                                match &v.to_le_bytes() {
                                    b"susp" | b"offw" => {
                                        self.shutdown_requested = true;
                                    }
                                    b"rest" => self.reset_requested = true,
                                    _ => {}
                                }
                            } else {
                                let n = (size as usize).min(self.sram.len());
                                let k =
                                    self.keys.iter_mut().find(|k| &k.key == &key).unwrap();
                                k.data.copy_from_slice(&self.sram[..n]);
                            }
                        }
                    }
                }
            }
            SMC_GET_KEY_BY_INDEX => match self.keys.get(msg.key_u32() as usize) {
                Some(k) => {
                    resp.status = SMC_RESULT_SUCCESS;
                    resp.response = k.key;
                }
                None => resp.status = SMC_RESULT_KEY_INDEX_RANGE_ERROR,
            },
            SMC_GET_KEY_INFO => match self.keys.iter().find(|k| &k.key == &msg.key) {
                None => resp.status = SMC_RESULT_KEY_NOT_FOUND,
                // SMCKeyInfo { size, type, attr } lands in SRAM upstream
                Some(k) => {
                    self.sram[0] = k.size;
                    self.sram[1..5].copy_from_slice(&k.typ.to_le_bytes());
                    self.sram[5] = k.attr;
                    resp.status = SMC_RESULT_SUCCESS;
                }
            },
            _ => resp.status = SMC_RESULT_BAD_COMMAND,
        }
        self.result = resp.status as u32;
        self.rsp_byte = resp.response[0];
        self.status = SMC_STATUS_READY;
        self.respond_queue.push_back(resp);
        resp
    }
}

impl MMIODevice for Smc {
    fn name(&self) -> &'static str {
        "apple-smc"
    }
    fn size(&self) -> u64 {
        0x100
    }

    fn read(&mut self, offset: u64, _width: u32) -> u64 {
        match offset {
            SMC_STATUS => self.status as u64,
            SMC_CMD_RESULT => self.result as u64,
            SMC_RSP_DATA => self.rsp_byte as u64,
            SMC_KEY => u32::from_le_bytes(self.cur_key) as u64,
            _ => {
                self.unknown_reads += 1;
                0
            }
        }
    }

    fn write(&mut self, offset: u64, value: u64, _width: u32) {
        match offset {
            SMC_KEY => self.cur_key = (value as u32).to_le_bytes(),
            SMC_RSP_DATA => self.sram[0] = value as u8, // 1-byte staging path
            SMC_CMD => {
                let msg = KeyMessage {
                    cmd: value as u8,
                    tag_and_id: ((value >> 8) & 0xFF) as u8,
                    length: ((value >> 16) & 0xFF) as u8,
                    payload_length: ((value >> 24) & 0xFF) as u8,
                    key: self.cur_key,
                };
                self.dispatch(msg);
            }
            _ => {}
        }
    }
}

pub const PARITY_PCT: u8 = 55; // key protocol + respond queue implemented/tested; RTKit transport + sensor funcs pending

impl crate::bus::Device for Smc {
    fn mmio(&mut self) -> &mut dyn MMIODevice {
        self
    }
    fn parity_pct(&self) -> u8 {
        PARITY_PCT
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::W4;

    fn key_u32(k: &[u8; 4]) -> u64 {
        u32::from_le_bytes(*k) as u64
    }

    fn read(s: &mut Smc, key: &[u8; 4], tag: u8) -> KeyResponse {
        s.dispatch(KeyMessage {
            cmd: SMC_READ_KEY,
            tag_and_id: tag,
            length: s.key(key).unwrap().size,
            payload_length: 0,
            key: *key,
        })
    }

    fn write(s: &mut Smc, key: &[u8; 4], data: &[u8], tag: u8) -> KeyResponse {
        s.sram[..data.len()].copy_from_slice(data);
        s.dispatch(KeyMessage {
            cmd: SMC_WRITE_KEY,
            tag_and_id: tag,
            length: data.len() as u8,
            payload_length: 0,
            key: *key,
        })
    }

    #[test]
    fn key_count_and_read_roundtrip() {
        let mut s = Smc::new();
        // '#KEY' read → big-endian key count in response bytes
        let resp = read(&mut s, b"#KEY", 0x42);
        assert_eq!(resp.status, SMC_RESULT_SUCCESS);
        assert_eq!(resp.tag_and_id, 0x42);
        assert_eq!(resp.length, 4);
        assert_eq!(u32::from_be_bytes(resp.response), s.key_count());
        // queued on the respond queue (command → response cycle)
        assert_eq!(s.respond_queue.pop_back(), Some(resp));
        assert!(s.respond_queue.is_empty());
    }

    #[test]
    fn write_then_read_back() {
        let mut s = Smc::new();
        let r = write(&mut s, b"LGPB", &[0x55], 1);
        assert_eq!(r.status, SMC_RESULT_SUCCESS);
        let resp = read(&mut s, b"LGPB", 2);
        assert_eq!(resp.status, SMC_RESULT_SUCCESS);
        assert_eq!(resp.response[0], 0x55);
    }

    #[test]
    fn result_codes_match_smc_h() {
        let mut s = Smc::new();
        // not found
        let r = s.dispatch(KeyMessage {
            cmd: SMC_READ_KEY,
            tag_and_id: 0,
            length: 4,
            payload_length: 0,
            key: *b"NOPE",
        });
        assert_eq!(r.status, SMC_RESULT_KEY_NOT_FOUND);
        // 'NESN' is write-only upstream → read NAKs
        let r = read(&mut s, b"NESN", 0);
        assert_eq!(r.status, SMC_RESULT_KEY_NOT_READABLE);
        // 'RGEN' is read-only → write NAKs
        let r = write(&mut s, b"RGEN", &[7], 0);
        assert_eq!(r.status, SMC_RESULT_KEY_NOT_WRITABLE);
        // size mismatch: 'CLKH' is 8 bytes
        let r = write(&mut s, b"CLKH", &[7], 0);
        assert_eq!(r.status, SMC_RESULT_KEY_SIZE_MISMATCH);
        // index range
        let r = s.dispatch(KeyMessage {
            cmd: SMC_GET_KEY_BY_INDEX,
            tag_and_id: 0,
            length: 0,
            payload_length: 0,
            key: s.key_count().to_le_bytes(),
        });
        assert_eq!(r.status, SMC_RESULT_KEY_INDEX_RANGE_ERROR);
        // unknown command
        let r = s.dispatch(KeyMessage {
            cmd: 0x99,
            tag_and_id: 0,
            length: 0,
            payload_length: 0,
            key: *b"#KEY",
        });
        assert_eq!(r.status, SMC_RESULT_BAD_COMMAND);
    }

    #[test]
    fn get_key_by_index_walks_table() {
        let mut s = Smc::new();
        let n = s.key_count();
        let mut seen = Vec::new();
        for i in 0..n {
            let r = s.dispatch(KeyMessage {
                cmd: SMC_GET_KEY_BY_INDEX,
                tag_and_id: i as u8,
                length: 0,
                payload_length: 0,
                key: i.to_le_bytes(),
            });
            assert_eq!(r.status, SMC_RESULT_SUCCESS);
            seen.push(r.response);
        }
        assert!(seen.contains(&*b"#KEY"));
        assert!(seen.contains(&*b"OSK0"));
        assert!(seen.contains(&*b"OSK1"));
    }

    #[test]
    fn osk_placeholders_write_via_sram() {
        let mut s = Smc::new();
        let r = write(&mut s, b"OSK0", &[0xAB; 32], 0);
        assert_eq!(r.status, SMC_RESULT_SUCCESS);
        assert_eq!(s.key(b"OSK0").unwrap().data, vec![0xAB; 32]);
        assert_eq!(s.key(b"OSK1").unwrap().data, vec![0; 32]);
    }

    #[test]
    fn mbse_suspend_reset_wake() {
        let mut s = Smc::new();
        assert!(!s.reset_requested && !s.shutdown_requested);
        assert_eq!(write(&mut s, b"MBSE", b"waka", 0).status, SMC_RESULT_SUCCESS);
        assert!(!s.reset_requested && !s.shutdown_requested);
        assert_eq!(write(&mut s, b"MBSE", b"rest", 0).status, SMC_RESULT_SUCCESS);
        assert!(s.reset_requested);
        assert_eq!(write(&mut s, b"MBSE", b"offw", 0).status, SMC_RESULT_SUCCESS);
        assert!(s.shutdown_requested);
    }

    #[test]
    fn mailbox_mmio_command_cycle() {
        let mut s = Smc::new();
        s.write(SMC_KEY, key_u32(b"#KEY"), W4);
        // CMD word: cmd | tag<<8 | len<<16 | payload_len<<24
        s.write(SMC_CMD, (SMC_READ_KEY as u64) | (0x7Eu64 << 8) | (4 << 16), W4);
        assert_eq!(
            s.read(SMC_STATUS, W4) as u32 & SMC_STATUS_READY,
            SMC_STATUS_READY
        );
        assert_eq!(s.read(SMC_CMD_RESULT, W4), SMC_RESULT_SUCCESS as u64);
        let resp = *s.respond_queue.back().unwrap();
        assert_eq!(u32::from_be_bytes(resp.response), s.key_count());
        assert_eq!(s.read(SMC_RSP_DATA, W4), resp.response[0] as u64);
        assert_eq!(KeyResponse::from_raw(resp.raw()), resp);
        // unknown reg RAZ + counted
        assert_eq!(s.read(0x50, W4), 0);
        assert_eq!(s.unknown_reads, 1);
    }

    #[test]
    fn hid_notification_and_boot_gate() {
        let mut s = Smc::new();
        s.send_hid_button(2, true);
        let n = s.notifications.pop().unwrap();
        assert_eq!(n.status, SMC_NOTIFICATION);
        assert_eq!(n.response, [1, 2, 1, 0x71]);
        s.set_booted(false);
        s.send_hid_button(1, true);
        assert!(s.notifications.is_empty());
    }
}
