//! Apple AOP (Always-On Processor) mailbox shim.
//!
//! Port of ChefKiss Inferno `hw/misc/apple-silicon/aop.c`: the AOP is an
//! RTKit coprocessor whose firmware isn't executed; the interesting part is
//! the v7 ring-buffer service protocol the AP drives over user endpoints
//! (HELLO → REQUEST_REGION → SET_QUEUE → READY_REPORT → RX_SIGNAL packets).
//!
//! Ported surface:
//!   * IOP→AP ops: OP_HELLO 0x80, OP_REQUEST_REGION_BYTES 0x81,
//!     OP_SET_RX/TX_QUEUE_BY_ADDR 0x82/0x83, OP_TX_SIGNAL 0x85,
//!     OP_ACK_START/STOP_QUEUE 0x86/0x87, OP_ACK_HIBERNATE_QUEUE 0xC3,
//!   * AP→IOP ops: OP_ACK_HELLO 0xA0, OP_ACK_REQUEST_REGION 0xA1,
//!     OP_RX_SIGNAL 0xA2, OP_START/STOP_QUEUE 0xA3/0xA4,
//!     OP_HIBERNATE_QUEUE 0xC2,
//!   * EP state machine POWERED_OFF → AWAITING_HELLO → AWAITING_RX_ACK →
//!     AWAITING_TX_ACK → IDLE,
//!   * v7 ring-buffer framing: `RB_V7_AOP_MAGIC` 'AOP ' (BE), 16-byte rb
//!     entry header, packet (version 2) + sub-packet (payload len, category,
//!     type, seq, timestamp, out_len), packet types SET/GET_PROPERTY 0x4/0xA,
//!     SET/GET_NAMED_PROPERTY 0x10/0x11, COMMAND 0x20, READY_REPORT 0xC0,
//!     MSG_REPORT 0xD0.
//!
//! Upstream t8030 registers **no** service endpoints (aop-audio is `#if 0`);
//! [`Aop::add_endpoint`] exists so the protocol stays exercisable/testable.
//! Ring contents live in the bounded [`Aop::dma_window`]; traffic outside it
//! lands in [`AopEndpoint::pending_writes`].
//!
//! License: AGPL-3.0-or-later (derived work).

use vm_core::Device;

use crate::rtkit::Rtkit;

// IOP → AP ops.
pub const OP_HELLO: u64 = 0x80;
pub const OP_REQUEST_REGION_BYTES: u64 = 0x81;
pub const OP_SET_RX_QUEUE_BY_ADDR: u64 = 0x82;
pub const OP_SET_TX_QUEUE_BY_ADDR: u64 = 0x83;
pub const OP_SET_HISTORICAL_QUEUE_BY_ADDR: u64 = 0x84;
pub const OP_TX_SIGNAL: u64 = 0x85;
pub const OP_ACK_START_QUEUE: u64 = 0x86;
pub const OP_ACK_STOP_QUEUE: u64 = 0x87;
pub const OP_REQUEST_REGION_CHUNKS: u64 = 0x89;
pub const OP_ACK_HIBERNATE_QUEUE: u64 = 0xC3;

// AP → IOP ops.
pub const OP_ACK_HELLO: u64 = 0xA0;
pub const OP_ACK_REQUEST_REGION: u64 = 0xA1;
pub const OP_RX_SIGNAL: u64 = 0xA2;
pub const OP_START_QUEUE: u64 = 0xA3;
pub const OP_STOP_QUEUE: u64 = 0xA4;
pub const OP_HIBERNATE_QUEUE: u64 = 0xC2;

pub const fn msg_op(op: u64) -> u64 {
    op << 48
}
pub const fn msg_op_get(msg: u64) -> u8 {
    ((msg >> 48) & 0xFF) as u8
}

pub const RB_V7_IOP_MAGIC: u32 = u32::from_le_bytes(*b"IOP ");
pub const RB_V7_AOP_MAGIC: u32 = u32::from_le_bytes(*b"AOP ");

// Sub-packet categories (high nibble of flags).
pub const SUB_PACKET_FLAG_CAT_REPORT: u8 = 0;
pub const SUB_PACKET_FLAG_CAT_COMMAND: u8 = 1;
pub const SUB_PACKET_FLAG_CAT_RESPONSE: u8 = 2;
pub const SUB_PACKET_FLAG_CAT_LONG_COMMAND: u8 = 3;

// Packet types.
pub const PACKET_TYPE_SET_PROPERTY: u16 = 0x4;
pub const PACKET_TYPE_GET_PROPERTY: u16 = 0xA;
pub const PACKET_TYPE_SET_NAMED_PROPERTY: u16 = 0x10;
pub const PACKET_TYPE_GET_NAMED_PROPERTY: u16 = 0x11;
pub const PACKET_TYPE_COMMAND: u16 = 0x20;
pub const PACKET_TYPE_READY_REPORT: u16 = 0xC0;
pub const PACKET_TYPE_MSG_REPORT: u16 = 0xD0;

pub const READY_REPORT_FLAG_MUX: u32 = 1 << 3;
pub const READY_REPORT_FLAG_SPU_APP: u32 = 1 << 31;

pub const RB_ENTRY_LEN: usize = 16;
pub const PACKET_LEN: usize = 16;
pub const SUB_PACKET_LEN: usize = 24;
pub const READY_REPORT_LEN: usize = 44;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpState {
    PoweredOff,
    AwaitingHello,
    AwaitingRxAck,
    AwaitingTxAck,
    Idle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpType {
    Hid,
    Mux,
    App,
}

/// Service endpoint description (`AppleAOPEndpointDescription`).
pub struct EpDescription {
    pub service_name: String,
    pub service_id: u32,
    pub interface_num: u32,
    pub ep_type: EpType,
    pub rx_len: u32,
    pub tx_len: u32,
}

pub struct AopEndpoint {
    pub num: u8,
    pub descr: EpDescription,
    pub state: EpState,
    pub rx_off: u32,
    pub tx_off: u32,
    pub seq: u16,
    /// Last decoded RX packet (type, category, seq, payload) for census.
    pub last_rx: Option<(u16, u8, u16, Vec<u8>)>,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub pending_writes: Vec<(u64, Vec<u8>)>,
}

/// Apple AOP: RTKit mailbox + ascv2-core region (RAZ) + EP protocol.
pub struct Aop {
    pub rtkit: Rtkit,
    pub align: u32,
    pub endpoints: Vec<AopEndpoint>,
    /// DMA window: guest `dma_base` ↔ window[0].
    pub dma_window: Vec<u8>,
    pub dma_base: u64,
    /// ascv2 core region size (upstream `reg[3]`, reads 0 / writes dropped).
    pub ascv2_len: u64,
    pub boot_done: bool,
}

impl Aop {
    pub fn new() -> Self {
        // Upstream registers one user EP slot per endpoint created; none by
        // default (matches t8030.c where aop-audio is disabled).
        Aop {
            rtkit: Rtkit::new("AOP", 0x4000),
            align: 0x40,
            endpoints: Vec::new(),
            dma_window: vec![0u8; 0x20_0000], // 2 MiB
            dma_base: 0,
            ascv2_len: 0x4000,
            boot_done: false,
        }
    }

    pub fn set_dma_window(&mut self, base: u64) {
        self.dma_base = base;
    }

    /// Register a service endpoint (EP index = position in the list).
    pub fn add_endpoint(
        &mut self,
        service_name: &str,
        service_id: u32,
        ep_type: EpType,
        rx_len: u32,
        tx_len: u32,
    ) -> u8 {
        let num = self.endpoints.len() as u8;
        assert!(rx_len % self.align == 0 && tx_len % self.align == 0);
        self.endpoints.push(AopEndpoint {
            num,
            descr: EpDescription {
                service_name: service_name.to_string(),
                service_id,
                interface_num: 0,
                ep_type,
                rx_len,
                tx_len,
            },
            state: EpState::PoweredOff,
            rx_off: 0,
            tx_off: 0,
            seq: 0,
            last_rx: None,
            rx_packets: 0,
            tx_packets: 0,
            pending_writes: Vec::new(),
        });
        self.rtkit.register_user_ep(num);
        num
    }

    fn dma_write(&mut self, addr: u32, data: &[u8]) -> bool {
        if self.dma_base == 0 {
            return false;
        }
        let guest = self.dma_base + addr as u64;
        let off = addr as usize;
        if off + data.len() <= self.dma_window.len() {
            self.dma_window[off..off + data.len()].copy_from_slice(data);
            true
        } else {
            if let Some(ep) = self.endpoints.last_mut() {
                ep.pending_writes.push((guest, data.to_vec()));
            }
            false
        }
    }

    fn dma_read(&self, addr: u32, buf: &mut [u8]) -> bool {
        let off = addr as usize;
        if off + buf.len() <= self.dma_window.len() {
            buf.copy_from_slice(&self.dma_window[off..off + buf.len()]);
            true
        } else {
            buf.fill(0);
            false
        }
    }

    /// `apple_aop_ep_init_rb`.
    fn ep_init_rb(&mut self, ep: usize, addr: u32, len: u32) {
        let v = (len - self.align * 3) as u32;
        let mut b4 = [0u8; 4];
        b4.copy_from_slice(&v.to_le_bytes());
        self.dma_write(addr, &b4);
        let mut b2 = [0u8; 2];
        b2.copy_from_slice(&6u16.to_le_bytes());
        self.dma_write(addr + 4, &b2);
        b2.copy_from_slice(&7u16.to_le_bytes());
        self.dma_write(addr + 6, &b2);
        let _ = ep;
    }

    fn ep_set_wptr(&mut self, queue_off: u32, val: u32) {
        let mut b = [0u8; 4];
        b.copy_from_slice(&val.to_le_bytes());
        self.dma_write(queue_off + self.align * 2, &b);
    }

    fn ep_get_wptr(&mut self, queue_off: u32) -> u32 {
        let mut b = [0u8; 4];
        self.dma_read(queue_off + self.align * 2, &mut b);
        u32::from_le_bytes(b)
    }

    fn ep_get_rptr(&mut self, queue_off: u32) -> u32 {
        let mut b = [0u8; 4];
        self.dma_read(queue_off + self.align, &mut b);
        u32::from_le_bytes(b)
    }

    fn ep_set_rptr(&mut self, queue_off: u32, val: u32) {
        let mut b = [0u8; 4];
        b.copy_from_slice(&val.to_le_bytes());
        self.dma_write(queue_off + self.align, &b);
    }

    /// `apple_aop_ep_write_rb_entry` (magic 'IOP ' BE + length + zeros).
    fn write_rb_entry(&mut self, addr: u32, length: u32) {
        let mut b = [0u8; 8];
        b[0..4].copy_from_slice(&RB_V7_IOP_MAGIC.to_be_bytes());
        b[4..8].copy_from_slice(&length.to_le_bytes());
        self.dma_write(addr, &b);
        self.dma_write(addr + 8, &[0u8; 8]);
    }

    /// `apple_aop_ep_write_packet` (version 2 + seq + timestamp).
    fn write_packet(&mut self, addr: u32, seq: u16, timestamp: u64) {
        let mut b = [0u8; PACKET_LEN];
        b[0] = 2;
        b[1..3].copy_from_slice(&seq.to_le_bytes());
        b[8..16].copy_from_slice(&timestamp.to_le_bytes());
        self.dma_write(addr, &b);
    }

    /// `apple_aop_ep_write_sub_packet`.
    fn write_sub_packet(
        &mut self,
        addr: u32,
        payload_len: u32,
        category: u8,
        ty: u16,
        seq: u16,
        timestamp: u64,
        out_len: u32,
    ) {
        let mut b = [0u8; SUB_PACKET_LEN];
        b[0..4].copy_from_slice(&payload_len.to_le_bytes());
        b[4] = 2; // version
        b[5] = category << 4;
        b[6..8].copy_from_slice(&ty.to_le_bytes());
        b[8..10].copy_from_slice(&seq.to_le_bytes());
        b[10..18].copy_from_slice(&timestamp.to_le_bytes());
        b[20..24].copy_from_slice(&out_len.to_le_bytes());
        self.dma_write(addr, &b);
    }

    /// `apple_aop_ep_read_sub_packet`.
    #[allow(clippy::too_many_arguments)]
    fn read_sub_packet(
        &mut self,
        addr: u32,
    ) -> Option<(u32, u8, u16, u16, u32)> {
        let mut b = [0u8; SUB_PACKET_LEN];
        self.dma_read(addr, &mut b);
        if b[4] != 2 {
            return None;
        }
        let payload_len = u32::from_le_bytes(b[0..4].try_into().unwrap());
        let category = b[5] >> 4;
        let ty = u16::from_le_bytes(b[6..8].try_into().unwrap());
        let seq = u16::from_le_bytes(b[8..10].try_into().unwrap());
        let out_len = u32::from_le_bytes(b[20..24].try_into().unwrap());
        Some((payload_len, category, ty, seq, out_len))
    }

    /// `apple_aop_ep_write_ready_report`.
    fn write_ready_report(&mut self, ep: usize) -> Vec<u8> {
        let mut buf = vec![0u8; READY_REPORT_LEN];
        let name = self.endpoints[ep].descr.service_name.as_bytes();
        let n = name.len().min(31);
        buf[..n].copy_from_slice(&name[..n]);
        let sid = self.endpoints[ep].descr.service_id;
        buf[32..36].copy_from_slice(&sid.to_le_bytes());
        let flags = match self.endpoints[ep].descr.ep_type {
            EpType::Hid => 0,
            EpType::Mux => READY_REPORT_FLAG_MUX,
            EpType::App => READY_REPORT_FLAG_SPU_APP,
        };
        buf[36..40].copy_from_slice(&flags.to_le_bytes());
        let ifc = self.endpoints[ep].descr.interface_num;
        buf[40..44].copy_from_slice(&ifc.to_le_bytes());
        buf
    }

    /// `apple_aop_ep_send_packet_full` over the TX ring.
    fn send_packet(
        &mut self,
        ep: usize,
        ty: u16,
        category: u8,
        seq: u16,
        payload: &[u8],
        out_len: u32,
    ) {
        let tx_off = self.endpoints[ep].tx_off as usize;
        let tx_len = self.endpoints[ep].descr.tx_len as usize;
        let mut wptr = self.ep_get_wptr(self.endpoints[ep].tx_off);
        let data_off = self.align as usize * 3;
        let total =
            (RB_ENTRY_LEN + PACKET_LEN + SUB_PACKET_LEN + payload.len()
                + self.align as usize
                - 1)
                / self.align as usize
                * self.align as usize;
        let mut end_wptr = wptr as usize + total;
        if data_off + end_wptr > tx_len {
            wptr = 0;
            end_wptr = total;
        }
        let base = tx_off + data_off + wptr as usize;
        let rb_len =
            (PACKET_LEN + SUB_PACKET_LEN + payload.len()) as u32;
        self.write_rb_entry(base as u32, rb_len);
        self.write_packet((base + RB_ENTRY_LEN) as u32, seq, 0);
        self.write_sub_packet(
            (base + RB_ENTRY_LEN + PACKET_LEN) as u32,
            payload.len() as u32,
            category,
            ty,
            seq,
            0,
            out_len,
        );
        self.dma_write(
            (base + RB_ENTRY_LEN + PACKET_LEN + SUB_PACKET_LEN) as u32,
            payload,
        );
        self.ep_set_wptr(self.endpoints[ep].tx_off, end_wptr as u32);
        self.rtkit
            .send_user_msg(self.endpoints[ep].num, msg_op(OP_TX_SIGNAL));
        self.endpoints[ep].tx_packets += 1;
        self.endpoints[ep].seq = self.endpoints[ep].seq.wrapping_add(1);
    }

    /// `apple_aop_ep_recv_packet_locked` — decode one RX ring packet.
    fn recv_packet(&mut self, ep: usize) -> Option<(u16, u8, u16, Vec<u8>, u32)> {
        let rx_off = self.endpoints[ep].rx_off;
        let rx_len = self.endpoints[ep].descr.rx_len;
        let wptr = self.ep_get_wptr(rx_off);
        let rptr = self.ep_get_rptr(rx_off);
        if wptr == rptr {
            return None;
        }
        let data_off = self.align * 3;
        let base = rx_off + data_off + rptr;
        let mut rb = [0u8; 8];
        self.dma_read(base, &mut rb);
        let magic = u32::from_be_bytes(rb[0..4].try_into().unwrap());
        if magic != RB_V7_AOP_MAGIC {
            return None;
        }
        let rb_payload_len = u32::from_le_bytes(rb[4..8].try_into().unwrap());
        let sp = self.read_sub_packet(base + RB_ENTRY_LEN as u32 + PACKET_LEN as u32)?;
        let (payload_len, category, ty, seq, out_len) = sp;
        let mut payload = vec![0u8; (payload_len as usize).min(0x1000)];
        self.dma_read(
            base + RB_ENTRY_LEN as u32 + PACKET_LEN as u32 + SUB_PACKET_LEN as u32,
            &mut payload,
        );
        // advance rptr past this packet (rounded to align)
        let total = rb_payload_len as usize;
        let total = (total + self.align as usize - 1) / self.align as usize
            * self.align as usize;
        let final_rptr = rptr + total as u32;
        self.ep_set_rptr(rx_off, if final_rptr as usize + data_off as usize >= rx_len as usize { 0 } else { final_rptr });
        Some((ty, category, seq, payload, out_len))
    }

    /// `apple_aop_ep_handle_message` — drive the EP state machine.
    pub fn handle_user_msg(&mut self, ep: u8, msg: u64) {
        if ep as usize >= self.endpoints.len() {
            return;
        }
        match self.endpoints[ep as usize].state {
            EpState::PoweredOff => {}
            EpState::AwaitingHello => {
                if msg_op_get(msg) as u64 != OP_ACK_HELLO {
                    return;
                }
                let rx_len = self.endpoints[ep as usize].descr.rx_len;
                self.rtkit
                    .send_user_msg(ep, msg_op(OP_REQUEST_REGION_BYTES) | rx_len as u64);
                self.endpoints[ep as usize].state = EpState::AwaitingRxAck;
            }
            EpState::AwaitingRxAck => {
                if msg_op_get(msg) as u64 != OP_ACK_REQUEST_REGION {
                    return;
                }
                let rx_off = (msg & 0xFFFF_FFFF_FFFF) as u32;
                self.endpoints[ep as usize].rx_off = rx_off;
                let rx_len = self.endpoints[ep as usize].descr.rx_len;
                self.ep_init_rb(ep as usize, rx_off, rx_len);
                self.rtkit
                    .send_user_msg(ep, msg_op(OP_SET_RX_QUEUE_BY_ADDR) | rx_off as u64);
                let tx_len = self.endpoints[ep as usize].descr.tx_len;
                self.rtkit
                    .send_user_msg(ep, msg_op(OP_REQUEST_REGION_BYTES) | tx_len as u64);
                self.endpoints[ep as usize].state = EpState::AwaitingTxAck;
            }
            EpState::AwaitingTxAck => {
                if msg_op_get(msg) as u64 != OP_ACK_REQUEST_REGION {
                    return;
                }
                let tx_off = (msg & 0xFFFF_FFFF_FFFF) as u32;
                self.endpoints[ep as usize].tx_off = tx_off;
                let tx_len = self.endpoints[ep as usize].descr.tx_len;
                self.ep_init_rb(ep as usize, tx_off, tx_len);
                self.rtkit
                    .send_user_msg(ep, msg_op(OP_SET_TX_QUEUE_BY_ADDR) | tx_off as u64);
                self.endpoints[ep as usize].state = EpState::Idle;
                // READY_REPORT + TX_SIGNAL
                let report = self.write_ready_report(ep as usize);
                self.send_packet(
                    ep as usize,
                    PACKET_TYPE_READY_REPORT,
                    SUB_PACKET_FLAG_CAT_REPORT,
                    self.endpoints[ep as usize].seq,
                    &report,
                    0,
                );
            }
            EpState::Idle => {
                if msg_op_get(msg) as u64 == OP_STOP_QUEUE {
                    self.rtkit.send_user_msg(ep, msg_op(OP_ACK_STOP_QUEUE));
                    return;
                }
                if msg_op_get(msg) as u64 != OP_RX_SIGNAL {
                    return;
                }
                while let Some((ty, category, seq, payload, _out_len)) =
                    self.recv_packet(ep as usize)
                {
                    let e = &mut self.endpoints[ep as usize];
                    e.rx_packets += 1;
                    e.last_rx = Some((ty, category, seq, payload.clone()));
                    let _ = category;
                    // Reply: GET_PROPERTY → {0, value 0}; COMMAND → {0}.
                    let res: u32 = 0;
                    let mut out = Vec::with_capacity(4 + 4);
                    out.extend_from_slice(&res.to_le_bytes());
                    if ty == PACKET_TYPE_GET_PROPERTY
                        || ty == PACKET_TYPE_COMMAND
                    {
                        out.extend_from_slice(&0u32.to_le_bytes());
                    }
                    self.send_packet(
                        ep as usize,
                        ty,
                        SUB_PACKET_FLAG_CAT_RESPONSE,
                        seq,
                        &out,
                        0,
                    );
                }
            }
        }
    }
}

impl Device for Aop {
    fn name(&self) -> &'static str {
        "aop"
    }

    fn read(&mut self, off: u64, size: u8) -> u64 {
        // Two MMIO regions upstream: rtkit mailbox (reg[1]) + ascv2 (reg[3]).
        if off < self.rtkit.mmio_size {
            // Service the RTKit boot: pump user messages first.
            let msgs = std::mem::take(&mut self.rtkit.user_msgs);
            for (ep, msg) in msgs {
                self.handle_user_msg(ep, msg);
            }
            self.rtkit.read(off, size)
        } else if off < self.rtkit.mmio_size + self.ascv2_len {
            0 // ascv2_core_reg_ops: RAZ
        } else {
            0
        }
    }

    fn write(&mut self, off: u64, size: u8, val: u64) {
        if off < self.rtkit.mmio_size {
            self.rtkit.write(off, size, val);
            if self.rtkit.boot_done && !self.boot_done {
                self.boot_done = true;
                // apple_aop_boot_done: HELLO(8) on every EP.
                let n = self.endpoints.len();
                for i in 0..n {
                    self.rtkit.send_user_msg(i as u8, msg_op(OP_HELLO) | 8);
                    self.endpoints[i].state = EpState::AwaitingHello;
                }
            }
            // pump user messages generated by this write
            let msgs = std::mem::take(&mut self.rtkit.user_msgs);
            for (ep, msg) in msgs {
                self.handle_user_msg(ep, msg);
            }
        }
        // ascv2 region: WI
    }
}

impl Default for Aop {
    fn default() -> Self {
        Self::new()
    }
}

impl Aop {
    pub fn regs_documented() -> &'static [(&'static str, u64)] {
        &[
            ("OP_HELLO", OP_HELLO),
            ("OP_REQUEST_REGION_BYTES", OP_REQUEST_REGION_BYTES),
            ("OP_SET_RX_QUEUE_BY_ADDR", OP_SET_RX_QUEUE_BY_ADDR),
            ("OP_SET_TX_QUEUE_BY_ADDR", OP_SET_TX_QUEUE_BY_ADDR),
            ("OP_TX_SIGNAL", OP_TX_SIGNAL),
            ("OP_ACK_START_QUEUE", OP_ACK_START_QUEUE),
            ("OP_ACK_STOP_QUEUE", OP_ACK_STOP_QUEUE),
            ("OP_ACK_HELLO", OP_ACK_HELLO),
            ("OP_ACK_REQUEST_REGION", OP_ACK_REQUEST_REGION),
            ("OP_RX_SIGNAL", OP_RX_SIGNAL),
            ("OP_START_QUEUE", OP_START_QUEUE),
            ("OP_STOP_QUEUE", OP_STOP_QUEUE),
            ("PACKET_TYPE_GET_PROPERTY", PACKET_TYPE_GET_PROPERTY as u64),
            ("PACKET_TYPE_COMMAND", PACKET_TYPE_COMMAND as u64),
            ("PACKET_TYPE_READY_REPORT", PACKET_TYPE_READY_REPORT as u64),
            ("PACKET_TYPE_MSG_REPORT", PACKET_TYPE_MSG_REPORT as u64),
            ("RB_ENTRY_LEN", RB_ENTRY_LEN as u64),
            ("PACKET_LEN", PACKET_LEN as u64),
            ("SUB_PACKET_LEN", SUB_PACKET_LEN as u64),
            ("READY_REPORT_LEN", READY_REPORT_LEN as u64),
        ]
    }
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtkit::{REG_AP_RECV0, REG_AP_SEND0};

    /// Drive a 16-byte mailbox message through the rtkit block.
    fn mbox_send(aop: &mut Aop, ep: u8, msg: u64) {
        let mut m = [0u8; 16];
        m[0..8].copy_from_slice(&msg.to_le_bytes());
        m[8..12].copy_from_slice(&(ep as u32).to_le_bytes());
        for w in 0..4 {
            let v = u32::from_le_bytes(m[w * 4..w * 4 + 4].try_into().unwrap());
            aop.write(crate::rtkit::REG_AP_SEND0 + w * 4, 4, v as u64);
        }
    }

    fn mbox_recv(aop: &mut Aop) -> Option<(u8, u64)> {
        if matches!(
            aop.read(crate::rtkit::REG_AP_CTRL, 4),
            x if x & CTRL_EMPTY != 0
        ) {
            return None;
        }
        let mut m = [0u8; 16];
        for w in 0..4 {
            let v = aop.read(REG_AP_RECV0 + w * 4, 4) as u32;
            m[w * 4..w * 4 + 4].copy_from_slice(&v.to_le_bytes());
        }
        Some((
            (u32::from_le_bytes(m[8..12].try_into().unwrap())) as u8,
            u64::from_le_bytes(m[0..8].try_into().unwrap()),
        ))
    }

    use crate::rtkit::{CTRL_EMPTY, EP_USER_START, MSG_HELLO_ACK, MSG_TYPE_ROLLCALL, REG_AP_CTRL};

    /// Full RTKit handshake for the AOP.
    fn rtkit_boot(aop: &mut Aop) {
        aop.add_endpoint("aop-test", 1, EpType::App, 0x1000, 0x1000);
        aop.write(crate::rtkit::REG_AP_CTRL, 4, crate::rtkit::CTRL_ENABLE as u64);
        // HELLO
        let (_, m) = mbox_recv(aop).unwrap();
        assert_eq!(crate::rtkit::mgmt_type(m), crate::rtkit::MSG_HELLO);
        mbox_send(
            aop,
            crate::rtkit::EP_MANAGEMENT,
            crate::rtkit::mgmt_msg(MSG_HELLO_ACK, (12u64 << 16) | 3),
        );
        let (_, m) = mbox_recv(aop).unwrap(); // ROLLCALL
        assert_eq!(crate::rtkit::mgmt_type(m), MSG_TYPE_ROLLCALL);
        mbox_send(aop, crate::rtkit::EP_MANAGEMENT, crate::rtkit::mgmt_msg(MSG_TYPE_ROLLCALL, 0));
        assert!(aop.boot_done);
    }

    #[test]
    fn aop_endpoint_full_boot() {
        let mut aop = Aop::new();
        aop.set_dma_window(0x0); // window-relative addressing
        rtkit_boot(&mut aop);

        // boot_done → HELLO(8) on EP 0
        let (ep, m) = mbox_recv(&mut aop).unwrap();
        assert_eq!(ep, EP_USER_START);
        assert_eq!(msg_op_get(m) as u64, OP_HELLO);
        assert_eq!(m & 0xFFFF, 8);

        // AP: ACK_HELLO
        mbox_send(&mut aop, EP_USER_START, msg_op(OP_ACK_HELLO));
        let (_, m) = mbox_recv(&mut aop).unwrap();
        assert_eq!(msg_op_get(m) as u64, OP_REQUEST_REGION_BYTES);
        assert_eq!(m & 0xFFFF, 0x1000); // rx_len

        // AP: ACK_REQUEST_REGION(rx=0x10000)
        mbox_send(&mut aop, EP_USER_START, msg_op(OP_ACK_REQUEST_REGION) | 0x10000);
        let (_, m) = mbox_recv(&mut aop).unwrap(); // SET_RX_QUEUE
        assert_eq!(msg_op_get(m) as u64, OP_SET_RX_QUEUE_BY_ADDR);
        assert_eq!(m & 0xFFFF_FFFF, 0x10000);
        let (_, m) = mbox_recv(&mut aop).unwrap(); // REQUEST_REGION(tx)
        assert_eq!(msg_op_get(m) as u64, OP_REQUEST_REGION_BYTES);
        assert_eq!(m & 0xFFFF, 0x1000);

        // AP: ACK_REQUEST_REGION(tx=0x20000)
        mbox_send(&mut aop, EP_USER_START, msg_op(OP_ACK_REQUEST_REGION) | 0x20000);
        let (_, m) = mbox_recv(&mut aop).unwrap(); // SET_TX_QUEUE
        assert_eq!(msg_op_get(m) as u64, OP_SET_TX_QUEUE_BY_ADDR);
        let (_, m) = mbox_recv(&mut aop).unwrap(); // TX_SIGNAL
        assert_eq!(msg_op_get(m) as u64, OP_TX_SIGNAL);
        assert_eq!(aop.endpoints[0].state, EpState::Idle);

        // RX ring initialised: len - 3*align at 0x10000, wptr/rptr zero
        let mut b = [0u8; 4];
        aop.dma_read(0x10000, &mut b);
        assert_eq!(u32::from_le_bytes(b), 0x1000 - 0x40 * 3);

        // READY_REPORT in the TX ring at 0x20000
        let mut rb = [0u8; 8];
        aop.dma_read(0x20000 + 0xC0, &mut rb);
        let magic = u32::from_be_bytes(rb[0..4].try_into().unwrap());
        assert_eq!(magic, RB_V7_IOP_MAGIC);
        let mut nm = [0u8; 8];
        aop.dma_read(0x20000 + 0xC0 + (16 + 16) as u32, &mut nm);
        assert_eq!(&nm[..8], b"aop-test");
    }
}
