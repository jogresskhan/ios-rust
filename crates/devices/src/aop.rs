//! Apple AOP (Always-On Processor) shim — port of ChefKiss Inferno
//! `hw/misc/apple-silicon/aop.c` (AGPL-3.0, Visual Ehrmanntraut; fork cloned
//! to /home/z/research/inferno). Workspace license: GPL-2.0-or-later.
//!
//! What is faithful (opcodes + endpoint ladder are 1:1 from aop.c):
//!   * IOP→AP opcodes 0x80-0x89/0x8A-0x8C, 0xC3; AP→IOP 0xA0-0xA4, 0xC2;
//!   * endpoint ladder
//!     POWERED_OFF → AWAITING_HELLO → AWAITING_RX_ACK → AWAITING_TX_ACK →
//!     IDLE, driven by ACK_HELLO / ACK_REQUEST_REGION / RX_SIGNAL /
//!     STOP_QUEUE exactly as `apple_aop_ep_handle_message`;
//!   * HELLO carries the protocol version, REQUEST_REGION_BYTES the queue
//!     length, ACK_REQUEST_REGION returns the shared-region offset that the
//!     IOP then publishes via SET_RX/TX_QUEUE_BY_ADDR;
//!   * reaching IDLE emits the READY_REPORT packet type (0xC0).
//!
//! What is a documented shim (the honest part): upstream moves packets
//! through DMA'd ring buffers (`IOP `/`AOP ` magic ring entries, 16-byte
//! packets, 24-byte sub-packets) inside the guest's shared region. Here the
//! rings are a fixed shared window plus an in-model packet queue, and the
//! **doorbell** (`apple_aop`-style accept/ack used by boot ladders that
//! AOP-probe) is modeled explicitly. Enough for XNU/iBoot boot ladders to
//! probe AOP and for the RTKit hello exchange; not a packet-for-packet
//! port of the RB engine yet.

use crate::bus::MMIODevice;
use std::collections::VecDeque;

// IOP -> AP opcodes (aop.c)
pub const OP_HELLO: u8 = 0x80;
pub const OP_REQUEST_REGION_BYTES: u8 = 0x81;
pub const OP_SET_RX_QUEUE_BY_ADDR: u8 = 0x82;
pub const OP_SET_TX_QUEUE_BY_ADDR: u8 = 0x83;
pub const OP_SET_HISTORICAL_QUEUE_BY_ADDR: u8 = 0x84;
pub const OP_TX_SIGNAL: u8 = 0x85;
pub const OP_ACK_START_QUEUE: u8 = 0x86;
pub const OP_ACK_STOP_QUEUE: u8 = 0x87;
pub const OP_REQUEST_REGION_CHUNKS: u8 = 0x89;
pub const OP_SET_RX_QUEUE_BY_REGION_OFFSET: u8 = 0x8A;
pub const OP_SET_TX_QUEUE_BY_REGION_OFFSET: u8 = 0x8B;
pub const OP_SET_HISTORICAL_QUEUE_BY_REGION_OFFSET: u8 = 0x8C;
pub const OP_ACK_HIBERNATE_QUEUE: u8 = 0xC3;

// AP -> IOP opcodes (aop.c)
pub const OP_ACK_HELLO: u8 = 0xA0;
pub const OP_ACK_REQUEST_REGION: u8 = 0xA1;
pub const OP_RX_SIGNAL: u8 = 0xA2;
pub const OP_START_QUEUE: u8 = 0xA3;
pub const OP_STOP_QUEUE: u8 = 0xA4;
pub const OP_HIBERNATE_QUEUE: u8 = 0xC2;

// Packet types (aop.c)
pub const PACKET_TYPE_COMMAND: u16 = 0x20;
pub const PACKET_TYPE_READY_REPORT: u16 = 0xC0;
pub const PACKET_TYPE_MSG_REPORT: u16 = 0xD0;

pub const MSG_OP_SHIFT: u64 = 48;
pub fn msg_op(msg: u64) -> u8 {
    ((msg >> MSG_OP_SHIFT) & 0xFF) as u8
}
pub fn msg_op_arg(op: u8, arg: u64) -> u64 {
    ((op as u64) << MSG_OP_SHIFT) | (arg & 0x0000_FFFF_FFFF_FFFF)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AopEpState {
    PoweredOff,
    AwaitingHello,
    AwaitingRxAck,
    AwaitingTxAck,
    Idle,
}

impl AopEpState {
    pub fn name(&self) -> &'static str {
        match self {
            AopEpState::PoweredOff => "POWERED_OFF",
            AopEpState::AwaitingHello => "AWAITING_HELLO",
            AopEpState::AwaitingRxAck => "AWAITING_RX_ACK",
            AopEpState::AwaitingTxAck => "AWAITING_TX_ACK",
            AopEpState::Idle => "IDLE",
        }
    }
}

pub struct AopEndpoint {
    pub num: u8,
    pub service_name: &'static str,
    pub state: AopEpState,
    pub rx_off: u32,
    pub tx_off: u32,
    pub rx_len: u32,
    pub tx_len: u32,
    pub seq: u16,
    /// packets received from the AP ring (accept side)
    pub rx_packets: VecDeque<Vec<u8>>,
    /// packets the IOP produced toward the AP (report side)
    pub tx_packets: VecDeque<(u16, Vec<u8>)>,
}

/// Shared-memory doorbell: the boot-ladder probe surface. AP raises,
/// AOP accepts, AP observes the ack — Idle → Requested → Accepted → Acked.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum DoorbellState {
    #[default]
    Idle,
    Requested,
    Accepted,
    Acked,
}

#[derive(Debug, Default)]
pub struct Doorbell {
    pub state: DoorbellState,
    pub rings: u64,
    pub accepts: u64,
    pub acks: u64,
    /// payload staged by the AP when ringing (e.g. probe command word)
    pub payload: u64,
}

impl Doorbell {
    pub fn ring(&mut self, payload: u64) {
        self.state = DoorbellState::Requested;
        self.rings += 1;
        self.payload = payload;
    }
    pub fn accept(&mut self) -> bool {
        if self.state == DoorbellState::Requested {
            self.state = DoorbellState::Accepted;
            self.accepts += 1;
            true
        } else {
            false
        }
    }
    pub fn ack(&mut self) -> bool {
        if self.state == DoorbellState::Accepted {
            self.state = DoorbellState::Acked;
            self.acks += 1;
            true
        } else {
            false
        }
    }
    pub fn reset(&mut self) {
        self.state = DoorbellState::Idle;
        self.payload = 0;
    }
}

/// AOP device model.
pub struct AopDevice {
    pub endpoints: Vec<AopEndpoint>,
    /// IOP → AP message outbox (upstream RTKit user-EP messages)
    pub outbox: VecDeque<(u8, u64)>,
    pub doorbell: Doorbell,
    pub booted: bool,
    pub unexpected_msgs: u64,
    pub unknown_reads: u64,
}

pub const AOP_MMIO_SIZE: u64 = 0x10000;
pub const REG_AOP_STAT: u64 = 0x0;
pub const REG_AOP_MAILBOX_SEND: u64 = 0x1000;
pub const REG_AOP_MAILBOX_RECV: u64 = 0x1008;
pub const REG_AOP_DOORBELL: u64 = 0x2000;

const DEFAULT_RX_LEN: u32 = 0x1000;
const DEFAULT_TX_LEN: u32 = 0x1000;

impl Default for AopDevice {
    fn default() -> Self {
        Self::new()
    }
}

impl AopDevice {
    pub fn new() -> Self {
        // Upstream endpoints come from the ADT; the default set here covers
        // the ladder boot ladders actually probe (sensor/mux app endpoints).
        AopDevice {
            endpoints: vec![
                AopEndpoint {
                    num: 0,
                    service_name: "ais",
                    state: AopEpState::PoweredOff,
                    rx_off: 0,
                    tx_off: 0,
                    rx_len: DEFAULT_RX_LEN,
                    tx_len: DEFAULT_TX_LEN,
                    seq: 0,
                    rx_packets: VecDeque::new(),
                    tx_packets: VecDeque::new(),
                },
                AopEndpoint {
                    num: 1,
                    service_name: "mux",
                    state: AopEpState::PoweredOff,
                    rx_off: 0,
                    tx_off: 0,
                    rx_len: DEFAULT_RX_LEN,
                    tx_len: DEFAULT_TX_LEN,
                    seq: 0,
                    rx_packets: VecDeque::new(),
                    tx_packets: VecDeque::new(),
                },
            ],
            outbox: VecDeque::new(),
            doorbell: Doorbell::default(),
            booted: false,
            unexpected_msgs: 0,
            unknown_reads: 0,
        }
    }

    pub fn endpoint(&self, num: u8) -> Option<&AopEndpoint> {
        self.endpoints.iter().find(|e| e.num == num)
    }

    fn endpoint_mut(&mut self, num: u8) -> Option<&mut AopEndpoint> {
        self.endpoints.iter_mut().find(|e| e.num == num)
    }

    /// RTKit boot: every endpoint wakes and starts the ladder with HELLO.
    pub fn boot(&mut self) {
        self.booted = true;
        let eps: Vec<u8> = self.endpoints.iter().map(|e| e.num).collect();
        for ep in eps {
            let ver = 7u64; // RB protocol version carried in HELLO
            if let Some(e) = self.endpoint_mut(ep) {
                e.state = AopEpState::AwaitingHello;
            }
            self.outbox.push_back((ep, msg_op_arg(OP_HELLO, ver)));
        }
    }

    /// AP → IOP message (drives the ladder; mirrors
    /// `apple_aop_ep_handle_message`).
    pub fn ap_send(&mut self, ep: u8, msg: u64) {
        let Some(e) = self.endpoints.iter_mut().find(|e| e.num == ep) else {
            self.unexpected_msgs += 1;
            return;
        };
        match e.state {
            AopEpState::PoweredOff => self.unexpected_msgs += 1,
            AopEpState::AwaitingHello => {
                if msg_op(msg) != OP_ACK_HELLO {
                    self.unexpected_msgs += 1;
                    return;
                }
                e.state = AopEpState::AwaitingRxAck;
                self.outbox.push_back((ep, msg_op_arg(OP_REQUEST_REGION_BYTES, e.rx_len as u64)));
            }
            AopEpState::AwaitingRxAck => {
                if msg_op(msg) != OP_ACK_REQUEST_REGION {
                    self.unexpected_msgs += 1;
                    return;
                }
                e.rx_off = (msg & 0xFFFF_FFFF) as u32;
                e.state = AopEpState::AwaitingTxAck;
                self.outbox.push_back((ep, msg_op_arg(OP_SET_RX_QUEUE_BY_ADDR, e.rx_off as u64)));
                self.outbox.push_back((ep, msg_op_arg(OP_REQUEST_REGION_BYTES, e.tx_len as u64)));
            }
            AopEpState::AwaitingTxAck => {
                if msg_op(msg) != OP_ACK_REQUEST_REGION {
                    self.unexpected_msgs += 1;
                    return;
                }
                e.tx_off = (msg & 0xFFFF_FFFF) as u32;
                e.state = AopEpState::Idle;
                self.outbox.push_back((ep, msg_op_arg(OP_SET_TX_QUEUE_BY_ADDR, e.tx_off as u64)));
                // READY_REPORT toward the AP (packet type 0xC0)
                e.tx_packets.push_back((
                    PACKET_TYPE_READY_REPORT,
                    e.service_name.as_bytes().to_vec(),
                ));
                self.outbox.push_back((ep, msg_op_arg(OP_TX_SIGNAL, 0)));
            }
            AopEpState::Idle => match msg_op(msg) {
                OP_RX_SIGNAL => {
                    // accept one AP packet; the reply is a TX_SIGNAL so the
                    // AP drains our ring (accept/ack shape of the RB engine)
                    let _ = e.rx_packets.pop_front();
                    self.outbox.push_back((ep, msg_op_arg(OP_TX_SIGNAL, 0)));
                }
                OP_START_QUEUE => {
                    self.outbox.push_back((ep, msg_op_arg(OP_ACK_START_QUEUE, 0)));
                }
                OP_STOP_QUEUE => {
                    self.outbox.push_back((ep, msg_op_arg(OP_ACK_STOP_QUEUE, 0)));
                }
                OP_HIBERNATE_QUEUE => {
                    self.outbox.push_back((ep, msg_op_arg(OP_ACK_HIBERNATE_QUEUE, 0)));
                }
                _ => self.unexpected_msgs += 1,
            },
        }
    }

    /// AP drains the IOP outbox.
    pub fn iop_recv(&mut self) -> Option<(u8, u64)> {
        self.outbox.pop_front()
    }

    /// AP pushes a packet into an endpoint's RX ring (DMA stand-in).
    pub fn push_rx_packet(&mut self, ep: u8, payload: &[u8]) -> bool {
        match self.endpoint_mut(ep) {
            Some(e) => {
                e.rx_packets.push_back(payload.to_vec());
                true
            }
            None => false,
        }
    }

    /// AP pops one IOP packet (type, payload).
    pub fn pop_tx_packet(&mut self, ep: u8) -> Option<(u16, Vec<u8>)> {
        self.endpoint_mut(ep)?.tx_packets.pop_front()
    }
}

impl MMIODevice for AopDevice {
    fn name(&self) -> &'static str {
        "apple-aop"
    }
    fn size(&self) -> u64 {
        AOP_MMIO_SIZE
    }

    fn read(&mut self, offset: u64, _width: u32) -> u64 {
        match offset {
            REG_AOP_STAT => (self.booted as u64)
                | ((self.endpoints.iter().all(|e| e.state == AopEpState::Idle) as u64) << 1),
            REG_AOP_MAILBOX_RECV => match self.outbox.front() {
                Some(&(ep, msg)) => ((ep as u64) << 56) | (msg & 0x00FF_FFFF_FFFF_FFFF),
                None => 0,
            },
            REG_AOP_DOORBELL => self.doorbell.state as u64,
            _ => {
                self.unknown_reads += 1;
                0
            }
        }
    }

    fn write(&mut self, offset: u64, value: u64, _width: u32) {
        match offset {
            REG_AOP_MAILBOX_SEND => {
                let ep = ((value >> 56) & 0xFF) as u8;
                self.ap_send(ep, value & 0x00FF_FFFF_FFFF_FFFF);
            }
            REG_AOP_MAILBOX_RECV => {
                let _ = self.outbox.pop_front(); // ack = pop
            }
            REG_AOP_DOORBELL => match value & 0xFF {
                0 => self.doorbell.reset(),
                1 => self.doorbell.ring(value >> 8),
                2 => {
                    self.doorbell.accept();
                }
                3 => {
                    self.doorbell.ack();
                }
                _ => {}
            },
            _ => {}
        }
    }
}

pub const PARITY_PCT: u8 = 40; // reg map + mailbox ladder core; RB packet engine + DMA ring buffers pending

impl crate::bus::Device for AopDevice {
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

    #[test]
    fn doorbell_roundtrip() {
        let mut aop = AopDevice::new();
        assert_eq!(aop.doorbell.state, DoorbellState::Idle);
        aop.doorbell.ring(0xB00B);
        assert_eq!(aop.doorbell.state, DoorbellState::Requested);
        assert_eq!(aop.doorbell.payload, 0xB00B);
        assert!(aop.doorbell.accept());
        assert_eq!(aop.doorbell.state, DoorbellState::Accepted);
        assert!(aop.doorbell.ack());
        assert_eq!(aop.doorbell.state, DoorbellState::Acked);
        assert_eq!((aop.doorbell.rings, aop.doorbell.accepts, aop.doorbell.acks), (1, 1, 1));
        // accept out of order is refused
        assert!(!aop.doorbell.accept());
        aop.doorbell.reset();
        assert_eq!(aop.doorbell.state, DoorbellState::Idle);
    }

    #[test]
    fn boot_ladder_reaches_idle_with_ready_report() {
        let mut aop = AopDevice::new();
        aop.boot();
        assert!(aop.booted);
        // Answer whatever the IOP asks, in order, like the AP driver does.
        loop {
            let Some((ep, msg)) = aop.iop_recv() else { break };
            match msg_op(msg) {
                OP_HELLO => aop.ap_send(ep, msg_op_arg(OP_ACK_HELLO, 0)),
                OP_REQUEST_REGION_BYTES => aop.ap_send(
                    ep,
                    msg_op_arg(OP_ACK_REQUEST_REGION, 0x4000 + (ep as u64) * 0x4000),
                ),
                OP_SET_RX_QUEUE_BY_ADDR
                | OP_SET_TX_QUEUE_BY_ADDR
                | OP_TX_SIGNAL => {}
                op => panic!("unexpected op {op:#x}"),
            }
        }
        // both endpoints now IDLE with a READY_REPORT queued
        for ep in [0u8, 1] {
            assert_eq!(aop.endpoint(ep).unwrap().state, AopEpState::Idle);
            let (ptype, payload) = aop.pop_tx_packet(ep).unwrap();
            assert_eq!(ptype, PACKET_TYPE_READY_REPORT);
            assert!(payload == b"ais" || payload == b"mux");
        }
        // STAT bit1 = all-endpoints-idle
        assert_eq!(aop.read(REG_AOP_STAT, W4) & 0b10, 0b10);
    }

    #[test]
    fn rx_signal_exchanges_tx_signal() {
        let mut aop = AopDevice::new();
        aop.boot();
        let ep = 0u8;
        // fast-forward: answer whatever the IOP asks until all ladders end
        loop {
            let Some((e, msg)) = aop.iop_recv() else { break };
            match msg_op(msg) {
                OP_HELLO => aop.ap_send(e, msg_op_arg(OP_ACK_HELLO, 0)),
                OP_REQUEST_REGION_BYTES => {
                    aop.ap_send(e, msg_op_arg(OP_ACK_REQUEST_REGION, 0x100))
                }
                _ => {}
            }
        }
        assert_eq!(aop.endpoint(ep).unwrap().state, AopEpState::Idle);
        // drain residual signals so the controlled exchange below is exact
        while aop.iop_recv().is_some() {}

        // AP pushes a packet then signals; IOP accepts and replies TX_SIGNAL
        assert!(aop.push_rx_packet(ep, &[1, 2, 3]));
        aop.ap_send(ep, msg_op_arg(OP_RX_SIGNAL, 0));
        let (e, msg) = aop.iop_recv().unwrap();
        assert_eq!((e, msg_op(msg)), (ep, OP_TX_SIGNAL));
        assert!(!aop.outbox.contains(&(ep, msg_op_arg(OP_TX_SIGNAL, 0))));

        // queue stop/start roundtrips
        aop.ap_send(ep, msg_op_arg(OP_STOP_QUEUE, 0));
        assert_eq!(msg_op(aop.iop_recv().unwrap().1), OP_ACK_STOP_QUEUE);
        aop.ap_send(ep, msg_op_arg(OP_START_QUEUE, 0));
        assert_eq!(msg_op(aop.iop_recv().unwrap().1), OP_ACK_START_QUEUE);
    }

    #[test]
    fn unexpected_messages_counted() {
        let mut aop = AopDevice::new();
        // powered-off endpoint: any message is unexpected
        aop.ap_send(0, msg_op_arg(OP_ACK_HELLO, 0));
        assert_eq!(aop.unexpected_msgs, 1);
        // wrong opcode in AWAITING_HELLO
        aop.boot();
        let _ = aop.iop_recv();
        aop.ap_send(0, msg_op_arg(OP_RX_SIGNAL, 0));
        assert_eq!(aop.unexpected_msgs, 2);
        // unknown endpoint
        aop.ap_send(42, msg_op_arg(OP_ACK_HELLO, 0));
        assert_eq!(aop.unexpected_msgs, 3);
    }

    #[test]
    fn mmio_doorbell_and_mailbox() {
        let mut aop = AopDevice::new();
        // doorbell via MMIO: ring(1) / accept(2) / ack(3)
        aop.write(REG_AOP_DOORBELL, 1 | (0x55 << 8), W4);
        assert_eq!(aop.read(REG_AOP_DOORBELL, W4), DoorbellState::Requested as u64);
        aop.write(REG_AOP_DOORBELL, 2, W4);
        assert_eq!(aop.read(REG_AOP_DOORBELL, W4), DoorbellState::Accepted as u64);
        aop.write(REG_AOP_DOORBELL, 3, W4);
        assert_eq!(aop.read(REG_AOP_DOORBELL, W4), DoorbellState::Acked as u64);
        aop.write(REG_AOP_DOORBELL, 0, W4);
        assert_eq!(aop.read(REG_AOP_DOORBELL, W4), DoorbellState::Idle as u64);

        // mailbox: boot → STAT booted; RECV surfaces outbox head
        aop.boot();
        assert_eq!(aop.read(REG_AOP_STAT, W4) & 1, 1);
        let head = aop.read(REG_AOP_MAILBOX_RECV, W4);
        assert_eq!((head >> 56) as u8, 0);
        assert_eq!(msg_op(head & 0x00FF_FFFF_FFFF_FFFF), OP_HELLO);
        // write to RECV pops (ack) → next head is the other endpoint's HELLO
        aop.write(REG_AOP_MAILBOX_RECV, 0, W4);
        assert_eq!(aop.read(REG_AOP_MAILBOX_RECV, W4) >> 56, 1);
        // unknown reg RAZ + counted
        assert_eq!(aop.read(0x9000, W4), 0);
        assert_eq!(aop.unknown_reads, 1);
    }
}
