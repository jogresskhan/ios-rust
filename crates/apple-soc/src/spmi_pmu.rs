//! spmi + spmi-pmu — Apple System Management and Power Interface and the
//! Dialog PMU slave behind it.
//!
//! Faithful Rust port of:
//! * ChefKiss Inferno `hw/spmi/apple_spmi.c` (queue/control/fault
//!   register windows, REQ/RSP FIFO protocol, INT banks; AGPL-3.0,
//!   © 2024-2026 Visual Ehrmanntraut) and `hw/spmi/core.c` (bus),
//! * `hw/misc/apple-silicon/spmi-pmu.c` (the SPMI slave; RTC tick at
//!   32768 Hz kept in the legacy scratchpad, alarm + event IRQ).
//!
//! The QEMU SPMI bus becomes an attached-slave table
//! ([`Spmi::attach`]) with the [`SpmiSlave`] trait mirroring
//! `SPMISlaveClass::command/send/recv/finish`. Slave IRQ lines map to
//! the controller's `qdev_init_gpio_in(apple_spmi_set_irq)` inputs via
//! [`SpmiSlave::irq_line`] / [`SpmiSlave::irq_level`], and slave timers
//! run from [`Spmi::tick`] — the same graph QEMU wires with gpios.
//!
//! Window layout inside the 0x4000 container (exactly the C):
//! control @ 0x000 (0x100), queue @ 0x700 (0x100),
//! fault @ 0xD00 (0x100), fault-counter @ 0xE00 (0x64).

use std::collections::VecDeque;

use vm_core::Device;

pub const APPLE_SPMI_MMIO_SIZE: u64 = 0x4000;

pub const SPMI_CONTROL_REGS_START: u64 = 0x000;
pub const SPMI_QUEUE_REGS_START: u64 = 0x700;
pub const SPMI_FAULT_REGS_START: u64 = 0xD00;
pub const SPMI_FAULT_COUNTER_REGS_START: u64 = 0xE00;
const WINDOW_SIZE: usize = 0x100;

// SPMI command opcodes (include/hw/spmi/spmi.h).
pub const SPMI_CMD_EXT_WRITE: u8 = 0x00;
pub const SPMI_CMD_RESET: u8 = 0x10;
pub const SPMI_CMD_SLEEP: u8 = 0x11;
pub const SPMI_CMD_SHUTDOWN: u8 = 0x12;
pub const SPMI_CMD_WAKEUP: u8 = 0x13;
pub const SPMI_CMD_AUTHENTICATE: u8 = 0x14;
pub const SPMI_CMD_MSTR_READ: u8 = 0x15;
pub const SPMI_CMD_MSTR_WRITE: u8 = 0x16;
pub const SPMI_CMD_TRANSFER_BUS_OWNERSHIP: u8 = 0x1A;
pub const SPMI_CMD_DDB_MASTER_READ: u8 = 0x1B;
pub const SPMI_CMD_DDB_SLAVE_READ: u8 = 0x1C;
pub const SPMI_CMD_EXT_READ: u8 = 0x20;
pub const SPMI_CMD_EXT_WRITEL: u8 = 0x30;
pub const SPMI_CMD_EXT_READL: u8 = 0x38;
pub const SPMI_CMD_WRITE: u8 = 0x40;
pub const SPMI_CMD_READ: u8 = 0x60;
pub const SPMI_CMD_ZERO_WRITE: u8 = 0x80;

// Queue-window registers (relative to SPMI_QUEUE_REGS_START).
pub const SPMI_QUEUE_STATUS: u64 = 0x0;
pub const SPMI_REQ_QUEUE_PUSH: u64 = 0x4;
pub const SPMI_RSP_QUEUE_POP: u64 = 0x8;
pub const SPMI_INT_ENAB: u64 = 0x20; // + b*4
pub const SPMI_INT_STATUS_V0: u64 = 0x40; // + b*4
pub const SPMI_INT_STATUS_V1: u64 = 0x60; // + b*4

// Control-window registers.
pub const SPMI_CONTROL_QUEUE_RESET: u64 = 0x14;
pub const SPMI_CONTROL_QUEUE_RESET_REQ: u32 = 1 << 0;
pub const SPMI_CONTROL_QUEUE_RESET_RSP: u32 = 1 << 1;

// Queue status bits.
pub const SPMI_QUEUE_STATUS_REQ_EMPTY: u32 = 1 << 8;
pub const SPMI_QUEUE_STATUS_RSP_EMPTY: u32 = 1 << 24;

// REQ queue word fields.
pub const SPMI_REQ_SID_SHIFT: u32 = 8;
pub const SPMI_REQ_ADDR_SHIFT: u32 = 16;
pub const SPMI_REQ_FINAL: u32 = 1 << 15;

pub const SPMI_NUM_IRQ_BANK: usize = 9;
pub const SPMI_NUM_IRQ: usize = SPMI_NUM_IRQ_BANK * 32;
const SPMI_QUEUE_DEPTH: usize = 0x100;

// Fault codes (SPMI_FAULT_* in apple_spmi.c) — documented for the
// census; the model never injects them itself.
pub const SPMI_FAULT_UNMAPPED_WRITE: u8 = 0x00;
pub const SPMI_FAULT_UNSUPPORTED_READ: u8 = 0x04;
pub const SPMI_FAULT_NO_RESPONSE: u8 = 0x08;
pub const SPMI_FAULT_UNRECOGNIZED_CMD: u8 = 0x20;

/// SPMI bus slave (`SPMISlaveClass` + the gpio/timer wiring QEMU does
/// at the machine level).
pub trait SpmiSlave: Send {
    /// Command frame; return false to NAK the operation.
    fn command(&mut self, opcode: u8, addr: u16) -> bool;
    /// Master → slave; returns the number of bytes accepted.
    fn send(&mut self, data: &[u8]) -> usize;
    /// Slave → master; returns the number of bytes provided.
    fn recv(&mut self, data: &mut [u8]) -> usize;
    /// End of transfer.
    fn finish(&mut self) {}
    /// Periodic callback (PMU RTC/alarm). Default: no-op.
    fn tick(&mut self, _now_ns: u64) {}
    /// IRQ output level (PMU alarm/event). Default: low.
    fn irq_level(&self) -> bool {
        false
    }
    /// Which controller input (`apple_spmi_set_irq` line) this slave
    /// drives. `None` = not wired. Default: not wired.
    fn irq_line(&self) -> Option<usize> {
        None
    }
}

#[derive(Debug)]
struct SlaveSlot {
    sid: u8,
    slave: Box<dyn SpmiSlave>,
}

/// Apple SPMI controller (T8030 `spmi` node, reg-vers 1).
#[derive(Debug)]
pub struct Spmi {
    pub reg_vers: u32,
    control_reg: [u32; WINDOW_SIZE / 4],
    queue_reg: [u32; WINDOW_SIZE / 4],
    fault_reg: [u32; WINDOW_SIZE / 4],
    fault_counter_reg: [u32; 0x64 / 4],
    resp_fifo: VecDeque<u32>,
    slaves: Vec<SlaveSlot>,
    current_slave: Option<usize>,
    /// Pending EXT_WRITE payload words (`s->data`).
    data: Option<Vec<u32>>,
    data_filled: usize,
    command: u32,
    pub irq_level: bool,
    pub unmapped_writes: u64,
    pub unknown_reads: u64,
    pub unknown_writes: u64,
}

fn spmi_opcode(spmi_request: u32) -> u32 {
    match (spmi_request >> 4) & 0xf {
        1 => spmi_request & 0xff,
        _ => spmi_request & 0xf8,
    }
}

fn spmi_data_length(spmi_request: u32) -> u32 {
    match (spmi_request >> 4) & 0xf {
        1 => 0,
        _ => (spmi_request & 0x7) + 1,
    }
}

fn spmi_address(spmi_request: u32) -> u16 {
    match spmi_opcode(spmi_request) {
        SPMI_CMD_EXT_WRITE | SPMI_CMD_EXT_READ | SPMI_CMD_EXT_WRITEL
        | SPMI_CMD_EXT_READL => ((spmi_request >> SPMI_REQ_ADDR_SHIFT) & 0xffff) as u16,
        _ => ((spmi_request >> SPMI_REQ_ADDR_SHIFT) & 0xff) as u16,
    }
}

fn spmi_sid(value: u32) -> u8 {
    ((value >> SPMI_REQ_SID_SHIFT) & 0xf) as u8
}

impl Spmi {
    pub fn new() -> Self {
        Spmi {
            reg_vers: 1,
            control_reg: [0; WINDOW_SIZE / 4],
            queue_reg: [0; WINDOW_SIZE / 4],
            fault_reg: [0; WINDOW_SIZE / 4],
            fault_counter_reg: [0; 0x64 / 4],
            resp_fifo: VecDeque::with_capacity(SPMI_QUEUE_DEPTH),
            slaves: Vec::new(),
            current_slave: None,
            data: None,
            data_filled: 0,
            command: 0,
            irq_level: false,
            unmapped_writes: 0,
            unknown_reads: 0,
            unknown_writes: 0,
        }
    }

    /// `spmi_set_slave_sid` + bus attach in one step.
    pub fn attach(&mut self, sid: u8, slave: Box<dyn SpmiSlave>) {
        self.slaves.push(SlaveSlot { sid, slave });
    }

    fn find_slave(&self, sid: u8) -> Option<usize> {
        self.slaves.iter().position(|s| s.sid == sid)
    }

    /// `spmi_start_transfer`: bus scan + command frame. Returns false on
    /// NAK / missing slave.
    fn start_transfer(&mut self, sid: u8, opcode: u8, address: u16) -> bool {
        if self.current_slave.is_none() {
            self.current_slave = self.find_slave(sid);
        }
        match self.current_slave {
            Some(i) => self.slaves[i].slave.command(opcode, address),
            None => false,
        }
    }

    fn end_transfer(&mut self) {
        if let Some(i) = self.current_slave.take() {
            self.slaves[i].slave.finish();
        }
    }

    /// GPIO input from slave IRQ lines (`apple_spmi_set_irq`).
    pub fn ext_irq_set(&mut self, irq: usize, level: bool) {
        if irq >= SPMI_NUM_IRQ {
            return;
        }
        let bank = irq >> 5;
        let status_off = (match self.reg_vers {
            0 => SPMI_INT_STATUS_V0,
            _ => SPMI_INT_STATUS_V1,
        } / 4) as usize
            + bank;
        if level {
            self.queue_reg[status_off] |= 1 << (irq & 31);
        } else {
            self.queue_reg[status_off] &= !(1 << (irq & 31));
        }
        self.update_irq();
    }

    /// `apple_spmi_update_irq`.
    fn update_irq(&mut self) {
        let mut level = false;
        for bank in 0..SPMI_NUM_IRQ_BANK {
            let status_off = (match self.reg_vers {
                0 => SPMI_INT_STATUS_V0,
                _ => SPMI_INT_STATUS_V1,
            } / 4) as usize
                + bank;
            let enab_off = (SPMI_INT_ENAB / 4) as usize + bank;
            if self.queue_reg[status_off] & self.queue_reg[enab_off] != 0 {
                level = true;
                break;
            }
        }
        self.irq_level = level;
    }

    /// The C's dedicated response-queue IRQ (`SPMI_RESP_IRQ`).
    pub fn resp_pending(&self) -> bool {
        !self.resp_fifo.is_empty()
    }

    /// Handle one write to SPMI_REQ_QUEUE_PUSH.
    fn req_queue_push(&mut self, value: u32) {
        if self.data.is_none() {
            let sid = spmi_sid(value);
            let opc = spmi_opcode(value) as u8;
            let addr2 = spmi_address(value);
            let parity = value & SPMI_REQ_FINAL == 0;
            let len = spmi_data_length(value);

            self.command = value;

            if opc == SPMI_CMD_EXT_WRITE || opc == SPMI_CMD_EXT_WRITEL {
                let data_length = ((len + 3) / 4) as usize;
                self.data = Some(vec![0; data_length]);
                self.data_filled = 0;
            }
            if !self.start_transfer(sid, opc, addr2) {
                // C: `return;` — push word not stored, no IRQ update.
                self.data = None;
                self.unmapped_writes += 1;
                return;
            }
            if self.data.is_none() && len > 0 {
                // EXT_READ path.
                let mut data2 = vec![0u8; (len + 3) as usize];
                let count = self.slave_recv(&mut data2[..len as usize]);
                let ack: u32 = if count > 0 {
                    (!0u32.wrapping_shl(count as u32)) & 0xFF
                } else {
                    0
                };
                let value = (value & 0xFFF) | (ack << 16);
                self.resp_fifo.push_back(value);
                for i in 0..((len + 3) / 4) as usize {
                    let mut w: u32 = 0;
                    for b in 0..4 {
                        w |= (data2[i * 4 + b] as u32) << (8 * b);
                    }
                    self.resp_fifo.push_back(w);
                }
            }
            if self.data.is_none() && !parity {
                self.end_transfer();
            }
        } else {
            if let Some(data) = self.data.as_mut() {
                if self.data_filled < data.len() {
                    data[self.data_filled] = value;
                }
            }
            self.data_filled += 1;
            let data_length = self.data.as_ref().map_or(0, |d| d.len());
            if self.data_filled >= data_length {
                let requested_len = spmi_data_length(self.command) as usize;
                let bytes = self
                    .data
                    .take()
                    .map(|words| {
                        words
                            .iter()
                            .flat_map(|w| w.to_le_bytes())
                            .collect::<Vec<u8>>()
                    })
                    .unwrap_or_default();
                let count = self.slave_send(&bytes[..requested_len.min(bytes.len())]);
                self.resp_fifo.push_back(
                    (self.command & 0xFFF) | (((count == requested_len) as u32) << 15),
                );
                self.data_filled = 0;
                if self.command & SPMI_REQ_FINAL != 0 {
                    self.end_transfer();
                }
            }
        }
    }

    fn slave_send(&mut self, data: &[u8]) -> usize {
        match self.current_slave {
            Some(i) => self.slaves[i].slave.send(data),
            None => 0,
        }
    }

    fn slave_recv(&mut self, data: &mut [u8]) -> usize {
        match self.current_slave {
            Some(i) => self.slaves[i].slave.recv(data),
            None => 0,
        }
    }

    fn queue_reg_write(&mut self, addr: u64, value: u32) {
        match addr {
            SPMI_REQ_QUEUE_PUSH => {
                self.req_queue_push(value);
                return; // the push word itself is never stored (C)
            }
            a if (SPMI_INT_ENAB..SPMI_INT_ENAB + 4 * SPMI_NUM_IRQ_BANK as u64)
                .contains(&a) =>
            {
                let b = ((a - SPMI_INT_ENAB) / 4) as usize;
                self.queue_reg[(SPMI_INT_ENAB / 4) as usize + b] = value;
                self.update_irq();
                return;
            }
            a if (SPMI_INT_STATUS_V1
                ..SPMI_INT_STATUS_V1 + 4 * SPMI_NUM_IRQ_BANK as u64)
                .contains(&a) =>
            {
                // W1C (reg-vers 1 view; v0 overlaps STS/ENAB upstream).
                let b = ((a - SPMI_INT_STATUS_V1) / 4) as usize;
                let off = (SPMI_INT_STATUS_V1 / 4) as usize + b;
                self.queue_reg[off] &= !value;
                self.update_irq();
                return;
            }
            _ => {}
        }
        if (addr as usize) < self.queue_reg.len() * 4 {
            self.queue_reg[(addr >> 2) as usize] = value;
        } else {
            self.unknown_writes += 1;
        }
    }

    fn queue_reg_read(&mut self, addr: u64) -> u32 {
        match addr {
            SPMI_RSP_QUEUE_POP => {
                let value = self.resp_fifo.pop_front().unwrap_or(0);
                self.update_irq();
                return value;
            }
            SPMI_QUEUE_STATUS => {
                let mut value = self.queue_reg[(addr >> 2) as usize];
                value &= !(SPMI_QUEUE_STATUS_REQ_EMPTY | SPMI_QUEUE_STATUS_RSP_EMPTY);
                value |= SPMI_QUEUE_STATUS_REQ_EMPTY;
                if self.resp_fifo.is_empty() {
                    value |= SPMI_QUEUE_STATUS_RSP_EMPTY;
                }
                return value;
            }
            _ => {}
        }
        if (addr as usize) < self.queue_reg.len() * 4 {
            self.queue_reg[(addr >> 2) as usize]
        } else {
            self.unknown_reads += 1;
            0
        }
    }

    fn control_reg_write(&mut self, addr: u64, mut value: u32) {
        if addr == SPMI_CONTROL_QUEUE_RESET {
            if value & SPMI_CONTROL_QUEUE_RESET_RSP != 0 {
                self.resp_fifo.clear();
                value &= !SPMI_CONTROL_QUEUE_RESET_RSP;
            }
            value &= !SPMI_CONTROL_QUEUE_RESET_REQ;
        }
        if (addr as usize) < self.control_reg.len() * 4 {
            self.control_reg[(addr >> 2) as usize] = value;
        } else {
            self.unknown_writes += 1;
        }
    }
}

impl Default for Spmi {
    fn default() -> Self {
        Self::new()
    }
}

impl Device for Spmi {
    fn name(&self) -> &'static str {
        "spmi"
    }

    fn read(&mut self, off: u64, _size: u8) -> u64 {
        if (SPMI_QUEUE_REGS_START..SPMI_FAULT_REGS_START).contains(&off) {
            return self.queue_reg_read(off - SPMI_QUEUE_REGS_START) as u64;
        }
        if (SPMI_FAULT_REGS_START..SPMI_FAULT_COUNTER_REGS_START).contains(&off) {
            let addr = off - SPMI_FAULT_REGS_START;
            if addr == SPMI_QUEUE_STATUS {
                // Fault window's own QUEUE_STATUS view: both queues empty.
                let mut value = self.fault_reg[(addr >> 2) as usize];
                value &= !(SPMI_QUEUE_STATUS_REQ_EMPTY | SPMI_QUEUE_STATUS_RSP_EMPTY);
                value |= SPMI_QUEUE_STATUS_REQ_EMPTY | SPMI_QUEUE_STATUS_RSP_EMPTY;
                return value as u64;
            }
            return self.fault_reg[(addr >> 2) as usize] as u64;
        }
        if (SPMI_FAULT_COUNTER_REGS_START..SPMI_FAULT_COUNTER_REGS_START + 0x64)
            .contains(&off)
        {
            return self.fault_counter_reg
                [((off - SPMI_FAULT_COUNTER_REGS_START) >> 2) as usize]
                as u64;
        }
        if (SPMI_CONTROL_REGS_START..SPMI_QUEUE_REGS_START).contains(&off) {
            return self.control_reg[(off >> 2) as usize] as u64;
        }
        self.unknown_reads += 1;
        0
    }

    fn write(&mut self, off: u64, _size: u8, val: u64) {
        if (SPMI_QUEUE_REGS_START..SPMI_FAULT_REGS_START).contains(&off) {
            self.queue_reg_write(off - SPMI_QUEUE_REGS_START, val as u32);
            return;
        }
        if (SPMI_FAULT_REGS_START..SPMI_FAULT_COUNTER_REGS_START).contains(&off) {
            let addr = (off - SPMI_FAULT_REGS_START) as usize;
            if addr < self.fault_reg.len() * 4 {
                self.fault_reg[addr >> 2] = val as u32;
            }
            return;
        }
        if (SPMI_FAULT_COUNTER_REGS_START..SPMI_FAULT_COUNTER_REGS_START + 0x64)
            .contains(&off)
        {
            let i = ((off - SPMI_FAULT_COUNTER_REGS_START) >> 2) as usize;
            if i < self.fault_counter_reg.len() {
                self.fault_counter_reg[i] = val as u32;
            }
            return;
        }
        if (SPMI_CONTROL_REGS_START..SPMI_QUEUE_REGS_START).contains(&off) {
            self.control_reg_write(off - SPMI_CONTROL_REGS_START, val as u32);
            return;
        }
        self.unknown_writes += 1;
    }

    fn tick(&mut self, now_ns: u64) {
        // Slave timers first (PMU alarm), then fold their IRQ lines into
        // the status banks (the gpio graph QEMU wires at machine level).
        let mut lines: Vec<(usize, bool)> = Vec::new();
        for s in &mut self.slaves {
            s.slave.tick(now_ns);
            if let Some(line) = s.slave.irq_line() {
                lines.push((line, s.slave.irq_level()));
            }
        }
        for (line, level) in lines {
            self.ext_irq_set(line, level);
        }
    }
}

pub fn regs_documented() -> &'static [(&'static str, u64)] {
    &[
        ("SPMI_QUEUE_STATUS", SPMI_QUEUE_REGS_START + SPMI_QUEUE_STATUS),
        ("SPMI_REQ_QUEUE_PUSH", SPMI_QUEUE_REGS_START + SPMI_REQ_QUEUE_PUSH),
        ("SPMI_RSP_QUEUE_POP", SPMI_QUEUE_REGS_START + SPMI_RSP_QUEUE_POP),
        ("SPMI_INT_ENAB(b)", SPMI_QUEUE_REGS_START + SPMI_INT_ENAB),
        ("SPMI_INT_STATUS_V0(b)", SPMI_QUEUE_REGS_START + SPMI_INT_STATUS_V0),
        ("SPMI_INT_STATUS_V1(b)", SPMI_QUEUE_REGS_START + SPMI_INT_STATUS_V1),
        ("SPMI_CONTROL_QUEUE_RESET", SPMI_CONTROL_QUEUE_RESET),
        ("SPMI_FAULT_REGS_START", SPMI_FAULT_REGS_START),
        ("SPMI_FAULT_COUNTER_REGS_START", SPMI_FAULT_COUNTER_REGS_START),
    ]
}

// ---------------------------------------------------------------------------
// PMU slave (hw/misc/apple-silicon/spmi-pmu.c)
// ---------------------------------------------------------------------------

pub const RTC_TICK_FREQ: u64 = 32768;

// REG_FIELD bits of the C's RTC registers.
pub const R_RTC_CONTROL_ALARM_EN: u8 = 1 << 6;
pub const R_RTC_EVENT_ALARM: u8 = 1 << 0;

/// Dialog PMU (T8030 `pmu` node) attached to the SPMI bus. The whole
/// 64 KiB register file is the device; ADC channels etc. are plain
/// registers the host can pre-seed via [`SpmiPmu::set_reg`] (the C
/// reads them from the IPSW's DT too).
#[derive(Debug)]
pub struct SpmiPmu {
    pub sid: u8,
    reg: Vec<u8>,
    addr: u16,
    // info-* DT offsets (machine-provided in the C).
    pub reg_rtc: u16,
    pub reg_alarm: u16,
    pub reg_alarm_ctrl: u16,
    pub reg_alarm_event: u16,
    pub reg_rtc_irq_mask: u16,
    pub reg_leg_scrpad: u16,
    /// PMU IRQ line (gpio out in the C).
    pub irq_level: bool,
    /// rtc_clock captured by [`SpmiSlave::tick`].
    now_ns: u64,
    alarm_deadline: Option<u64>,
}

impl SpmiPmu {
    /// Offsets come from the pmu node's `info-*` properties.
    pub fn new(
        sid: u8,
        reg_rtc: u16,
        reg_alarm: u16,
        reg_alarm_ctrl: u16,
        reg_alarm_event: u16,
        reg_rtc_irq_mask: u16,
        reg_leg_scrpad: u16,
    ) -> Self {
        let mut pmu = SpmiPmu {
            sid,
            reg: vec![0; 0x10000],
            addr: 0,
            reg_rtc,
            reg_alarm,
            reg_alarm_ctrl,
            reg_alarm_event,
            reg_rtc_irq_mask,
            reg_leg_scrpad,
            irq_level: false,
            now_ns: 0,
            alarm_deadline: None,
        };
        pmu.set_tick_offset(pmu.rtc_get_current_tick());
        pmu
    }

    /// Host-side register seeding (ADC channels, GPIO state, ...).
    pub fn set_reg(&mut self, addr: u16, val: u8) {
        self.reg[addr as usize] = val;
    }

    pub fn get_reg(&self, addr: u16) -> u8 {
        self.reg[addr as usize]
    }

    fn get_tick_offset(&self) -> u64 {
        let secs_reg = (self.reg_leg_scrpad + 4) as usize;
        let ticks_reg = (self.reg_leg_scrpad + 21) as usize;
        let mut tick_offset: u64 = 0;
        tick_offset |= (self.reg[secs_reg + 3] as u64) << 39;
        tick_offset |= (self.reg[secs_reg + 2] as u64) << 31;
        tick_offset |= (self.reg[secs_reg + 1] as u64) << 23;
        tick_offset |= (self.reg[secs_reg + 0] as u64) << 15;
        tick_offset |= ((self.reg[ticks_reg + 1] as u64) & 0x7F) << 8;
        tick_offset |= self.reg[ticks_reg + 0] as u64;
        tick_offset
    }

    fn set_tick_offset(&mut self, tick_offset: u64) {
        let secs_reg = (self.reg_leg_scrpad + 4) as usize;
        let ticks_reg = (self.reg_leg_scrpad + 21) as usize;
        self.reg[secs_reg + 3] = ((tick_offset >> 39) & 0xFF) as u8;
        self.reg[secs_reg + 2] = ((tick_offset >> 31) & 0xFF) as u8;
        self.reg[secs_reg + 1] = ((tick_offset >> 23) & 0xFF) as u8;
        self.reg[secs_reg + 0] = ((tick_offset >> 15) & 0xFF) as u8;
        self.reg[ticks_reg + 1] = ((tick_offset >> 8) & 0x7F) as u8;
        self.reg[ticks_reg + 0] = (tick_offset & 0xFF) as u8;
    }

    fn rtc_ns_to_tick(&self, now: u64) -> u64 {
        let secs = now / 1_000_000_000;
        let frac_ns = now % 1_000_000_000;
        let frac_ticks = (frac_ns * RTC_TICK_FREQ + 500_000_000) / 1_000_000_000;
        let ticks = (secs << 15) | (frac_ticks & 0x7FFF);
        ticks.wrapping_sub(self.get_tick_offset())
    }

    fn rtc_get_current_tick(&self) -> u64 {
        self.rtc_ns_to_tick(self.now_ns)
    }

    fn update_irq(&mut self) {
        self.irq_level = self.reg[self.reg_rtc_irq_mask as usize]
            & self.reg[self.reg_alarm_event as usize]
            != 0;
    }

    /// `apple_spmi_pmu_set_alarm`.
    fn set_alarm(&mut self) {
        let now = self.now_ns;
        let alarm = u32::from_le_bytes([
            self.reg[self.reg_alarm as usize],
            self.reg[self.reg_alarm as usize + 1],
            self.reg[self.reg_alarm as usize + 2],
            self.reg[self.reg_alarm as usize + 3],
        ]);
        let seconds = (alarm as i64).wrapping_sub((self.rtc_ns_to_tick(now) >> 15) as i64);

        if self.reg[self.reg_alarm_ctrl as usize] & R_RTC_CONTROL_ALARM_EN != 0 {
            if seconds <= 0 {
                self.alarm_deadline = None;
                self.alarm_fire();
            } else {
                self.alarm_deadline = Some(now + seconds as u64 * 1_000_000_000);
            }
        } else {
            self.alarm_deadline = None;
        }
    }

    fn alarm_fire(&mut self) {
        self.reg[self.reg_alarm_event as usize] |= R_RTC_EVENT_ALARM;
        self.update_irq();
    }

    /// Refresh the 6-byte RTC register run (47-bit tick, shifted left 1).
    fn refresh_rtc(&mut self) {
        let now = self.rtc_get_current_tick();
        self.reg[self.reg_rtc as usize] = ((now << 1) & 0xFF) as u8;
        self.reg[self.reg_rtc as usize + 1] = ((now >> 7) & 0xFF) as u8;
        self.reg[self.reg_rtc as usize + 2] = ((now >> 15) & 0xFF) as u8;
        self.reg[self.reg_rtc as usize + 3] = ((now >> 23) & 0xFF) as u8;
        self.reg[self.reg_rtc as usize + 4] = ((now >> 31) & 0xFF) as u8;
        self.reg[self.reg_rtc as usize + 5] = ((now >> 39) & 0xFF) as u8;
    }
}

impl SpmiSlave for SpmiPmu {
    fn command(&mut self, opcode: u8, addr: u16) -> bool {
        self.addr = addr;
        matches!(
            opcode,
            SPMI_CMD_EXT_READ
                | SPMI_CMD_EXT_READL
                | SPMI_CMD_EXT_WRITE
                | SPMI_CMD_EXT_WRITEL
        )
    }

    fn send(&mut self, data: &[u8]) -> usize {
        let mut addr = self.addr;
        for &b in data {
            self.reg[addr as usize] = b;
            if addr == self.reg_alarm_ctrl
                || (self.reg_alarm..self.reg_alarm + 4).contains(&addr)
            {
                self.set_alarm();
            }
            addr = addr.wrapping_add(1);
        }
        self.addr = addr;
        data.len()
    }

    fn recv(&mut self, data: &mut [u8]) -> usize {
        let start = self.addr;
        let end_addr = self.addr.wrapping_add(data.len() as u16);
        if end_addr > self.reg_rtc && start < self.reg_rtc + 6 {
            self.refresh_rtc();
        }
        let mut addr = start;
        for b in data.iter_mut() {
            *b = self.reg[addr as usize];
            addr = addr.wrapping_add(1);
        }
        self.addr = addr;
        data.len()
    }

    fn tick(&mut self, now_ns: u64) {
        self.now_ns = now_ns;
        if let Some(deadline) = self.alarm_deadline {
            if now_ns >= deadline {
                self.alarm_deadline = None;
                self.alarm_fire();
            }
        }
    }

    fn irq_level(&self) -> bool {
        self.irq_level
    }

    /// First free PMU input line on the controller (machine's choice in
    /// the C; 0 keeps the test + default wiring deterministic).
    fn irq_line(&self) -> Option<usize> {
        Some(0)
    }
}

/// The `ios-rust verify` parity walk for the PMU half.
pub fn pmu_regs_documented() -> &'static [(&'static str, u64)] {
    &[
        ("RTC_CONTROL.ALARM_EN bit", R_RTC_CONTROL_ALARM_EN as u64),
        ("RTC_EVENT.ALARM bit", R_RTC_EVENT_ALARM as u64),
        ("LEG_SCRPAD_OFFSET_SECS", 4),
        ("LEG_SCRPAD_OFFSET_TICKS", 21),
        ("RTC_TICK_FREQ (Hz)", RTC_TICK_FREQ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal echo slave for bus tests.
    struct EchoSlave {
        regs: [u8; 256],
        addr: u16,
    }
    impl EchoSlave {
        fn new() -> Self {
            EchoSlave {
                regs: [0; 256],
                addr: 0,
            }
        }
    }
    impl SpmiSlave for EchoSlave {
        fn command(&mut self, opcode: u8, addr: u16) -> bool {
            self.addr = addr & 0xFF;
            matches!(opcode, SPMI_CMD_EXT_READ | SPMI_CMD_EXT_WRITE)
        }
        fn send(&mut self, data: &[u8]) -> usize {
            for &b in data {
                self.regs[self.addr as usize] = b;
                self.addr = (self.addr + 1) & 0xFF;
            }
            data.len()
        }
        fn recv(&mut self, data: &mut [u8]) -> usize {
            for b in data.iter_mut() {
                *b = self.regs[self.addr as usize];
                self.addr = (self.addr + 1) & 0xFF;
            }
            data.len()
        }
    }

    fn push_ext_read(spmi: &mut Spmi, sid: u8, addr: u16, len: u32) {
        let req = (addr as u32) << SPMI_REQ_ADDR_SHIFT
            | (sid as u32) << SPMI_REQ_SID_SHIFT
            | (SPMI_CMD_EXT_READ as u32)
            | (len - 1)
            | SPMI_REQ_FINAL;
        spmi.write(SPMI_QUEUE_REGS_START + SPMI_REQ_QUEUE_PUSH, 4, req as u64);
    }

    fn push_ext_write(spmi: &mut Spmi, sid: u8, addr: u16, data: &[u8]) {
        let len = data.len() as u32;
        let req = (addr as u32) << SPMI_REQ_ADDR_SHIFT
            | (sid as u32) << SPMI_REQ_SID_SHIFT
            | (SPMI_CMD_EXT_WRITE as u32)
            | (len - 1)
            | SPMI_REQ_FINAL;
        spmi.write(SPMI_QUEUE_REGS_START + SPMI_REQ_QUEUE_PUSH, 4, req as u64);
        for chunk in data.chunks(4) {
            let mut w: u32 = 0;
            for (i, &b) in chunk.iter().enumerate() {
                w |= (b as u32) << (8 * i);
            }
            spmi.write(SPMI_QUEUE_REGS_START + SPMI_REQ_QUEUE_PUSH, 4, w as u64);
        }
    }

    fn pop_resp(spmi: &mut Spmi) -> u32 {
        spmi.read(SPMI_QUEUE_REGS_START + SPMI_RSP_QUEUE_POP, 4) as u32
    }

    #[test]
    fn ext_read_roundtrip() {
        let mut spmi = Spmi::new();
        let mut echo = Box::new(EchoSlave::new());
        echo.regs[0x10] = 0xAB;
        echo.regs[0x11] = 0xCD;
        spmi.attach(2, echo);

        push_ext_read(&mut spmi, 2, 0x10, 2);
        assert!(spmi.resp_pending());
        let status = pop_resp(&mut spmi);
        assert_eq!(status & 0xFFF, SPMI_CMD_EXT_READ as u32);
        assert_eq!((status >> 16) & 0xFF, 0x3, "two ack bits for two bytes");
        let data = pop_resp(&mut spmi);
        assert_eq!(data, 0xCDAB);
        assert!(!spmi.resp_pending());
    }

    #[test]
    fn ext_write_roundtrip_and_missing_sid_nak() {
        let mut spmi = Spmi::new();
        spmi.attach(5, Box::new(EchoSlave::new()));
        push_ext_write(&mut spmi, 5, 0x20, &[0x11, 0x22]);
        let status = pop_resp(&mut spmi);
        assert_eq!(status >> 15 & 1, 1, "full write accepted");
        push_ext_read(&mut spmi, 5, 0x20, 2);
        let _ = pop_resp(&mut spmi);
        let data = pop_resp(&mut spmi);
        assert_eq!(data, 0x2211);

        // Unknown SID → early return, no response (the C's bare `return`).
        push_ext_read(&mut spmi, 9, 0x00, 1);
        assert!(!spmi.resp_pending());
        assert_eq!(spmi.unmapped_writes, 1);
    }

    #[test]
    fn queue_status_and_irq_banks() {
        let mut spmi = Spmi::new();
        let st = spmi.read(SPMI_QUEUE_REGS_START + SPMI_QUEUE_STATUS, 4) as u32;
        assert_eq!(st & SPMI_QUEUE_STATUS_REQ_EMPTY, SPMI_QUEUE_STATUS_REQ_EMPTY);
        assert_eq!(st & SPMI_QUEUE_STATUS_RSP_EMPTY, SPMI_QUEUE_STATUS_RSP_EMPTY);
        spmi.ext_irq_set(8, true);
        assert!(!spmi.irq_level, "no enable yet");
        spmi.write(SPMI_QUEUE_REGS_START + SPMI_INT_ENAB, 4, 1 << 8);
        assert!(spmi.irq_level);
        // W1C on status V1.
        spmi.write(SPMI_QUEUE_REGS_START + SPMI_INT_STATUS_V1, 4, 1 << 8);
        assert!(!spmi.irq_level);
    }

    #[test]
    fn pmu_rtc_ticks_via_spmi() {
        let mut spmi = Spmi::new();
        let mut pmu = SpmiPmu::new(0, 0x2600, 0x2610, 0x2614, 0x2618, 0x2620, 0x2000);
        pmu.set_reg(0x42, 0x99);
        assert_eq!(pmu.get_reg(0x42), 0x99);
        spmi.attach(0, Box::new(pmu));

        // 3 seconds → 3 * 32768 ticks; RTC readout is tick<<1.
        spmi.tick(3 * 1_000_000_000);
        push_ext_read(&mut spmi, 0, 0x2600, 6);
        let _ = pop_resp(&mut spmi);
        let raw = pop_resp(&mut spmi) as u64
            | ((pop_resp(&mut spmi) as u64) << 32);
        assert_eq!(raw >> 1, 3 << 15, "3 seconds of 32768 Hz ticks");
    }

    #[test]
    fn pmu_alarm_fires_irq_through_gpio() {
        let mut spmi = Spmi::new();
        spmi.attach(0, Box::new(SpmiPmu::new(0, 0x2600, 0x2610, 0x2614, 0x2618, 0x2620, 0x2000)));
        spmi.tick(3 * 1_000_000_000);

        // alarm = now_secs + 1
        let bytes = (4u32).to_le_bytes();
        push_ext_write(&mut spmi, 0, 0x2610, &bytes);
        // alarm_ctrl = ALARM_EN
        push_ext_write(&mut spmi, 0, 0x2614, &[R_RTC_CONTROL_ALARM_EN]);
        // irq_mask = 0xFF (unmask alarm event)
        push_ext_write(&mut spmi, 0, 0x2620, &[0xFF]);
        // drain responses
        while spmi.resp_pending() {
            pop_resp(&mut spmi);
        }
        // Enable IRQ bank 0 (line 0) so the gpio level is visible.
        spmi.write(SPMI_QUEUE_REGS_START + SPMI_INT_ENAB, 4, 1);
        assert!(!spmi.irq_level, "alarm not fired yet");
        spmi.tick(5 * 1_000_000_000);
        assert!(spmi.irq_level, "PMU alarm raised the SPMI input line");
        let st = spmi.read(SPMI_QUEUE_REGS_START + SPMI_INT_STATUS_V1, 4) as u32;
        assert_eq!(st & 1, 1, "status bank latched the PMU line");
    }
}
