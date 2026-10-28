//! pmu_d2255 — Apple PMU D2255 (port of hw/misc/apple-silicon/
//! pmu-d2255.c): the power-management unit slave of A7..A11-class SoCs.
//! A byte-serial register file (I2C slave in the C model — an SPMI-style
//! address/data protocol) with an RTC + alarm IRQ and a 0xFF-filled
//! identity block. The `Device` impl exposes the same register file as a
//! flat window (the vm-core Bus has no I2C yet); the real transaction
//! state machine is ported 1:1 via [`PmuD2255::i2c_event`] /
//! [`PmuD2255::i2c_tx`] / [`PmuD2255::i2c_rx`].

use vm_core::Device;

/// Register file size (C: `#define REG_SIZE (0x8800)`).
pub const REG_SIZE: usize = 0x8800;
pub const RTC_TICK_FREQ: u32 = 32768;
pub const RTC_EVENT_ALARM: u32 = 1 << 0;
pub const RTC_CONTROL_MONITOR: u32 = 1 << 0;
pub const RTC_CONTROL_ALARM_EN: u32 = 1 << 6;
pub const SCRATCH_LEN: usize = 0x27;
pub const OFF_SCRATCH_SECS_OFFSET: u64 = 4;
pub const OFF_SCRATCH_TICKS_OFFSET: u64 = 21;

// ---- register map (C #defines, byte offsets into reg[]) ----
pub const REG_EVENT_A: u64 = 0x140;
pub const REG_EVENT_B: u64 = 0x141;
pub const REG_EVENT_C: u64 = 0x142;
pub const REG_EVENT_D: u64 = 0x143;
pub const REG_EVENT_E: u64 = 0x144;
pub const REG_EVENT_F: u64 = 0x145;
pub const REG_EVENT_G: u64 = 0x146;
pub const REG_EVENT_H: u64 = 0x147;
pub const REG_EVENT_I: u64 = 0x148;
pub const REG_EVENT_J: u64 = 0x149;
pub const REG_EVENT_K: u64 = 0x14A;
pub const REG_EVENT_L: u64 = 0x14B;
pub const REG_EVENT_M: u64 = 0x14C;
pub const REG_EVENT_N: u64 = 0x14D;
pub const REG_EVENT_O: u64 = 0x14E;
pub const REG_EVENT_P: u64 = 0x14F;
pub const REG_EVENT_Q: u64 = 0x150;
pub const REG_EVENT_R: u64 = 0x151;
pub const REG_EVENT_S: u64 = 0x152;
pub const REG_EVENT_T: u64 = 0x153;
pub const REG_EVENT_U: u64 = 0x154;
pub const REG_EVENT_V: u64 = 0x155;
pub const REG_EVENT_W: u64 = 0x156;
pub const REG_EVENT_X: u64 = 0x157;
pub const REG_EVENT_Y: u64 = 0x158;
pub const REG_STATUS_A: u64 = 0x180;
pub const REG_STATUS_B: u64 = 0x181;
pub const REG_STATUS_C: u64 = 0x182;
pub const REG_STATUS_D: u64 = 0x183;
pub const REG_STATUS_E: u64 = 0x184;
pub const REG_STATUS_F: u64 = 0x185;
pub const REG_STATUS_G: u64 = 0x186;
pub const REG_STATUS_H: u64 = 0x187;
pub const REG_STATUS_I: u64 = 0x188;
pub const REG_STATUS_J: u64 = 0x189;
pub const REG_STATUS_K: u64 = 0x18A;
pub const REG_STATUS_L: u64 = 0x18B;
pub const REG_STATUS_M: u64 = 0x18C;
pub const REG_STATUS_N: u64 = 0x18D;
pub const REG_STATUS_O: u64 = 0x18E;
pub const REG_STATUS_P: u64 = 0x18F;
pub const REG_STATUS_Q: u64 = 0x190;
pub const REG_STATUS_R: u64 = 0x191;
pub const REG_STATUS_S: u64 = 0x192;
pub const REG_STATUS_T: u64 = 0x193;
pub const REG_STATUS_U: u64 = 0x194;
pub const REG_STATUS_V: u64 = 0x195;
pub const REG_STATUS_W: u64 = 0x196;
pub const REG_STATUS_X: u64 = 0x197;
pub const REG_STATUS_Y: u64 = 0x198;
pub const REG_IRQ_MASK_A: u64 = 0x1C0;
pub const REG_IRQ_MASK_B: u64 = 0x1C1;
pub const REG_IRQ_MASK_C: u64 = 0x1C2;
pub const REG_IRQ_MASK_D: u64 = 0x1C3;
pub const REG_IRQ_MASK_E: u64 = 0x1C4;
pub const REG_IRQ_MASK_F: u64 = 0x1C5;
pub const REG_IRQ_MASK_G: u64 = 0x1C6;
pub const REG_IRQ_MASK_H: u64 = 0x1C7;
pub const REG_IRQ_MASK_I: u64 = 0x1C8;
pub const REG_IRQ_MASK_J: u64 = 0x1C9;
pub const REG_IRQ_MASK_K: u64 = 0x1CA;
pub const REG_IRQ_MASK_L: u64 = 0x1CB;
pub const REG_IRQ_MASK_M: u64 = 0x1CC;
pub const REG_IRQ_MASK_N: u64 = 0x1CD;
pub const REG_IRQ_MASK_O: u64 = 0x1CE;
pub const REG_IRQ_MASK_P: u64 = 0x1CF;
pub const REG_IRQ_MASK_Q: u64 = 0x1D0;
pub const REG_IRQ_MASK_R: u64 = 0x1D1;
pub const REG_IRQ_MASK_S: u64 = 0x1D2;
pub const REG_IRQ_MASK_T: u64 = 0x1D3;
pub const REG_IRQ_MASK_U: u64 = 0x1D4;
pub const REG_IRQ_MASK_V: u64 = 0x1D5;
pub const REG_IRQ_MASK_W: u64 = 0x1D6;
pub const REG_IRQ_MASK_X: u64 = 0x1D7;
pub const REG_IRQ_MASK_Y: u64 = 0x1D8;
pub const REG_MASK_REV_CODE: u64 = 0x200;
pub const REG_TRIM_REL_CODE: u64 = 0x201;
pub const REG_PLATFORM_ID: u64 = 0x202;
pub const REG_DEVICE_ID0: u64 = 0x203;
pub const REG_DEVICE_ID1: u64 = 0x204;
pub const REG_DEVICE_ID2: u64 = 0x205;
pub const REG_DEVICE_ID3: u64 = 0x206;
pub const REG_DEVICE_ID4: u64 = 0x207;
pub const REG_DEVICE_ID5: u64 = 0x208;
pub const REG_DEVICE_ID6: u64 = 0x209;
pub const REG_DEVICE_ID7: u64 = 0x20A;
pub const REG_APP_TMUX: u64 = 0x212;
pub const REG_SYSCTL_PRE_UVLO_CTRL: u64 = 0x268;
pub const REG_FAULT_LOG1: u64 = 0x2C0;
pub const REG_FAULT_LOG2: u64 = 0x2C1;
pub const REG_RTC_CONTROL: u64 = 0x500;
pub const REG_RTC_TIMEZONE: u64 = 0x501;
pub const REG_RTC_SUB_SECOND_A: u64 = 0x502;
pub const REG_RTC_SUB_SECOND_B: u64 = 0x503;
pub const REG_RTC_SECOND_A: u64 = 0x504;
pub const REG_RTC_SECOND_B: u64 = 0x505;
pub const REG_RTC_SECOND_C: u64 = 0x506;
pub const REG_RTC_SECOND_D: u64 = 0x507;
pub const REG_RTC_ALARM_A: u64 = 0x508;
pub const REG_RTC_ALARM_B: u64 = 0x509;
pub const REG_RTC_ALARM_C: u64 = 0x50A;
pub const REG_RTC_ALARM_D: u64 = 0x50B;
pub const REG_SCRATCH: u64 = 0x5000;

/// C: `PMUOpState`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PmuOpState {
    None,
    Recv,
    Send,
}

/// C: `PMUAddrState`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PmuAddrState {
    Upper,
    Lower,
    Received,
}

/// C: `enum i2c_event` (the subset pmu_d2255_event handles).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum I2cEvent {
    StartRecv,
    StartSend,
    StartSendAsync,
    Finish,
    Nack,
}

pub struct PmuD2255 {
    /// Register file (C: `uint8_t reg[REG_SIZE]`).
    pub reg: Vec<u8>,
    /// ns per 32768 Hz RTC tick (C: `tick_period`).
    pub tick_period: u32,
    /// Host ns at RTC epoch (C: `rtc_offset`).
    pub rtc_offset: u64,
    /// Last time seen via [`Device::tick`] (QEMU: rtc_clock).
    pub now_ns: u64,
    pub op_state: PmuOpState,
    pub address_state: PmuAddrState,
    pub address: u16,
    /// IRQ output line (C: qemu_irq raise/lower).
    pub irq: bool,
    /// Alarm deadline in host ns (C: QEMUTimer); None = disarmed.
    pub alarm_deadline_ns: Option<u64>,
    /// Wakeup requests (C: qemu_system_wakeup_request(RTC)).
    pub wakeups: u64,
    /// LOG_GUEST_ERROR counter.
    pub guest_errors: u64,
    pub unknown_reads: u64,
    pub unknown_writes: u64,
}

impl PmuD2255 {
    pub fn new() -> Self {
        let mut s = PmuD2255 {
            reg: vec![0u8; REG_SIZE],
            tick_period: 1,
            rtc_offset: 0,
            now_ns: 0,
            op_state: PmuOpState::None,
            address_state: PmuAddrState::Upper,
            address: 0,
            irq: false,
            alarm_deadline_ns: None,
            wakeups: 0,
            guest_errors: 0,
            unknown_reads: 0,
            unknown_writes: 0,
        };
        s.reset();
        // C instance_init: fixed tick period, then stamp the boot tick into
        // the scratch registers (rtc_get_tick also latches rtc_offset).
        s.tick_period = 1_000_000_000u32 / RTC_TICK_FREQ;
        let tick = s.rtc_get_tick();
        s.rtc_offset = s.now_ns;
        s.set_tick_offset(tick);
        s
    }

    /// C: `pmu_d2255_reset`.
    pub fn reset(&mut self) {
        self.op_state = PmuOpState::None;
        self.address = 0;
        self.address_state = PmuAddrState::Upper;
        self.reg.iter_mut().for_each(|b| *b = 0);
        // memset(reg + REG_MASK_REV_CODE, 0xFF, REG_DEVICE_ID7 - REG_MASK_REV_CODE)
        let lo = REG_MASK_REV_CODE as usize;
        let len = (REG_DEVICE_ID7 - REG_MASK_REV_CODE) as usize;
        for b in &mut self.reg[lo..lo + len] {
            *b = 0xFF;
        }
        self.alarm_deadline_ns = None;
        self.irq = false;
    }

    // ---- little-endian register file accessors (RREG32/WREG32 macros) ----
    pub fn rreg32(&self, off: u64) -> u32 {
        let off = off as usize;
        let mut b = [0u8; 4];
        b.copy_from_slice(&self.reg[off..off + 4]);
        u32::from_le_bytes(b)
    }
    pub fn wreg32(&mut self, off: u64, val: u32) {
        let off = off as usize;
        self.reg[off..off + 4].copy_from_slice(&val.to_le_bytes());
    }
    pub fn wreg32_or(&mut self, off: u64, val: u32) {
        let v = self.rreg32(off);
        self.wreg32(off, v | val);
    }

    /// C: `rtc_get_tick` — 32.768 kHz RTC: seconds in the upper bits,
    /// sub-second ticks in the low 15.
    pub fn rtc_get_tick(&self) -> u64 {
        let now = self.now_ns;
        let t = now - self.rtc_offset;
        ((t / 1_000_000_000) << 15) | ((t / self.tick_period as u64) & 0x7FFF)
    }

    /// C: `pmu_d2255_set_tick_offset` — stamp a tick into SCRATCH.
    pub fn set_tick_offset(&mut self, tick_offset: u64) {
        self.wreg32(REG_SCRATCH + OFF_SCRATCH_SECS_OFFSET, (tick_offset >> 15) as u32);
        self.wreg32(REG_SCRATCH + OFF_SCRATCH_TICKS_OFFSET, (tick_offset & 0xFF) as u32);
        self.wreg32(
            REG_SCRATCH + OFF_SCRATCH_TICKS_OFFSET + 1,
            ((tick_offset >> 8) & 0x7F) as u32,
        );
    }

    /// C: `pmu_d2255_update_irq` — IRQ tracks (IRQ_MASK_A & EVENT_C).
    pub fn update_irq(&mut self) {
        self.irq = (self.rreg32(REG_IRQ_MASK_A) & self.rreg32(REG_EVENT_C)) != 0;
    }

    /// C: `pmu_d2255_alarm`.
    fn alarm(&mut self) {
        self.wreg32_or(REG_EVENT_C, RTC_EVENT_ALARM);
        self.update_irq();
        // qemu_system_wakeup_request(QEMU_WAKEUP_REASON_RTC)
        self.wakeups += 1;
    }

    /// C: `pmu_d2255_set_alarm` — (re)arm from RTC_ALARM_A vs current tick.
    pub fn set_alarm(&mut self) {
        let seconds = self
            .rreg32(REG_RTC_ALARM_A)
            .wrapping_sub((self.rtc_get_tick() >> 15) as u32);
        if self.rreg32(REG_RTC_CONTROL) & RTC_CONTROL_ALARM_EN != 0 {
            if seconds == 0 {
                self.alarm_deadline_ns = None;
                self.alarm();
            } else {
                self.alarm_deadline_ns =
                    Some(self.now_ns + (seconds as u64) * 1_000_000_000);
            }
        } else {
            self.alarm_deadline_ns = None;
        }
    }

    /// C: `pmu_d2255_event`. Returns 0 on success, -1 on error.
    pub fn i2c_event(&mut self, event: I2cEvent) -> i32 {
        match event {
            I2cEvent::StartRecv => {
                if self.op_state != PmuOpState::None {
                    // "attempted to start transaction while a transaction is
                    // already ongoing"
                    self.guest_errors += 1;
                    return -1;
                }
                self.op_state = PmuOpState::Recv;
                0
            }
            I2cEvent::StartSend => {
                if self.op_state != PmuOpState::None {
                    self.guest_errors += 1;
                    return -1;
                }
                self.op_state = PmuOpState::Send;
                self.address = 0;
                self.address_state = PmuAddrState::Upper;
                0
            }
            I2cEvent::StartSendAsync => {
                // "async is not supported"
                -1
            }
            I2cEvent::Finish => {
                self.op_state = PmuOpState::None;
                0
            }
            I2cEvent::Nack => -1,
        }
    }

    /// C: `pmu_d2255_rx` — read one byte at the latched (auto-incrementing)
    /// address.
    pub fn i2c_rx(&mut self) -> u8 {
        if self.op_state != PmuOpState::Recv {
            self.guest_errors += 1;
            return 0x00;
        }
        if self.address_state != PmuAddrState::Received {
            self.guest_errors += 1;
            return 0x00;
        }
        if self.address as usize >= REG_SIZE {
            self.guest_errors += 1;
            return 0x00;
        }
        if self.address as u64 == REG_RTC_SUB_SECOND_A {
            // Latch the live RTC into the register file before returning it.
            let now = self.rtc_get_tick();
            self.reg[REG_RTC_SUB_SECOND_A as usize] = ((now << 1) & 0xFF) as u8;
            self.reg[REG_RTC_SUB_SECOND_B as usize] = ((now >> 7) & 0xFF) as u8;
            self.reg[REG_RTC_SECOND_A as usize] = ((now >> 15) & 0xFF) as u8;
            self.reg[REG_RTC_SECOND_B as usize] = ((now >> 23) & 0xFF) as u8;
            self.reg[REG_RTC_SECOND_C as usize] = ((now >> 31) & 0xFF) as u8;
            self.reg[REG_RTC_SECOND_D as usize] = ((now >> 39) & 0xFF) as u8;
        }
        let v = self.reg[self.address as usize];
        self.address = self.address.wrapping_add(1);
        v
    }

    /// C: `pmu_d2255_tx` — first two bytes latch a 16-bit address (big-endian
    /// halves, little-endian interpretation), further bytes write the file.
    pub fn i2c_tx(&mut self, data: u8) -> i32 {
        if self.op_state != PmuOpState::Send {
            self.guest_errors += 1;
            return 0x00;
        }
        match self.address_state {
            PmuAddrState::Upper => {
                self.address |= (data as u16) << 8;
                self.address_state = PmuAddrState::Lower;
                0
            }
            PmuAddrState::Lower => {
                self.address |= data as u16;
                // C: le16_to_cpu() — no-op on LE hosts.
                self.address_state = PmuAddrState::Received;
                0
            }
            PmuAddrState::Received => {
                if self.op_state == PmuOpState::Recv {
                    // Dead upstream (tx requires SEND), mirrored honestly.
                    self.guest_errors += 1;
                    return -1;
                }
                if self.address as usize >= REG_SIZE {
                    self.guest_errors += 1;
                    return -1;
                }
                self.reg[self.address as usize] = data;
                match self.address as u64 {
                    REG_RTC_CONTROL | REG_RTC_ALARM_A..=REG_RTC_ALARM_D => {
                        self.set_alarm()
                    }
                    _ => {}
                }
                self.address = self.address.wrapping_add(1);
                0
            }
        }
    }

    /// I2C address-latch helper used by tests and the future bus bridge:
    /// performs a StartSend + two address bytes + Finish.
    pub fn i2c_set_address(&mut self, addr: u16) {
        self.i2c_event(I2cEvent::StartSend);
        self.i2c_tx((addr >> 8) as u8);
        self.i2c_tx(addr as u8);
        self.i2c_event(I2cEvent::Finish);
    }

    /// Full write transaction: address latch + one data byte + Finish
    /// (the C guest sends <addr_hi, addr_lo, data...> in one transfer).
    pub fn i2c_write8(&mut self, addr: u16, data: u8) {
        self.i2c_event(I2cEvent::StartSend);
        self.i2c_tx((addr >> 8) as u8);
        self.i2c_tx(addr as u8);
        self.i2c_tx(data);
        self.i2c_event(I2cEvent::Finish);
    }

    pub fn regs_documented() -> &'static [(&'static str, u64)] {
        &[
            ("EVENT_C", REG_EVENT_C),
            ("STATUS_A", REG_STATUS_A),
            ("IRQ_MASK_A", REG_IRQ_MASK_A),
            ("MASK_REV_CODE", REG_MASK_REV_CODE),
            ("RTC_CONTROL", REG_RTC_CONTROL),
            ("RTC_SECOND_A", REG_RTC_SECOND_A),
            ("RTC_ALARM_A", REG_RTC_ALARM_A),
            ("SCRATCH", REG_SCRATCH),
        ]
    }
}

impl Default for PmuD2255 {
    fn default() -> Self {
        Self::new()
    }
}

impl Device for PmuD2255 {
    fn name(&self) -> &'static str {
        "pmu-d2255"
    }
    /// Flat window onto `reg[]` (the C device is I2C-only; this exists so the
    /// vm-core Bus can attach it directly and so tests can inspect state).
    fn read(&mut self, off: u64, size: u8) -> u64 {
        let off_us = off as usize;
        if off_us + size as usize > REG_SIZE {
            self.unknown_reads += 1;
            return 0;
        }
        match size {
            1 => self.reg[off_us] as u64,
            2 => u16::from_le_bytes([self.reg[off_us], self.reg[off_us + 1]]) as u64,
            4 => self.rreg32(off) as u64,
            8 => {
                let mut b = [0u8; 8];
                b.copy_from_slice(&self.reg[off_us..off_us + 8]);
                u64::from_le_bytes(b)
            }
            _ => {
                self.unknown_reads += 1;
                0
            }
        }
    }
    fn write(&mut self, off: u64, size: u8, val: u64) {
        let off_us = off as usize;
        if off_us + size as usize > REG_SIZE {
            self.unknown_writes += 1;
            return;
        }
        let bytes = val.to_le_bytes();
        self.reg[off_us..off_us + size as usize].copy_from_slice(&bytes[..size as usize]);
        // Same side effects as the I2C byte path (C: case REG_RTC_CONTROL /
        // REG_RTC_ALARM_A..D in pmu_d2255_tx), checked per byte like upstream.
        for i in 0..size as u64 {
            match off + i {
                REG_RTC_CONTROL | REG_RTC_ALARM_A..=REG_RTC_ALARM_D => {
                    self.set_alarm();
                }
                _ => {}
            }
        }
    }
    /// C: QEMUTimer on QEMU_CLOCK_VIRTUAL firing `pmu_d2255_alarm`.
    fn tick(&mut self, now_ns: u64) {
        self.now_ns = now_ns;
        if let Some(deadline) = self.alarm_deadline_ns {
            if now_ns >= deadline {
                self.alarm_deadline_ns = None;
                self.alarm();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reset_identity_block_and_scratch() {
        let pmu = PmuD2255::new();
        assert_eq!(pmu.op_state, PmuOpState::None);
        assert_eq!(pmu.tick_period, 30517); // 1e9 / 32768
        // 0xFF identity block: MASK_REV_CODE ..= DEVICE_ID6 (0xA bytes).
        assert_eq!(pmu.reg[REG_MASK_REV_CODE as usize], 0xFF);
        assert_eq!(pmu.reg[REG_PLATFORM_ID as usize], 0xFF);
        assert_eq!(pmu.reg[REG_DEVICE_ID6 as usize], 0xFF);
        assert_eq!(pmu.reg[REG_DEVICE_ID7 as usize], 0x00);
        // instance_init stamps the boot tick into SCRATCH.
        assert_eq!(pmu.rreg32(REG_SCRATCH + OFF_SCRATCH_SECS_OFFSET), 0);
        let mut pmu = PmuD2255::new();
        pmu.tick(5_000_000_000);
        let t = pmu.rtc_get_tick();
        pmu.set_tick_offset(t);
        assert_eq!(pmu.rreg32(REG_SCRATCH + OFF_SCRATCH_SECS_OFFSET), (t >> 15) as u32);
        assert_eq!(pmu.rreg32(REG_SCRATCH + OFF_SCRATCH_SECS_OFFSET), 5); // 5 s since boot
    }

    #[test]
    fn i2c_write_read_echo() {
        let mut pmu = PmuD2255::new();
        // Write 0xAB at 0x0140 (REG_EVENT_A) then read it back and beyond.
        pmu.i2c_event(I2cEvent::StartSend);
        assert_eq!(pmu.i2c_tx(0x01), 0);
        assert_eq!(pmu.i2c_tx(0x40), 0);
        assert_eq!(pmu.address_state, PmuAddrState::Received);
        assert_eq!(pmu.i2c_tx(0xAB), 0);
        pmu.i2c_event(I2cEvent::Finish);
        assert_eq!(pmu.reg[REG_EVENT_A as usize], 0xAB);

        // The tx path auto-increments the address, so a read-back re-latches
        // the address (fresh StartSend resets the two-byte address state).
        pmu.i2c_set_address(REG_EVENT_A as u16);
        pmu.i2c_event(I2cEvent::StartRecv);
        assert_eq!(pmu.i2c_rx(), 0xAB);
        assert_eq!(pmu.i2c_rx(), 0x00); // auto-increment into EVENT_B
        pmu.i2c_event(I2cEvent::Finish);

        // Starting a recv while busy is a guest error, as upstream.
        pmu.i2c_event(I2cEvent::StartSend);
        assert_eq!(pmu.i2c_event(I2cEvent::StartRecv), -1);
        assert_eq!(pmu.guest_errors, 1);
        // Async send unsupported.
        assert_eq!(pmu.i2c_event(I2cEvent::StartSendAsync), -1);
    }

    #[test]
    fn rtc_latch_on_subsecond_read() {
        let mut pmu = PmuD2255::new();
        pmu.tick(2_500_000_000);
        pmu.i2c_set_address(REG_RTC_SUB_SECOND_A as u16);
        pmu.i2c_event(I2cEvent::StartRecv);
        let _ = pmu.i2c_rx(); // triggers the RTC latch
        let tick = pmu.rtc_get_tick();
        assert_eq!(pmu.reg[REG_RTC_SUB_SECOND_A as usize], ((tick << 1) & 0xFF) as u8);
        assert_eq!(pmu.reg[REG_RTC_SUB_SECOND_B as usize], ((tick >> 7) & 0xFF) as u8);
        assert_eq!(pmu.reg[REG_RTC_SECOND_A as usize], ((tick >> 15) & 0xFF) as u8);
        assert_eq!(pmu.reg[REG_RTC_SECOND_A as usize], 2); // 2.5 s since boot
        pmu.i2c_event(I2cEvent::Finish);
    }

    #[test]
    fn alarm_fires_and_raises_irq() {
        let mut pmu = PmuD2255::new();
        pmu.tick(10_000_000_000);
        // IRQ_MASK_A = RTC_EVENT_ALARM
        pmu.i2c_write8(REG_IRQ_MASK_A as u16, 0x01);
        // RTC_CONTROL = ALARM_EN (ALARM_A still 0 → far-future deadline)
        pmu.i2c_write8(REG_RTC_CONTROL as u16, RTC_CONTROL_ALARM_EN as u8);
        assert_eq!(pmu.irq, false);
        // RTC_ALARM_A = 12, one byte per transfer like the C switch-case.
        pmu.i2c_write8(REG_RTC_ALARM_A as u16, 12);
        pmu.i2c_write8(REG_RTC_ALARM_B as u16, 0);
        pmu.i2c_write8(REG_RTC_ALARM_C as u16, 0);
        pmu.i2c_write8(REG_RTC_ALARM_D as u16, 0);
        assert_eq!(pmu.alarm_deadline_ns, Some(12_000_000_000));
        pmu.tick(11_999_999_999);
        assert_eq!(pmu.irq, false);
        assert_eq!(pmu.rreg32(REG_EVENT_C) & RTC_EVENT_ALARM, 0);
        pmu.tick(12_000_000_000);
        assert_eq!(pmu.rreg32(REG_EVENT_C) & RTC_EVENT_ALARM, RTC_EVENT_ALARM);
        assert!(pmu.irq);
        assert_eq!(pmu.wakeups, 1);
        // Disarming via ALARM_EN clear removes the deadline.
        pmu.i2c_write8(REG_RTC_CONTROL as u16, 0);
        assert_eq!(pmu.alarm_deadline_ns, None);
    }

    #[test]
    fn flat_window_roundtrip_and_unknown() {
        let mut pmu = PmuD2255::new();
        pmu.write(REG_SCRATCH, 4, 0xDEADBEEF);
        assert_eq!(pmu.read(REG_SCRATCH, 4), 0xDEADBEEF);
        assert_eq!(pmu.read(REG_SCRATCH, 1), 0xEF);
        assert_eq!(pmu.read(REG_SCRATCH + 2, 1), 0xAD);
        assert_eq!(pmu.read(REG_SCRATCH + 3, 1), 0xDE);
        assert_eq!(pmu.unknown_reads, 0);
        let _ = pmu.read(REG_SIZE as u64 + 1, 1);
        assert_eq!(pmu.unknown_reads, 1);
        pmu.write(REG_SIZE as u64 + 1, 1, 0xFF);
        assert_eq!(pmu.unknown_writes, 1);
    }
}
