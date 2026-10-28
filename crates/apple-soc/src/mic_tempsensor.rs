//! mic_tempsensor — Apple Mic/ICA60 temp sensor (port of hw/misc/
//! apple-silicon/mic_tempsensor.c).
//!
//! Upstream is an **I2C slave** with an 8-bit register-addressed register
//! file: the first byte written after `START_SEND` sets the address
//! pointer, reads return the register at the pointer and auto-increment
//! it, and on `I2C_FINISH` the pointer rewinds to the last address byte.
//! Register map (REG8 offsets from the C `registerfields` block):
//! ID0=0x0 (PRODUCT_ID 0..5 / VENDOR_ID 5..8), ID1=0x1 (REVISION/FAB_ID),
//! STATUS=0x2 (OK = bit 1), VALUE0=0x4 (0x0A), VALUE1=0x5 (0x00),
//! VALUE2=0x6 (0x00). Unknown register addresses decode to 0x00 (the C
//! `default:` arm).
//!
//! License: upstream Inferno file is AGPL-3.0; this crate is AGPL-3.0-or-later.
//!
//! The exact I2C protocol lives in [`MicTempSensor::i2c_tx`]/[`i2c_rx`]
//! (public methods, mirroring the QEMU I2CSlaveClass callbacks). The
//! flat-bus [`Device`] view is a stateless peek: `read(off)` decodes the
//! register at fixed address `off` without moving the pointer; the sensor
//! exposes no writable registers, so every `write` counts as unknown.

use vm_core::Device;

pub const R_ID0: u64 = 0x0;
pub const R_ID1: u64 = 0x1;
pub const R_STATUS: u64 = 0x2;
pub const R_VALUE0: u64 = 0x4;
pub const R_VALUE1: u64 = 0x5;
pub const R_VALUE2: u64 = 0x6;

/// `STATUS.OK` field: bit 1 set when the sensor reports healthy.
pub const STATUS_OK_MASK: u8 = 1 << 1;

/// VALUE0 fixed reading upstream (`ret = 0x0A`).
pub const VALUE0_READING: u8 = 0x0A;

/// I2C bus events (subset of QEMU `enum i2c_event` this model handles).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum I2cEvent {
    StartSend,
    Finish,
}

/// Apple Mic/ICA60 temp sensor (port of `AppleMicTempSensorState`).
pub struct MicTempSensor {
    /// Address-phase latch: next tx byte is the register address.
    receiving_addr: bool,
    /// Last address byte received (rewind target on I2C_FINISH).
    addr: u8,
    /// Current auto-incrementing register pointer.
    cur_addr: u8,
    /// ID0: PRODUCT_ID (bits 0..5) | VENDOR_ID (bits 5..8).
    pub id0: u8,
    /// ID1: REVISION (bits 0..5) | FAB_ID (bits 5..8).
    pub id1: u8,
    pub unknown_reads: u64,
    pub unknown_writes: u64,
}

impl MicTempSensor {
    pub fn new() -> Self {
        MicTempSensor {
            receiving_addr: false,
            addr: 0,
            cur_addr: 0,
            id0: 0,
            id1: 0,
            unknown_reads: 0,
            unknown_writes: 0,
        }
    }

    /// Port of `apple_mic_temp_sensor_create`'s ID packing
    /// (`REG_FIELD_DP8` chains): 5-bit low field + 3-bit field at bit 5.
    pub fn with_ids(product_id: u8, vendor_id: u8, revision: u8, fab_id: u8) -> Self {
        let mut s = Self::new();
        s.id0 = (product_id & 0x1F) | ((vendor_id & 0x7) << 5);
        s.id1 = (revision & 0x1F) | ((fab_id & 0x7) << 5);
        s
    }

    /// Register decode shared by the I2C rx path and the Device peek view
    /// (port of the `apple_mic_temp_sensor_rx` switch, minus side effects).
    fn decode_at(&self, addr: u8) -> u8 {
        match addr as u64 {
            R_ID0 => self.id0,
            R_ID1 => self.id1,
            R_STATUS => STATUS_OK_MASK, // REG_FIELD_DP8(0, STATUS, OK, 1)
            R_VALUE0 => VALUE0_READING,
            R_VALUE1 | R_VALUE2 => 0x00,
            _ => 0x00, // C default arm
        }
    }

    /// Port of `apple_mic_temp_sensor_event`.
    pub fn i2c_event(&mut self, event: I2cEvent) {
        match event {
            I2cEvent::StartSend => self.receiving_addr = true,
            I2cEvent::Finish => self.cur_addr = self.addr,
        }
    }

    /// Port of `apple_mic_temp_sensor_tx`.
    pub fn i2c_tx(&mut self, data: u8) -> i32 {
        if self.receiving_addr {
            self.receiving_addr = false;
            self.addr = data;
            self.cur_addr = data;
        } else {
            self.cur_addr = self.cur_addr.wrapping_add(1);
        }
        0
    }

    /// Port of `apple_mic_temp_sensor_rx` (reads + pointer auto-increment).
    pub fn i2c_rx(&mut self) -> u8 {
        let ret = self.decode_at(self.cur_addr);
        self.cur_addr = self.cur_addr.wrapping_add(1);
        ret
    }
}

impl Default for MicTempSensor {
    fn default() -> Self {
        Self::new()
    }
}

impl Device for MicTempSensor {
    fn name(&self) -> &'static str {
        "apple-mic-temp-sensor"
    }
    fn read(&mut self, off: u64, _size: u8) -> u64 {
        // Stateless peek at the register file; the pointer semantics are
        // owned by the I2C protocol methods above.
        match off {
            R_ID0 | R_ID1 | R_STATUS | R_VALUE0 | R_VALUE1 | R_VALUE2 => {
                self.decode_at(off as u8) as u64
            }
            _ => {
                self.unknown_reads += 1;
                0
            }
        }
    }
    fn write(&mut self, _off: u64, _size: u8, _val: u64) {
        // Read-only sensor: register writes do not exist; the I2C address
        // phase is driven via i2c_event/i2c_tx, not Device::write.
        self.unknown_writes += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_status_and_value_regs() {
        // Reset-value assert through the Device peek view.
        let mut d = MicTempSensor::with_ids(0x12, 0x5, 0x34, 0x3);
        assert_eq!(d.id0, 0x12 | (0x5 << 5));
        assert_eq!(d.id1, 0x34 | (0x3 << 5));
        assert_eq!(d.read(R_ID0, 1), d.id0 as u64);
        assert_eq!(d.read(R_ID1, 1), d.id1 as u64);
        assert_eq!(d.read(R_STATUS, 1), STATUS_OK_MASK as u64); // OK bit set
        assert_eq!(d.read(R_VALUE0, 1), VALUE0_READING as u64);
        assert_eq!(d.read(R_VALUE1, 1), 0);
        assert_eq!(d.read(R_VALUE2, 1), 0);

        // I2C protocol roundtrip: address phase, then auto-increment reads
        // across VALUE0..VALUE2 (pointer must advance like the C model).
        d.i2c_event(I2cEvent::StartSend);
        d.i2c_tx(R_VALUE0 as u8);
        assert_eq!(d.i2c_rx(), VALUE0_READING);
        assert_eq!(d.i2c_rx(), 0x00);
        assert_eq!(d.i2c_rx(), 0x00);
        // I2C_FINISH rewinds the pointer to the addressed register.
        d.i2c_event(I2cEvent::Finish);
        assert_eq!(d.i2c_rx(), VALUE0_READING);
    }

    #[test]
    fn unknown_offsets_counted() {
        let mut d = MicTempSensor::new();
        assert_eq!(d.unknown_reads, 0);
        assert_eq!(d.unknown_writes, 0);
        // 0x3 is unassigned in the register map; the bus view counts it.
        assert_eq!(d.read(0x3, 1), 0);
        assert_eq!(d.unknown_reads, 1);
        // Read-only sensor: any bus write is unexpected.
        d.write(R_STATUS, 1, 0xFF);
        assert_eq!(d.unknown_writes, 1);
        // The I2C rx path itself still decodes unknown addresses as 0
        // (C default arm) without touching the bus counters.
        assert_eq!(d.i2c_rx(), 0x00);
        assert_eq!(d.unknown_reads, 1);
    }
}
