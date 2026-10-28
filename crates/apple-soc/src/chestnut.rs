//! chestnut — Apple Chestnut Display PMU (port of hw/misc/apple-silicon/
//! chestnut.c).
//!
//! Upstream is an **I2C slave** stub for the TI/Intersil display PMU: the
//! C source defines the chip's register map (`REG_DEVICE_ID_0` 0x00 …
//! `REG_VNEG_CONTROL` 0x0F) and the TI/Intersil device-ID values, but the
//! handlers themselves are pure stubs — `recv` returns `0x00` and `send`
//! ACKs (`0`) without keeping any state. This port mirrors that honestly:
//! the register constants are preserved, reads return 0, writes are ACKed
//! and dropped, and there is no state to reset.
//!
//! License: upstream Inferno file is AGPL-3.0; this crate is AGPL-3.0-or-later.
//!
//! For the flat-bus [`Device`] view (QEMU has no MMIO region here) the
//! documented window is the 8-bit I2C register-address space (0x00..=0xFF):
//! inside it the C stub behavior applies; offsets ≥ 0x100 cannot be
//! produced by the I2C protocol and count as unknown accesses.

use vm_core::Device;

/// Chestnut register map as defined (but not implemented) upstream.
pub const REG_DEVICE_ID_0: u64 = 0x00;
pub const REG_DEVICE_ID_1: u64 = 0x01;
pub const REG_DEVICE_ID_2: u64 = 0x02;
pub const REG_REVISION: u64 = 0x03;
pub const REG_STATUS: u64 = 0x04;
pub const REG_ENABLE: u64 = 0x05;
pub const REG_VNEG_CONTROL: u64 = 0x0F;

/// Device-ID values from the C source (TI vs Intersil panel variants).
pub const TI_DEVICE_ID_0: u32 = 0x7365;
pub const TI_DEVICE_ID_1: u32 = 0xF365;
pub const INTERSIL_DEVICE_ID: u32 = 0x0BA46E;

/// I2C register-address space end (exclusive) — the documented bus window.
pub const I2C_REG_SPACE: u64 = 0x100;

/// Apple Chestnut Display PMU (port of `AppleChestnutState`).
pub struct Chestnut {
    pub unknown_reads: u64,
    pub unknown_writes: u64,
}

impl Chestnut {
    pub fn new() -> Self {
        Chestnut { unknown_reads: 0, unknown_writes: 0 }
    }

    /// Port of `apple_chestnut_rx`: stub returning 0x00.
    pub fn i2c_rx(&mut self) -> u8 {
        0x00
    }

    /// Port of `apple_chestnut_tx`: stub ACK (0), no state.
    pub fn i2c_tx(&mut self, _data: u8) -> i32 {
        0
    }
}

impl Default for Chestnut {
    fn default() -> Self {
        Self::new()
    }
}

impl Device for Chestnut {
    fn name(&self) -> &'static str {
        "apple-chestnut"
    }
    fn read(&mut self, off: u64, _size: u8) -> u64 {
        if off < I2C_REG_SPACE {
            // Stub register file: every defined register reads 0x00
            // (upstream recv has no address decode and returns 0).
            return 0;
        }
        self.unknown_reads += 1;
        0
    }
    fn write(&mut self, off: u64, _size: u8, _val: u64) {
        if off < I2C_REG_SPACE {
            // ACKed and dropped (upstream send returns 0, keeps no state).
            return;
        }
        self.unknown_writes += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_reads_return_zero() {
        let mut d = Chestnut::new();
        // Reset-value assert across the documented register map.
        assert_eq!(d.read(REG_DEVICE_ID_0, 1), 0x00);
        assert_eq!(d.read(REG_DEVICE_ID_1, 1), 0x00);
        assert_eq!(d.read(REG_DEVICE_ID_2, 1), 0x00);
        assert_eq!(d.read(REG_REVISION, 1), 0x00);
        assert_eq!(d.read(REG_STATUS, 1), 0x00);
        assert_eq!(d.read(REG_ENABLE, 1), 0x00);
        assert_eq!(d.read(REG_VNEG_CONTROL, 1), 0x00);
        // In-window (but undefined) registers also read 0 per the stub.
        assert_eq!(d.read(0x42, 1), 0x00);

        // I2C stub protocol: rx = 0x00, tx = ACK with no state change.
        assert_eq!(d.i2c_rx(), 0x00);
        assert_eq!(d.i2c_tx(0x42), 0);
        assert_eq!(d.i2c_rx(), 0x00);
    }

    #[test]
    fn unknown_offsets_counted() {
        let mut d = Chestnut::new();
        assert_eq!(d.unknown_reads, 0);
        assert_eq!(d.unknown_writes, 0);
        // Offsets outside the 8-bit I2C register-address space.
        assert_eq!(d.read(0x100, 1), 0);
        assert_eq!(d.unknown_reads, 1);
        d.write(0x100, 1, 0xAA);
        assert_eq!(d.unknown_writes, 1);
        // In-window accesses never touch the counters.
        d.write(REG_ENABLE, 1, 0x1);
        assert_eq!(d.read(REG_ENABLE, 1), 0x00);
        assert_eq!(d.unknown_reads, 1);
        assert_eq!(d.unknown_writes, 1);
    }
}
