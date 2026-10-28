//! fan53740 — ACC Buck FAN53740 (port of hw/misc/apple-silicon/fan53740.c).
//!
//! Upstream is an **I2C slave** stub for the Fairchild/onsemi FAN53740
//! buck converter: `recv` returns `0x00`, `send` ACKs (`0`) and `event`
//! returns `0`, with no state, no register decode and no reset handler.
//! The C source defines no register constants, so this port defines none
//! either — it mirrors the stub honestly (reads 0, writes ACKed/dropped).
//!
//! License: upstream Inferno file is AGPL-3.0; this crate is AGPL-3.0-or-later.
//!
//! For the flat-bus [`Device`] view (QEMU has no MMIO region here) the
//! documented window is the 8-bit I2C register-address space (0x00..=0xFF):
//! inside it the C stub behavior applies; offsets ≥ [`I2C_REG_SPACE`]
//! cannot be produced by the I2C protocol and count as unknown accesses.

use vm_core::Device;

/// I2C register-address space end (exclusive) — the documented bus window.
pub const I2C_REG_SPACE: u64 = 0x100;

/// ACC Buck FAN53740 (port of `FAN53740State`).
pub struct Fan53740 {
    pub unknown_reads: u64,
    pub unknown_writes: u64,
}

impl Fan53740 {
    pub fn new() -> Self {
        Fan53740 { unknown_reads: 0, unknown_writes: 0 }
    }

    /// Port of `fan53740_rx`: stub returning 0x00.
    pub fn i2c_rx(&mut self) -> u8 {
        0x00
    }

    /// Port of `fan53740_tx`: stub ACK (0), no state.
    pub fn i2c_tx(&mut self, _data: u8) -> i32 {
        0
    }

    /// Port of `fan53740_event`: stub, always succeeds (event kind ignored
    /// upstream; use [`crate::mic_tempsensor::I2cEvent`] for the bus event).
    pub fn i2c_event(&mut self, _event: crate::mic_tempsensor::I2cEvent) -> i32 {
        0
    }
}

impl Default for Fan53740 {
    fn default() -> Self {
        Self::new()
    }
}

impl Device for Fan53740 {
    fn name(&self) -> &'static str {
        "fan53740"
    }
    fn read(&mut self, off: u64, _size: u8) -> u64 {
        if off < I2C_REG_SPACE {
            // Stub: every register reads 0x00.
            return 0;
        }
        self.unknown_reads += 1;
        0
    }
    fn write(&mut self, off: u64, _size: u8, _val: u64) {
        if off < I2C_REG_SPACE {
            // ACKed and dropped (stub send returns 0, keeps no state).
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
        let mut d = Fan53740::new();
        // Reset-value assert: the stub register space reads 0 and stays 0
        // after (dropped) writes.
        d.write(0x00, 1, 0xFF);
        assert_eq!(d.read(0x00, 1), 0x00);
        d.write(0xFE, 1, 0x42);
        assert_eq!(d.read(0xFE, 1), 0x00);

        // I2C stub protocol: rx = 0x00, tx = ACK, event = OK, no state.
        use crate::mic_tempsensor::I2cEvent;
        assert_eq!(d.i2c_rx(), 0x00);
        assert_eq!(d.i2c_tx(0x5A), 0);
        assert_eq!(d.i2c_event(I2cEvent::StartSend), 0);
        assert_eq!(d.i2c_event(I2cEvent::Finish), 0);
        assert_eq!(d.i2c_rx(), 0x00);
    }

    #[test]
    fn unknown_offsets_counted() {
        let mut d = Fan53740::new();
        assert_eq!(d.unknown_reads, 0);
        assert_eq!(d.unknown_writes, 0);
        // Offsets outside the 8-bit I2C register-address space.
        assert_eq!(d.read(0x100, 1), 0);
        assert_eq!(d.unknown_reads, 1);
        d.write(0x123, 1, 0xAA);
        assert_eq!(d.unknown_writes, 1);
        // In-window accesses never touch the counters.
        let _ = d.read(0x10, 1);
        d.write(0x10, 1, 0);
        assert_eq!(d.unknown_reads, 1);
        assert_eq!(d.unknown_writes, 1);
    }
}
