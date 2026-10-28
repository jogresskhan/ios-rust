//! roswell — Apple Roswell, Display Authentication CP relay IC (port of
//! hw/misc/apple-silicon/roswell.c).
//!
//! Upstream is an **I2C slave** (no MMIO registers): the host writes a
//! CP-Auth command ID byte, then clocks out the prepared response stream
//! byte by byte; the command auto-resets when the response is drained.
//! This port keeps the exact command table, the `0x261`-byte response
//! buffer, the GET_DEVICE_INFO payload (`00 00 02 00` + BE DeviceID
//! `0xDEADBEEF`) and the EXTENDED/GET_IDSN payload (`E3` ack + "CKRosw").
//! Commands without a modelled payload (signature/cert) latch the command
//! with `resp_len == 0`, so reads return `0x00` — mirroring upstream
//! honestly (they are not implemented in the C model either).
//!
//! License: upstream Inferno file is AGPL-3.0; this crate is AGPL-3.0-or-later.
//!
//! For the flat-bus [`Device`] view (QEMU has no MMIO region here) the I2C
//! protocol maps to one documented pseudo-offset: `read(0)` pops the
//! response stream (I2C `recv`), `write(0, b)` sends a command byte
//! (I2C `send`). Any other offset hits the unknown-access counters.

use vm_core::Device;

/// Port of the CP Auth command IDs written by the host (I2C tx bytes).
pub const CMD_BYTE_GET_DEVICE_INFO: u8 = 0x00;
pub const CMD_BYTE_GEN_SIGNATURE: u8 = 0x10;
pub const CMD_BYTE_GET_SIGNATURE_LENGTH: u8 = 0x11;
pub const CMD_BYTE_GET_SIGNATURE: u8 = 0x12;
pub const CMD_BYTE_GET_CERT_LENGTH: u8 = 0x30;
pub const CMD_BYTE_GET_CERT: u8 = 0x31;
pub const CMD_BYTE_GET_CERT_SN: u8 = 0x4E;
pub const CMD_BYTE_EXTENDED: u8 = 0x60;

/// Port of the internal `enum` (latched command state).
pub const ROSWELL_COMMAND_GET_DEVICE_INFO: u8 = 0;
pub const ROSWELL_COMMAND_GEN_SIGNATURE: u8 = 1;
pub const ROSWELL_COMMAND_GET_SIGNATURE_LENGTH: u8 = 2;
pub const ROSWELL_COMMAND_GET_SIGNATURE: u8 = 3;
pub const ROSWELL_COMMAND_GET_CERT_LENGTH: u8 = 4;
pub const ROSWELL_COMMAND_GET_CERT: u8 = 5;
pub const ROSWELL_COMMAND_GET_CERT_SN: u8 = 6;
pub const ROSWELL_COMMAND_EXTENDED: u8 = 7;
pub const ROSWELL_COMMAND_INVALID: u8 = 8;

/// `AppleRoswellResponse.buf` size upstream.
pub const RESP_BUF_LEN: usize = 0x261;

/// Bus-view offset carrying the I2C command/response byte stream.
pub const BUS_STREAM: u64 = 0x00;

/// Apple Roswell CP relay (port of `AppleRoswellState`).
pub struct AppleRoswell {
    /// Latched command (`ROSWELL_COMMAND_*`), reset to INVALID.
    pub command: u8,
    pub resp_buf: Box<[u8; RESP_BUF_LEN]>,
    pub resp_len: u16,
    pub resp_pos: u16,
    /// Guest-error count (`LOG_GUEST_ERROR` upstream).
    pub guest_errors: u64,
    pub unknown_reads: u64,
    pub unknown_writes: u64,
}

impl AppleRoswell {
    pub fn new() -> Self {
        AppleRoswell {
            command: ROSWELL_COMMAND_INVALID,
            resp_buf: Box::new([0; RESP_BUF_LEN]),
            resp_len: 0,
            resp_pos: 0,
            guest_errors: 0,
            unknown_reads: 0,
            unknown_writes: 0,
        }
    }

    /// Port of `apple_roswell_reset_command`.
    pub fn reset_command(&mut self) {
        self.command = ROSWELL_COMMAND_INVALID;
        self.resp_len = 0;
        self.resp_pos = 0;
        self.resp_buf = Box::new([0; RESP_BUF_LEN]);
    }

    /// Port of `apple_roswell_pop_resp` / I2C `recv`.
    pub fn i2c_rx(&mut self) -> u8 {
        if self.command == ROSWELL_COMMAND_INVALID {
            // qemu_log_mask(LOG_GUEST_ERROR, "no command set!!")
            self.guest_errors += 1;
            return 0x00;
        }
        if self.resp_len == 0 {
            return 0x00;
        }
        let ret = self.resp_buf[self.resp_pos as usize];
        self.resp_pos += 1;
        if self.resp_len == self.resp_pos {
            self.reset_command();
        }
        ret
    }

    /// Port of `apple_roswell_tx` / I2C `send`. Returns 0 on ACK, -1 (as
    /// upstream) when the command byte is unknown.
    pub fn i2c_tx(&mut self, data: u8) -> i32 {
        if self.command != ROSWELL_COMMAND_INVALID {
            return 0; // busy with a pending command: swallow
        }

        self.command = match data {
            CMD_BYTE_GET_DEVICE_INFO => ROSWELL_COMMAND_GET_DEVICE_INFO,
            CMD_BYTE_GEN_SIGNATURE => ROSWELL_COMMAND_GEN_SIGNATURE,
            CMD_BYTE_GET_SIGNATURE_LENGTH => ROSWELL_COMMAND_GET_SIGNATURE_LENGTH,
            CMD_BYTE_GET_SIGNATURE => ROSWELL_COMMAND_GET_SIGNATURE,
            CMD_BYTE_GET_CERT_LENGTH => ROSWELL_COMMAND_GET_CERT_LENGTH,
            CMD_BYTE_GET_CERT => ROSWELL_COMMAND_GET_CERT,
            CMD_BYTE_GET_CERT_SN => ROSWELL_COMMAND_GET_CERT_SN,
            CMD_BYTE_EXTENDED => ROSWELL_COMMAND_EXTENDED,
            _ => {
                self.guest_errors += 1;
                return -1;
            }
        };

        match self.command {
            ROSWELL_COMMAND_GET_DEVICE_INFO => {
                self.resp_buf[0] = 0x0; // Device Version
                self.resp_buf[1] = 0x0; // Firmware Version
                self.resp_buf[2] = 0x2; // Authentication Major Version
                self.resp_buf[3] = 0x0; // Authentication Minor Version
                self.resp_buf[4..8].copy_from_slice(&0xDEADBEEFu32.to_be_bytes()); // Device ID
                self.resp_len = 8;
            }
            ROSWELL_COMMAND_EXTENDED => {
                // Not sure about possible arguments, so just always doing
                // "GET_IDSN" (upstream comment).
                self.resp_buf[0..9].fill(0);
                self.resp_buf[9] = 0xE3; // ack byte, see AppleAuthCPAID::_getIDSN
                self.resp_buf[10..16].copy_from_slice(b"CKRosw");
                self.resp_len = 9 + 7; // header + ack byte + idsn
            }
            _ => {} // signature/cert commands: no modelled payload (len stays 0)
        }

        0
    }

    /// Port of `apple_roswell_reset_enter`.
    pub fn reset(&mut self) {
        self.reset_command();
    }
}

impl Default for AppleRoswell {
    fn default() -> Self {
        Self::new()
    }
}

impl Device for AppleRoswell {
    fn name(&self) -> &'static str {
        "apple-roswell"
    }
    fn read(&mut self, off: u64, _size: u8) -> u64 {
        if off == BUS_STREAM {
            return self.i2c_rx() as u64;
        }
        self.unknown_reads += 1;
        0
    }
    fn write(&mut self, off: u64, _size: u8, val: u64) {
        if off == BUS_STREAM {
            self.i2c_tx(val as u8);
            return;
        }
        self.unknown_writes += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_info_response_roundtrip() {
        let mut d = AppleRoswell::new();
        // Command dispatch then drain the 8-byte GET_DEVICE_INFO payload.
        d.write(BUS_STREAM, 1, CMD_BYTE_GET_DEVICE_INFO as u64);
        assert_eq!(d.command, ROSWELL_COMMAND_GET_DEVICE_INFO);
        let mut out = Vec::new();
        for _ in 0..8 {
            out.push(d.read(BUS_STREAM, 1) as u8);
        }
        assert_eq!(out, [0x00, 0x00, 0x02, 0x00, 0xDE, 0xAD, 0xBE, 0xEF]);
        // Response drained: command auto-resets, next read is a guest error.
        assert_eq!(d.command, ROSWELL_COMMAND_INVALID);
        assert_eq!(d.read(BUS_STREAM, 1), 0);
        assert_eq!(d.guest_errors, 1);

        // EXTENDED → "GET_IDSN": 9 zero header bytes, 0xE3 ack, "CKRosw".
        d.write(BUS_STREAM, 1, CMD_BYTE_EXTENDED as u64);
        assert_eq!(d.resp_len, 16);
        let mut payload = Vec::new();
        for _ in 0..d.resp_len {
            payload.push(d.i2c_rx());
        }
        assert_eq!(&payload[0..9], &[0; 9]);
        assert_eq!(payload[9], 0xE3);
        assert_eq!(&payload[10..16], b"CKRosw");
    }

    #[test]
    fn unknown_offsets_and_unknown_command() {
        let mut d = AppleRoswell::new();
        assert_eq!(d.unknown_reads, 0);
        assert_eq!(d.unknown_writes, 0);
        assert_eq!(d.read(0x10, 1), 0);
        assert_eq!(d.unknown_reads, 1);
        d.write(0x10, 1, 0);
        assert_eq!(d.unknown_writes, 1);

        // Unknown command byte: NAK (-1), command stays INVALID.
        assert_eq!(d.i2c_tx(0x77), -1);
        assert_eq!(d.command, ROSWELL_COMMAND_INVALID);
        assert_eq!(d.guest_errors, 1);
    }
}
