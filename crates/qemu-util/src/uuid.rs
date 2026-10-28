//! uuid — libqemuutil port (`qemu/util/uuid.c` + `qemu/include/qemu/uuid.h`).
//!
//! Upstream: "QEMU UUID functions", Copyright 2016 Red Hat, Inc. (Fam Zheng),
//! GPL-2.0-or-later. `QemuUUID` stores the 16 bytes in RFC-4122 network
//! (big-endian) order: `time_low`, `time_mid`, `time_hi_and_version`,
//! `clock_seq_hi_and_reserved`, `clock_seq_low`, `node[6]`.
//! `UUID_FMT`/`qemu_uuid_unparse` render the canonical dashed lowercase form
//! and `qemu_uuid_parse` validates exactly 36 characters with dashes at
//! 8/13/18/23 — both reproduced here. Generation (v4) is omitted because the
//! workspace is dependency-free; use [`Uuid::from_fields`] or [`Uuid::from_bytes`].

use std::fmt;

/// RFC-4122 UUID in QEMU `QemuUUID` layout (big-endian canonical bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Uuid(pub [u8; 16]);

/// QEMU `UUID_NONE` / `UUID_STR_LEN`: 36 characters.
pub const UUID_STR_LEN: usize = 36;

impl Uuid {
    /// QEMU `qemu_uuid_is_null` — the all-zero UUID.
    pub fn nil() -> Uuid {
        Uuid([0u8; 16])
    }

    /// Build from raw bytes (already in canonical wire order).
    pub const fn from_bytes(bytes: [u8; 16]) -> Uuid {
        Uuid(bytes)
    }

    /// QEMU `UUID(...)` macro: network byte order field constructor.
    pub const fn from_fields(
        time_low: u32,
        time_mid: u16,
        time_hi_and_version: u16,
        clock_seq_hi_and_reserved: u8,
        clock_seq_low: u8,
        node: [u8; 6],
    ) -> Uuid {
        Uuid([
            ((time_low >> 24) & 0xff) as u8,
            ((time_low >> 16) & 0xff) as u8,
            ((time_low >> 8) & 0xff) as u8,
            (time_low & 0xff) as u8,
            ((time_mid >> 8) & 0xff) as u8,
            (time_mid & 0xff) as u8,
            ((time_hi_and_version >> 8) & 0xff) as u8,
            (time_hi_and_version & 0xff) as u8,
            clock_seq_hi_and_reserved,
            clock_seq_low,
            node[0],
            node[1],
            node[2],
            node[3],
            node[4],
            node[5],
        ])
    }

    /// Raw bytes (wire order).
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// QEMU `qemu_uuid_is_null`.
    pub fn is_nil(&self) -> bool {
        self.0 == [0u8; 16]
    }

    /// QEMU `qemu_uuid_parse`: strict dashed-hex validation then decode.
    pub fn parse(s: &str) -> Result<Uuid, String> {
        if !uuid_is_valid(s) {
            return Err(format!("invalid UUID string: {s}"));
        }
        let hex = |chars: &[u8]| -> u8 {
            let hi = (chars[0] as char).to_digit(16).unwrap() as u8;
            let lo = (chars[1] as char).to_digit(16).unwrap() as u8;
            (hi << 4) | lo
        };
        let b = s.as_bytes();
        let mut out = [0u8; 16];
        let mut pos = 0usize;
        let mut i = 0usize;
        while i < UUID_STR_LEN {
            if i == 8 || i == 13 || i == 18 || i == 23 {
                i += 1; // '-'
                continue;
            }
            out[pos] = hex(&b[i..i + 2]);
            pos += 1;
            i += 2;
        }
        Ok(Uuid(out))
    }

    /// QEMU `qemu_uuid_bswap`: swap the BE time fields to LE and back.
    pub fn bswap(&self) -> Uuid {
        Uuid([
            self.0[3], self.0[2], self.0[1], self.0[0], // time_low
            self.0[5], self.0[4], // time_mid
            self.0[7], self.0[6], // time_hi_and_version
            self.0[8], self.0[9], self.0[10], self.0[11], self.0[12], self.0[13],
            self.0[14], self.0[15],
        ])
    }

    /// QEMU `qemu_uuid_hash` (djb2).
    pub fn hash(&self) -> u32 {
        let mut h: u32 = 5381;
        for &b in &self.0 {
            h = (h << 5).wrapping_add(h).wrapping_add(b as u32);
        }
        h
    }
}

/// QEMU `qemu_uuid_is_valid` (helper exposed for validation-only uses).
fn uuid_is_valid(s: &str) -> bool {
    if s.len() != UUID_STR_LEN {
        return false;
    }
    for (i, c) in s.chars().enumerate() {
        if i == 8 || i == 13 || i == 18 || i == 23 {
            if c != '-' {
                return false;
            }
        } else if !c.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

impl fmt::Display for Uuid {
    /// QEMU `UUID_FMT` output: lowercase, dashed, in wire order.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let u = &self.0;
        write!(
            f,
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-\
             {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7], u[8], u[9], u[10], u[11], u[12],
            u[13], u[14], u[15]
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "4a61a2b1-d0a9-4c96-a4a0-3d4f3c93b25f";

    #[test]
    fn parse_format_roundtrip() {
        let u = Uuid::parse(SAMPLE).unwrap();
        assert_eq!(u.to_string(), SAMPLE);
        // Uppercase accepted like upstream (hex digits case-insensitive).
        let u2 = Uuid::parse(&SAMPLE.to_uppercase()).unwrap();
        assert_eq!(u, u2);
        assert_eq!(u.to_string(), u2.to_string());
    }

    #[test]
    fn parse_rejects_invalid() {
        assert!(Uuid::parse("").is_err());
        assert!(Uuid::parse("4a61a2b1d0a94c96a4a03d4f3c93b25f").is_err()); // no dashes
        assert!(Uuid::parse("4a61a2b1_d0a9-4c96-a4a0-3d4f3c93b25f").is_err());
        assert!(Uuid::parse("4a61a2b1-d0a9-4c96-a4a0-3d4f3c93b25").is_err()); // short
        assert!(Uuid::parse("4a61a2b1-d0a9-4c96-a4a0-3d4f3c93b25z").is_err());
    }

    #[test]
    fn fields_and_bswap() {
        let u = Uuid::from_fields(0x0011_2233, 0x4455, 0x6677, 0x88, 0x99, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(
            u.to_string(),
            "00112233-4455-6677-8899-aabbccddeeff"
        );
        assert_eq!(u.as_bytes()[0], 0x00);
        // bswap() swaps only the time fields (QEMU qemu_uuid_bswap).
        let swapped = u.bswap();
        assert_eq!(swapped.as_bytes()[0..4], [0x33, 0x22, 0x11, 0x00]);
        assert_eq!(swapped.as_bytes()[8..], u.as_bytes()[8..]);
        assert_eq!(swapped.bswap(), u);
    }

    #[test]
    fn nil_and_hash() {
        let n = Uuid::nil();
        assert!(n.is_nil());
        assert_eq!(n.to_string(), "00000000-0000-0000-0000-000000000000");
        assert!(!Uuid::from_bytes([1u8; 16]).is_nil());
        // djb2 of nil = same as C loop starting at 5381 with zero bytes.
        let mut h: u32 = 5381;
        for _ in 0..16 {
            h = (h << 5).wrapping_add(h);
        }
        assert_eq!(n.hash(), h);
    }
}
