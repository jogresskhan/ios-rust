//! crc16 — libqemuutil port (`qemu/util/crc-ccitt.c` + `qemu/include/qemu/crc-ccitt.h`).
//!
//! Upstream: Copyright (c) 2021 Wind River Systems, Inc. (Bin Meng), from
//! Linux kernel v5.10 `lib/crc-ccitt.c`, GPL-2.0-only. Two variants exist:
//!
//! - `crc_ccitt` (reflected table, entry 128 = 0x8408, initial value 0) —
//!   the kernel "crc-ccitt" variant;
//! - `crc_ccitt_false` (MSB-first table, poly 0x1021, initial value 0xFFFF) —
//!   the "CCITT-FALSE" variant.
//!
//! Apple's SPMI/serial paths use CCITT-FALSE, so [`crc16_ccitt`] is the
//! FALSE variant seeded with 0xFFFF (matching `crc_ccitt_false(0xFFFF, ...)`),
//! with [`crc16_ccitt_byte`]/[`crc16_ccitt_update`] for streaming and the
//! kernel-style reflected variant exposed as [`crc16_ccitt_kernel`].

/// CRC-CCITT-FALSE table (poly 0x1021, MSB-first), generated like upstream.
static CRC16_CCITT_FALSE_TABLE: [u16; 256] = build_false_table();

const fn build_false_table() -> [u16; 256] {
    let mut table = [0u16; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut crc = (i as u16) << 8;
        let mut k = 0;
        while k < 8 {
            crc = if crc & 0x8000 != 0 { (crc << 1) ^ 0x1021 } else { crc << 1 };
            k += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

/// Reflected CRC-CCITT table (poly 0x8408, as in upstream `crc_ccitt_table`),
/// generated at compile time.
static CRC16_CCITT_TABLE: [u16; 256] = build_reflected_table();

const fn build_reflected_table() -> [u16; 256] {
    let mut table = [0u16; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut crc = i as u16;
        let mut k = 0;
        while k < 8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0x8408 } else { crc >> 1 };
            k += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

/// QEMU `crc_ccitt_false_byte`: `(crc << 8) ^ table[(crc >> 8) ^ c]`.
#[inline]
pub fn crc16_ccitt_false_byte(crc: u16, c: u8) -> u16 {
    (crc << 8) ^ CRC16_CCITT_FALSE_TABLE[((crc >> 8) ^ (c as u16)) as usize]
}

/// QEMU `crc_ccitt_byte`: `(crc >> 8) ^ table[(crc ^ c) & 0xff]` (reflected).
#[inline]
pub fn crc16_ccitt_kernel_byte(crc: u16, c: u8) -> u16 {
    (crc >> 8) ^ CRC16_CCITT_TABLE[((crc ^ c as u16) & 0xff) as usize]
}

/// Apple SPMI/serial CRC: CCITT-FALSE seeded with 0xFFFF —
/// upstream `crc_ccitt_false(0xFFFF, buffer, len)`.
pub fn crc16_ccitt(data: &[u8]) -> u16 {
    crc16_ccitt_update(0xffff, data)
}

/// Streaming CCITT-FALSE: feed the running value (start `0xffff`).
pub fn crc16_ccitt_update(crc: u16, data: &[u8]) -> u16 {
    let mut crc = crc;
    for &c in data {
        crc = crc16_ccitt_false_byte(crc, c);
    }
    crc
}

/// The Linux-kernel `crc_ccitt` variant (reflected, seeded 0) —
/// upstream `crc_ccitt(0, buffer, len)`.
pub fn crc16_ccitt_kernel(data: &[u8]) -> u16 {
    let mut crc = 0u16;
    for &c in data {
        crc = crc16_ccitt_kernel_byte(crc, c);
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_values() {
        // Standard CCITT-FALSE check value.
        assert_eq!(crc16_ccitt(b"123456789"), 0x29b1);
        assert_eq!(crc16_ccitt(b""), 0xffff);
        // Kernel reflected variant check value (crc-ccitt).
        assert_eq!(crc16_ccitt_kernel(b"123456789"), 0x31c3);
    }

    #[test]
    fn false_table_matches_upstream() {
        assert_eq!(CRC16_CCITT_FALSE_TABLE[0], 0x0000);
        assert_eq!(CRC16_CCITT_FALSE_TABLE[1], 0x1021);
        assert_eq!(CRC16_CCITT_FALSE_TABLE[2], 0x2042);
        assert_eq!(CRC16_CCITT_FALSE_TABLE[128], 0x8408);
        assert_eq!(CRC16_CCITT_FALSE_TABLE[255], 0x1ef0);
    }

    #[test]
    fn reflected_table_matches_upstream() {
        assert_eq!(CRC16_CCITT_TABLE[0], 0x0000);
        assert_eq!(CRC16_CCITT_TABLE[1], 0x1189);
        assert_eq!(CRC16_CCITT_TABLE[128], 0x8408);
        assert_eq!(CRC16_CCITT_TABLE[255], 0x0f78);
    }

    #[test]
    fn streaming_matches_one_shot() {
        let data = b"SPMI frame payload";
        let (a, b) = data.split_at(6);
        let chained = crc16_ccitt_update(crc16_ccitt_update(0xffff, a), b);
        assert_eq!(chained, crc16_ccitt(data));
    }
}
