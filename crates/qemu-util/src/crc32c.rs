//! crc32c — libqemuutil port (`qemu/util/crc32c.c` + `qemu/include/qemu/crc32c.h`).
//!
//! Upstream: "Castagnoli CRC32C Checksum Algorithm", Copyright (c) 2013 Red
//! Hat, Inc. (Jeff Cody), based on the Linux kernel crypto module,
//! GPL-2.0-or-later. Polynomial `0x1EDC6F41`, reflected in/out.
//!
//! Upstream contract: `crc32c(crc, data, len)` processes `crc` as the running
//! (pre-inverted) state and applies `^ 0xffffffff` at the end, so callers
//! start with `0xffffffff` and chain with `crc32c(prev, ...) ^ 0xffffffff`
//! (see `iov_crc32c`). [`crc32c`] here is the one-shot standard CRC-32C
//! (`crc32c(0xffffffff, data, len)`), and [`crc32c_update`] is the upstream
//! raw call for streaming.

/// The CRC-32C (Castagnoli) table, generated at compile time exactly like the
/// upstream static table (poly 0x1EDC6F41 reflected = 0x82F63B78).
static CRC32C_TABLE: [u32; 256] = build_table();

const fn build_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut crc = i as u32;
        let mut k = 0;
        while k < 8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0x82f6_3b78 } else { crc >> 1 };
            k += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

/// QEMU `crc32c` raw call: running state in `crc` (start with `0xffffffff`),
/// final `^0xffffffff` applied as upstream.
pub fn crc32c_update(crc: u32, data: &[u8]) -> u32 {
    let mut crc = crc;
    for &b in data {
        crc = CRC32C_TABLE[((crc ^ b as u32) & 0xff) as usize] ^ (crc >> 8);
    }
    crc ^ 0xffff_ffff
}

/// One-shot standard CRC-32C of `data` (Castagnoli, reflected).
/// Check value: `crc32c(b"123456789") == 0xE3069283`.
pub fn crc32c(data: &[u8]) -> u32 {
    crc32c_update(0xffff_ffff, data)
}

/// QEMU `iov_crc32c`: CRC across a scatter-gather vector (chained through
/// `^ 0xffffffff` between elements exactly like upstream).
pub fn iov_crc32c(crc: u32, iov: &[crate::iov::IoVec]) -> u32 {
    let mut crc = crc;
    for v in iov {
        crc = crc32c_update(crc, &v.data) ^ 0xffff_ffff;
    }
    crc ^ 0xffff_ffff
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_value() {
        // Standard CRC-32C check value from RFC 3720 / Castagnoli.
        assert_eq!(crc32c(b"123456789"), 0xe306_9283);
        assert_eq!(crc32c(b""), 0x0000_0000);
        assert_eq!(crc32c(b"a"), 0xc1d0_4330);
    }

    #[test]
    fn table_matches_upstream_entries() {
        // Spot-check against the literal upstream table.
        assert_eq!(CRC32C_TABLE[0], 0x0000_0000);
        assert_eq!(CRC32C_TABLE[1], 0xf26b_8303);
        assert_eq!(CRC32C_TABLE[2], 0xe13b_70f7);
        assert_eq!(CRC32C_TABLE[15], 0x5e13_3c24);
        assert_eq!(CRC32C_TABLE[255], 0xad7d_5351);
    }

    #[test]
    fn streaming_matches_one_shot() {
        let data = b"The quick brown fox jumps over the lazy dog";
        let (a, b) = data.split_at(10);
        // Chain exactly like iov_crc32c does.
        let chained = crc32c_update(crc32c_update(0xffff_ffff, a) ^ 0xffff_ffff, b);
        assert_eq!(chained, crc32c(data));
    }

    #[test]
    fn iov_crc32c_matches_flat() {
        let flat = b"scatter gather bytes";
        let iov = vec![
            crate::iov::IoVec { offset: 0, data: flat[..7].to_vec() },
            crate::iov::IoVec { offset: 7, data: flat[7..12].to_vec() },
            crate::iov::IoVec { offset: 12, data: flat[12..].to_vec() },
        ];
        assert_eq!(iov_crc32c(0xffff_ffff, &iov), crc32c(flat));
    }
}
