//! Port of libqemuutil `include/qemu/bitops.h`.

/// Return the number of bits set (popcount), as `ctpop32` in C.
pub fn ctpop32(x: u32) -> u32 {
    x.count_ones()
}

/// Extract `len` bits starting at `start` (QEMU `extract32` semantics).
pub const fn extract32(value: u32, start: u32, len: u32) -> u32 {
    assert!(len != 0 && start + len <= 32, "extract32 range");
    (value >> start) & (!0u32 >> (32 - len))
}

/// QEMU `extract64`.
pub const fn extract64(value: u64, start: u32, len: u32) -> u64 {
    assert!(len != 0 && start + len <= 64, "extract64 range");
    (value >> start) & (!0u64 >> (64 - len))
}

/// QEMU `deposit32`: insert `field` into `value` at `start..start+len`.
pub fn deposit32(value: u32, start: u32, len: u32, field: u32) -> u32 {
    assert!(len != 0 && start + len <= 32, "deposit32 range");
    let mask = if len == 32 { u32::MAX } else { ((1u32 << len) - 1) << start };
    (value & !mask) | ((field << start) & mask)
}

/// QEMU `deposit64`.
pub fn deposit64(value: u64, start: u32, len: u32, field: u64) -> u64 {
    assert!(len != 0 && start + len <= 64, "deposit64 range");
    let mask = if len == 64 { u64::MAX } else { ((1u64 << len) - 1) << start };
    (value & !mask) | ((field << start) & mask)
}

/// ROL/ROR as used by MMIO models and crypto glue.
pub fn rol32(x: u32, n: u32) -> u32 {
    x.rotate_left(n & 31)
}
pub fn ror32(x: u32, n: u32) -> u32 {
    x.rotate_right(n & 31)
}

/// `BIT(n)` / `GENMASK(h, l)` helpers every Apple device model uses.
pub const fn bit(n: u32) -> u64 {
    1u64 << n
}
pub const fn genmask(high: u32, low: u32) -> u64 {
    assert!(high >= low && high < 64);
    ((1u64 << (high - low + 1)) - 1) << low
}

/// Find first (least-significant) set bit, or None (ffs semantics).
pub fn ffs32(x: u32) -> Option<u32> {
    if x == 0 { None } else { Some(x.trailing_zeros()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_deposit_roundtrip() {
        let v = 0xDEAD_BEEF_u32;
        assert_eq!(extract32(v, 16, 8), 0xAD); // bits 16..23
        assert_eq!(extract32(v, 24, 8), 0xDE); // bits 24..31
        assert_eq!(extract32(v, 0, 4), 0xF);
        let merged = deposit32(0, 8, 8, 0x42);
        assert_eq!(merged, 0x4200);
        assert_eq!(extract32(deposit32(v, 4, 8, 0x77), 4, 8), 0x77);
    }

    #[test]
    fn extract64_high() {
        let v = 0x8000_0000_0000_0001_u64;
        assert_eq!(extract64(v, 63, 1), 1);
        assert_eq!(extract64(v, 0, 1), 1);
    }

    #[test]
    fn masks_and_ffs() {
        assert_eq!(bit(3), 8);
        assert_eq!(genmask(7, 4), 0xF0);
        assert_eq!(ffs32(0x40), Some(6));
        assert_eq!(ffs32(0), None);
        assert_eq!(rol32(0x8000_0001, 1), 3);
    }
}
