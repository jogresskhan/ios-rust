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
    if high == 63 {
        u64::MAX << low
    } else {
        ((1u64 << (high + 1)) - 1) << low
    }
}

/// Find first (least-significant) set bit, or None (ffs semantics).
pub fn ffs32(x: u32) -> Option<u32> {
    if x == 0 { None } else { Some(x.trailing_zeros()) }
}

// ---------------------------------------------------------------------------
// Word-array bit ops (upstream set_bit/clear_bit/test_bit over `long *`)
// ---------------------------------------------------------------------------

/// `unsigned long` width of the word-array bit helpers (QEMU assumes 64-bit
/// hosts; `BIT_WORD(nr)` = `nr / 64`).
pub const BITS_PER_LONG: u32 = 64;

/// Inclusive `nbits`-wide mask starting at `start_bit` inside one u64 word
/// (helper shared with the `bitmap` module; clamped to the word).
pub const fn make_64bit_mask(start_bit: u32, nbits: u32) -> u64 {
    let start = start_bit.min(64);
    let len = nbits.min(64 - start);
    if len == 0 {
        return 0;
    }
    let ones = if len == 64 { u64::MAX } else { (1u64 << len) - 1 };
    ones << start
}

/// QEMU `set_bit(nr, addr)`: set bit `nr` of a u64 word array (LSB-first).
#[inline]
pub fn set_bit(nr: usize, addr: &mut [u64]) {
    addr[nr / BITS_PER_LONG as usize] |= 1u64 << (nr % BITS_PER_LONG as usize);
}

/// QEMU `clear_bit(nr, addr)`.
#[inline]
pub fn clear_bit(nr: usize, addr: &mut [u64]) {
    addr[nr / BITS_PER_LONG as usize] &= !(1u64 << (nr % BITS_PER_LONG as usize));
}

/// QEMU `test_bit(nr, addr)`.
#[inline]
pub fn test_bit(nr: usize, addr: &[u64]) -> bool {
    addr[nr / BITS_PER_LONG as usize] & (1u64 << (nr % BITS_PER_LONG as usize)) != 0
}

// ---------------------------------------------------------------------------
// Sign-extended field extraction (upstream sextract32/64)
// ---------------------------------------------------------------------------

/// QEMU `sextract32`: extract `len` bits at `start`, sign-extended to i32.
pub const fn sextract32(value: u32, start: u32, len: u32) -> i32 {
    assert!(len != 0 && start + len <= 32, "sextract32 range");
    let shift = 32 - start - len;
    ((value << shift) as i32) >> (32 - len)
}

/// QEMU `sextract64`.
pub const fn sextract64(value: u64, start: u32, len: u32) -> i64 {
    assert!(len != 0 && start + len <= 64, "sextract64 range");
    let shift = 64 - start - len;
    ((value << shift) as i64) >> (64 - len)
}

// ---------------------------------------------------------------------------
// Count/rotate helpers (upstream clz/ctz/revbit/rot families)
// ---------------------------------------------------------------------------

/// QEMU `clz32` (0 yields 32, like the upstream helpers).
pub fn clz32(x: u32) -> u32 {
    x.leading_zeros()
}
/// QEMU `clz64`.
pub fn clz64(x: u64) -> u32 {
    x.leading_zeros()
}
/// QEMU `ctz32` (0 yields 32).
pub fn ctz32(x: u32) -> u32 {
    x.trailing_zeros()
}
/// QEMU `ctz64`.
pub fn ctz64(x: u64) -> u32 {
    x.trailing_zeros()
}
/// QEMU `revbit32` (`revbit32 = rbit`): reverse all 32 bits.
pub fn revbit32(x: u32) -> u32 {
    x.reverse_bits()
}
/// QEMU `revbit32_64`: reverse all 64 bits.
pub fn revbit64(x: u64) -> u64 {
    x.reverse_bits()
}
/// 64-bit rotate left (`rol32` is above; devices also rotate words).
pub fn rol64(x: u64, n: u32) -> u64 {
    x.rotate_left(n & 63)
}
/// 64-bit rotate right.
pub fn ror64(x: u64, n: u32) -> u64 {
    x.rotate_right(n & 63)
}

/// QEMU `is_power_of_2` (0 is not a power of two).
pub const fn is_power_of_2(x: u64) -> bool {
    x != 0 && (x & (x - 1)) == 0
}

/// QEMU `pow2ceil`: smallest power of two `>= value` (1 for 0/1; saturates
/// at `u64::MAX` where the C helper would overflow).
pub fn pow2ceil(value: u64) -> u64 {
    if value <= 1 {
        return 1;
    }
    if is_power_of_2(value) {
        return value;
    }
    match 64u32.checked_sub((value - 1).leading_zeros()) {
        Some(shift) if shift < 64 => 1u64 << shift,
        _ => u64::MAX,
    }
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
        assert_eq!(genmask(63, 0), u64::MAX); // must not shift by 64
        assert_eq!(ffs32(0x40), Some(6));
        assert_eq!(ffs32(0), None);
        assert_eq!(rol32(0x8000_0001, 1), 3);
    }

    #[test]
    fn word_array_bits() {
        let mut words = [0u64; 2];
        set_bit(0, &mut words);
        set_bit(63, &mut words);
        set_bit(70, &mut words);
        assert!(test_bit(0, &words) && test_bit(63, &words) && test_bit(70, &words));
        assert!(!test_bit(1, &words));
        clear_bit(63, &mut words);
        assert!(!test_bit(63, &words));
        assert_eq!(make_64bit_mask(60, 8), 0xF000_0000_0000_0000); // clamped
        assert_eq!(make_64bit_mask(0, 64), u64::MAX);
        assert_eq!(make_64bit_mask(4, 0), 0);
    }

    #[test]
    fn sign_extract_clz_ctz_rev() {
        // -1 stored in an 8-bit field reads back as -1.
        assert_eq!(sextract32(0xFF, 0, 8), -1);
        assert_eq!(sextract32(0x7F, 0, 8), 127);
        assert_eq!(sextract64(0x8000u64, 0, 16), -32768);
        assert_eq!(clz32(0), 32);
        assert_eq!(clz32(1), 31);
        assert_eq!(ctz64(0), 64);
        assert_eq!(ctz64(0x10), 4);
        assert_eq!(revbit32(0b1), 0x8000_0000);
        assert_eq!(rol64(1, 64), 1);
        assert_eq!(ror64(3, 1), 0x8000_0000_0000_0001);
    }

    #[test]
    fn pow2_helpers() {
        assert!(is_power_of_2(1) && is_power_of_2(4096));
        assert!(!is_power_of_2(0) && !is_power_of_2(4095));
        assert_eq!(pow2ceil(0), 1);
        assert_eq!(pow2ceil(1), 1);
        assert_eq!(pow2ceil(4095), 4096);
        assert_eq!(pow2ceil(4096), 4096);
        assert_eq!(pow2ceil(u64::MAX), u64::MAX); // saturating, no panic
        assert_eq!(BITS_PER_LONG, 64);
    }
}
