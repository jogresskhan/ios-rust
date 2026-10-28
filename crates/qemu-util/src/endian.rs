//! endian — libqemuutil port (`qemu/include/qemu/bswap.h` load/store helpers).
//!
//! Upstream exposes `ld{w,l,q}_{le,be}_p` / `st{w,l,q}_{le,be}_p` families
//! (LGPL-2.1-or-later, Fabrice Bellard & friends) which read/write unaligned
//! 16/32/64-bit integers from byte buffers in a fixed endianness. The Rust
//! equivalents operate on slices; out-of-bounds access panics exactly like a
//! failed upstream assertion rather than being UB.

/// QEMU `bswap16`.
#[inline]
pub const fn bswap16(v: u16) -> u16 {
    v.swap_bytes()
}

/// QEMU `bswap32`.
#[inline]
pub const fn bswap32(v: u32) -> u32 {
    v.swap_bytes()
}

/// QEMU `bswap64`.
#[inline]
pub const fn bswap64(v: u64) -> u64 {
    v.swap_bytes()
}

// ---------------------------------------------------------------------------
// Loads (ld*_p)
// ---------------------------------------------------------------------------

/// QEMU `ldwu_le_p`: little-endian 16-bit load from `buf[offset..]`.
#[inline]
pub fn ldle16(buf: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([buf[offset], buf[offset + 1]])
}

/// QEMU `ldl_le_p`: little-endian 32-bit load.
#[inline]
pub fn ldle32(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(buf[offset..offset + 4].try_into().expect("ldle32 OOB"))
}

/// QEMU `ldq_le_p`: little-endian 64-bit load.
#[inline]
pub fn ldle64(buf: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(buf[offset..offset + 8].try_into().expect("ldle64 OOB"))
}

/// QEMU `ldwu_be_p`: big-endian 16-bit load.
#[inline]
pub fn ldbe16(buf: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([buf[offset], buf[offset + 1]])
}

/// QEMU `ldl_be_p`: big-endian 32-bit load.
#[inline]
pub fn ldbe32(buf: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(buf[offset..offset + 4].try_into().expect("ldbe32 OOB"))
}

/// QEMU `ldq_be_p`: big-endian 64-bit load.
#[inline]
pub fn ldbe64(buf: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(buf[offset..offset + 8].try_into().expect("ldbe64 OOB"))
}

// ---------------------------------------------------------------------------
// Stores (st*_p)
// ---------------------------------------------------------------------------

/// QEMU `stw_le_p`: little-endian 16-bit store into `buf[offset..]`.
#[inline]
pub fn stle16(buf: &mut [u8], offset: usize, v: u16) {
    buf[offset..offset + 2].copy_from_slice(&v.to_le_bytes());
}

/// QEMU `stl_le_p`: little-endian 32-bit store.
#[inline]
pub fn stle32(buf: &mut [u8], offset: usize, v: u32) {
    buf[offset..offset + 4].copy_from_slice(&v.to_le_bytes());
}

/// QEMU `stq_le_p`: little-endian 64-bit store.
#[inline]
pub fn stle64(buf: &mut [u8], offset: usize, v: u64) {
    buf[offset..offset + 8].copy_from_slice(&v.to_le_bytes());
}

/// QEMU `stw_be_p`: big-endian 16-bit store.
#[inline]
pub fn stbe16(buf: &mut [u8], offset: usize, v: u16) {
    buf[offset..offset + 2].copy_from_slice(&v.to_be_bytes());
}

/// QEMU `stl_be_p`: big-endian 32-bit store.
#[inline]
pub fn stbe32(buf: &mut [u8], offset: usize, v: u32) {
    buf[offset..offset + 4].copy_from_slice(&v.to_be_bytes());
}

/// QEMU `stq_be_p`: big-endian 64-bit store.
#[inline]
pub fn stbe64(buf: &mut [u8], offset: usize, v: u64) {
    buf[offset..offset + 8].copy_from_slice(&v.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn little_endian_roundtrip() {
        let mut buf = [0u8; 16];
        stle16(&mut buf, 0, 0x1234);
        stle32(&mut buf, 2, 0xdead_beef);
        stle64(&mut buf, 6, 0x0123_4567_89ab_cdef);
        assert_eq!(&buf[0..2], &[0x34, 0x12]);
        assert_eq!(&buf[2..6], &[0xef, 0xbe, 0xad, 0xde]);
        assert_eq!(&buf[6..14], &[0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01]);
        assert_eq!(ldle16(&buf, 0), 0x1234);
        assert_eq!(ldle32(&buf, 2), 0xdead_beef);
        assert_eq!(ldle64(&buf, 6), 0x0123_4567_89ab_cdef);
    }

    #[test]
    fn big_endian_roundtrip() {
        let mut buf = [0u8; 16];
        stbe16(&mut buf, 0, 0x1234);
        stbe32(&mut buf, 2, 0xdead_beef);
        stbe64(&mut buf, 6, 0x0123_4567_89ab_cdef);
        assert_eq!(&buf[0..2], &[0x12, 0x34]);
        assert_eq!(&buf[2..6], &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(&buf[6..14], &[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
        assert_eq!(ldbe16(&buf, 0), 0x1234);
        assert_eq!(ldbe32(&buf, 2), 0xdead_beef);
        assert_eq!(ldbe64(&buf, 6), 0x0123_4567_89ab_cdef);
    }

    #[test]
    fn unaligned_access_and_bswap() {
        // QEMU ld/st are unaligned-safe; offsets 1,3,5 are deliberately odd.
        let mut buf = [0u8; 9];
        stle64(&mut buf, 1, 0x1122_3344_5566_7788);
        assert_eq!(ldle64(&buf, 1), 0x1122_3344_5566_7788);
        stbe32(&mut buf, 3, 0xaabb_ccdd);
        assert_eq!(ldbe32(&buf, 3), 0xaabb_ccdd);
        assert_eq!(bswap16(0x1234), 0x3412);
        assert_eq!(bswap32(0x1234_5678), 0x7856_3412);
        assert_eq!(bswap64(0x0123_4567_89ab_cdef), 0xefcd_ab89_6745_2301);
    }

    #[test]
    fn le_be_agree_on_canonical_bytes() {
        let mut le = [0u8; 4];
        let mut be = [0u8; 4];
        stle32(&mut le, 0, 0x0102_0304);
        stbe32(&mut be, 0, 0x0102_0304);
        // LE emits value bytes reversed relative to BE.
        assert_eq!(le, [0x04, 0x03, 0x02, 0x01]);
        assert_eq!(be, [0x01, 0x02, 0x03, 0x04]);
    }
}
