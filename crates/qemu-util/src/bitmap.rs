//! bitmap — libqemuutil port (`qemu/util/bitmap.c` + `qemu/include/qemu/bitmap.h`, subset).
//!
//! Upstream: "Bitmaps" (LGPL-2.1-or-later, from Linux kernel). QEMU bitmaps
//! are arrays of `unsigned long` (64-bit words here); bit `n` lives in word
//! `n / 64`, bit `n % 64`, LSB-first. `set_range`/`clear_range` mirror
//! `bitmap_set`/`bitmap_clear` (inclusive start, exclusive end), and the
//! find helpers return the bitmap size when nothing is found (upstream
//! convention), expressed as `Option<usize>` here.
//!
//! `from_bytes`/`to_bytes` use the LSB-first little-endian bit order that
//! matches the word layout on disk-style serialisations.

use crate::bitops::{self, BITS_PER_LONG};

/// Word-backed bit map — QEMU `unsigned long *` + size.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Bitmap {
    words: Vec<u64>,
    bits: usize,
}

impl Bitmap {
    /// Allocate a bitmap holding `bits` bits (zero-initialised).
    pub fn new(bits: usize) -> Self {
        let words = bits.div_ceil(BITS_PER_LONG as usize);
        Bitmap { words: vec![0; words], bits }
    }

    /// Number of addressable bits.
    pub fn len(&self) -> usize {
        self.bits
    }

    pub fn is_empty(&self) -> bool {
        self.bits == 0
    }

    /// Raw word access (QEMU `BIT_WORD` indexing).
    pub fn words(&self) -> &[u64] {
        &self.words
    }

    /// QEMU `bitmap_set`: set bits `[start, start + nbits)`.
    pub fn set_range(&mut self, start: usize, nbits: usize) {
        let end = start + nbits;
        assert!(end <= self.bits, "bitmap_set out of bounds");
        let mut i = start;
        while i < end {
            let w = i / 64;
            let bit = i % 64;
            let take = (64 - bit).min(end - i);
            let mask = (bitops::make_64bit_mask(bit as u32, take as u32)) as u64;
            self.words[w] |= mask;
            i += take;
        }
    }

    /// QEMU `bitmap_clear`: clear bits `[start, start + nbits)`.
    pub fn clear_range(&mut self, start: usize, nbits: usize) {
        let end = start + nbits;
        assert!(end <= self.bits, "bitmap_clear out of bounds");
        let mut i = start;
        while i < end {
            let w = i / 64;
            let bit = i % 64;
            let take = (64 - bit).min(end - i);
            let mask = !(bitops::make_64bit_mask(bit as u32, take as u32) as u64);
            self.words[w] &= mask;
            i += take;
        }
    }

    /// QEMU `set_bit` on the bitmap.
    pub fn set(&mut self, bit: usize) {
        assert!(bit < self.bits, "bitmap_set out of bounds");
        self.set_range(bit, 1);
    }

    /// QEMU `clear_bit` on the bitmap.
    pub fn clear(&mut self, bit: usize) {
        assert!(bit < self.bits, "bitmap_clear out of bounds");
        self.clear_range(bit, 1);
    }

    /// QEMU `test_bit`: `get(bit).unwrap_or(false)`-style query.
    pub fn test(&self, bit: usize) -> bool {
        if bit >= self.bits {
            return false;
        }
        (self.words[bit / 64] >> (bit % 64)) & 1 != 0
    }

    /// Alias of [`Bitmap::test`] (QEMU has both spellings in users).
    pub fn get(&self, bit: usize) -> bool {
        self.test(bit)
    }

    /// QEMU `find_next_zero_bit` from bit 0: first clear bit.
    /// `None` when every bit is set (upstream returns `size`).
    pub fn find_first_zero(&self) -> Option<usize> {
        self.find_next_zero(0)
    }

    /// QEMU `find_next_zero_bit`: first clear bit at or after `from`.
    pub fn find_next_zero(&self, from: usize) -> Option<usize> {
        (from..self.bits).find(|&i| !self.test(i))
    }

    /// QEMU `find_first_bit`: first set bit, `None` when all clear.
    pub fn first_set(&self) -> Option<usize> {
        (0..self.bits).find(|&i| self.test(i))
    }

    /// Build from bytes (LSB-first bit order, LE words).
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let bits = bytes.len() * 8;
        let mut bm = Bitmap::new(bits);
        for (i, &b) in bytes.iter().enumerate() {
            if b != 0 {
                for k in 0..8 {
                    if b & (1 << k) != 0 {
                        bm.set(i * 8 + k);
                    }
                }
            }
        }
        bm
    }

    /// Serialise back to bytes (same bit order as `from_bytes`).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![0u8; self.bits.div_ceil(8)];
        for i in 0..self.bits {
            if self.test(i) {
                out[i / 8] |= 1 << (i % 8);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_test_clear() {
        let mut bm = Bitmap::new(70);
        bm.set(0);
        bm.set(63);
        bm.set(64);
        bm.set(69);
        assert!(bm.test(0) && bm.test(63) && bm.test(64) && bm.test(69));
        assert!(!bm.test(1) && !bm.test(62));
        bm.clear(63);
        assert!(!bm.test(63));
        assert_eq!(bm.words().len(), 2);
    }

    #[test]
    fn ranges() {
        let mut bm = Bitmap::new(128);
        bm.set_range(10, 20); // [10, 30)
        assert!(bm.test(10) && bm.test(29));
        assert!(!bm.test(9) && !bm.test(30));
        bm.set_range(120, 8);
        bm.clear_range(11, 18); // leaves 10 and 29
        assert!(bm.test(10) && bm.test(29));
        assert!(!bm.test(11) && !bm.test(28));
        assert!(bm.test(127));
    }

    #[test]
    fn find_first() {
        let mut bm = Bitmap::new(64);
        assert_eq!(bm.find_first_zero(), Some(0));
        assert_eq!(bm.first_set(), None);
        bm.set_range(0, 5);
        assert_eq!(bm.first_set(), Some(0));
        assert_eq!(bm.find_first_zero(), Some(5));
        bm.set_range(5, 59);
        assert_eq!(bm.find_first_zero(), None); // full bitmap
        bm.clear(40);
        assert_eq!(bm.find_first_zero(), Some(40));
        assert_eq!(bm.find_next_zero(41), None);
    }

    #[test]
    fn bytes_roundtrip() {
        let bm = Bitmap::from_bytes(&[0b1010_1010, 0x00, 0b0000_0001, 0x80]);
        assert!(bm.test(1) && bm.test(3) && bm.test(5) && bm.test(7));
        assert!(bm.test(16));
        assert!(bm.test(31));
        assert_eq!(bm.len(), 32);
        assert_eq!(bm.to_bytes(), vec![0b1010_1010, 0x00, 0b0000_0001, 0x80]);
    }
}
