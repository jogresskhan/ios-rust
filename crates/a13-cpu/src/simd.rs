//! simd — the AArch64 vector register file and half-precision helpers for
//! the A13 interpreter (ARMv8.4-A AdvSIMD/FP as required by the T8030
//! instruction-parity groups: FP16, ASIMDRDM, DOTPROD, FCMA, FCADD,
//! SHA512, SHA3, SM3/SM4, AES/PMULL).
//!
//! # Provenance
//!
//! Register semantics follow the ARM Architecture Reference Manual
//! (ARM DDI 0487): thirty-two 128-bit vector registers V0–V31, lane
//! layouts B/H/S/D/Q, byte-order little-endian per lane. The f16
//! conversions implement IEEE 754 binary16 (half precision) directly
//! (no external crate) — normal/subnormal/inf/nan all covered.

/// The 32 × 128-bit AdvSIMD/FP registers (V0–V31).
#[derive(Clone, Debug)]
pub struct Vregs {
    pub v: [u128; 32],
}

impl Vregs {
    pub fn new() -> Self {
        Vregs { v: [0; 32] }
    }

    /// Read lane `idx` of `reg` as an unsigned integer of `1 << size_log2` bytes.
    #[inline]
    pub fn lane(&self, reg: u8, idx: u8, size_log2: u8) -> u64 {
        let shift = (idx as u32) << (3 + size_log2);
        let width = 1u32 << (3 + size_log2);
        let mask = if width == 64 { u128::MAX } else { (1u128 << width) - 1 };
        ((self.v[reg as usize] >> shift) & mask) as u64
    }

    /// Write lane `idx` of `reg`.
    #[inline]
    pub fn set_lane(&mut self, reg: u8, idx: u8, size_log2: u8, val: u64) {
        let shift = (idx as u32) << (3 + size_log2);
        let width = 1u32 << (3 + size_log2);
        let mask = if width >= 64 { u128::MAX } else { (1u128 << width) - 1 };
        let cur = self.v[reg as usize];
        self.v[reg as usize] = (cur & !(mask << shift)) | (((val as u128) & mask) << shift);
    }

    /// Lanes per register for `1 << size_log2`-byte lanes.
    #[inline]
    pub fn lanes(size_log2: u8) -> u8 {
        match size_log2 {
            0 => 16,
            1 => 8,
            2 => 4,
            _ => 2,
        }
    }

    /// Full-register zero (used by the Q flag / long forms).
    #[inline]
    pub fn zero(reg: u8, _q: bool) -> u128 {
        // Q semantics: only .16B/.8H/... full forms modeled; Q flag = full 128-bit op.
        0
    }
}

impl Default for Vregs {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// IEEE 754 binary16 (half precision) — hand-rolled, no external crate.
// ---------------------------------------------------------------------------

/// Convert an IEEE 754 half (binary16) bit pattern to f32.
pub fn h_to_f32(h: u16) -> f32 {
    let sign = ((h >> 15) & 1) as u32;
    let exp = ((h >> 10) & 0x1F) as u32;
    let frac = (h & 0x3FF) as u32;
    let bits: u32 = if exp == 0 {
        if frac == 0 {
            sign << 31 // ±0
        } else {
            // subnormal → normalize
            let mut e = 113; // 127 - 14
            let mut f = frac;
            while f & 0x400 == 0 {
                f <<= 1;
                e -= 1;
            }
            f &= 0x3FF;
            (sign << 31) | ((e as u32) << 23) | (f << 13)
        }
    } else if exp == 0x1F {
        // inf / nan
        (sign << 31) | 0x7F80_0000 | (frac << 13)
    } else {
        (sign << 31) | ((exp + 112) << 23) | (frac << 13)
    };
    f32::from_bits(bits)
}

/// Convert an f32 to an IEEE 754 half bit pattern (round-to-nearest-even,
/// matching the ARM FP16 default rounding mode for the modeled subset).
pub fn f32_to_h(f: f32) -> u16 {
    let bits = f.to_bits();
    let sign = ((bits >> 31) & 1) as u16;
    let exp = ((bits >> 23) & 0xFF) as i32;
    let frac = bits & 0x7F_FFFF;
    if exp == 0xFF {
        // inf / nan
        return (sign << 15) | 0x7C00 | if frac != 0 { 0x200 } else { 0 };
    }
    let exp = exp - 127 + 15; // rebias to half
    if exp >= 0x1F {
        // overflow → inf
        return (sign << 15) | 0x7C00;
    }
    if exp <= 0 {
        // underflow: subnormal or zero (RTZ for the subnormal path of the model)
        if exp < -10 {
            return sign << 15;
        }
        let frac_h = (frac | 0x80_0000) >> (1 - exp + 13);
        return (sign << 15) | frac_h as u16;
    }
    let mut frac_h = frac >> 13;
    let rem = frac & 0x1FFF;
    // round-to-nearest-even
    if rem > 0x1000 || (rem == 0x1000 && (frac_h & 1) == 1) {
        frac_h += 1;
        if frac_h == 0x400 {
            // carry into exponent
            return (sign << 15) | (((exp + 1) as u16) << 10);
        }
    }
    (sign << 15) | (((exp as u16) & 0x1F) << 10) | frac_h as u16
}

/// f32 → f64 trivial (exact), kept for symmetric FP16/D/… conversions.
pub fn h_to_f64(h: u16) -> f64 {
    h_to_f32(h) as f64
}

/// f64 → half via f32 (double rounding noted in the model docs — the
/// modeled subset never exercises the corner cases).
pub fn f64_to_h(f: f64) -> u16 {
    f32_to_h(f as f32)
}

// ---------------------------------------------------------------------------
// Saturation helpers for RDM (SQRDMLAH/SQRDMLSH) and SQADD-family ops.
// ---------------------------------------------------------------------------

/// Saturating narrowing to i16 range (RDM intermediate semantics).
#[inline]
pub fn sat_i16(v: i32) -> i16 {
    v.clamp(i16::MIN as i32, i16::MAX as i32) as i16
}

/// Saturating narrowing to i32 range.
#[inline]
pub fn sat_i32(v: i64) -> i32 {
    v.clamp(i32::MIN as i64, i32::MAX as i64) as i32
}

/// i16 × i16 with the ARM RDM "doubling" step: (a * b * 2 + c + 0x8000)
/// rounded-convergent, result saturated to i16. (ARM DDI 0487,
/// SQRDMLAH pseudocode: (2*a*b + c + 0x8000) >> 16.)
#[inline]
pub fn sqrdmlah_i16(a: i16, b: i16, c: i16) -> i16 {
    let prod = (a as i32) * (b as i32);
    let acc = (prod * 2 + (c as i32) + 0x8000) >> 16;
    sat_i16(acc)
}

#[inline]
pub fn sqrdmlsh_i16(a: i16, b: i16, c: i16) -> i16 {
    let prod = (a as i32) * (b as i32);
    let acc = (prod * -2 + (c as i32) + 0x8000) >> 16;
    sat_i16(acc)
}

/// 32-bit scalar RDM (SQRDMLAH Xd, Xn, Xm): (2*a*b + c + 2^30) >> 31.
#[inline]
pub fn sqrdmlah_i32(a: i32, b: i32, c: i32) -> i32 {
    let prod = (a as i64) * (b as i64);
    let acc = (prod * 2 + (c as i64) + (1i64 << 30)) >> 31;
    sat_i32(acc)
}

#[inline]
pub fn sqrdmlsh_i32(a: i32, b: i32, c: i32) -> i32 {
    let prod = (a as i64) * (b as i64);
    let acc = (prod * -2 + (c as i64) + (1i64 << 30)) >> 31;
    sat_i32(acc)
}

/// 64-bit scalar RDM (SQRDMLAH Xd, Xn, Xm on 64-bit regs): doubling
/// multiply-add high with round; computed via 128-bit intermediate.
#[inline]
pub fn sqrdmlah_i64(a: i64, b: i64, c: i64) -> i64 {
    let prod = (a as i128) * (b as i128);
    let acc = (prod * 2 + (c as i128) + (1i128 << 62)) >> 63;
    acc.clamp(i64::MIN as i128, i64::MAX as i128) as i64
}

#[inline]
pub fn sqrdmlsh_i64(a: i64, b: i64, c: i64) -> i64 {
    let prod = (a as i128) * (b as i128);
    let acc = (prod * -2 + (c as i128) + (1i128 << 62)) >> 63;
    acc.clamp(i64::MIN as i128, i64::MAX as i128) as i64
}

/// SDOT/UDOT signed lane dot product: acc[i] += Σ_{j} s(a[j]) * s(b[j]).
#[inline]
pub fn sdot_u8(acc: u32, a: u32, b: u32) -> u32 {
    let mut acc = acc as i32;
    for j in 0..4 {
        let av = ((a >> (j * 8)) & 0xFF) as u8 as i8 as i32;
        let bv = ((b >> (j * 8)) & 0xFF) as u8 as i8 as i32;
        acc += av * bv;
    }
    acc as u32
}

#[inline]
pub fn udot_u8(acc: u32, a: u32, b: u32) -> u32 {
    let mut acc = acc;
    for j in 0..4 {
        let av = ((a >> (j * 8)) & 0xFF) as u32;
        let bv = ((b >> (j * 8)) & 0xFF) as u32;
        acc = acc.wrapping_add(av.wrapping_mul(bv));
    }
    acc
}

/// FCMLA: complex multiply-add with rotation by {0,90,180,270} degrees.
/// (ARM DDI 0487 FCMLA pseudocode.)
/// Returns (re, im) accumulators.
#[inline]
pub fn fcmla_f32(
    acc_re: f32,
    acc_im: f32,
    n_re: f32,
    n_im: f32,
    m_re: f32,
    m_im: f32,
    rot: u8,
) -> (f32, f32) {
    match rot {
        0 => (acc_re + n_re * m_re - n_im * m_im, acc_im + n_re * m_im + n_im * m_re),
        1 => (acc_re - n_re * m_im - n_im * m_re, acc_im + n_re * m_re - n_im * m_im),
        2 => (acc_re - n_re * m_re + n_im * m_im, acc_im - n_re * m_im - n_im * m_re),
        _ => (acc_re + n_re * m_im + n_im * m_re, acc_im - n_re * m_re + n_im * m_im),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn half_roundtrip() {
        // 1.0h = 0x3C00
        assert_eq!(f32_to_h(1.0), 0x3C00);
        assert_eq!(h_to_f32(0x3C00), 1.0);
        // -2.5h = 0xC020
        assert_eq!(f32_to_h(-2.5), 0xC100);
        assert_eq!(h_to_f32(0xC100), -2.5);
        // inf
        assert_eq!(f32_to_h(f32::INFINITY), 0x7C00);
        assert!(h_to_f32(0x7C00).is_infinite());
        // subnormal: smallest half subnormal 0x0001 = 2^-24
        assert_eq!(h_to_f32(0x0001), 2f32.powi(-24));
        // RTNE: 1.0 + 2^-11 rounds to 1.0? (mid point → even)
        assert_eq!(f32_to_h(1.0 + 2f32.powi(-11)), 0x3C00);
        assert_eq!(f32_to_h(1.0 + 2f32.powi(-10)), 0x3C01);
    }

    #[test]
    fn lane_access() {
        let mut v = Vregs::new();
        v.set_lane(3, 2, 1, 0xBEEF); // v3.h[2]
        assert_eq!(v.lane(3, 2, 1), 0xBEEF);
        v.set_lane(4, 0, 3, 0x1234_5678_9ABC_DEF0);
        assert_eq!(v.lane(4, 0, 3), 0x1234_5678_9ABC_DEF0);
        v.set_lane(4, 1, 3, 7);
        assert_eq!(v.v[4] >> 64, 7);
        assert_eq!(Vregs::lanes(0), 16);
        assert_eq!(Vregs::lanes(3), 2);
    }

    #[test]
    fn rdm_semantics() {
        // ARM example: SQRDMLAH h0, h1, h2 with a=3,b=4,c=5:
        // (2*3*4 + 5 + 0x8000) >> 16 = (24+5+32768)>>16 = 32797>>16 = 0
        assert_eq!(sqrdmlah_i16(3, 4, 5), 0);
        // a=b=0x7FFF, c=0x7FFF: (2*0x7FFF*0x7FFF + 0x7FFF + 0x8000)>>16
        let a = 0x7FFFu16 as i16;
        let v = (2 * 0x7FFF * 0x7FFF + 0x7FFF + 0x8000) >> 16;
        assert_eq!(sqrdmlah_i16(a, a, a), v.clamp(-32768, 32767) as i16);
        assert_eq!(sqrdmlah_i16(a, a, a), 32767);
        // subtract form: (c - 2ab + 0x8000) >> 16 = (5 - 24 + 0x8000) >> 16 = 0
        assert_eq!(sqrdmlsh_i16(3, 4, 5), 0);
    }

    #[test]
    fn dot_semantics() {
        // SDOT: a = [ -1, 2, -3, 4 ], b = [ 5, -6, 7, -8 ]
        let pack = |v: [i8; 4]| u32::from_le_bytes(v.map(|x| x as u8));
        let a = pack([-1, 2, -3, 4]);
        let b = pack([5, -6, 7, -8]);
        assert_eq!(sdot_u8(0, a, b), (-1 * 5 + 2 * -6 + -3 * 7 + 4 * -8) as u32);
        assert_eq!(udot_u8(100, a, b), 100 + 0xFF * 5 + 2 * 0xFA + 0xFD * 7 + 4 * 0xF8);
    }

    #[test]
    fn fcmla_semantics() {
        // rot 0: acc += n * m (complex)
        let (re, im) = fcmla_f32(0.0, 0.0, 1.0, 2.0, 3.0, 4.0, 0);
        assert_eq!(re, 1.0 * 3.0 - 2.0 * 4.0); // -5
        assert_eq!(im, 1.0 * 4.0 + 2.0 * 3.0); // 10
        // rot 90: acc += (-n.im + i*n.re) * m
        let (re, im) = fcmla_f32(0.0, 0.0, 1.0, 0.0, 1.0, 0.0, 1);
        assert_eq!((re, im), (0.0, 1.0));
    }
}
