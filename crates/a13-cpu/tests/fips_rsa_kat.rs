//! REAL-DATA repro (BUG #52): the 18C66 FIPS-POST RSA self-check fails with
//! sign returning −27 and the recovered value differing from the padded input
//! in exactly 6 limbs (8,10,12,14,16,18 — stride 2), each −1.
//!
//! Chain (boot insn 180,993,288, stop @0x82d8eb8): 0x82a4fd4 sign →
//! 0x82b361c wrapper → 0x82b34cc body → 0x82d8d0c modexp → 0x82d8f60 CRT
//! private op → 0x82b7a3c public op → 0x82d48cc constant-time compare ≠ 0.
//!
//! Root (this file pins it): the ADD side of `add_with_flags` computed the
//! carry-out as `res < a`, which WRAPS exactly when b == u64::MAX and the
//! carry-in is set — a + 2^64 ≡ a makes `res < a` false while the true carry
//! is 1. The captured padded input (PKCS#1 type-01) carries a 24-limb run of
//! 0xFFFF…FFFF (limbs 7..30); every ADCS over that run with carry-in 1 drops
//! its carry, so the following limb lands −1 and the carry self-restores —
//! producing EXACTLY the measured alternating −1 signature, and the final
//! `adc w0, w0, w0` return of ccn_add reads a dropped carry too.
//!
//! The kernel helpers here are extracted verbatim: ccn_add (0x82cbcd0, the
//! Duff's-device unrolled ADCS chain called 4× by the CRT private op and all
//! over the Montgomery region), ccn_add1 (0x82cbd88), ccn_mul1 (0x82b05d8).

use a13_cpu::interp::Interpreter;
use a13_cpu::{CpuBackend, MemAccess, StopReason};
use std::collections::HashMap;

include!("rsa_kat_data.rs");

// ---- kernel function VAs (18C66, no slide) ----
const CCN_MUL1: u64 = 0xfffffff0082b05d8;
const CCN_ADD: u64 = 0xfffffff0082cbcd0;
const CCN_ADD1: u64 = 0xfffffff0082cbd88;

// ---- repro memory map (sparse pages; code at kernel VAs) ----
const HALT: u64 = 0x60000000;
const STACK: u64 = 0x5000_8000;
const BUF_A: u64 = 0x4001_0000;
const BUF_B: u64 = 0x4001_2000;
const BUF_R: u64 = 0x4001_4000;

const PAGE: u64 = 0x1000;

/// Sparse paged RAM — code lives at the ORIGINAL kernel VAs so every
/// relative branch resolves unchanged.
struct PagedRam {
    pages: HashMap<u64, Box<[u8; 4096]>>,
}

impl PagedRam {
    fn new() -> Self {
        PagedRam { pages: HashMap::new() }
    }
    fn page(&mut self, va: u64) -> &mut [u8; 4096] {
        let pn = (va / PAGE) as u64;
        self.pages.entry(pn).or_insert_with(|| Box::new([0u8; 4096]))
    }
    fn write(&mut self, va: u64, bytes: &[u8]) {
        let mut i = 0usize;
        while i < bytes.len() {
            let a = va + i as u64;
            let off = (a % PAGE) as usize;
            let n = (4096 - off).min(bytes.len() - i);
            let p = self.page(a);
            p[off..off + n].copy_from_slice(&bytes[i..i + n]);
            i += n;
        }
    }
}

impl MemAccess for PagedRam {
    fn load(&mut self, addr: u64, size: u8) -> u64 {
        let mut v = 0u64;
        for k in 0..size as usize {
            let a = addr + k as u64;
            let b = {
                let pn = (a / PAGE) as u64;
                match self.pages.get(&pn) {
                    Some(p) => p[(a % PAGE) as usize],
                    None => 0,
                }
            };
            v |= (b as u64) << (k * 8);
        }
        v
    }
    fn store(&mut self, addr: u64, size: u8, val: u64) {
        for k in 0..size as usize {
            let a = addr + k as u64;
            let b = ((val >> (k * 8)) & 0xFF) as u8;
            let p = self.page(a);
            p[(a % PAGE) as usize] = b;
        }
    }
    fn fetch32(&mut self, addr: u64) -> u32 {
        self.load(addr, 4) as u32
    }
}

fn hex_bytes(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
        .collect()
}

fn make_cpu() -> Interpreter {
    let mut ram = PagedRam::new();
    for (i, (va, len)) in CODE_RANGES.iter().enumerate() {
        let bytes = hex_bytes(CODE_HEX[i]);
        assert_eq!(bytes.len(), *len, "code range {va:#x} length mismatch");
        ram.write(*va, &bytes);
    }
    ram.write(HALT, &0xD440_0000u32.to_le_bytes());
    let mut cpu = Interpreter::new(Box::new(ram));
    cpu.sp = STACK;
    cpu.x[30] = HALT;
    cpu
}

fn wr_words(cpu: &mut Interpreter, va: u64, words: &[u64]) {
    for (i, w) in words.iter().enumerate() {
        cpu.mem().store(va + (i as u64) * 8, 8, *w);
    }
}

fn rd_words(cpu: &mut Interpreter, va: u64, n: usize) -> Vec<u64> {
    (0..n).map(|i| cpu.mem().load(va + (i as u64) * 8, 8)).collect()
}

fn run_fn(cpu: &mut Interpreter, entry: u64, args: &[u64], max_insn: u64) -> StopReason {
    for (i, a) in args.iter().enumerate() {
        cpu.x[i] = *a;
    }
    cpu.sp = STACK;
    cpu.x[30] = HALT;
    cpu.set_reset_vector(entry);
    let res = cpu.run(a13_cpu::InterpBudget {
        max_insn,
        max_ns: 120_000_000_000,
    });
    res.stop
}

// ------------------------------------------------------------------
// Micro-test 1: THE BUG-#52 edge, pinned directly — ADCS where the second
// operand is u64::MAX and the carry-in is SET: a + 0xFFFF…FFFF + 1 = a WITH
// carry-out 1 (C must stay 1). The old `res < a` form returned res == a and
// read C=0, breaking every other limb of corecrypto's unrolled ADCS chains
// over the padded input's all-ones run (and ccn_add's `adc w0,w0,w0` return).
// Encodings assembled with keystone (tools/re convention: never hand-split).
// ------------------------------------------------------------------
#[test]
fn adcs_max_carry_edge() {
    let mut ram = vec![0u8; 0x80000];
    // movz x1, #0x1234 = 0xD2824681
    // movz x3, #1      = 0xD2800023   (cmp operand: 1 > 0 → C=1)
    // movn x2, #0      = 0x92800002   (x2 = 0xFFFF…FFFF)
    // cmp  x3, xzr     = 0xEB1F007F   (SUBS 1 − 0: no borrow → C=1)
    // adcs x0, x1, x2  = 0xBA020020   (0x1234 + MAX + 1 = 0x1234, C=1)
    // adcs x4, x1, xzr = 0xBA1F0024   (0x1234 + 0 + C  → 0x1235 iff C lived)
    // hlt              = 0xD4400000
    let code: [u32; 7] = [
        0xD2824681, 0xD2800023, 0x92800002, 0xEB1F007F,
        0xBA020020, 0xBA1F0024, 0xD4400000,
    ];
    for (i, w) in code.iter().enumerate() {
        ram[0x10000 + i * 4..0x10004 + i * 4].copy_from_slice(&w.to_le_bytes());
    }
    let mut cpu = Interpreter::new(Box::new(Ram(ram)));
    cpu.nzcv = 0;
    cpu.set_reset_vector(0x10000);
    let res = cpu.run(a13_cpu::InterpBudget { max_insn: 100, max_ns: 1_000_000_000 });
    assert_eq!(res.stop, StopReason::Halted);
    assert_eq!(cpu.x[0], 0x1234, "result of a + MAX + 1 must be a");
    // THE assertion: the carry must survive — the second ADCS adds it.
    assert_eq!(
        cpu.x[4], 0x1235,
        "BUG #52 REPRODUCED: ADCS dropped the carry for b == u64::MAX, cin == 1"
    );
    // after the second adcs (0x1234 + 0 + 1 = 0x1235) the carry-out is 0
    assert_eq!(cpu.nzcv & 0x2, 0, "C must be CLEAR after the no-carry adcs");
}

// ------------------------------------------------------------------
// The real-data repro: the kernel's own ccn_add (0x82cbcd0) over the
// captured padded-input limbs (all-ones run 7..19). Pre-fix this fails with
// EXACTLY the measured bug-#52 signature: limbs 8,10,12,14,16,18 each −1,
// and the carry return value 0 instead of 1.
// ------------------------------------------------------------------
#[test]
fn ccn_add_allones_run_real_case() {
    let mut cpu = make_cpu();
    wr_words(&mut cpu, BUF_A, &ADD_S);
    wr_words(&mut cpu, BUF_B, &ADD_T);
    let stop = run_fn(&mut cpu, CCN_ADD, &[ADD_S.len() as u64, BUF_R, BUF_A, BUF_B], 1_000_000);
    assert_eq!(stop, StopReason::Halted, "ccn_add must return: {stop:?}");
    let got = rd_words(&mut cpu, BUF_R, ADD_S.len());
    let mut diffs = 0;
    for i in 0..ADD_S.len() {
        if got[i] != ADD_REF[i] {
            let d = got[i] as i128 - ADD_REF[i] as i128;
            eprintln!("  limb {i}: engine {:#018x} != ref {:#018x} ({d:+})", got[i], ADD_REF[i]);
            diffs += 1;
        }
    }
    assert_eq!(diffs, 0, "BUG #52 REPRODUCED: ccn_add diverges on the real captured operands");
    // the carry-out return (ccn_add ends with `adc w0, w0, w0`)
    assert_eq!(cpu.x[0], ADD_REF_CARRY, "ccn_add carry return must be {ADD_REF_CARRY}");
}

// ------------------------------------------------------------------
// Micro-test 3: ccn_add with an explicit mid-chain all-ones run (n=9, odd,
// so the Duff's-device 1-word head runs too).
// ------------------------------------------------------------------
#[test]
fn ccn_add_n9_odd_head() {
    let mut cpu = make_cpu();
    let s: [u64; 9] = [
        0x0000_0000_0000_0001, 0x1111_1111_1111_1111, 0x2222_2222_2222_2222,
        0x3333_3333_3333_3333, u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX,
    ];
    let t: [u64; 9] = [
        u64::MAX, u64::MAX, 0x1, 0x0, u64::MAX, u64::MAX, 0x0, 0x0, 0x1,
    ];
    wr_words(&mut cpu, BUF_A, &s);
    wr_words(&mut cpu, BUF_B, &t);
    let stop = run_fn(&mut cpu, CCN_ADD, &[9, BUF_R, BUF_A, BUF_B], 1_000_000);
    assert_eq!(stop, StopReason::Halted);
    // u128 reference
    let mut carry = 0u128;
    let mut want = [0u64; 9];
    for i in 0..9 {
        let tot = s[i] as u128 + t[i] as u128 + carry;
        want[i] = tot as u64;
        carry = tot >> 64;
    }
    let got = rd_words(&mut cpu, BUF_R, 9);
    for i in 0..9 {
        assert_eq!(got[i], want[i], "ccn_add n=9 limb {i}: {:#018x} != {:#018x}", got[i], want[i]);
    }
    assert_eq!(cpu.x[0], carry as u64, "carry return");
}

// ------------------------------------------------------------------
// Micro-test 4: ccn_add1 (0x82cbd88) — r = s + v, an all-ones run with a
// large scalar (its `adcs x3, x8, xzr` carry latch reuses x3 as the next
// addend; pin it against the same wrap class).
// ------------------------------------------------------------------
#[test]
fn ccn_add1_allones() {
    let mut cpu = make_cpu();
    let s: [u64; 12] = [
        0x0000_00ff_1234_5678, u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX,
        u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX,
    ];
    let v: u64 = 0xFFFF_FFFF_0000_0001;
    wr_words(&mut cpu, BUF_A, &s);
    let stop = run_fn(&mut cpu, CCN_ADD1, &[12, BUF_R, BUF_A, v], 1_000_000);
    assert_eq!(stop, StopReason::Halted, "ccn_add1 must return: {stop:?}");
    let mut carry = v;
    let mut want = [0u64; 12];
    for i in 0..12 {
        let tot = s[i] as u128 + carry as u128;
        want[i] = tot as u64;
        carry = (tot >> 64) as u64;
    }
    let got = rd_words(&mut cpu, BUF_R, 12);
    for i in 0..12 {
        assert_eq!(got[i], want[i], "ccn_add1 limb {i}: {:#018x} != {:#018x}", got[i], want[i]);
    }
    assert_eq!(cpu.x[0], carry, "ccn_add1 carry return: {:#x} != {:#x}", cpu.x[0], carry);
}

// ------------------------------------------------------------------
// Micro-test 5: ccn_mul1 (0x82b05d8) — r = s * v + carry chain, against a
// u128 reference, over the captured padded-input limbs (the CRT private op
// multiplies the primes by odd scalars through this leaf).
// ------------------------------------------------------------------
#[test]
fn ccn_mul1_matches_u128() {
    let mut cpu = make_cpu();
    wr_words(&mut cpu, BUF_A, &ADD_T);
    let v: u64 = 0x9E37_79B9_7F4A_7C15;
    let stop = run_fn(&mut cpu, CCN_MUL1, &[ADD_T.len() as u64, BUF_R, BUF_A, v], 1_000_000);
    assert_eq!(stop, StopReason::Halted, "ccn_mul1 must return: {stop:?}");
    let mut carry = 0u128;
    let mut want = [0u64; 20];
    for i in 0..ADD_T.len() {
        let tot = ADD_T[i] as u128 * v as u128 + carry;
        want[i] = tot as u64;
        carry = tot >> 64;
    }
    let got = rd_words(&mut cpu, BUF_R, 20);
    for i in 0..20 {
        assert_eq!(got[i], want[i], "ccn_mul1 limb {i}: {:#018x} != {:#018x}", got[i], want[i]);
    }
    assert_eq!(cpu.x[0], carry as u64, "ccn_mul1 top carry: {:#x} != {:#x}", cpu.x[0], carry as u64);
}

/// Minimal flat RAM for the flag micro-test (same shape as the sqrt KAT).
struct Ram(Vec<u8>);
impl MemAccess for Ram {
    fn load(&mut self, addr: u64, size: u8) -> u64 {
        let mut v = [0u8; 8];
        for k in 0..size as usize {
            v[k] = self.0.get((addr + k as u64) as usize).copied().unwrap_or(0);
        }
        u64::from_le_bytes(v)
    }
    fn store(&mut self, addr: u64, size: u8, val: u64) {
        let b = val.to_le_bytes();
        for k in 0..size as usize {
            if let Some(slot) = self.0.get_mut((addr + k as u64) as usize) {
                *slot = b[k];
            }
        }
    }
    fn fetch32(&mut self, addr: u64) -> u32 {
        u32::from_le_bytes(self.0[(addr as usize)..(addr as usize) + 4].try_into().unwrap())
    }
}
