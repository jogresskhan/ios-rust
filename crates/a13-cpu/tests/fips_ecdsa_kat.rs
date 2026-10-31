//! REAL-DATA repro (BUG #53): the FIPS-POST ECDSA test (phase 7,
//! fipspost_post_ecdsa) fails — ccec_generate_key_fips → the public-key
//! validation reports the generated point is NOT on the P-256 curve
//! (wrapper −18 → test −75 → POST −7075 → "FIPS Kernel POST Failed" panic
//! at boot insn 186,277,618, after the #52 RSA fix moved the frontier
//! 181,012,637 → 186,260,780+).
//!
//! This KAT runs the kernel's own P-256 field-op cores verbatim:
//!   0x82b6020  field multiply   (out = a·b mod p)
//!   0x82b6260  field square     (out = a² mod p)
//!   0x82b6f60  field reduce     (out = in mod p, in < 2^256)
//! against python mod-p references. The first diverging core is the bug.

use a13_cpu::interp::Interpreter;
use a13_cpu::{CpuBackend, MemAccess, StopReason};
use std::collections::HashMap;

include!("ecdsa_kat_data.rs");

const F_MUL: u64 = 0xfffffff0082b6020;
const F_SQR: u64 = 0xfffffff0082b6260;
const F_RED: u64 = 0xfffffff0082b6f60;

const HALT: u64 = 0x60000000;
const STACK: u64 = 0x5000_8000;
const BUF_A: u64 = 0x4001_0000;
const BUF_B: u64 = 0x4001_2000;
const BUF_R: u64 = 0x4001_4000;

const PAGE: u64 = 0x1000;

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

fn wr4(cpu: &mut Interpreter, va: u64, w: &[u64; 4]) {
    for i in 0..4 {
        cpu.mem().store(va + (i as u64) * 8, 8, w[i]);
    }
}

fn rd4(cpu: &mut Interpreter, va: u64) -> [u64; 4] {
    let mut r = [0u64; 4];
    for i in 0..4 {
        r[i] = cpu.mem().load(va + (i as u64) * 8, 8);
    }
    r
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

#[test]
fn field_mul_matches_oracle() {
    let mut cpu = make_cpu();
    for i in 0..VEC_A.len() {
        wr4(&mut cpu, BUF_A, &VEC_A[i]);
        wr4(&mut cpu, BUF_B, &VEC_B[i]);
        let stop = run_fn(&mut cpu, F_MUL, &[BUF_R, BUF_A, BUF_B], 1_000_000);
        assert_eq!(stop, StopReason::Halted, "mul must return: {stop:?}");
        let got = rd4(&mut cpu, BUF_R);
        assert_eq!(got, MUL_REF[i], "field mul vector {i}: {got:016x?} != {:?}", MUL_REF[i]);
    }
}

#[test]
fn field_sqr_matches_oracle() {
    let mut cpu = make_cpu();
    for i in 0..VEC_A.len() {
        wr4(&mut cpu, BUF_A, &VEC_A[i]);
        let stop = run_fn(&mut cpu, F_SQR, &[BUF_R, BUF_A], 1_000_000);
        assert_eq!(stop, StopReason::Halted, "sqr must return: {stop:?}");
        let got = rd4(&mut cpu, BUF_R);
        assert_eq!(got, SQR_REF[i], "field sqr vector {i}: {got:016x?} != {:?}", SQR_REF[i]);
    }
}

