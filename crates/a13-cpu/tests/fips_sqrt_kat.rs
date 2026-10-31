//! REAL-DATA repro (BUG #51): the 18C66 corecrypto reciprocal/Newton
//! workspace fn 0xfffffff0082b0708 (FIPS-POST later tests), with its full
//! helper graph extracted verbatim from the decoded kernelcache, plus the
//! captured failing input (boot insn 155688539, x1=16 words).
//!
//! The kernel aborts this fn at insn 155,746,479: `cbz x8` at 0x…b0b40 →
//! 'internal error, file radar to (corecrypto | all)'. This test reproduces
//! the abort on the engine and bisects the loop against the python model
//! (scripts/re/sqrt_model2.py) to find the first diverging helper.
//!
//! Reference per-iteration values from the model (S1[0..3] / S4[0..3] at
//! each loop-check pc 0x…b0a24).

use a13_cpu::interp::Interpreter;
use a13_cpu::{CpuBackend, MemAccess, StopReason};
use std::collections::HashMap;

include!("sqrt_kat_data.rs");

// ---- kernel function VAs (18C66, no slide) ----
const CORE: u64 = 0xfffffff0082b0708; // the reciprocal/newton fn
const CLEAR: u64 = 0xfffffff0082c2250; // clear wrapper → PPL memset
const MEMSET: u64 = 0xfffffff00987c4c0; // PPL memset
const SHR: u64 = 0xfffffff0082e208c; // NEON shift-right
const SHL: u64 = 0xfffffff0082aaea0; // NEON shift-left
const MUL: u64 = 0xfffffff0082b2df0; // ccn mul core
const SUBN: u64 = 0xfffffff0082d59e4; // ccn sub (arrays)
const LOOP_CHECK: u64 = 0xfffffff0082b0a24; // end of each loop body
const ABORT_GLUE_LO: u64 = 0xfffffff0082b0bb0;
const ABORT_GLUE_HI: u64 = 0xfffffff0082b0bd8;

// ---- repro memory map (sparse pages; code at kernel VAs) ----
const HALT: u64 = 0x60000000;
const STACK: u64 = 0x5000_8000; // grows down; helpers use ≤0x200
const SCRATCH: u64 = 0x4001_0000; // memset/shift test buffers
const ARENA: u64 = 0x4002_0000; // {current, end} struct
const ARENA_BUF: u64 = 0x4002_1000; // 0x570 bytes + slack
const IN_VEC: u64 = 0x4002_2000; // 16-word input
const OUT_VEC: u64 = 0x4002_3000; // out pointer

const PAGE: u64 = 0x1000;

/// Sparse paged RAM — code lives at the ORIGINAL kernel VAs so every
/// relative branch / adrp resolves unchanged.
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

/// Build a CPU with the kernel code loaded at original VAs.
fn make_cpu() -> Interpreter {
    let mut ram = PagedRam::new();
    for (i, (va, len)) in CODE_RANGES.iter().enumerate() {
        let bytes = hex_bytes(CODE_HEX[i]);
        assert_eq!(bytes.len(), *len, "code range {va:#x} length mismatch");
        ram.write(*va, &bytes);
    }
    // HALT word
    ram.write(HALT, &0xD440_0000u32.to_le_bytes());
    // canary page 0xfffffff009a8a000: zeros are fine (consistency only)
    ram.page(0xfffffff009a8a000u64);
    let mut cpu = Interpreter::new(Box::new(ram));
    cpu.sp = STACK;
    cpu.x[30] = HALT;
    cpu
}

fn rd64(cpu: &mut Interpreter, va: u64) -> u64 {
    cpu.mem().load(va, 8)
}

fn wr64(cpu: &mut Interpreter, va: u64, v: u64) {
    cpu.mem().store(va, 8, v)
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
// Micro-test 1: the PPL memset zeroes 272 bytes (the post-loop clear).
// The abort dump showed the C region NOT cleared — check the primitive.
// ------------------------------------------------------------------
#[test]
fn ppl_memset_zeroes_272() {
    let mut cpu = make_cpu();
    // pre-fill with 0xAA
    for i in 0..34 {
        wr64(&mut cpu, SCRATCH + i * 8, 0xAAAA_AAAA_AAAA_AAAA);
    }
    let stop = run_fn(&mut cpu, MEMSET, &[SCRATCH, 0, 272], 100_000);
    assert_eq!(stop, StopReason::Halted, "memset must return: {stop:?}");
    for i in 0..34usize {
        let got = rd64(&mut cpu, SCRATCH + (i as u64) * 8);
        assert_eq!(got, 0, "word {i} not cleared: {got:#x}");
    }
}

// ------------------------------------------------------------------
// Micro-test 2: the clear wrapper 0x82c2250(size, ptr).
// ------------------------------------------------------------------
#[test]
fn clear_wrapper_zeroes_region() {
    let mut cpu = make_cpu();
    for i in 0..40 {
        wr64(&mut cpu, SCRATCH + i * 8, 0x5555_5555_5555_5555);
    }
    let stop = run_fn(&mut cpu, CLEAR, &[272, SCRATCH], 100_000);
    assert_eq!(stop, StopReason::Halted, "clear must return: {stop:?}");
    for i in 0..34usize {
        let got = rd64(&mut cpu, SCRATCH + (i as u64) * 8);
        assert_eq!(got, 0, "word {i} not cleared: {got:#x}");
    }
}

// ------------------------------------------------------------------
// Micro-test 3: NEON shift-right with count=0 is the identity
// (the loop's shift amount is BITLEN & 63 = 0 for this input).
// ------------------------------------------------------------------
#[test]
fn neon_shr_count0_identity() {
    let mut cpu = make_cpu();
    // fill src with a non-trivial 34-word pattern
    let mut seed = 0x243F_6A88_85A3_08D3u64;
    let mut src = [0u64; 34];
    for i in 0..34usize {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        src[i] = seed;
        wr64(&mut cpu, SCRATCH + 0x200 + (i as u64) * 8, src[i]);
    }
    let stop = run_fn(&mut cpu, SHR, &[34, SCRATCH, SCRATCH + 0x200, 0], 2_000_000);
    assert_eq!(stop, StopReason::Halted, "shr must return: {stop:?}");
    for i in 0..34usize {
        let got = rd64(&mut cpu, SCRATCH + (i as u64) * 8);
        assert_eq!(got, src[i], "shr count=0 word {i}: {got:#x} != {:#x}", src[i]);
    }
}

// ------------------------------------------------------------------
// Micro-test 4: NEON shift-right count=1 (multi-limb carry-down).
// ------------------------------------------------------------------
#[test]
fn neon_shr_count1_matches() {
    let mut cpu = make_cpu();
    let mut seed = 0x1319_8A2E_0370_7344u64;
    let mut src = [0u64; 34];
    for i in 0..34usize {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        src[i] = seed;
        wr64(&mut cpu, SCRATCH + 0x200 + (i as u64) * 8, src[i]);
    }
    let stop = run_fn(&mut cpu, SHR, &[34, SCRATCH, SCRATCH + 0x200, 1], 2_000_000);
    assert_eq!(stop, StopReason::Halted, "shr must return: {stop:?}");
    for i in 0..33usize {
        let want = (src[i] >> 1) | (src[i + 1] << 63);
        let got = rd64(&mut cpu, SCRATCH + (i as u64) * 8);
        assert_eq!(got, want, "shr count=1 word {i}: {got:#x} != {want:#x}");
    }
    let want_last = src[33] >> 1;
    let got = rd64(&mut cpu, SCRATCH + 33 * 8);
    assert_eq!(got, want_last, "shr count=1 last word");
}

// ------------------------------------------------------------------
// Micro-test 5: ccn mul core (17×17 → 34 words) against u128 math.
// ------------------------------------------------------------------
#[test]
fn ccn_mul_matches_reference() {
    let mut cpu = make_cpu();
    let mut a = [0u64; 17];
    let mut b = [0u64; 17];
    let mut seed = 0xA409_3822_299F_31D0u64;
    let mut next = || {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        seed
    };
    for i in 0..17usize {
        a[i] = next();
        b[i] = next();
        wr64(&mut cpu, SCRATCH + (i as u64) * 8, a[i]);
        wr64(&mut cpu, SCRATCH + 0x200 + (i as u64) * 8, b[i]);
    }
    let stop = run_fn(
        &mut cpu,
        MUL,
        &[17, SCRATCH + 0x400, SCRATCH, SCRATCH + 0x200],
        2_000_000,
    );
    assert_eq!(stop, StopReason::Halted, "mul must return: {stop:?}");
    // reference schoolbook with u128 carries
    let mut want = [0u64; 34];
    for i in 0..17 {
        let mut carry = 0u128;
        for j in 0..17 {
            let t = a[i] as u128 * b[j] as u128 + want[i + j] as u128 + carry;
            want[i + j] = t as u64;
            carry = t >> 64;
        }
        want[i + 17] = carry as u64;
    }
    for i in 0..34usize {
        let got = rd64(&mut cpu, SCRATCH + 0x400 + (i as u64) * 8);
        assert_eq!(got, want[i], "mul word {i}: {got:#x} != {:#x}", want[i]);
    }
}

// ------------------------------------------------------------------
// Micro-test 6: ccn sub (arrays) borrow semantics.
// ------------------------------------------------------------------
#[test]
fn ccn_sub_borrow() {
    let mut cpu = make_cpu();
    // a = 0, b = 1 → borrow 1, result all-ones
    for i in 0..4usize {
        wr64(&mut cpu, SCRATCH + (i as u64) * 8, 0);
        wr64(&mut cpu, SCRATCH + 0x100 + (i as u64) * 8, if i == 0 { 1 } else { 0 });
    }
    let stop = run_fn(
        &mut cpu,
        SUBN,
        &[4, SCRATCH + 0x200, SCRATCH, SCRATCH + 0x100],
        100_000,
    );
    assert_eq!(stop, StopReason::Halted, "sub must return: {stop:?}");
    assert_eq!(cpu.x[0], 1, "0 - 1 must borrow");
    for i in 0..4usize {
        let got = rd64(&mut cpu, SCRATCH + 0x200 + (i as u64) * 8);
        assert_eq!(got, u64::MAX, "0-1 word {i} = {got:#x}");
    }
}

// ------------------------------------------------------------------
// The full repro: run the kernel's own 0x82b0708 with the captured
// input and report where it stops + per-iteration divergence vs the
// python model (sqrt_model2.py).
// ------------------------------------------------------------------
/// Model reference: (S1[0..3], S4[0..3]) at each loop-check, from
/// scripts/re/sqrt_model2.py on the same input.
const MODEL_ITERS: [([u64; 3], [u64; 3]); 9] = [
    ([0x15ab177f9b6d0d49, 0xe8dcb05bb3aa9f66, 0xb4acaf161ef532b0],
     [0xea54e8806492f2b7, 0x17234fa44c556099, 0x4b5350e9e10acd4f]),
    ([0xe53f0964ac07d676, 0x33a9e0d7cdcfd213, 0xefe857b6374f1aa2],
     [0x1ac0f69b53f8298a, 0xcc561f2832302dec, 0x1017a849c8b0e55d]),
    ([0x5ddc26a458cc492f, 0xcfaaeb1971caed2e, 0x19cb8eee08cea3e7],
     [0xa223d95ba733b6d1, 0x305514e68e3512d1, 0xe6347111f7315c18]),
    ([0x69e08540c7702217, 0x852ce16e34014e78, 0x25befb0fd4932daa],
     [0x961f7abf388fdde9, 0x7ad31e91cbfeb187, 0xda4104f02b6cd255]),
    ([0xd38eade1bd796807, 0xecc502830e28c339, 0x84101c7caeb0fef3],
     [0x2c71521e428697f9, 0x133afd7cf1d73cc6, 0x7befe383514f010c]),
    ([0xdb3e728fcc05c7fa, 0x97f1136687ce0c04, 0xaebca3d0d5dd57f8],
     [0x24c18d7033fa3806, 0x680eec997831f3fb, 0x51435c2f2a22a807]),
    ([0x2d7fc2f00a618277, 0x1a008bd769e7ef97, 0x6fe9437eb9760918],
     [0xd2803d0ff59e7d89, 0xe5ff742896181068, 0x9016bc814689f6e7]),
    ([0x8f9ce495aa13314d, 0xa7e19f3269c5858e, 0x25db27150d50c6a2],
     [0x1563958a4129c9c5, 0x241d491ec26a9b43, 0xfa5251ed7fc3272d]),
    ([0x1563958a4129c9c5, 0x241d491ec26a9b43, 0xfa5251ed7fc3272d],
     [0x1563958a4129c9c5, 0x241d491ec26a9b43, 0xfa5251ed7fc3272d]),
];

/// Model product (S4_final × INPUT, 34 words) from scripts/re/sqrt_model2.py.
const MODEL_PRODUCT: [u64; 34] = [
    0x3225e59efaa09f27, 0x46bd9410a1bef0e1, 0x9febd427b2a5ba03, 0xca60908b893010e5,
    0x1555e7d047454025, 0x566f6864d8e29427, 0x9c7b65cc1284edba, 0x4e9575312cf08155,
    0xe9286112f63ffdda, 0x8bac980aaf148f67, 0xe1370fcee4bee10a, 0x06f0757391402b93,
    0x92dcd6e84a48a209, 0xaaf52bd6d4130c4d, 0x25b8dfefc063d0d1, 0x145223dc1432579d,
    0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
    0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
    0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
    0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
    0x0000000000000000, 0x0000000000000000,
];

#[test]
fn sqrt_repro_real_case() {
    let mut cpu = make_cpu();
    // THE REAL CALL (boot insn 155,688,539): x1 = 0x10 = 16 words, input =
    // the 128-byte buffer at 0xffffffe802fab410 (stop-dumped).
    for (i, w) in INPUT.iter().enumerate() {
        wr64(&mut cpu, IN_VEC + (i as u64) * 8, *w);
    }
    // arena {current=ARENA_BUF, end=ARENA_BUF+0x570} — 1392 B, the n=16 size
    wr64(&mut cpu, ARENA, ARENA_BUF);
    wr64(&mut cpu, ARENA + 8, ARENA_BUF + 0x570);
    cpu.x[0] = ARENA;
    cpu.x[1] = 16;
    cpu.x[2] = OUT_VEC;
    cpu.x[3] = IN_VEC;
    cpu.sp = STACK;
    cpu.x[30] = HALT;
    cpu.set_reset_vector(CORE);

    let mut loop_iters = 0u32;
    let mut aborted = false;
    let mut steps = 0u64;
    let mut mul3_checked = false;
    loop {
        match cpu.step() {
            Ok(()) => {}
            Err(StopReason::Halted) => break,
            Err(StopReason::Budget) => break,
            Err(e) => panic!("unexpected stop: {e:?}"),
        }
        steps += 1;
        if steps > 50_000_000 {
            panic!("runaway");
        }
        if cpu.pc == LOOP_CHECK {
            loop_iters += 1;
        }
        // post-loop stage dumps
        if cpu.pc == 0xfffffff0082b0a94 {
            // after sub#1 (C -= product): C must equal the model remainder
            let sp = cpu.sp;
            let c = rd64(&mut cpu, sp + 0x48);
            let want: [u64; 17] = [
                0xcdda1a61055f60d9, 0xb9426bef5e410f1e, 0x60142bd84d5a45fc, 0x359f6f7476cfef1a,
                0xeaaa182fb8babfda, 0xa990979b271d6bd8, 0x63849a33ed7b1245, 0xb16a8aced30f7eaa,
                0x16d79eed09c00225, 0x745367f550eb7098, 0x1ec8f0311b411ef5, 0xf90f8a8c6ebfd46c,
                0x6d232917b5b75df6, 0x550ad4292becf3b2, 0xda4720103f9c2f2e, 0xebaddc23ebcda862,
                0x0000000000000000,
            ];
            eprintln!("--- post-loop stage: after sub#1 (C -= product) ---");
            for i in 0..17usize {
                let got = rd64(&mut cpu, c + (i as u64) * 8);
                let w = if i < 16 { want[i] } else { 0 };
                if got != w {
                    eprintln!("  C_low[{i}] = {got:#018x} want {w:#018x} {}", if got != w { "MISMATCH" } else { "" });
                }
            }
            for i in 17..34usize {
                let got = rd64(&mut cpu, c + (i as u64) * 8);
                if got != 0 {
                    eprintln!("  C_high[{i}] = {got:#018x} want 0 MISMATCH");
                }
            }
        }
        if cpu.pc == 0xfffffff0082b0aac {
            // after sub#2 (C_low -= INPUT): x0 = borrowA (model: 0)
            eprintln!("--- after sub#2: borrowA = {} ---", cpu.x[0]);
        }
        if cpu.pc == 0xfffffff0082b0ac0 {
            // after sub1#1: x0 = bA
            eprintln!("--- after sub1#1: bA = {} ---", cpu.x[0]);
        }
        if cpu.pc == 0xfffffff0082b0aec {
            // after sub1#2: x0 = bB (model: 1 — THE decider)
            eprintln!("--- after sub1#2: bB = {} (model wants 1) ---", cpu.x[0]);
        }
        if cpu.pc == 0xfffffff0082b0b3c {
            eprintln!("--- before final cbz: bA|bB = {} (x20), bC = {} (x0) ---", cpu.x[20], cpu.x[0]);
        }
        // after MUL3 (pc = 0x82b0a80): compare the product S1 against the model
        if cpu.pc == 0xfffffff0082b0a80 && !mul3_checked {
            mul3_checked = true;
            let sp = cpu.sp;
            let s1 = rd64(&mut cpu, sp + 0x40);
            let s4 = cpu.x[24];
            let s3 = cpu.x[28];
            eprintln!("MUL3 done: S1={s1:#x} S4={s4:#x} S3={s3:#x}");
            eprintln!("S4[0..3] (engine): {:016x} {:016x} {:016x}",
                rd64(&mut cpu, s4), rd64(&mut cpu, s4 + 8), rd64(&mut cpu, s4 + 16));
            eprintln!("S3[0..3] (engine): {:016x} {:016x} {:016x}",
                rd64(&mut cpu, s3), rd64(&mut cpu, s3 + 8), rd64(&mut cpu, s3 + 16));
            let mut diffs = 0;
            for i in 0..34usize {
                let got = rd64(&mut cpu, s1 + (i as u64) * 8);
                if got != MODEL_PRODUCT[i] {
                    if diffs < 8 {
                        eprintln!(
                            "product word {i}: engine {got:#018x} != model {:#018x}",
                            MODEL_PRODUCT[i]
                        );
                    }
                    diffs += 1;
                }
            }
            eprintln!("MUL3 product diffs vs model: {diffs}/34 words");
            assert_eq!(diffs, 0, "MUL3 product diverges from the model");
        }
        if cpu.pc >= ABORT_GLUE_LO && cpu.pc < ABORT_GLUE_HI {
            aborted = true;
            break;
        }
    }
    eprintln!("loop iters: {loop_iters}, steps: {steps}, aborted: {aborted}");
    assert_eq!(loop_iters, 9, "expected 9 loop iterations");
    assert!(mul3_checked, "never reached MUL3");
    // NOTE: the product itself was verified IN-FLIGHT at pc=0x82b0a80
    // (0/34 diffs vs the model, logged above); the arena is reused by the
    // epilogue so a post-return re-read is not meaningful.
    assert!(!aborted, "BUG #51 REPRODUCED: the engine aborted the real case");
}

// ------------------------------------------------------------------
// Micro-test 7: the branchless bitlen/count fn 0x82ccd9c — THE BUG-#51
// suspect. The boot's only call passes x0=10 (a 10-word ccz) but the
// arena was sliced for W=17 (bitlen 1024 = SIXTEEN words) — the loop
// must be over-iterating. Reference: per-element x0 from the python
// trace (scripts/re/, branchless semantics).
// ------------------------------------------------------------------
const COUNTFN: u64 = 0xfffffff0082ccd9c;

#[test]
fn countfn_ten_words() {
    let mut cpu = make_cpu();
    // the REAL 10-word input (boot stop-dump @0xffffffe802fab410) + the
    // 6 following words of the 128B buffer (what an over-run would read)
    let words10: [u64; 10] = [
        0xfb4f14961893d263, 0x6f3f4a66d02a7f9f, 0xbc05aea1d4ab4786, 0x0387ae9c6bb3d121,
        0x4064911548591649, 0x9adaf22be8502268, 0xeb23e30213d49afb, 0x6d58dcf3d7b734df,
        0x61e4390905ddcf49, 0x8904bb84b3bf6c64,
    ];
    let words6: [u64; 6] = [
        0xad4d0757b9eab2cd, 0x182524ac377f6c16, 0x1a46ff5d0cb20745, 0x8640e97b5e4d1654,
        0x33f616c9172dd0b1, 0x7d1e1d3f63c28fbe,
    ];
    for (i, w) in words10.iter().chain(words6.iter()).enumerate() {
        wr64(&mut cpu, IN_VEC + (i as u64) * 8, *w);
    }
    let stop = run_fn(&mut cpu, COUNTFN, &[10, IN_VEC], 100_000);
    assert_eq!(stop, StopReason::Halted, "count must return: {stop:?}");
    assert_eq!(
        cpu.x[0], 640,
        "count(10, real_input) must be the bitlen 640, got {:#x}",
        cpu.x[0]
    );
}

#[test]
fn countfn_one_word_82() {
    let mut cpu = make_cpu();
    wr64(&mut cpu, IN_VEC, 82);
    let stop = run_fn(&mut cpu, COUNTFN, &[1, IN_VEC], 100_000);
    assert_eq!(stop, StopReason::Halted, "count must return: {stop:?}");
    assert_eq!(cpu.x[0], 7, "bitlen(82) = 7, got {:#x}", cpu.x[0]);
}

#[test]
fn countfn_zero_and_small() {
    let mut cpu = make_cpu();
    wr64(&mut cpu, IN_VEC, 0);
    let stop = run_fn(&mut cpu, COUNTFN, &[1, IN_VEC], 100_000);
    assert_eq!(stop, StopReason::Halted);
    assert_eq!(cpu.x[0], 0, "bitlen(0) = 0, got {:#x}", cpu.x[0]);

    let mut cpu = make_cpu();
    wr64(&mut cpu, IN_VEC, 1);
    let stop = run_fn(&mut cpu, COUNTFN, &[1, IN_VEC], 100_000);
    assert_eq!(stop, StopReason::Halted);
    assert_eq!(cpu.x[0], 1, "bitlen(1) = 1, got {:#x}", cpu.x[0]);

    let mut cpu = make_cpu();
    wr64(&mut cpu, IN_VEC, 0);
    wr64(&mut cpu, IN_VEC + 8, 0x8000_0000_0000_0000);
    let stop = run_fn(&mut cpu, COUNTFN, &[2, IN_VEC], 100_000);
    assert_eq!(stop, StopReason::Halted);
    assert_eq!(cpu.x[0], 128, "bitlen([0, 2^63]) = 128, got {:#x}", cpu.x[0]);
}

// ------------------------------------------------------------------
// Micro-test 8: THE BUG-#51 edge, pinned directly — SBCS where the
// subtrahend is u64::MAX and the carry-in is CLEAR (borrow-in):
// 0 − 0xFFFF…FFFF − 1 = 0 WITH borrow-out (C must be 0). The old
// `a >= b + !carry` form wrapped b+1 to 0 and set C=1, breaking every
// other limb of corecrypto's reciprocal-invariant SBCS chains.
// Encoding: sbcs x0, x1, x2 = 0xFA0003E0; the chain runs twice.
// ------------------------------------------------------------------
#[test]
fn sbcs_max_borrow_edge() {
    let mut ram = vec![0u8; 0x80000];
    // movz x1, #0        = 0xD2800001
    // movn x2, #0        = 0x92800002  (x2 = 0xFFFF…FFFF, 64-bit)
    // sbcs x0, x1, x2    = 0xFA020020  (kernel-verified encoding)
    // sbcs x0, x1, x2    = 0xFA020020  (C from the first must be 0)
    // hlt                = 0xD4400000
    let code: [u32; 5] = [0xD2800001, 0x92800002, 0xFA020020, 0xFA020020, 0xD4400000];
    for (i, w) in code.iter().enumerate() {
        ram[0x10000 + i * 4..0x10004 + i * 4].copy_from_slice(&w.to_le_bytes());
    }
    let mut cpu = Interpreter::new(Box::new(Ram(ram)));
    cpu.nzcv = 0; // C clear (borrow-in) before the first sbcs
    cpu.set_reset_vector(0x10000);
    let res = cpu.run(a13_cpu::InterpBudget { max_insn: 100, max_ns: 1_000_000_000 });
    assert_eq!(res.stop, StopReason::Halted);
    assert_eq!(cpu.x[0], 0, "0 − MAX − 1 twice must be 0, got {:#x}", cpu.x[0]);
    // and the flags: Z set, C clear (still borrowing)
    assert_eq!(cpu.nzcv & 0x4, 0x4, "Z must be set");
    assert_eq!(cpu.nzcv & 0x2, 0, "C must be CLEAR (borrow-out)");
}

// ------------------------------------------------------------------
// Micro-test 9: THE BUG-#52 edge, pinned directly — ADCS where the
// addend is u64::MAX and the carry-in is SET:
// 5 + 0xFFFF…FFFF + 1 = 5 (mod 2^64) WITH carry-out (C must STAY 1).
// The old `res < a` form reports C=0 (5 < 5 is false), so the next
// ADCS in the chain reads carry-in 0 and computes one LESS — the RSA
// self-check's 6 alternating limbs off by −1 (indices 8,10,12,14,16,18)
// are exactly this: 2-word-unrolled Montgomery ADCS over 0xFF…FF limbs.
// Encoding: adcs x0, x1, x2 = 0xBA020020.
// ------------------------------------------------------------------
#[test]
fn adcs_max_carry_edge() {
    let mut ram = vec![0u8; 0x80000];
    // movz x1, #5        = 0xD28000A1   (a = 5)
    // movn x2, #0        = 0x92800002   (b = 0xFFFF…FFFF)
    // movz x3, #0        = 0xD2800003   (a = 0 for the zero-result variant)
    // adcs x0, x1, x2    = 0xBA020020   (5 + MAX + 1 = 5, C must stay 1)
    // adcs x4, x1, x2    = 0xBA020024   (5 again ONLY if C survived)
    // adcs x5, x3, x2    = 0xBA020065   (0 + MAX + 1 = 0, C must stay 1)
    // adcs x6, x3, x2    = 0xBA020066   (0 again ONLY if C survived)
    // hlt                = 0xD4400000
    let code: [u32; 8] = [
        0xD28000A1, 0x92800002, 0xD2800003, 0xBA020020, 0xBA020024, 0xBA020065, 0xBA020066,
        0xD4400000,
    ];
    for (i, w) in code.iter().enumerate() {
        ram[0x10000 + i * 4..0x10004 + i * 4].copy_from_slice(&w.to_le_bytes());
    }
    let mut cpu = Interpreter::new(Box::new(Ram(ram)));
    cpu.nzcv = 0x2; // C SET (carry-in) before the first adcs
    cpu.set_reset_vector(0x10000);
    let res = cpu.run(a13_cpu::InterpBudget { max_insn: 100, max_ns: 1_000_000_000 });
    assert_eq!(res.stop, StopReason::Halted);
    assert_eq!(cpu.x[0], 5, "5 + MAX + 1 must be 5, got {:#x}", cpu.x[0]);
    assert_eq!(
        cpu.x[4], 5,
        "second adcs must read the carried C: 5 again, got {:#x} (off by −1 = the lost carry)",
        cpu.x[4]
    );
    assert_eq!(cpu.x[5], 0, "0 + MAX + 1 must be 0, got {:#x}", cpu.x[5]);
    assert_eq!(
        cpu.x[6], 0,
        "second zero-variant adcs must read the carried C: 0 again, got {:#x}",
        cpu.x[6]
    );
    // and the flags after the last: Z set (result 0), C STILL set
    assert_eq!(cpu.nzcv & 0x4, 0x4, "Z must be set");
    assert_eq!(cpu.nzcv & 0x2, 0x2, "C must be SET (carry-out through MAX+1)");
}

// ------------------------------------------------------------------
// Micro-test 10: THE BUG-#53 edge — `ADCS Xd, XZR, XZR` (the Montgomery
// carry-capture idiom, kernel site 0x82dd298 in the P-256-order modmul):
// 0 + 0 + C must be 1 when C is set. The boot trace caught the engine
// answering 0 (Z=1 after the insn) inside the ECDSA sign's mod-n
// modmul — every accumulating limb's carry-out was dropped and s came
// out wrong (fipspost_post_ecdsa → CCERR_PARAMETER, boot insn
// 186,260,774). Encoding: adcs x11, xzr, xzr = 0xBA1F03EB.
// ------------------------------------------------------------------
#[test]
fn adcs_xzr_carry_capture() {
    let mut ram = vec![0u8; 0x80000];
    // movz x1, #5          = 0xD28000A1   (a = 5)
    // movn x2, #0          = 0x92800002   (b = 0xFFFF…FFFF)
    // adds x1, x1, x2      = 0xAB020021   (5 + MAX = 4, C SET)
    // adcs x11, xzr, xzr   = 0xBA1F03EB   (0 + 0 + C = 1 expected)
    // adcs x12, xzr, xzr   = 0xBA1F03EC   (0 + 0 + C' where C' from the
    //                                       first adcs: 0+0+1 = 1 → C'=0
    //                                       → x12 = 0)
    // hlt                  = 0xD4400000
    let code: [u32; 6] = [0xD28000A1, 0x92800002, 0xAB020021, 0xBA1F03EB, 0xBA1F03EC, 0xD4400000];
    for (i, w) in code.iter().enumerate() {
        ram[0x10000 + i * 4..0x10004 + i * 4].copy_from_slice(&w.to_le_bytes());
    }
    let mut cpu = Interpreter::new(Box::new(Ram(ram)));
    cpu.nzcv = 0; // C clear before the adds
    cpu.set_reset_vector(0x10000);
    let res = cpu.run(a13_cpu::InterpBudget { max_insn: 100, max_ns: 1_000_000_000 });
    assert_eq!(res.stop, StopReason::Halted);
    assert_eq!(cpu.x[1], 4, "5 + MAX = 4, got {:#x}", cpu.x[1]);
    assert_eq!(cpu.x[11], 1, "adcs x11, xzr, xzr with C=1 must be 1, got {:#x}", cpu.x[11]);
    assert_eq!(cpu.x[12], 0, "0 + 0 + 0 = 0 (C cleared by the first adcs), got {:#x}", cpu.x[12]);
}

/// Minimal flat RAM for the flag micro-test (same shape as the sha512 KAT).
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
