//! REAL-DATA repro (BUG #53): the ORDER-zp modmul used by the ECDSA sign's
//! s-ladder — the generic modmul dispatcher 0x82dfb40 (→ wrapper 0x82dfac4 →
//! ccn_mul 0x82b2df0 → Barrett REDUCE 0x82df894 with the NEON shift
//! 0x82e208c and the conditional-subtract driver 0x82d59e4), driven from the
//! EXACT captured boot state: the ORDER zp rodata (0x77c23f8 with its
//! Barrett mu at +0x38), the runtime GOT page, and the sign's own operands.
//!
//! Boot evidence (session-V staged stops): MUL#1 of the s-ladder
//! (insn ~184,565,100) computed ab5c0 = 0x0cec…940d from a = k =
//! 0x3830…6c5f and b = ws = 0x528e…fdb1 — but python says k·b mod n =
//! 0x4af2…2b9b. MUL#2 (same fn, same b) also diverged — the two effective
//! multipliers differ, so the generic mod-n Barrett path is broken while
//! the PRIME zp's special path (point math, 0x82bd54c) is not: keygen,
//! k·G and r are all proven correct.
//!
//! This test reproduces the wrong product in isolation (no scheduler, no
//! mutexes — the full sign-tail replay spins in thread_dispatch) and pins
//! the fix: the engine's product must equal the python truth.

use a13_cpu::interp::Interpreter;
use a13_cpu::{CpuBackend, MemAccess, StopReason};
use std::collections::HashMap;

include!("sign_kat_data.rs");

const MODMUL_DISPATCH: u64 = 0xfffffff0082dfb40;
const AFTER_WRAPPER: u64 = 0xfffffff0082dfbbc; // stop once modmul returns
const ZP_ORDER: u64 = 0xfffffff0077c23f8;

// scratch buffers (below the captured stack block — untouched pages)
const BUF_A: u64 = 0xffffffe802fa0000; // k
const BUF_B: u64 = 0xffffffe802fa0040; // ws operand
const BUF_OUT: u64 = 0xffffffe802fa0080; // result
const SCRATCH_SP: u64 = 0xffffffe802fa7000;

const PAGE: u64 = 0x1000;

// the captured operands (boot staged stop at 0x82b5ec0, after MUL#1):
// a = k (LE limbs @ab5c0 pre-MUL), b = ws (LE limbs @ab580 post-init+tag-OR)
const K_LIMBS: [u64; 4] = [
    0x20fc663cc74a6c5f,
    0x69f38c1a973d61aa,
    0xdac4077981e2ea52,
    0x3830b344fc565fe6,
];
const W_LIMBS: [u64; 4] = [
    0xe02c245772dbfdb1,
    0xc0a0f60dbf0fa61c,
    0x52427bccedb4a8b2,
    0x528e86873cbdf347,
];
// python: k·w mod n (LE limbs)
const TRUE_LIMBS: [u64; 4] = [
    0xb49bdb21d4032b9b,
    0x02b76fd53d918c11,
    0x5908e771f54e679a,
    0x4af2cc07e1a5efe1,
];
// what the BOOT's MUL#1 actually wrote (staged stop 0x82b5ec0) — the repro
// must reproduce THIS first (faithfulness), then be fixed to the truth
const BOOT_WRONG_LIMBS: [u64; 4] = [
    0x7c7c22e69de5940d,
    0x8333e79b59475cfe,
    0x70261e5f18f0383c,
    0x0cec698d825880fa,
];

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
            v |= (b as u64) << (8 * k);
        }
        v
    }
    fn store(&mut self, addr: u64, size: u8, val: u64) {
        for k in 0..size as usize {
            let a = addr + k as u64;
            // auto-create the page — stack stores must land even on fresh pages
            let p = self.page(a);
            p[(a % PAGE) as usize] = (val >> (8 * k)) as u8;
        }
    }
    fn fetch32(&mut self, addr: u64) -> u32 {
        let mut v = 0u32;
        for k in 0..4usize {
            let a = addr + k as u64;
            let b = {
                let pn = (a / PAGE) as u64;
                match self.pages.get(&pn) {
                    Some(p) => p[(a % PAGE) as usize],
                    None => 0,
                }
            };
            v |= (b as u32) << (8 * k);
        }
        v
    }
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn make_modmul_cpu(stop_at: u64) -> Interpreter {
    let mut ram = PagedRam::new();
    for ((va, len), bytes) in CODE_RANGES.iter().zip(CODE_HEX.iter()) {
        let bytes = hex_decode(bytes);
        assert_eq!(bytes.len(), *len, "code range {va:#x} length mismatch");
        ram.write(*va, &bytes);
    }
    for ((va, len), bytes) in RODATA_RANGES.iter().zip(RODATA_HEX.iter()) {
        let bytes = hex_decode(bytes);
        assert_eq!(bytes.len(), *len, "rodata range {va:#x} length mismatch");
        ram.write(*va, &bytes);
    }
    for ((va, len), bytes) in RUNTIME_RANGES.iter().zip(RUNTIME_HEX.iter()) {
        let bytes = hex_decode(bytes);
        assert_eq!(bytes.len(), *len, "runtime block {va:#x} length mismatch");
        ram.write(*va, &bytes);
    }
    // operands
    for (i, l) in K_LIMBS.iter().enumerate() {
        ram.write(BUF_A + 8 * i as u64, &l.to_le_bytes());
    }
    for (i, l) in W_LIMBS.iter().enumerate() {
        ram.write(BUF_B + 8 * i as u64, &l.to_le_bytes());
    }
    ram.write(BUF_OUT, &[0u8; 32]);

    let mut cpu = Interpreter::new(Box::new(ram));
    // x0 = zp (ORDER), x1 = out, x2 = a, x3 = b
    cpu.x[0] = ZP_ORDER;
    cpu.x[1] = BUF_OUT;
    cpu.x[2] = BUF_A;
    cpu.x[3] = BUF_B;
    cpu.sp = SCRATCH_SP;
    cpu.set_reset_vector(MODMUL_DISPATCH);
    cpu.stop_pc_range = Some((stop_at, stop_at + 4));
    cpu.trace_enabled = true;
    cpu.sys.tpidr_el1 = 0xfffffff009ab8be8;
    cpu
}

fn run_to(cpu: &mut Interpreter) -> [u64; 4] {
    let res = cpu.run(a13_cpu::InterpBudget { max_insn: 200_000, max_ns: 60_000_000_000 });
    match res.stop {
        StopReason::Halted => panic!("halted early at pc {:#x} — missing code range?", cpu.pc),
        StopReason::UnknownInsn { pc, insn } => {
            for (pc, w, regs, nzcv) in cpu.trace.iter().rev().take(150).collect::<Vec<_>>().iter().rev() {
                if *pc == 0xfffffff0082dfaec || *pc == 0xfffffff0082dfae0 || *pc == 0xfffffff0082dfaf0 {
                    println!(
                        "  *** {pc:#x}: x21={:#x} x8={:#x} x9={:#x} x29={:#x} sp={:#x}",
                        regs[21], regs[8], regs[9], regs[29], cpu.sp
                    );
                }
                println!(
                    "  trace {pc:#x}: {w:#010x} nzcv={nzcv:04b} x0={:#x} x1={:#x} x2={:#x} x3={:#x}",
                    regs[0], regs[1], regs[2], regs[3]
                );
            }
            // dump the ws_desc region
            println!("== ws_desc region ==");
            for va in (0xffffffe802fa6fc0..0xffffffe802fa7000).step_by(8) {
                println!("  {va:#x}: {:#018x}", cpu.mem().load(va, 8));
            }
            panic!("unknown insn {insn:#010x} at {pc:#x} — add the range", )
        }
        _ => {}
    }
    let mut out = [0u64; 4];
    for i in 0..4 {
        out[i] = cpu.mem().load(BUF_OUT + 8 * i as u64, 8);
    }
    // debug: dump the dispatcher's stack frame region
    println!("== stack dump 0x...6e00..0x...7000 ==");
    for va in (0xffffffe802fa6e00..0xffffffe802fa7000).step_by(8) {
        let v = cpu.mem().load(va, 8);
        println!("  {va:#x}: {v:016x}");
    }
    out
}

fn fmt_limbs(l: &[u64; 4]) -> String {
    l.iter().rev().map(|x| format!("{x:016x}")).collect()
}

/// Stage-bisect of the Barrett pipeline (run with --nocapture): dumps each
/// intermediate so the first divergent fn can be pinned against python.
#[test]
fn order_modmul_barrett_stages() {
    // python-true intermediates are computed in scripts/re/modmul_check.py;
    // this test prints the engine's values at each stage boundary.
    let stages: [(u64, &str); 6] = [
        (0xfffffff0082dfb04, "after ccn_mul (raw 8-limb product @cursor)"),
        (0xfffffff0082df960, "after shift#1 (q_hat = product>>255 @cursor)"),
        (0xfffffff0082df97c, "after mul#1 (mu*q_hat @temp1)"),
        (0xfffffff0082df994, "after shift#2 (q = mu*q_hat>>257 @cursor)"),
        (0xfffffff0082df9ac, "after mul#2 (n*q @temp1)"),
        (0xfffffff0082dfa44, "after the REDUCE returns (out written)"),
    ];
    for (stop, what) in stages {
        let mut cpu = make_modmul_cpu(stop);
        let res = cpu.run(a13_cpu::InterpBudget { max_insn: 200_000, max_ns: 60_000_000_000 });
        let hit = cpu.pc == stop;
        println!("== {what} (stop {stop:#x}, reached: {hit}, executed {})", res.executed);
        // cursor area: product/q area at 0x...6e40, temp1 at 0x...6e70
        for base in (0xffffffe802fa6e00u64..0xffffffe802fa6f10u64).step_by(8) {
            let v = cpu.mem().load(base, 8);
            println!("  {base:#x}: {v:016x}");
        }
        let o0 = cpu.mem().load(BUF_OUT, 8);
        let o1 = cpu.mem().load(BUF_OUT + 8, 8);
        println!("  OUT: {o0:016x} {o1:016x}");
    }
}

/// The engine must reproduce the BOOT's wrong product first (faithfulness
/// of the repro), then — after the fix — the python truth. Until the fix
/// lands, this prints both and asserts the truth (red pin).
#[test]
fn order_modmul_barrett_repro() {
    let mut cpu = make_modmul_cpu(AFTER_WRAPPER);
    let out = run_to(&mut cpu);
    println!("engine out : {}", fmt_limbs(&out));
    println!("boot wrote : {}", fmt_limbs(&BOOT_WRONG_LIMBS));
    println!("python true: {}", fmt_limbs(&TRUE_LIMBS));
    // CAMPAIGN PIN (was RED before the #53 fix: the engine used to
    // reproduce BOOT_WRONG_LIMBS — the truncated `mov v3.d[1], x5` INS-GPR
    // decode lost the high 32 bits of the shift-loop's last feed limb):
    // the isolated ORDER-zp modmul must equal the python truth k·w mod n.
    assert_eq!(out, TRUE_LIMBS, "the mod-n Barrett modmul is still wrong");
}
