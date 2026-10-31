//! REAL-DATA repro (BUG #53): the 18C66 ECDSA sign's s-computation — the
//! sign-core tail (entry 0x82b5e10, right after the k·G point mult) with its
//! full helper graph extracted verbatim from the decoded kernelcache, driven
//! from the EXACT captured boot state (insn 184,560,198): registers, the
//! stack frame (incl. the k·G point {x=r, y1} and the hash message), the
//! heap workspaces, the runtime-resolved GOT page, and the curve RODATA.
//!
//! The boot's sign produced s = 0x7b1b1e35… (verify: ccec_verify rejects,
//! fipspost_post_ecdsa → CCERR_PARAMETER −18 → "FIPS Kernel POST Failed").
//! Python ground truth for the same (k, r, d, e): s = 0x8c6e8645… — this
//! test reproduces the divergence on the engine and bisects the mod-n
//! division/reciprocal chain against python (scripts/re/ecdsa_check.py).

use a13_cpu::interp::Interpreter;
use a13_cpu::{CpuBackend, MemAccess, StopReason};
use std::collections::HashMap;

include!("sign_kat_data.rs");

const HALT: u64 = 0x60000000;
const SIGN_RETURN: u64 = 0xfffffff0082c449c; // sign-core returns into the wrapper

// python ground truth for the captured inputs
const TRUE_R: u64 = 0x0842c57f8a8085da; // r limb 0 (LE) — r = 0x1232…c57f
const TRUE_S_LIMB0: u64 = 0x64617b96429ba89c; // true s limb 0 — s = 0x8c6e…e527
const ENGINE_S_LIMB0: u64 = 0x64617b96429ba89c; // filled after first run

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
            v |= (b as u64) << (8 * k);
        }
        v
    }
    fn store(&mut self, addr: u64, size: u8, val: u64) {
        for k in 0..size as usize {
            let a = addr + k as u64;
            let pn = (a / PAGE) as u64;
            if let Some(p) = self.pages.get_mut(&pn) {
                p[(a % PAGE) as usize] = (val >> (8 * k)) as u8;
            }
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

fn make_sign_cpu() -> Interpreter {
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
    ram.write(HALT, &0xD440_0000u32.to_le_bytes());

    let mut cpu = Interpreter::new(Box::new(ram));
    for (i, v) in ENTRY_REGS.iter().enumerate() {
        cpu.x[i] = *v;
    }
    cpu.sp = ENTRY_SP;
    cpu.set_reset_vector(ENTRY_PC);
    cpu.stop_pc_range = Some((SIGN_RETURN, SIGN_RETURN + 4));
    cpu.trace_enabled = true;
    // per-CPU state (mutex/preemption counters) via TPIDR_EL1 — the boot had
    // it set by the kernel (report: tpidr 0xfffffff009ab8be8)
    cpu.sys.tpidr_el1 = 0xfffffff009ab8be8;
    cpu
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn dump_region(cpu: &mut Interpreter, va: u64, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    for i in 0..len {
        out[i] = (cpu.mem().load(va + i as u64, 1) & 0xFF) as u8;
    }
    out
}

// WIP diagnostic for BUG #53 (run with --ignored --nocapture): the
// sign-tail replay needs kernel allocator/scheduler state fidelity that is
// still being staged (auto-range loop converged; the mutex path spins in
// thread_dispatch). Kept for the next block — see session-U notes.
#[test]
#[ignore]
fn ecdsa_sign_tail_repro() {
    let mut cpu = make_sign_cpu();
    let res = cpu.run(a13_cpu::InterpBudget { max_insn: 5_000_000, max_ns: 120_000_000_000 });
    let executed = res.executed;
    println!("stop: {:?} after {} insns, pc {:#x}", res.stop, executed, cpu.pc);
    // dump the last 24 instructions on any failure path
    for (pc, w, regs, nzcv) in cpu.trace.iter().rev().take(24).collect::<Vec<_>>().iter().rev() {
        println!(
            "  trace {pc:#x}: {w:#010x} nzcv={nzcv:04b} x0={:#x} x1={:#x} x2={:#x} x9={:#x}",
            regs[0], regs[1], regs[2], regs[9]
        );
    }
    match res.stop {
        StopReason::Halted => panic!("halted early at pc {:#x} — missing code range?", cpu.pc),
        StopReason::UnknownInsn { pc, insn } => {
            panic!("unknown insn {insn:#010x} at {pc:#x} — add the range (fn {:#x})", pc)
        }
        _ => {}
    }

    // The sign-core wrote r into VLA x20 (0x…ab560) and s into its out VLA.
    // Dump the whole stack window and report the limbs.
    let stack = dump_region(&mut cpu, 0xffffffe802fab400, 0x400);
    for off in (0..0x400).step_by(0x20) {
        let row = &stack[off..off + 0x20];
        let hexs: String = row.iter().map(|b| format!("{b:02x}")).collect();
        println!("  +{:#x}: {}", 0xffffffe802fab400 + off as u64, hexs);
    }

    // r sanity: the point-x (== r, engine == truth — proven on-curve)
    let r0 = cpu.mem().load(0xffffffe802fab560, 8);
    println!("r limb0 @ab560: {r0:#x} (expected {TRUE_R:#x})");
    assert_eq!(r0, TRUE_R, "r itself diverged — the mult/reduce is broken too");

    // find s: scan the stack for the true-s or engine-s patterns
    let true_s = hex_decode("27e59506c0b6f3f48fc2c273b43cda22d8fb7da5a52ac8985a78b22554568e8c");
    let eng_s = hex_decode("9ca89b42967b61642cbce03225f1c0a8159bdabedddc96c1a8c496aa351e1b7b");
    let blob = dump_region(&mut cpu, 0xffffffe802fab000, 0x1000);
    let find = |pat: &[u8]| -> Option<usize> {
        (0..blob.len().saturating_sub(pat.len())).find(|&i| &blob[i..i + pat.len()] == pat)
    };
    let tpos = find(&true_s);
    let epos = find(&eng_s);
    println!("true-s found on stack: {:?}", tpos.map(|i| format!("{:#x}", 0xffffffe802fab000 + i)));
    println!("engine-s (wrong) found: {:?}", epos.map(|i| format!("{:#x}", 0xffffffe802fab000 + i)));
    // RED assertion for the campaign: the engine's s must equal the python truth
    assert!(tpos.is_some(), "the TRUE s was never produced — still broken");
}
