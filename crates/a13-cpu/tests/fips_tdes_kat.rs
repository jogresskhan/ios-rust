//! REAL-DATA repro (BUG #54): the kernel's 3DES block fn 0x82e2fd0 (the
//! SP-table DES with folded IP/FP — a pure leaf, no calls), driven with the
//! CAPTURED scheduled keys and the CBC-whitened block from the fipspost
//! tdes_cbc test (boot insn 2,218,418,09).
//!
//! Boot evidence: the POST's tdes_cbc round-1 compare failed — the engine
//! produced 0xa83c81282d62a782 where python 3DES-CBC says 0x68c06c8af772abff
//! (key 5ee4db0c…e07f, P 88137a562beab0e2, IV b90969d0503f61f3, the
//! whitened block 311a13867bd5d111). The SP tables in runtime memory match
//! the kernel file bit-for-bit — so the corruption is in the fn's execution
//! (or the key schedule that produced the captured ws).
//!
//! This test runs the fn single-stepped and prints w4/w5 after every
//! 2-round iteration, so the first divergent round can be pinned against
//! scripts/re/des_model.py.

use a13_cpu::interp::Interpreter;
use a13_cpu::{CpuBackend, MemAccess, StopReason};

include!("tdes_kat_data.rs");

const CODE_VA: u64 = 0xfffffff0082e2fd0;
const TABS_VA: u64 = 0xfffffff007051e30;
const WS_VA: u64 = 0x5000;
const BLOCK_VA: u64 = 0x6000;
const STACK: u64 = 0x7000;
const HALT: u64 = 0x4000;

const ENGINE_OUT: [u8; 8] = [0xa8, 0x3c, 0x81, 0x28, 0x2d, 0x62, 0xa7, 0x82];
const TRUE_OUT: [u8; 8] = [0x68, 0xc0, 0x6c, 0x8a, 0xf7, 0x72, 0xab, 0xff];

struct PagedRam {
    pages: std::collections::HashMap<u64, Box<[u8; 4096]>>,
}
impl PagedRam {
    fn new() -> Self {
        PagedRam { pages: std::collections::HashMap::new() }
    }
    fn page(&mut self, va: u64) -> &mut [u8; 4096] {
        let pn = (va / 0x1000) as u64;
        self.pages.entry(pn).or_insert_with(|| Box::new([0u8; 4096]))
    }
    fn write(&mut self, va: u64, bytes: &[u8]) {
        let mut i = 0usize;
        while i < bytes.len() {
            let a = va + i as u64;
            let off = (a % 0x1000) as usize;
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
            let pn = (a / 0x1000) as u64;
            let b = match self.pages.get(&pn) {
                Some(p) => p[(a % 0x1000) as usize],
                None => 0,
            };
            v |= (b as u64) << (8 * k);
        }
        v
    }
    fn store(&mut self, addr: u64, size: u8, val: u64) {
        for k in 0..size as usize {
            let a = addr + k as u64;
            let p = self.page(a);
            p[(a % 0x1000) as usize] = (val >> (8 * k)) as u8;
        }
    }
    fn fetch32(&mut self, addr: u64) -> u32 {
        self.load(addr, 4) as u32
    }
}

fn hexb(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// builds the ws with the ENGINE's own (fixed) schedule fn — K1/K2/K3
fn make_cpu_with_fresh_ws() -> Interpreter {
    let mut cpu = make_cpu();
    // run the three schedules into WS_VA via a side interpreter
    let key = hexb("5ee4db0cdfdf719e40fc962d2f31f416d9aa0f228d89e07f");
    for i in 0..3usize {
        let dir = if i == 1 { 1u64 } else { 0 };
        let off = (i as u64) * 0x80;
        let mut sram = PagedRam::new();
        let sched = hexb(SCHED_CODE_HEX);
        sram.write(SCHED_VA, &sched);
        let stabs = hexb(SCHED_TABS_HEX);
        sram.write(STAB_VA, &stabs);
        let nlz = hexb(SCHED_NLZ_HEX);
        sram.write(0xfffffff0070528d0, &nlz);
        sram.write(HALT, &0xD440_0000u32.to_le_bytes());
        sram.write(KEY_VA, &key);
        let mut scpu = Interpreter::new(Box::new(sram));
        scpu.x[0] = KEY_VA + 8 * i as u64;
        scpu.x[1] = dir;
        scpu.x[2] = WS_VA + off;
        scpu.x[30] = HALT;
        scpu.sp = STACK;
        scpu.set_reset_vector(SCHED_VA);
        let r = scpu.run(a13_cpu::InterpBudget { max_insn: 200_000, max_ns: 30_000_000_000 });
        assert!(matches!(r.stop, a13_cpu::StopReason::Halted), "sched {i}: {:?}", r.stop);
        for b in 0..0x80usize {
            let v = scpu.mem().load(WS_VA + off + b as u64, 1) as u8;
            cpu.mem().store(WS_VA + off + b as u64, 1, v as u64);
        }
    }
    cpu
}

fn make_cpu() -> Interpreter {
    let mut ram = PagedRam::new();
    let code = hexb(CODE_HEX);
    ram.write(CODE_VA, &code);
    let tabs = hexb(TABS_HEX);
    ram.write(TABS_VA, &tabs);
    let ws = hexb(WS_HEX);
    ram.write(WS_VA, &ws);
    // the block: the caller (0x82b3dac) stores the whitened block BE-rev'd:
    // sp[0:4] = rev32(BE32(block[0:4])) — i.e. ldp reads back BE32(block[0:4])
    let block: [u8; 8] = [0x31, 0x1a, 0x13, 0x86, 0x7b, 0xd5, 0xd1, 0x11];
    let w0 = u32::from_be_bytes([block[0], block[1], block[2], block[3]]);
    let w1 = u32::from_be_bytes([block[4], block[5], block[6], block[7]]);
    ram.write(BLOCK_VA, &w0.to_le_bytes());
    ram.write(BLOCK_VA + 4, &w1.to_le_bytes());
    // halt insn at the return target
    ram.write(HALT, &0xD440_0000u32.to_le_bytes());

    let mut cpu = Interpreter::new(Box::new(ram));
    cpu.x[0] = BLOCK_VA;
    cpu.x[1] = WS_VA;
    cpu.x[30] = HALT;
    cpu.sp = STACK;
    cpu.set_reset_vector(CODE_VA);
    cpu
}

#[test]
fn tdes_block_fn_repro() {
    let mut cpu = make_cpu_with_fresh_ws();
    // single-step, dumping w4/w5 (regs 4,5) after each loop-back branch
    let mut iter = 0usize;
    let mut prev_pc = 0u64;
    for _ in 0..4000 {
        match cpu.step() {
            Ok(()) => {}
            Err(StopReason::Halted) => break,
            Err(e) => panic!("stop {:?} at pc {:#x}", e, cpu.pc),
        }
        if (0xfffffff0082e2fec..=0xfffffff0082e3040).contains(&cpu.pc) {
            println!(
                "IP {:#x}: w8={:#010x} w9={:#010x} w10={:#010x} w4={:#010x} w5={:#010x}",
                cpu.pc, cpu.x[8] as u32, cpu.x[9] as u32, cpu.x[10] as u32, cpu.x[4] as u32, cpu.x[5] as u32
            );
        }
        if cpu.pc == 0xfffffff0082e3090 || cpu.pc == 0xfffffff0082e3180 || cpu.pc == 0xfffffff0082e3270 {
            if prev_pc != cpu.pc {
                println!(
                    "pass-iter {:2} (loop {:#x}): w4={:#010x} w5={:#010x}",
                    iter,
                    cpu.pc,
                    cpu.x[4] as u32,
                    cpu.x[5] as u32
                );
                iter += 1;
            }
        }
        prev_pc = cpu.pc;
    }
    let out0 = cpu.mem().load(BLOCK_VA, 4) as u32;
    let out1 = cpu.mem().load(BLOCK_VA + 4, 4) as u32;
    let bytes = [
        (out0 >> 24) as u8, (out0 >> 16) as u8, (out0 >> 8) as u8, out0 as u8,
        (out1 >> 24) as u8, (out1 >> 16) as u8, (out1 >> 8) as u8, out1 as u8,
    ];
    println!("engine fn out: {}", bytes.iter().map(|b| format!("{b:02x}")).collect::<String>());
    println!("boot engine out: {}", ENGINE_OUT.iter().map(|b| format!("{b:02x}")).collect::<String>());
    println!("python true out: {}", TRUE_OUT.iter().map(|b| format!("{b:02x}")).collect::<String>());
    // CAMPAIGN PIN (was RED pre-#54-fix, reproducing ENGINE_OUT exactly —
    // the 32-bit ROR shifted-operand rotated at 64-bit width): the isolated
    // fn must now produce the python 3DES-CBC truth for the captured inputs.
    assert_eq!(
        bytes, TRUE_OUT,
        "the kernel 3DES block fn still diverges from the python truth"
    );
}


const SCHED_VA: u64 = 0xfffffff0082e2b64;
const STAB_VA: u64 = 0xfffffff007051d38; // pc1|bitmask|shifts|pc2|spread, 248 B
const KEY_VA: u64 = 0x8000;
const SCHED_OUT: u64 = 0x9000;

/// The single-key schedule fn 0x82e2b64 (pure leaf): drives K1/dir=0 and
/// prints per-round (klo, khi) so the engine can be diffed against the
/// python model (scripts/re — session V) one round at a time.
#[test]
fn tdes_key_schedule_rounds() {
    let mut ram = PagedRam::new();
    let code = hexb(SCHED_CODE_HEX);
    ram.write(SCHED_VA, &code);
    let tabs = hexb(SCHED_TABS_HEX);
    ram.write(STAB_VA, &tabs);
    let nlz = hexb(SCHED_NLZ_HEX);
    ram.write(0xfffffff0070528d0, &nlz);
    ram.write(HALT, &0xD440_0000u32.to_le_bytes());
    // K1 = 5ee4db0cdfdf719e (the first 8 bytes of the POST key)
    ram.write(KEY_VA, &hexb("5ee4db0cdfdf719e"));

    let mut cpu = Interpreter::new(Box::new(ram));
    cpu.x[0] = KEY_VA;
    cpu.x[1] = 0; // dir = encrypt
    cpu.x[2] = SCHED_OUT;
    cpu.x[30] = HALT;
    cpu.sp = STACK;
    cpu.set_reset_vector(SCHED_VA);

    // dump each round's (klo, khi) at the round-loop tail (0x82e2cc4:
    // after the 24-entry PC-2 inner loop completed)
    let mut round = 0usize;
    let mut prev_pc = 0u64;
    loop {
        match cpu.step() {
            Ok(()) => {}
            Err(StopReason::Halted) => break,
            Err(e) => panic!("stop {:?} at pc {:#x}", e, cpu.pc),
        }
        if cpu.pc == 0xfffffff0082e2d10 && prev_pc != cpu.pc {
            println!(
                "repack setup: v0={:016x} v1={:016x} v2={:016x} v3={:016x} v4={:016x} v5={:016x} v6={:016x}",
                cpu.v.v[0], cpu.v.v[1], cpu.v.v[2], cpu.v.v[3], cpu.v.v[4], cpu.v.v[5], cpu.v.v[6]
            );
        }
        if cpu.pc == 0xfffffff0082e2cc4 && prev_pc != cpu.pc {
            let klo = cpu.mem().load(SCHED_OUT + (round as u64) * 8, 4);
            let khi = cpu.mem().load(SCHED_OUT + (round as u64) * 8 + 4, 4);
            println!(
                "round {:2}: w5={:#010x} w4={:#010x}  [out {:#010x} {:#010x}]",
                round, cpu.x[5] as u32, cpu.x[4] as u32, klo, khi
            );
            round += 1;
        }
        prev_pc = cpu.pc;
    }
    println!("completed {} rounds", round);
    // the full schedule output
    let mut ws = [0u8; 0x80];
    for i in 0..0x80 {
        ws[i] = cpu.mem().load(SCHED_OUT + i as u64, 1) as u8;
    }
    println!("engine sched(K1): {}", ws.iter().map(|b| format!("{b:02x}")).collect::<String>());
    // the python model's K1 repack (tools/re/oracle — session V; the OLD
    // boot capture had the pre-#54-fix garbage in the never-stable bits)
    let expect = hexb("3d0b023d343b0b3d0a372f273b252b032d35392c2d3719372f2c3f13382b04173c3c3714371b1d2f3a1f15173a32231e251f36381f172f3c03090e3e3e3f071a3f36393e1b262e310c1f2b3a193f080f153c3d042a373e0f2c3b35392e0b13073b3d3d193e07253e2b1f16323b19133f31251f1f3b3f3b183e3e2e2a0f15383d");
    println!("model K1       : {}", expect.iter().map(|b| format!("{b:02x}")).collect::<String>());
    assert_eq!(&ws[..], &expect[..], "isolated schedule != python model");
}


/// END-TO-END (BUG #54 campaign pin): the engine runs the kernel's own
/// schedule fn (0x82e2b64) for K1-enc/K2-dec/K3-enc, then the kernel's own
/// 3DES block fn (0x82e2fd0) on the CBC-whitened block — the result must
/// equal the python 3DES-CBC truth (68c06c8af772abff) for the POST's key.
#[test]
fn tdes_end_to_end_engine_chain() {
    let mut ram = PagedRam::new();
    let code = hexb(CODE_HEX);
    ram.write(CODE_VA, &code);
    let sched = hexb(SCHED_CODE_HEX);
    ram.write(SCHED_VA, &sched);
    let tabs = hexb(TABS_HEX);
    ram.write(TABS_VA, &tabs);
    let stabs = hexb(SCHED_TABS_HEX);
    ram.write(STAB_VA, &stabs);
    let nlz = hexb(SCHED_NLZ_HEX);
    ram.write(0xfffffff0070528d0, &nlz);
    ram.write(HALT, &0xD440_0000u32.to_le_bytes());
    // the POST key
    let key = hexb("5ee4db0cdfdf719e40fc962d2f31f416d9aa0f228d89e07f");
    ram.write(KEY_VA, &key);

    // build the ws: K1-enc @0, K2-dec @0x80, K3-enc @0x100
    for (i, (off, dir)) in [(0u64, 0u64), (0x80, 1), (0x100, 0)].iter().enumerate() {
        let mut cpu = Interpreter::new(Box::new(ram_copy(&ram)));
        cpu.x[0] = KEY_VA + 8 * i as u64;
        cpu.x[1] = *dir;
        cpu.x[2] = WS_VA + off;
        cpu.x[30] = HALT;
        cpu.sp = STACK;
        cpu.set_reset_vector(SCHED_VA);
        let r = cpu.run(a13_cpu::InterpBudget { max_insn: 200_000, max_ns: 30_000_000_000 });
        assert!(matches!(r.stop, a13_cpu::StopReason::Halted), "schedule {i} stopped: {:?}", r.stop);
        // merge the produced 0x80 bytes back into the shared ram
        for b in 0..0x80usize {
            let v = cpu.mem().load(WS_VA + off + b as u64, 1) as u8;
            ram.write(WS_VA + off + b as u64, &[v]);
        }
    }

    // run the block fn on the whitened block
    let mut cpu = Interpreter::new(Box::new(ram_copy(&ram)));
    let block: [u8; 8] = [0x31, 0x1a, 0x13, 0x86, 0x7b, 0xd5, 0xd1, 0x11];
    let w0 = u32::from_be_bytes([block[0], block[1], block[2], block[3]]);
    let w1 = u32::from_be_bytes([block[4], block[5], block[6], block[7]]);
    cpu_mem_write(&mut cpu, BLOCK_VA, &w0.to_le_bytes());
    cpu_mem_write(&mut cpu, BLOCK_VA + 4, &w1.to_le_bytes());
    cpu.x[0] = BLOCK_VA;
    cpu.x[1] = WS_VA;
    cpu.x[30] = HALT;
    cpu.sp = STACK;
    cpu.set_reset_vector(CODE_VA);
    let r = cpu.run(a13_cpu::InterpBudget { max_insn: 100_000, max_ns: 30_000_000_000 });
    assert!(matches!(r.stop, a13_cpu::StopReason::Halted), "block fn stopped: {:?}", r.stop);
    let out0 = cpu.mem().load(BLOCK_VA, 4) as u32;
    let out1 = cpu.mem().load(BLOCK_VA + 4, 4) as u32;
    let bytes = [
        (out0 >> 24) as u8, (out0 >> 16) as u8, (out0 >> 8) as u8, out0 as u8,
        (out1 >> 24) as u8, (out1 >> 16) as u8, (out1 >> 8) as u8, out1 as u8,
    ];
    println!("engine chain out: {}", bytes.iter().map(|b| format!("{b:02x}")).collect::<String>());
    assert_eq!(bytes, TRUE_OUT, "the engine's own schedule+block chain must give the 3DES truth");
}

// helper: clone the paged ram (the Interpreter takes ownership)
fn ram_copy(ram: &PagedRam) -> PagedRam {
    PagedRam { pages: ram.pages.clone() }
}

fn cpu_mem_write(cpu: &mut Interpreter, va: u64, bytes: &[u8]) {
    for (i, b) in bytes.iter().enumerate() {
        cpu.mem().store(va + i as u64, 1, *b as u64);
    }
}
