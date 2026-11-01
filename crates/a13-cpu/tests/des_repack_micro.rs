//! REAL-DATA micro-repro (BUG #54): the kernel's DES key-schedule REPACK
//! loop (0x82e2d10..0x82e2d58 — 18 words, verbatim), single-stepped with
//! v-register dumps after every instruction.
//!
//! The repack reshuffles each raw (klo, khi) subkey pair into the
//! S-box-index layout the block fn expects. Engine-vs-model evidence:
//! round 0 raw = (klo 0x00f7d08b, khi 0x002fbf74) must repack to
//! (0x3D223E3D, 0x3D0B0234); the engine produced (0x3D02003D, 0x3D0B3B34)
//! — the v17 (fmov s17,mov v17.s[1]) contribution to klo' bits 8-13 is
//! missing and khi' bits 8-13 got v16-lane-1's value with a wrong mask.

use a13_cpu::interp::Interpreter;
use a13_cpu::{CpuBackend, MemAccess, StopReason};

const WORDS: [u32; 18] = [
    0x8b08012b, // add  x11, x9, x8
    0x0ddfc967, // ld1r {v7.2s}, [x11], #4
    0xb940016b, // ldr  w11, [x11]
    0x530a7d6c, // lsr  w12, w11, #0xa
    0x2ea044f0, // ushl v16.2s, v7.2s, v0.2s
    0x0e211e10, // and  v16.8b, v16.8b, v1.8b
    0x2ea244e7, // ushl v7.2s, v7.2s, v2.2s
    0x0e231ce7, // and  v7.8b, v7.8b, v3.8b
    0x0ea71e07, // orr  v7.8b, v7.8b, v16.8b
    0x0e040d70, // dup  v16.2s, w11
    0x2ea44610, // ushl v16.2s, v16.2s, v4.2s
    0x0e251e10, // and  v16.8b, v16.8b, v5.8b
    0x1e270191, // fmov s17, w12
    0x4e0c1d71, // mov  v17.s[1], w11
    0x0e261e31, // and  v17.8b, v17.8b, v6.8b
    0x0eb11ce7, // orr  v7.8b, v7.8b, v17.8b
    0x0eb01ce7, // orr  v7.8b, v7.8b, v16.8b
    0xfc286947, // str  d7, [x10], #8
];

const CODE_VA: u64 = 0x1000;
const RAW_VA: u64 = 0x2000; // the raw (klo, khi)
const OUT_VA: u64 = 0x3000;
const STACK: u64 = 0x7000;

struct FlatRam(Vec<u8>);
impl MemAccess for FlatRam {
    fn load(&mut self, addr: u64, size: u8) -> u64 {
        let mut v = 0u64;
        for k in 0..size as usize {
            v |= (self.0[addr as usize + k] as u64) << (8 * k);
        }
        v
    }
    fn store(&mut self, addr: u64, size: u8, val: u64) {
        for k in 0..size as usize {
            self.0[addr as usize + k] = (val >> (8 * k)) as u8;
        }
    }
    fn fetch32(&mut self, addr: u64) -> u32 {
        u32::from_le_bytes(self.0[addr as usize..addr as usize + 4].try_into().unwrap())
    }
}

fn f128(v: u128) -> String {
    format!("[{:08x} {:08x}]", (v >> 32) as u32, v as u32)
}

#[test]
fn des_repack_loop_micro() {
    let mut ram = FlatRam(vec![0u8; 0x10000]);
    for (i, w) in WORDS.iter().enumerate() {
        ram.store(CODE_VA + 4 * i as u64, 4, *w as u64);
    }
    // raw round-0 subkey: klo = 0x00f7d08b, khi = 0x002fbf74
    ram.store(RAW_VA, 4, 0x00f7_d08b);
    ram.store(RAW_VA + 4, 4, 0x002f_bf74);
    // v0 = [6, 12], v2 = [10, 16], v4 = [−6, −4] (the NEG'd constant)
    let mut cpu = Interpreter::new(Box::new(ram));
    cpu.v.v[0] = (12u128 << 32) | 6;
    cpu.v.v[2] = (16u128 << 32) | 10;
    let neg = |x: i32| -> u32 { (x as i64) as u32 };
    cpu.v.v[4] = ((neg(-4) as u128) << 32) | neg(-6) as u128;
    // v1 = 0x3F000000 per lane, v3 = 0x003F0000 per lane
    cpu.v.v[1] = (0x3F00_0000u128 << 32) | 0x3F00_0000;
    cpu.v.v[3] = (0x003F_0000u128 << 32) | 0x003F_0000;
    // v5 = [0x0000003f, 0x00003f00], v6 = [0x00003f00, 0x0000003f]
    cpu.v.v[5] = (0x0000_3F00u128 << 32) | 0x0000_003F;
    cpu.v.v[6] = (0x0000_003Fu128 << 32) | 0x0000_3F00;
    // registers: x9 = RAW_VA, x8 = 0, x10 = OUT_VA
    cpu.x[9] = RAW_VA;
    cpu.x[8] = 0;
    cpu.x[10] = OUT_VA;
    cpu.sp = STACK;
    cpu.set_reset_vector(CODE_VA);

    let names = [
        "add x11,x9,x8", "ld1r v7,[x11],#4", "ldr w11,[x11]", "lsr w12,w11,#10",
        "ushl v16,v7,v0", "and v16,v16,v1", "ushl v7,v7,v2", "and v7,v7,v3",
        "orr v7,v7,v16", "dup v16,w11", "ushl v16,v16,v4", "and v16,v16,v5",
        "fmov s17,w12", "mov v17.s[1],w11", "and v17,v17,v6", "orr v7,v7,v17",
        "orr v7,v7,v16", "str d7,[x10],#8",
    ];
    for (i, name) in names.iter().enumerate() {
        cpu.step().expect("step");
        let w11 = cpu.x[11] as u32;
        let w12 = cpu.x[12] as u32;
        println!(
            "{:2} {:22} w11={w11:08x} w12={w12:08x} v7={} v16={} v17={}",
            i + 1, name, f128(cpu.v.v[7]), f128(cpu.v.v[16]), f128(cpu.v.v[17])
        );
    }
    // expected repack (python model, des_full_model.py): klo' = 0x3D020B3D, khi' = 0x3D0B3B34
    let lo = cpu.mem().load(OUT_VA, 4) as u32;
    let hi = cpu.mem().load(OUT_VA + 4, 4) as u32;
    println!("out: klo'={lo:08x} khi'={hi:08x} (want 3d020b3d / 3d0b3b34)");
    assert_eq!(lo, 0x3D02_0B3D, "repacked klo' wrong");
    assert_eq!(hi, 0x3D0B_3B34, "repacked khi' wrong");
}
