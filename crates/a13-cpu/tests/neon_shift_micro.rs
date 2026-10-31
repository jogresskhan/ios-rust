//! REAL-DATA micro-repro (BUG #53): the NEON right-shift loop of the
//! kernel's ccn_shift (fn 0x82e208c, the Barrett q̂/q shifter) — the EXACT
//! 11-word loop at 0x82e20d0..0x82e20fc, single-stepped with v-register
//! dumps after every instruction.
//!
//! Boot/stage evidence: q̂ = product>>255 came out right in limbs 0..2 but
//! limb3 = 0x00000001_6be2c6eb instead of 0x243dc3ed_6be2c6eb — the
//! (next_limb << 1) high half never made it; only its low 32 bits did.
//! The suspects, in order: ext v3.16b,v1.16b,v1.16b,#8 / mov v3.d[1],x5
//! / ushl v3.2d,v3.2d,v5.2d / eor v1.16b,v1.16b,v3.16b.

use a13_cpu::interp::Interpreter;
use a13_cpu::{CpuBackend, MemAccess};

const CODE_VA: u64 = 0x1000;
const SRC_VA: u64 = 0x2000;
const DST_VA: u64 = 0x3000;
const STACK: u64 = 0x7000;

// the exact loop words (0x82e20d0..0x82e20fc) + a halt
const WORDS: [u32; 12] = [
    0x4cdfac40, // ld1 {v0.2d, v1.2d}, [x2], #32
    0x6e014002, // ext v2.16b, v0.16b, v1.16b, #8
    0xf9400045, // ldr x5, [x2]
    0x6e014023, // ext v3.16b, v1.16b, v1.16b, #8
    0x4e181ca3, // mov v3.d[1], x5
    0x6ee44400, // ushl v0.2d, v0.2d, v4.2d
    0x6ee44421, // ushl v1.2d, v1.2d, v4.2d
    0x6ee54442, // ushl v2.2d, v2.2d, v5.2d
    0x6ee54463, // ushl v3.2d, v3.2d, v5.2d
    0x6e221c00, // eor v0.16b, v0.16b, v2.16b
    0x6e231c21, // eor v1.16b, v1.16b, v3.16b
    0x4c9fac20, // st1 {v0.2d, v1.2d}, [x1], #32
];

// the product's limbs 3..8 (LE) — src for q̂ = product>>255
const SRC: [u64; 5] = [
    0xd7b29413dca226bc,
    0x6881276235008f7c,
    0xbffaab4e8f9d842c,
    0xd2ac7b6e9db6eb94,
    0x121ee1f6b5f16375,
];
// python truth: dst = [R0..R3] with R3 = (L6>>63)|(L7<<1)
const TRUE_R3: u64 = 0x243dc3ed6be2c6eb;

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
    format!("[{:016x} {:016x}]", (v >> 64) as u64, v as u64)
}

#[test]
fn neon_shift_loop_micro() {
    let mut ram = FlatRam(vec![0u8; 0x8000]);
    for (i, w) in WORDS.iter().enumerate() {
        ram.store(CODE_VA + 4 * i as u64, 4, *w as u64);
    }
    for (i, l) in SRC.iter().enumerate() {
        ram.store(SRC_VA + 8 * i as u64, 8, *l);
    }
    let mut cpu = Interpreter::new(Box::new(ram));
    cpu.x[0] = 5; // n limbs (not used by the loop body itself)
    cpu.x[1] = DST_VA; // dst
    cpu.x[2] = SRC_VA; // src
    cpu.x[3] = 63; // shift amount
    // v4 = [-63, -63] (dup of the negated amount), v5 = [1, 1] (64-63) —
    // BOTH lanes duplicated, like the real fn's `dup v4.2d/v5.2d`
    let d = (-63i64) as u64;
    cpu.v.v[4] = ((d as u128) << 64) | (d as u128);
    cpu.v.v[5] = (1u128 << 64) | 1;
    cpu.sp = STACK;
    cpu.set_reset_vector(CODE_VA);

    let names = [
        "ld1 v0,v1 <- [x2],#32",
        "ext v2, v0, v1, #8",
        "ldr x5, [x2]",
        "ext v3, v1, v1, #8",
        "mov v3.d[1], x5",
        "ushl v0, v0, v4",
        "ushl v1, v1, v4",
        "ushl v2, v2, v5",
        "ushl v3, v3, v5",
        "eor v0, v0, v2",
        "eor v1, v1, v3",
        "st1 v0,v1 -> [x1],#32",
    ];
    for (i, name) in names.iter().enumerate() {
        cpu.step().expect("step");
        let x5 = cpu.x[5];
        println!(
            "{:2} {name:24} x5={x5:016x} v1={} v2={} v3={}",
            i + 1,
            f128(cpu.v.v[1]),
            f128(cpu.v.v[2]),
            f128(cpu.v.v[3]),
        );
    }
    // R3 = dst[3] must equal (L6>>63)|(L7<<1)
    let r3 = cpu.mem().load(DST_VA + 24, 8);
    println!("dst limb3 = {r3:016x} (expected {TRUE_R3:016x})");
    assert_eq!(r3, TRUE_R3, "the NEON shift loop's last lane is broken");
}
