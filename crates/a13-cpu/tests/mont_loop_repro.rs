//! BUG #53 repro attempt: replay the exact Montgomery modmul loop captured
//! by the boot trace at 0x82dd284..0x82dd2ac (the P-256-order mod-n modmul
//! inside the ECDSA sign). The boot trace showed `ADCS x11, xzr, xzr`
//! answering 0 despite the preceding ADDS carrying — replay the exact
//! encodings to reproduce locally.
use a13_cpu::interp::Interpreter;
use a13_cpu::{CpuBackend, MemAccess, StopReason};

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

#[test]
fn montgomery_loop_replay() {
    // The exact loop from the trace (VAs → flat RAM at 0x10000):
    //   0x82dd284: ldr   x9, [x2], #8
    //   0x82dd288: umulh x10, x9, x3
    //   0x82dd28c: mul   x9, x9, x3
    //   0x82dd290: ldr   x11, [x1]
    //   0x82dd294: adds  x8, x11, x8
    //   0x82dd298: adcs  x11, xzr, xzr      ; carry capture
    //   0x82dd29c: adds  x9, x8, x9
    //   0x82dd2a0: adcs  x8, x11, x10
    //   0x82dd2a4: str   x9, [x1], #8
    //   0x82dd2a8: cmp   x0, #0
    //   0x82dd2ac: b.ne  0x82dd284
    let code: [u32; 11] = [
        0xf8408449, 0x9bc37d2a, 0x9b037d29, 0xf940002b, 0xab080168, 0xba1f03eb, 0xab090109,
        0xba0a0168, 0xf8008429, 0xf1000400, 0x54fffec1,
    ];
    // hlt right after the loop (replace b.ne with a one-shot: run 2 limbs then halt
    // by placing hlt at the b.ne target after enough iterations — instead: make x0
    // count down from 4; after the loop the fall-through runs into hlt at +0x2c).
    let mut ram = vec![0u8; 0x80000];
    let base = 0x10000usize;
    for (i, w) in code.iter().enumerate() {
        ram[base + i * 4..base + i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    // fallthrough after b.ne-not-taken: hlt
    ram[base + 0x2c..base + 0x30].copy_from_slice(&0xD4400000u32.to_le_bytes());

    // operands modeled on the trace: x3 = the Montgomery constant 0x63f06547,
    // limbs include 0xFFFFFFFFFFFFFFFF and 0xFFFFFFFF00000000 (P-256 order L2/L3),
    // acc limbs make the ADDS carry (acc + chain ≥ 2^64).
    let a: [u64; 4] = [
        0xf3b9cac2fc632551,
        0xffffffffffffffff, // n's L2 == u64::MAX — the wrap-class limb
        0xffffffff00000000, // n's L3
        0x00000000000000ff,
    ];
    let acc: [u64; 4] = [
        0x9c0f9ab900000000,
        0xfffffffffffffffe,
        0x8000000000000000,
        0x0000000000000001,
    ];
    let in_base = 0x20000usize;
    let out_base = 0x21000usize;
    for i in 0..4 {
        ram[in_base + i * 8..in_base + i * 8 + 8].copy_from_slice(&a[i].to_le_bytes());
        ram[out_base + i * 8..out_base + i * 8 + 8].copy_from_slice(&acc[i].to_le_bytes());
    }

    let mut cpu = Interpreter::new(Box::new(Ram(ram)));
    cpu.set_reset_vector(0x10000);
    cpu.x[0] = 4; // cmp x0,#0 countdown — wait, the loop's countdown is via cmp x0,#0
    cpu.x[1] = out_base as u64;
    cpu.x[2] = in_base as u64;
    cpu.x[3] = 0x63f06547; // the constant from the trace
    cpu.x[8] = 0; // carry chain starts at 0
    let res = cpu.run(a13_cpu::InterpBudget { max_insn: 200, max_ns: 1_000_000_000 });
    assert_eq!(res.stop, StopReason::Halted);

    // Python oracle: the exact same loop semantics.
    let m = 0x63f06547u64;
    let mut chain: u128 = 0;
    let mut expect = [0u64; 4];
    for i in 0..4 {
        let prod = (a[i] as u128) * (m as u128);
        let hi = (prod >> 64) as u64;
        let lo = prod as u64;
        // adds x8, x11, x8 : acc[i] + chain (64-bit, carry out)
        let s1 = (acc[i] as u128) + chain;
        let x8 = s1 as u64;
        let c1 = (s1 >> 64) as u64; // captured by adcs x11, xzr, xzr
        // adds x9, x8, x9 : x8 + lo (carry out)
        let s2 = (x8 as u128) + (lo as u128);
        let limb = s2 as u64;
        let c2 = (s2 >> 64) as u64;
        // adcs x8, x11, x10 : c1 + hi + c2
        let s3 = (c1 as u128) + (hi as u128) + (c2 as u128);
        chain = s3;
        expect[i] = limb;
    }
    // Read the outputs through the engine's own memory interface:
    let mem = cpu.mem();
    let mut out = [0u64; 4];
    for i in 0..4 {
        let mut b = [0u8; 8];
        for k in 0..8 {
            b[k] = u8::try_from(mem.load(0x21000 + (i * 8 + k) as u64, 1) & 0xFF).unwrap();
        }
        out[i] = u64::from_le_bytes(b);
    }
    for i in 0..4 {
        assert_eq!(
            out[i], expect[i],
            "limb {i}: engine {:#x} != oracle {:#x} (diff {:#x})",
            out[i],
            expect[i],
            (out[i] as i64).wrapping_sub(expect[i] as i64)
        );
    }
}
