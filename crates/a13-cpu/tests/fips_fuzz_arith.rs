//! BUG #53 hunt: fuzz the engine's arithmetic against python-verified
//! oracles — the exact Montgomery/division inner loop captured at
//! 0x82dd284..0x82dd2ac, plus MUL/UMULH and full ADCS/SBCS chains.
//! The ECDSA sign's mod-n products (r·d, k⁻¹·t) come out wrong while the
//! field (mod-p) products are fine — n carries the INTERIOR u64::MAX
//! limb (L2), p carries it at L0. Suspect: a value-dependent carry bug.
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

/// xorshift64* deterministic rng (no external deps)
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn limb(&mut self) -> u64 {
        // bias toward the wrap-class patterns: MAX, MAX-1, 0, 1, 32-bit-ish
        match self.next() % 8 {
            0 => u64::MAX,
            1 => u64::MAX - 1,
            2 => 0,
            3 => 1,
            4 => 0xFFFF_FFFF_0000_0000,
            5 => 0x0000_0000_FFFF_FFFF,
            _ => self.next(),
        }
    }
}

#[test]
fn fuzz_division_inner_loop() {
    // The exact loop encodings from the boot trace (0x82dd284..0x82dd2ac):
    //   ldr x9,[x2],#8; umulh x10,x9,x3; mul x9,x9,x3; ldr x11,[x1];
    //   adds x8,x11,x8; adcs x11,xzr,xzr; adds x9,x8,x9; adcs x8,x11,x10;
    //   str x9, [x1], #8; subs x0,x0,#1; b.ne loop
    let code: [u32; 11] = [
        0xf8408449, 0x9bc37d2a, 0x9b037d29, 0xf940002b, 0xab080168, 0xba1f03eb, 0xab090109,
        0xba0a0168, 0xf8008429, 0xf1000400, 0x54fffec1,
    ];
    // NOTE: the traced word 0xF1000400 is `subs x0, x0, #1` — a COUNTDOWN
    // (my first read mislabeled it cmp); x0 = nlimbs runs exactly nlimbs
    // iterations. No patch needed — the code is byte-faithful.
    let mut ram = vec![0u8; 0x80000];
    let base = 0x10000usize;
    for (i, w) in code.iter().enumerate() {
        ram[base + i * 4..base + i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    ram[base + 0x2c..base + 0x30].copy_from_slice(&0xD4400000u32.to_le_bytes());

    let mut rng = Rng(0x1234_5678_9abc_def0);
    let in_base = 0x20000usize;
    let out_base = 0x21000usize;
    let rounds = 4000usize;
    for round in 0..rounds {
        let nlimbs = 4usize + (rng.next() as usize % 5); // 4..8 limbs
        let m: u64 = rng.limb();
        let a: Vec<u64> = (0..nlimbs).map(|_| rng.limb()).collect();
        // acc limbs chosen to force carries through the chain
        let acc: Vec<u64> = (0..nlimbs).map(|_| rng.limb()).collect();
        let init_chain: u64 = rng.limb();

        for i in 0..nlimbs {
            ram[in_base + i * 8..in_base + i * 8 + 8].copy_from_slice(&a[i].to_le_bytes());
            ram[out_base + i * 8..out_base + i * 8 + 8].copy_from_slice(&acc[i].to_le_bytes());
        }
        let mut cpu = Interpreter::new(Box::new(Ram(ram.clone())));
        cpu.set_reset_vector(0x10000);
        cpu.x[0] = nlimbs as u64;
        cpu.x[1] = out_base as u64;
        cpu.x[2] = in_base as u64;
        cpu.x[3] = m;
        cpu.x[8] = init_chain;
        let res = cpu.run(a13_cpu::InterpBudget { max_insn: 10_000, max_ns: 1_000_000_000 });
        assert_eq!(res.stop, StopReason::Halted, "round {round}: unexpected stop {res:?}");

        // python-equivalent oracle — FAITHFUL to hardware: the loop's
        // `adcs x8, x11, x10` carry-OUT is dropped by the code (STR only
        // stores x9); the chain value x8 wraps mod 2^64 exactly like the
        // register does.
        let mut chain: u128 = init_chain as u128;
        let mut expect = vec![0u64; nlimbs];
        for i in 0..nlimbs {
            let prod = (a[i] as u128) * (m as u128);
            let hi = (prod >> 64) as u64;
            let lo = prod as u64;
            let s1 = (acc[i] as u128) + chain;
            let x8 = s1 as u64;
            let c1 = (s1 >> 64) as u64;
            let s2 = (x8 as u128) + (lo as u128);
            expect[i] = s2 as u64;
            let c2 = (s2 >> 64) as u64;
            // adcs x8, x11, x10 : (c1 + hi + c2) mod 2^64, carry-out dropped
            chain = (((c1 as u128) + (hi as u128) + (c2 as u128)) as u64) as u128;
        }
        let mut out = vec![0u64; nlimbs];
        for i in 0..nlimbs {
            let mut b = [0u8; 8];
            for k in 0..8usize {
                b[k] = u8::try_from(cpu.mem().load((out_base + i * 8 + k) as u64, 1) & 0xFF)
                    .unwrap();
            }
            out[i] = u64::from_le_bytes(b);
        }
        for i in 0..nlimbs {
            assert_eq!(
                out[i], expect[i],
                "round {round} limb {i}: engine {:#x} != oracle {:#x} (a={:#x} m={:#x} acc={:#x} chain={:#x})",
                out[i], expect[i], a[i], m, acc[i], init_chain
            );
        }
    }
}

#[test]
fn fuzz_mul_umulh_pairs() {
    // MUL x9,x10,x3 (different dest so x9 survives for the UMULH read)
    // then UMULH x11,x9,x3 — no self-clobber (bug in the first fuzz draft
    // had MUL x9,x9,x3 first, clobbering the UMULH input).
    let mut ram = vec![0u8; 0x80000];
    let base = 0x10000usize;
    // mul x5, x9, x3     = 0x9B037D25  (Rd=5 — does NOT clobber x9)
    // umulh x11, x9, x3  = 0x9BC37D2B  (Rd=11, Rn=9, Rm=3)
    let code: [u32; 4] = [0x9B037D25, 0x9BC37D2B, 0xD503201F, 0xD4400000];
    for (i, w) in code.iter().enumerate() {
        ram[base + i * 4..base + i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    let mut rng = Rng(0xdead_beef_cafe_1234);
    for round in 0..4000usize {
        let a = rng.limb();
        let b = rng.limb();
        let mut cpu = Interpreter::new(Box::new(Ram(ram.clone())));
        cpu.set_reset_vector(0x10000);
        cpu.x[9] = a;
        cpu.x[3] = b;
        cpu.x[10] = 0xAAAA_AAAA_AAAA_AAAA;
        let res = cpu.run(a13_cpu::InterpBudget { max_insn: 100, max_ns: 1_000_000_000 });
        assert_eq!(res.stop, StopReason::Halted);
        let prod = (a as u128) * (b as u128);
        assert_eq!(cpu.x[11], (prod >> 64) as u64, "UMULH round {round}: a={a:#x} b={b:#x}");
        assert_eq!(cpu.x[5], prod as u64, "MUL round {round}: a={a:#x} b={b:#x}");
    }
}

#[test]
fn fuzz_adcs_sbcs_chains() {
    // 4-limb ADCS chain: adcs x0..x3, a-limbs + b-limbs + initial C
    // adcs x0,x4,x8 = 0xBA080080? build: ADCS Xd, Xn, Xm = 0xBA000000|Rm<<16|Rn<<5|Rd
    fn adcs(rd: u8, rn: u8, rm: u8) -> u32 {
        0xBA000000 | ((rm as u32) << 16) | ((rn as u32) << 5) | rd as u32
    }
    let mut ram = vec![0u8; 0x80000];
    let base = 0x10000usize;
    let mut code: Vec<u32> = Vec::new();
    for i in 0..6u8 {
        code.push(adcs(i, 10 + i, 16 + i)); // x0..x5 = x10..15 + x16..21 (+C)
    }
    code.push(0xD4400000); // hlt
    for (i, w) in code.iter().enumerate() {
        ram[base + i * 4..base + i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    let mut rng = Rng(0xfeed_face_c0de_8888);
    for round in 0..4000usize {
        let a: Vec<u64> = (0..6).map(|_| rng.limb()).collect();
        let b: Vec<u64> = (0..6).map(|_| rng.limb()).collect();
        let cin = rng.next() & 1 == 1;
        let mut cpu = Interpreter::new(Box::new(Ram(ram.clone())));
        cpu.set_reset_vector(0x10000);
        for i in 0..6 {
            cpu.x[10 + i] = a[i];
            cpu.x[16 + i] = b[i];
        }
        cpu.nzcv = if cin { 0x2 } else { 0x0 };
        let res = cpu.run(a13_cpu::InterpBudget { max_insn: 100, max_ns: 1_000_000_000 });
        assert_eq!(res.stop, StopReason::Halted);
        let mut carry = cin as u128;
        for i in 0..6 {
            let s = (a[i] as u128) + (b[i] as u128) + carry;
            let expect = s as u64;
            carry = s >> 64;
            assert_eq!(
                cpu.x[i], expect,
                "ADCS chain round {round} limb {i}: a={:#x} b={:#x} cin={cin}",
                a[i], b[i]
            );
        }
    }
}
