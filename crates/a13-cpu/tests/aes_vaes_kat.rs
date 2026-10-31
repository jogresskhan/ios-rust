//! REAL-DATA BUG #47 repro: full AES-128 through actual AESE/AESMC/EOR
//! instruction words (FIPS-197 Appendix C.1). The interpreter used to read
//! the state from Vn and drop the round key entirely — every kernel AES
//! round ran keyless, the early PRNG (AES-XTS) emitted one constant block,
//! and corecrypto panicked "RNG initialization failure (−10)".

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
        u32::from_le_bytes(
            self.0[(addr as usize)..(addr as usize) + 4]
                .try_into()
                .unwrap(),
        )
    }
}

// FIPS-197 C.1 AES-128, PLAIN schedule (rk0..rk10) — the feed the real
// 18C66 vng ECB loop uses (REAL-DATA BUG #50: AESE/AESD apply the round
// key BEFORE the SubBytes/ShiftRows table; the old XOR-last model needed
// pre-InvMixColumns'd middle keys — a circular golden that hid the bug).
// Schedule verified by scripts/aes_check.py + the extracted 18C66 KAT
// (tests/fips_aes_ecb_kat.rs runs the kernel's OWN keyexp to this exact
// table).
const RK: [u128; 11] = [
    0x000102030405060708090a0b0c0d0e0f,
    0xd6aa74fdd2af72fadaa678f1d6ab76fe,
    0xb692cf0b643dbdf1be9bc5006830b3fe,
    0xb6ff744ed2c2c9bf6c590cbf0469bf41,
    0x47f7f7bc95353e03f96c32bcfd058dfd,
    0x3caaa3e8a99f9deb50f3af57adf622aa,
    0x5e390f7df7a69296a7553dc10aa31f6b,
    0x14f9701ae35fe28c440adf4d4ea9c026,
    0x47438735a41c65b9e016baf4aebf7ad2,
    0x549932d1f08557681093ed9cbe2c974e,
    0x13111d7fe3944a17f307a78b4d2b30c5,
];
const PT: u128 = 0x00112233445566778899aabbccddeeff;
const EXPECT: u128 = 0x69c4e0d86a7b0430d8cdb78070b4c55a;

fn aese_word(vd: u8, vn: u8) -> u32 {
    0x4E28_4800 | ((vn as u32) << 5) | vd as u32
}
fn aesmc_word(vd: u8, vn: u8) -> u32 {
    0x4E28_6800 | ((vn as u32) << 5) | vd as u32
}
fn eor16b_word(vd: u8, vn: u8, vm: u8) -> u32 {
    0x6E20_1C00 | ((vm as u32) << 16) | ((vn as u32) << 5) | vd as u32
}
fn hlt_word() -> u32 {
    0xD440_0000
}

#[test]
fn aes128_fips197_via_instructions() {
    // Kernel-mirroring choreography (the 18C66 vng ECB 1-block loop,
    // 0xfffffff0082cb268): v0 = pt; 9×(AESE rk_r; AESMC) for r=0..8;
    // final AESE rk9; EOR rk10 — PLAIN schedule, no initial whitening EOR
    // (the first AESE's key does the whitening via the XOR-first table).
    // v0 = state; v1..v11 = round keys 0..10
    let mut code = Vec::new();
    let put = |c: &mut Vec<u8>, w: u32| c.extend_from_slice(&w.to_le_bytes());
    for r in 0..9u8 {
        put(&mut code, aese_word(0, r + 1)); // aese v0, v{r+1} (rk r)
        put(&mut code, aesmc_word(0, 0));
    }
    put(&mut code, aese_word(0, 10)); // final aese with rk9
    put(&mut code, eor16b_word(0, 0, 11)); // whitening: ^ rk10
    put(&mut code, hlt_word());

    let mut ram = vec![0u8; 0x4000];
    ram[0x1000..0x1000 + code.len()].copy_from_slice(&code);
    let mut cpu = Interpreter::new(Box::new(Ram(ram)));
    let set = |cpu: &mut Interpreter, r: u8, v: u128| {
        // register lane 0 = LSB: byte 0 of the block maps to B[0]
        cpu.v.v[r as usize] = u128::from_be_bytes(v.to_le_bytes());
    };
    set(&mut cpu, 0, PT);
    for (i, rk) in RK.iter().enumerate() {
        set(&mut cpu, i as u8 + 1, *rk);
    }
    cpu.set_reset_vector(0x1000);
    let res = cpu.run(a13_cpu::InterpBudget { max_insn: 100, max_ns: 60_000_000_000 });
    assert_eq!(res.stop, StopReason::Halted, "stop={res:?}");
    let got = u128::from_le_bytes(cpu.v.v[0].to_be_bytes()); // back to BE
    assert_eq!(got, EXPECT, "AES-128 through real AESE/AESMC/EOR words");
}

/// AES-128 DECRYPT through real AESD/AESIMC/EOR words (FIPS-197 C.1
/// inverse: ciphertext 69c4e0d8… → plaintext 00112233…), mirroring the
/// 18C66 decrypt ecb 1-block loop (0xfffffff0082b2754): AESD rk10 first,
/// then 8×(AESD aesimc(rk_r); AESIMC) for r=9..2, final AESD aesimc(rk1),
/// EOR rk0 — the equivalent-inverse-cipher schedule the kernel's decrypt
/// init (0xfffffff0082a89f0) builds: rk0/rk10 plain, rk1..rk9 AESIMC'd.
#[test]
fn aes128_decrypt_fips197_via_instructions() {
    // forward PLAIN round keys (rk0..rk10) — same table as RK above
    const FRK: [u128; 11] = [
        0x000102030405060708090a0b0c0d0e0f,
        0xd6aa74fdd2af72fadaa678f1d6ab76fe,
        0xb692cf0b643dbdf1be9bc5006830b3fe,
        0xb6ff744ed2c2c9bf6c590cbf0469bf41,
        0x47f7f7bc95353e03f96c32bcfd058dfd,
        0x3caaa3e8a99f9deb50f3af57adf622aa,
        0x5e390f7df7a69296a7553dc10aa31f6b,
        0x14f9701ae35fe28c440adf4d4ea9c026,
        0x47438735a41c65b9e016baf4aebf7ad2,
        0x549932d1f08557681093ed9cbe2c974e,
        0x13111d7fe3944a17f307a78b4d2b30c5,
    ];
    let aesd_word = |vd: u8, vn: u8| 0x4E28_5800u32 | ((vn as u32) << 5) | vd as u32;
    let aesimc_word = |vd: u8, vn: u8| 0x4E28_7800u32 | ((vn as u32) << 5) | vd as u32;

    let mut code = Vec::new();
    let put = |c: &mut Vec<u8>, w: u32| c.extend_from_slice(&w.to_le_bytes());
    // kernel loop: aesd(rk10); [aesd(rk_r'); aesimc] for r=9..2; aesd(rk1'); eor(rk0)
    put(&mut code, aesd_word(0, 11)); // aesd v0, rk10 (plain)
    put(&mut code, aesimc_word(0, 0));
    for vn in (3..=10u8).rev() {
        put(&mut code, aesd_word(0, vn)); // aesd v0, v{vn} = aesimc(rk_{vn-1})
        put(&mut code, aesimc_word(0, 0));
    }
    put(&mut code, aesd_word(0, 2)); // final aesd with aesimc(rk1)
    put(&mut code, eor16b_word(0, 0, 1)); // ^ rk0
    put(&mut code, hlt_word());

    let mut ram = vec![0u8; 0x4000];
    ram[0x1000..0x1000 + code.len()].copy_from_slice(&code);
    let mut cpu = Interpreter::new(Box::new(Ram(ram)));
    let set = |cpu: &mut Interpreter, r: u8, v: u128| {
        cpu.v.v[r as usize] = u128::from_be_bytes(v.to_le_bytes());
    };
    // Decrypt feed schedule (kernel decrypt init 0x82a89f0): rk0 and rk10
    // PLAIN, rk1..rk9 pre-AESIMC'd (InvMixColumns) — the equivalent-
    // inverse-cipher table that pairs with the XOR-first AESD.
    set(&mut cpu, 0, EXPECT); // ciphertext in
    set(&mut cpu, 1, FRK[0]); // rk0 (final eor)
    for (i, k) in FRK[1..10].iter().enumerate() {
        // v2..v10 = aesimc(rk1..rk9): apply InvMixColumns to the plain key
        set(&mut cpu, i as u8 + 2, a13_cpu::crypto::aesimc(*k));
    }
    set(&mut cpu, 11, FRK[10]); // rk10 (initial aesd key, plain)
    cpu.set_reset_vector(0x1000);
    let res = cpu.run(a13_cpu::InterpBudget { max_insn: 100, max_ns: 60_000_000_000 });
    assert_eq!(res.stop, StopReason::Halted, "stop={res:?}");
    let got = u128::from_le_bytes(cpu.v.v[0].to_be_bytes());
    println!("decrypt got  {got:032x}");
    println!("       want  {PT:032x}");
    assert_eq!(got, PT, "AES-128 decrypt through real AESD/AESIMC/EOR words");
}
