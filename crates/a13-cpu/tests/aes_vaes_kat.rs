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

// FIPS-197 C.1 AES-128, ARM-feed form: rk0 plain, middle round keys
// pre-InvMixColumns'd (AESE's EOR lands before the following AESMC),
// final key plain. Verified by scripts/aes_check.py (variant B).
const RK: [u128; 11] = [
    0x000102030405060708090a0b0c0d0e0f,
    0x8c56dff0825dd3f9805ad3fc8659d7fd,
    0xa0db02992286d160a2dc029c2485d561,
    0xc7c6e391e54032f1479c306d6319e50c,
    0xa8a2f5044de2c7f50a7ef79869671294,
    0x2ec410276326d7d26958204a003f32de,
    0x72e3098d11c5de5f789dfe1578a2cccb,
    0x8d82fc749c47222be4dadc3e9c7810f5,
    0x1362a4638f2586486bff5a76f7874a83,
    0x13aa29be9c8faff6f770f58000f7bf03,
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
    // v0 = state; v1..v11 = round keys 0..10
    let mut code = Vec::new();
    let put = |c: &mut Vec<u8>, w: u32| c.extend_from_slice(&w.to_le_bytes());
    put(&mut code, eor16b_word(0, 0, 1)); // state ^= rk0
    for r in 1..10u8 {
        put(&mut code, aese_word(0, r + 1)); // aese v0, v{r+1} (rk r)
        put(&mut code, aesmc_word(0, 0));
    }
    put(&mut code, aese_word(0, 11)); // final aese with rk10
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
/// inverse: ciphertext 69c4e0d8… → plaintext 00112233…). The equivalent-
/// inverse-cipher key schedule: state ^= rk10; 9×(AESD aesimc(rk_r);
/// AESIMC); final AESD rk0 — probes the aesd/aesimc pair that the
/// fipspost AES-ECB KAT (POST test 4, the current −4075 wall) exercises.
#[test]
fn aes128_decrypt_fips197_via_instructions() {
    // forward round keys (rk0..rk10) computed in aes_fips197 unit test
    // style; decrypt feeds aesimc(rk_r) for rounds 9..1 and rk0 last.
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
    put(&mut code, eor16b_word(0, 0, 11)); // state ^= rk10 (v11)
    for r in (1..10).rev() {
        put(&mut code, aesd_word(0, r as u8 + 1)); // aesd v0, v{r+1} = aesimc(rk_r)
        put(&mut code, aesimc_word(0, 0));
    }
    put(&mut code, aesd_word(0, 1)); // final aesd with rk0
    put(&mut code, hlt_word());

    let mut ram = vec![0u8; 0x4000];
    ram[0x1000..0x1000 + code.len()].copy_from_slice(&code);
    let mut cpu = Interpreter::new(Box::new(Ram(ram)));
    let set = |cpu: &mut Interpreter, r: u8, v: u128| {
        cpu.v.v[r as usize] = u128::from_be_bytes(v.to_le_bytes());
    };
    // Decrypt feed schedule (verified against the python reference):
    // FIPS InvCipher applies AddRoundKey BEFORE InvMixColumns, so the
    // AESD key for rounds 9..1 is the PLAIN rk_r (unlike encrypt, where
    // AESMC pulls MixColumns over the key and needs aesimc(rk_r)).
    set(&mut cpu, 0, EXPECT); // ciphertext in
    set(&mut cpu, 1, FRK[0]); // rk0 (final aesd key)
    for (i, k) in FRK[1..10].iter().enumerate() {
        set(&mut cpu, i as u8 + 2, *k); // v2..v10 = rk1..rk9 (plain)
    }
    set(&mut cpu, 11, FRK[10]); // rk10 (initial eor)
    cpu.set_reset_vector(0x1000);
    let res = cpu.run(a13_cpu::InterpBudget { max_insn: 100, max_ns: 60_000_000_000 });
    assert_eq!(res.stop, StopReason::Halted, "stop={res:?}");
    let got = u128::from_le_bytes(cpu.v.v[0].to_be_bytes());
    println!("decrypt got  {got:032x}");
    println!("       want  {PT:032x}");
    assert_eq!(got, PT, "AES-128 decrypt through real AESD/AESIMC/EOR words");
}
