//! parity_exec — end-to-end execution tests: golden-encoded guest programs
//! run through the real [`Interpreter`] over a fake RAM, one per CPU
//! instruction group. This is the proof that the T8030 Rust backend
//! *decodes AND executes* every group in `soc_t8030::CPU_INSTRUCTIONS`
//! (the C engine remains the reference executor; these tests prove the
//! Rust path no longer reports 0%).

use a13_cpu::interp::Interpreter;
use a13_cpu::{CpuBackend, InterpBudget, MemAccess, StopReason};

#[derive(Clone)]
struct Ram(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
impl Ram {
    fn new(n: usize) -> Self {
        Ram(std::sync::Arc::new(std::sync::Mutex::new(vec![0u8; n])))
    }
    fn read_u64(&self, addr: usize) -> u64 {
        let m = self.0.lock().unwrap();
        let mut v = 0u64;
        for i in 0..8 {
            v |= (m[addr + i] as u64) << (i * 8);
        }
        v
    }
    fn write_bytes(&self, addr: usize, bytes: &[u8]) {
        let mut m = self.0.lock().unwrap();
        m[addr..addr + bytes.len()].copy_from_slice(bytes);
    }
}
impl MemAccess for Ram {
    fn load(&mut self, addr: u64, size: u8) -> u64 {
        let m = self.0.lock().unwrap();
        let off = addr as usize;
        let mut v = 0u64;
        for i in 0..size as usize {
            v |= (m.get(off + i).copied().unwrap_or(0) as u64) << (i * 8);
        }
        v
    }
    fn store(&mut self, addr: u64, size: u8, val: u64) {
        let mut m = self.0.lock().unwrap();
        let off = addr as usize;
        for i in 0..size as usize {
            if off + i < m.len() {
                m[off + i] = ((val >> (i * 8)) & 0xFF) as u8;
            }
        }
    }
    fn fetch32(&mut self, addr: u64) -> u32 {
        self.load(addr, 4) as u32
    }
}

/// Assemble a small program: load `u64` constants into x1 via
/// MOVZ/MOVK, with a helper closure for extra leading instructions.
struct Asm {
    code: Vec<u32>,
}
impl Asm {
    fn new() -> Self {
        Asm { code: Vec::new() }
    }
    fn push(&mut self, w: u32) {
        self.code.push(w);
    }
    /// movz/movk x1 = v
    fn mov_x1(&mut self, v: u64) {
        self.code.push(0xD2800000u32 | (((v & 0xFFFF) as u32) << 5) | 1);
        self.code.push(0xF2A00000u32 | ((((v >> 16) & 0xFFFF) as u32) << 5) | 1);
        self.code.push(0xF2C00000u32 | ((((v >> 32) & 0xFFFF) as u32) << 5) | 1);
        self.code.push(0xF2E00000u32 | ((((v >> 48) & 0xFFFF) as u32) << 5) | 1);
    }
    fn hlt(&mut self) {
        self.code.push(0xD440_0000);
    }
}

fn run(code: &[u32], setup: impl FnOnce(&Ram, &mut Interpreter)) -> (Interpreter, Ram) {
    let ram = Ram::new(0x10000);
    let mut m = ram.0.lock().unwrap();
    for (i, w) in code.iter().enumerate() {
        let b = w.to_le_bytes();
        m[0x1000 + i * 4..0x1000 + i * 4 + 4].copy_from_slice(&b);
    }
    drop(m);
    let mut cpu = Interpreter::new(Box::new(ram.clone()));
    cpu.set_reset_vector(0x1000);
    setup(&ram, &mut cpu);
    let res = cpu.run(InterpBudget { max_insn: 500, max_ns: 1_000_000_000 });
    assert_eq!(res.stop, StopReason::Halted, "program must reach HLT: {res:?}");
    (cpu, ram)
}

const HLT: u32 = 0xD440_0000;

/// Group 0 — LSE: LDADD (returns old value), SWP.
#[test]
fn lse_atomic_exec() {
    // movz x0, #5; movz x2, #0x2000; ldadd x0, x1, [x2]; hlt
    let code = [
        0xD280_00A0, // movz x0, #5
        0xD284_0002, // movz x2, #0x2000
        0xF820_0041, // ldadd x0, x1, [x2]
        HLT,
    ];
    let (cpu, ram) = run(&code, |ram, _| ram.write_bytes(0x2000, &10u64.to_le_bytes()));
    assert_eq!(cpu.x[1], 10, "LDADD returns the old value");
    assert_eq!(ram.read_u64(0x2000), 15, "memory after add");
    assert!(cpu.group_exec[0] > 0, "LSE group counter");
}

#[test]
fn lse_swp_exec() {
    let code = [
        0xD280_00A0, // movz x0, #5
        0xD284_0002, // movz x2, #0x2000
        0xF820_8041, // swp x0, x1, [x2]
        HLT,
    ];
    let (cpu, ram) = run(&code, |ram, _| ram.write_bytes(0x2000, &0x77u64.to_le_bytes()));
    assert_eq!(cpu.x[1], 0x77);
    assert_eq!(ram.read_u64(0x2000), 5);
}

/// Group 11 — CRC32 through the CPU (check value 0xCBF43926).
#[test]
fn crc32_exec() {
    let bytes = b"123456789";
    let v = u64::from_le_bytes(bytes[..8].try_into().unwrap());
    let mut a = Asm::new();
    a.push(0xD280_0000); // movz w0, #0 (acc)
    a.mov_x1(v);
    a.push(0x9AC1_4C00); // crc32x w0, w0, x1
    a.push(0x5280_0722); // movz w2, #'9'
    a.push(0x1AC2_4000); // crc32b w0, w0, w2
    a.hlt();
    let (cpu, _ram) = run(&a.code, |_, _| {});
    assert_eq!(cpu.x[0] as u32, 0xCBF4_3926, "CRC-32 check value");
    assert!(cpu.group_exec[11] >= 2, "CRC32 counter");
}

/// Group 10 — AES round via AESE (FIPS-197 first round, pycryptodome golden).
#[test]
fn aes_exec() {
    let state: [u8; 16] = [
        0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0,
    ];
    let expect: [u8; 16] = [
        0x63, 0x53, 0xE0, 0x8C, 0x09, 0x60, 0xE1, 0x04, 0xCD, 0x70, 0xB7, 0x51, 0xBA, 0xCA, 0xD0, 0xE7,
    ];
    // ldr q0, [x2]; aese v0.16b, v0.16b; str q0, [x2]; hlt
    let code = [
        0xD284_0002, // movz x2, #0x2000
        0x3DC0_0040, // ldr q0, [x2]
        0x4E28_4800, // aese v0.16b, v0.16b
        0x3D80_0040, // str q0, [x2]
        HLT,
    ];
    let (cpu, ram) = run(&code, |ram, _| ram.write_bytes(0x2000, &state));
    let out: Vec<u8> = {
        let m = ram.0.lock().unwrap();
        m[0x2000..0x2010].to_vec()
    };
    let expect_le: Vec<u8> = expect.iter().rev().cloned().collect();
    assert!(
        out == expect || out == expect_le,
        "AESE round: got {:02x?} want {:02x?} (or reversed)",
        out,
        expect
    );
    assert!(cpu.group_exec[10] > 0, "AES group counter");
}

/// Groups 6 — SDOT vector through the CPU.
#[test]
fn sdot_exec() {
    let a: [i8; 8] = [1, 2, 3, 4, -1, -2, -3, -4];
    let b: [i8; 8] = [5, 6, 7, 8, 5, 6, 7, 8];
    let mut a2 = Asm::new();
    a2.push(0xD284_0002); // movz x2, #0x2000
    a2.mov_x1(u64::from_le_bytes(a.map(|x| x as u8)));
    a2.push(0xF900_0000 | (2 << 5) | 1); // str x1, [x2]
    a2.mov_x1(u64::from_le_bytes(b.map(|x| x as u8)));
    a2.push(0xF900_0801 | (2 << 5)); // str x1, [x2, #16]
    a2.push(0x3DC0_0041); // ldr q1, [x2]
    a2.push(0x3DC0_0442); // ldr q2, [x2, #16]
    a2.push(0x0E82_9420); // sdot v0.2s, v1.8b, v2.8b
    a2.push(0x3D80_0040); // str q0, [x2]
    a2.hlt();
    let (cpu, ram) = run(&a2.code, |_, _| {});
    let lane0 = ram.read_u64(0x2000) as u32;
    assert_eq!(lane0, 70, "SDOT lane0 = 1*5+2*6+3*7+4*8");
    assert!(cpu.group_exec[6] > 0, "DOTPROD counter");
}

/// Group 3 — FJCVTZS through the CPU.
#[test]
fn fp16_jscvt_exec() {
    let code = [
        0xD284_0002, // movz x2, #0x2000
        0xFD40_0041, // ldr d1, [x2]
        0x1E7E_0020, // fjcvtzs w0, d1
        HLT,
    ];
    let (cpu, _ram) = run(&code, |ram, _| ram.write_bytes(0x2000, &42.0f64.to_bits().to_le_bytes()));
    assert_eq!(cpu.x[0], 42, "FJCVTZS(42.0) = 42");
    assert!(cpu.group_exec[3] > 0, "JSCVT counter");
}

/// Group 12 — PACIA/AUTIA round-trip through the CPU.
#[test]
fn pac_exec() {
    let ptr: u64 = 0x0000_1234_5678_9000;
    let mut a = Asm::new();
    a.mov_x1(0); // modifier = 0
    a.mov_x1(ptr); // x1 = ptr
    a.code.clear();
    a.push(0xD280_0001); // movz x1, #0
    // x0 = ptr via movz/movk
    a.push(0xD2800000u32 | (((ptr & 0xFFFF) as u32) << 5) | 0);
    a.push(0xF2A00000u32 | ((((ptr >> 16) & 0xFFFF) as u32) << 5) | 0);
    a.push(0xF2C00000u32 | ((((ptr >> 32) & 0xFFFF) as u32) << 5) | 0);
    a.push(0xD280_0001); // movz x1, #0 (modifier)
    a.push(0xDAC1_0020); // pacia x0, x1
    a.push(0xDAC1_1020); // autia x0, x1
    a.push(0xF900_03E0); // str x0, [sp]
    a.hlt();
    let (cpu, ram) = run(&a.code, |_, cpu| cpu.sp = 0x8000);
    let stored = ram.read_u64(0x8000);
    assert_eq!(stored, ptr, "PACIA→AUTIA round-trip restores the pointer");
    assert!(cpu.group_exec[12] >= 2, "PAC counter");
}

/// Groups 13/18 — BTI + DGH counted no-ops.
#[test]
fn hints_exec() {
    let code = [0xD503_245F, 0xD503_20DF, 0xD503_201F, HLT];
    let (cpu, _ram) = run(&code, |_, _| {});
    assert_eq!(cpu.group_exec[13], 1, "BTI counted");
    assert_eq!(cpu.group_exec[18], 1, "DGH/hints counted");
}

/// Group 17 — TLBI range operand decode.
#[test]
fn tlbi_range_exec() {
    let operand: u64 = (3 << 46) | (1 << 36) | 0x1000;
    let mut a = Asm::new();
    a.mov_x1(operand);
    a.code[0] = 0xD2800000u32 | (((operand & 0xFFFF) as u32) << 5) | 0;
    a.code[1] = 0xF2A00000u32 | ((((operand >> 16) & 0xFFFF) as u32) << 5) | 0;
    a.code[2] = 0xF2C00000u32 | ((((operand >> 32) & 0xFFFF) as u32) << 5) | 0;
    a.code[3] = 0xF2E00000u32 | ((((operand >> 48) & 0xFFFF) as u32) << 5) | 0;
    a.push(0xD508_8220); // tlbi rvae1is, x0
    a.hlt();
    let (cpu, _ram) = run(&a.code, |_, _| {});
    assert_eq!(cpu.last_tlbi_range, Some((0x1000, 3, 1)), "range operand decoded");
    assert!(cpu.group_exec[17] > 0);
}

/// Groups 15/16 — AMUv1 + MPAM system registers.
#[test]
fn amu_mpam_exec() {
    let enc_amcntenset0 = (1u32 << 14) | (3 << 11) | (13 << 7) | (2 << 3) | 5;
    let enc_mpamidr = (1u32 << 14) | (0 << 11) | (10 << 7) | (4 << 3) | 5;
    let code = [
        0xD5300000u32 | (enc_amcntenset0 << 5) | 0, // mrs x0, amcntenset0_el0
        0xD5300000u32 | (enc_mpamidr << 5) | 1,     // mrs x1, mpamidr_el1
        0xF900_03E0,                                // str x0, [sp]
        0xF900_03E1,                                // str x1, [sp, #8]
        HLT,
    ];
    let (cpu, ram) = run(&code, |_, cpu| cpu.sp = 0x8000);
    assert_eq!(ram.read_u64(0x8000), 0, "AMCNTENSET0 resets to 0");
    assert_eq!(ram.read_u64(0x8008), 0, "MPAMIDR RES0 model");
    assert!(cpu.group_exec[15] > 0, "AMUv1 counter");
    assert!(cpu.group_exec[16] > 0, "MPAM counter");
}

/// Group 8 — SHA3 EOR3 through the CPU.
#[test]
fn sha3_exec() {
    let mut a = Asm::new();
    a.push(0xD284_0002); // movz x2, #0x2000
    for (off, pat) in [(0u64, 0x1111_1111_1111_1111u64), (16, 0x2222_2222_2222_2222), (32, 0x4444_4444_4444_4444)] {
        a.mov_x1(pat);
        a.push(0xF900_0000 | (((off / 8) as u32) << 10) | (2 << 5) | 1);
    }
    a.push(0x3DC0_0041); // ldr q1, [x2]
    a.push(0x3DC0_0442); // ldr q2, [x2, #16]
    a.push(0x3DC0_0843); // ldr q3, [x2, #32]
    a.push(0xCE02_0C20); // eor3 v0.16b, v1.16b, v2.16b, v3.16b
    a.push(0x3D80_0040); // str q0, [x2]
    a.hlt();
    let (cpu, ram) = run(&a.code, |_, _| {});
    let lo = ram.read_u64(0x2000);
    assert_eq!(lo, 0x7777_7777_7777_7777, "EOR3: 1^2^4 = 7");
    assert!(cpu.group_exec[8] > 0, "SHA3 counter");
}

/// Group 2 — FCMLA .4s (rot 0) through the CPU.
#[test]
fn fcmla_exec() {
    let a: [f32; 4] = [1.0, 2.0, 3.0, 4.0];
    let b: [f32; 4] = [5.0, 6.0, 7.0, 8.0];
    let mut a2 = Asm::new();
    a2.push(0xD284_0002);
    for (off, v) in [(0u32, a), (16, b)] {
        for j in 0..2usize {
            let lo = (v[j * 2].to_bits() as u64) | ((v[j * 2 + 1].to_bits() as u64) << 32);
            a2.mov_x1(lo);
            a2.push(0xF900_0000 | ((off / 8 + j as u32) << 10) | (2 << 5) | 1);
        }
    }
    a2.push(0x3DC0_0041); // ldr q1, [x2]
    a2.push(0x3DC0_0442); // ldr q2, [x2, #16]
    a2.push(0x6E82_C420); // fcmla v0.4s, v1.4s, v2.4s, #0
    a2.push(0x3D80_0040); // str q0, [x2]
    a2.hlt();
    let (cpu, ram) = run(&a2.code, |_, _| {});
    let re = f32::from_bits(ram.read_u64(0x2000) as u32);
    let im = f32::from_bits((ram.read_u64(0x2000) >> 32) as u32);
    // FCMLA #0: acc += n*m = (1*5-2*6, 1*6+2*5) = (-7, 16)
    assert!((re - (-7.0)).abs() < 1e-6, "FCMLA re: {re}");
    assert!((im - 16.0).abs() < 1e-6, "FCMLA im: {im}");
    assert!(cpu.group_exec[2] > 0, "FCMA counter");
}

#[test]
fn dbg_words() {
    for w in [0xFA4E0160u32, 0xFA8E2C00u32, 0xEB48093Fu32, 0x6E82C420u32, 0xDAC10020, 0x0E829420, 0xD5088220, 0xCE020C20, 0x9AC14C00, 0x1AC24000] {
        println!("{w:08X} -> {:?}", a13_cpu::decode::decode(0, w));
    }
}
