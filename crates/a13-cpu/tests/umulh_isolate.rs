//! Minimal UMULH isolation for bug #53.
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
fn umulh_isolation() {
    let a: u64 = 0xffffffff00000000;
    let b: u64 = 0x22202a53dc903af5;

    // variant 1: the EXACT traced word — umulh x10, x9, x3 = 0x9BC37D2A
    let mut ram = vec![0u8; 0x80000];
    let code: [u32; 3] = [0x9BC37D2A, 0xD503201F, 0xD4400000];
    for (i, w) in code.iter().enumerate() {
        ram[0x10000 + i * 4..0x10004 + i * 4].copy_from_slice(&w.to_le_bytes());
    }
    let mut cpu = Interpreter::new(Box::new(Ram(ram)));
    cpu.set_reset_vector(0x10000);
    cpu.x[9] = a;
    cpu.x[3] = b;
    cpu.x[10] = 0x1234_5678_9abc_def0;
    let res = cpu.run(a13_cpu::InterpBudget { max_insn: 100, max_ns: 1_000_000_000 });
    assert_eq!(res.stop, StopReason::Halted);
    let true_hi = (((a as u128) * (b as u128)) >> 64) as u64;
    println!("umulh x10,x9,x3 : x10 = {:#x} (true {:#x})", cpu.x[10], true_hi);
    assert_eq!(cpu.x[10], true_hi, "UMULH traced word wrong");

    // variant 2: umulh x11, x9, x3 = 0x9BC37D2B
    let mut ram2 = vec![0u8; 0x80000];
    let code2: [u32; 3] = [0x9BC37D2B, 0xD503201F, 0xD4400000];
    for (i, w) in code2.iter().enumerate() {
        ram2[0x10000 + i * 4..0x10004 + i * 4].copy_from_slice(&w.to_le_bytes());
    }
    let mut cpu2 = Interpreter::new(Box::new(Ram(ram2)));
    cpu2.set_reset_vector(0x10000);
    cpu2.x[9] = a;
    cpu2.x[3] = b;
    cpu2.x[11] = 0xdead_beef;
    let res2 = cpu2.run(a13_cpu::InterpBudget { max_insn: 100, max_ns: 1_000_000_000 });
    assert_eq!(res2.stop, StopReason::Halted);
    println!("umulh x11,x9,x3 : x11 = {:#x} (true {:#x})", cpu2.x[11], true_hi);
    assert_eq!(cpu2.x[11], true_hi, "UMULH x11 variant wrong");

    // variant 3: with the preceding mul x5, x9, x3 = 0x9B037D25 (as in the fuzz)
    let mut ram3 = vec![0u8; 0x80000];
    let code3: [u32; 4] = [0x9B037D25, 0x9BC37D2B, 0xD503201F, 0xD4400000];
    for (i, w) in code3.iter().enumerate() {
        ram3[0x10000 + i * 4..0x10004 + i * 4].copy_from_slice(&w.to_le_bytes());
    }
    let mut cpu3 = Interpreter::new(Box::new(Ram(ram3)));
    cpu3.set_reset_vector(0x10000);
    cpu3.x[9] = a;
    cpu3.x[3] = b;
    let res3 = cpu3.run(a13_cpu::InterpBudget { max_insn: 100, max_ns: 1_000_000_000 });
    assert_eq!(res3.stop, StopReason::Halted);
    println!("mul+umulh       : x11 = {:#x} x5 = {:#x} (true hi {:#x})", cpu3.x[11], cpu3.x[5], true_hi);
    assert_eq!(cpu3.x[11], true_hi, "UMULH after MUL wrong");
}
