//! Reproduction: the exact boot-real stop sequence —
//! `cmn w12, #1` (0x3100059F) + `b.eq` (0x540004E0) with x12 = 0xFFFFFFFF.
//! The real 18C66 kernel executes this at 0xfffffff007b8031c/0x7b80320 as
//! its thread_starts `-1` end-marker test; the branch must be TAKEN.

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

/// The exact real bytes, at their real relative offsets:
///   +0x00 cmn  w12, #1          0x3100059F
///   +0x04 b.eq +0x9c            0x540004E0   (target +0xA0)
///   +0x08 add  x12, x12, x22    0x8B16018C   (the "ran away" path)
///   +0xA0 wfe                   0xD503205F   (clean marker at target)
#[test]
fn bootstop_cmn_w12_minus1_b_eq_must_be_taken() {
    let base = 0x0u64;
    let mut code = vec![0u8; 0x200];
    code[0x00..0x04].copy_from_slice(&0x3100_059Fu32.to_le_bytes());
    code[0x04..0x08].copy_from_slice(&0x5400_04E0u32.to_le_bytes());
    code[0x08..0x0c].copy_from_slice(&0x8B16_018Cu32.to_le_bytes());
    code[0xA0..0xA4].copy_from_slice(&0xD440_0000u32.to_le_bytes());
    let mem = Ram(code);

    let mut cpu = Interpreter::new(Box::new(mem));
    cpu.set_reset_vector(base);
    cpu.x[12] = 0xFFFF_FFFF; // the -1 end marker, zero-extended
    cpu.x[22] = 0x1000;
    let res = cpu.run(a13_cpu::InterpBudget { max_insn: 10, max_ns: 1_000_000 });

    assert_eq!(
        res.stop,
        StopReason::Halted,
        "b.eq must be taken: cmn w12,#1 with w12=-1 sets Z; hlt at the target halts"
    );
    assert_eq!(res.executed, 3, "cmn + b.eq + hlt");
    assert_eq!(cpu.pc, base + 0xA0, "PC must sit at the branch target");
    assert_eq!(cpu.nzcv & 0b0100, 0b0100, "Z must be set by cmn w12,#1");
}

/// Same pair but x12 = 0x402 (the earlier in-loop value): Z clear → the
/// branch must NOT be taken and execution must fall through to the add.
#[test]
fn bootstop_cmn_nonzero_falls_through() {
    let base = 0x0u64;
    let mut code = vec![0u8; 0x200];
    code[0x00..0x04].copy_from_slice(&0x3100_059Fu32.to_le_bytes());
    code[0x04..0x08].copy_from_slice(&0x5400_04E0u32.to_le_bytes());
    code[0x08..0x0c].copy_from_slice(&0x8B16_018Cu32.to_le_bytes());
    code[0x0c..0x10].copy_from_slice(&0xD440_0000u32.to_le_bytes()); // fall-through hlt
    code[0xA0..0xA4].copy_from_slice(&0xD440_0000u32.to_le_bytes());
    let mem = Ram(code);

    let mut cpu = Interpreter::new(Box::new(mem));
    cpu.set_reset_vector(base);
    cpu.x[12] = 0x402;
    cpu.x[22] = 0x1000;
    let res = cpu.run(a13_cpu::InterpBudget { max_insn: 10, max_ns: 1_000_000 });

    assert_eq!(res.stop, StopReason::Halted, "falls through add, then hlt");
    assert_eq!(res.executed, 4, "cmn + b.eq(not taken) + add + hlt");
    assert_eq!(cpu.x[12], 0x1402, "add x12, x12, x22 must have executed");
    assert_eq!(cpu.pc, base + 0x0C, "stopped at the fall-through hlt");
}

/// Full runtime shape: `ldr w12,[x10]` (plain RAM) → `cmn w12,#1` → `b.eq`.
#[test]
fn bootstop_load_then_cmn_b_eq() {
    let base = 0x0u64;
    let mut code = vec![0u8; 0x1000];
    // +0x00 ldr w12, [x10]         0xB940014C
    code[0x00..0x04].copy_from_slice(&0xB940_014Cu32.to_le_bytes());
    // +0x04 cmn w12, #1            0x3100059F
    code[0x04..0x08].copy_from_slice(&0x3100_059Fu32.to_le_bytes());
    // +0x08 b.eq +0x9c             0x540004E0 → target +0xA4
    code[0x08..0x0c].copy_from_slice(&0x5400_04E0u32.to_le_bytes());
    // +0x0c add x12, x12, x22      0x8B16018C (ran-away path)
    code[0x0c..0x10].copy_from_slice(&0x8B16_018Cu32.to_le_bytes());
    // +0xA4 wfe                    0xD503205F
    code[0xA4..0xA8].copy_from_slice(&0xD440_0000u32.to_le_bytes());
    // data page: slot array at 0x800, slot 217 = -1 at 0x800+0x364
    code[0x800 + 0x364..0x800 + 0x368].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    let mem = Ram(code);

    let mut cpu = Interpreter::new(Box::new(mem));
    cpu.set_reset_vector(base);
    cpu.x[10] = 0x800 + 0x364;
    cpu.x[22] = 0x1000;
    let res = cpu.run(a13_cpu::InterpBudget { max_insn: 10, max_ns: 1_000_000 });

    assert_eq!(res.stop, StopReason::Halted,
        "ldr→cmn→b.eq must take the branch and hit the hlt");
    assert_eq!(res.executed, 4, "ldr + cmn + b.eq + hlt");
}
