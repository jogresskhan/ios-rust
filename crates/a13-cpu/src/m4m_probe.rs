//! M4-M targeted probe for the hw_lock destroy-divergence:
//! `cmp x9, x8, lsr #2` (0xEB48093F) + `cset w2, eq` must yield w2=1 for
//! x9=0x3ffffffc, x8=0xfffffff1 — the measured register state at
//! 0xfffffff007b88170 → 0xfffffff007b881cc (watch13 insns 21503410/21503427;
//! the real boot computed w2=0 and re-acquired a destroyed lock).

use crate::interp::Interpreter;
use crate::{CpuBackend, InterpBudget, MemAccess, StopReason};

struct ProbeRam(Vec<u8>);
impl ProbeRam {
    fn load_code(&mut self, base: usize, code: &[u8]) {
        self.0[base..base + code.len()].copy_from_slice(code);
    }
}
impl MemAccess for ProbeRam {
    fn load(&mut self, addr: u64, size: u8) -> u64 {
        let off = addr as usize;
        let mut v = 0u64;
        for i in 0..size as usize {
            v |= (*self.0.get(off + i).unwrap_or(&0) as u64) << (i * 8);
        }
        v
    }
    fn store(&mut self, _addr: u64, _size: u8, _val: u64) {}
    fn fetch32(&mut self, addr: u64) -> u32 {
        self.load(addr, 4) as u32
    }
}

#[test]
fn cmp_lsr2_then_cset_eq_yields_one() {
    // cmp x9, x8, lsr #2 = 0xEB48093F (measured @0xfffffff007b88174)
    // cset w2, eq = csinc w2, wzr, wzr, ne = 0x1A9F17E2 (capstone-verified)
    // hlt #0 = 0xD4400000
    let mut ram = ProbeRam(vec![0; 0x100]);
    ram.load_code(0x00, &0xEB48_093Fu32.to_le_bytes());
    ram.load_code(0x04, &0x1A9F_17E2u32.to_le_bytes());
    ram.load_code(0x08, &0xD440_0000u32.to_le_bytes());
    let mut cpu = Interpreter::new(Box::new(ram));
    cpu.set_reset_vector(0);
    cpu.x[9] = 0x0000_0000_3FFF_FFFC;
    cpu.x[8] = 0x0000_0000_FFFF_FFF1;
    let res = cpu.run(InterpBudget { max_insn: 4, max_ns: u64::MAX });
    assert_eq!(res.stop, StopReason::Halted);
    assert_eq!(
        cpu.x[2],
        1,
        "x8>>2 == x9 must set eq → cset yields 1 (got x2={:#x}, nzcv={:#x})",
        cpu.x[2],
        cpu.nzcv
    );
}
