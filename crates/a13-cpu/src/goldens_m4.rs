//! M4 session: CCMP register-form + the real-kernel DT-walk check sequence.
//!
//! Repro of the 18C66 boot panic at pc 0xfffffff008137014
//! (`tools/re/notes/m4-dt-gate-re.md` walk): `cmp x12, x8; ccmp x13, x8,
//! #0, ls; b.lo` must NOT branch when DTRootNode ≤ entry+8 ≤ DTEnd.
//! Encodings are keystone/capstone ground truth (0xEB08019F / 0xFA4891A0 /
//! 0x54000B63 read from the real kernel at 0xfffffff00813700c-14).

use crate::decode::decode;
use crate::interp::Interpreter;
use crate::{CpuBackend, InterpBudget, MemAccess, StopReason};

fn ram(words: &[u32]) -> (Interpreter, Vec<u8>) {
    let mut mem = Vec::new();
    for w in words {
        mem.extend_from_slice(&w.to_le_bytes());
    }
    let mut c = Interpreter::new(Box::new(TvMem(mem.clone())));
    c.set_reset_vector(0);
    (c, mem)
}

struct TvMem(Vec<u8>);
impl MemAccess for TvMem {
    fn load(&mut self, a: u64, s: u8) -> u64 {
        let mut v = 0u64;
        for i in 0..s as usize {
            v |= (*self.0.get(a as usize + i).unwrap_or(&0) as u64) << (i * 8);
        }
        v
    }
    fn store(&mut self, a: u64, s: u8, val: u64) {
        for i in 0..s as usize {
            if (a as usize + i) < self.0.len() {
                self.0[a as usize + i] = (val >> (i * 8)) as u8;
            }
        }
    }
    fn fetch32(&mut self, a: u64) -> u32 {
        self.load(a, 4) as u32
    }
}

const HLT: u32 = 0xD440_0000;
const C_BIT: u32 = 1 << 1; // NZCV.C
const Z_BIT: u32 = 1 << 2; // NZCV.Z

/// Keystone: `cmp x12, x8` = 0xEB08019F (capstone-confirmed on the real
/// kernel image). x12 < x8 unsigned → C=0, N=1, Z=0, V=0.
#[test]
fn gap_cmp_subs_xzr_c_semantics() {
    let w = 0xEB08_019F;
    // decode must recognize it (whatever the AddSubShift variant is named);
    // the flag semantics are the real assertion below.
    assert!(decode(0, w).is_some(), "decode(cmp x12, x8) failed");
    let (mut c, _) = ram(&[w, HLT]);
    c.x[12] = 0xFFFF_FFF0_09BA_D000;
    c.x[8] = 0xFFFF_FFF0_09BA_D008;
    let res = c.run(InterpBudget { max_insn: 2, max_ns: 1_000_000_000 });
    assert!(matches!(res.stop, StopReason::Halted), "{res:?}");
    // x12 < x8 → borrow → C CLEAR
    assert_eq!(c.nzcv & C_BIT, 0, "cmp x12,x8 with x12<x8 must clear C (nzcv={:04b})", c.nzcv);
}

/// THE REAL SEQUENCE (0xfffffff00813700c..14): with
/// DTRoot=0x…9BAD000 ≤ entry+8 ≤ DTEnd=0x…9BE2C2C the entry check must
/// PASS — b.lo must NOT branch. This is the check whose (wrong) branch
/// panicked the kernel with "Device tree pointer outside of device tree
/// region" at insn 8,135,371.
#[test]
fn gap_ccmp_reg_form_dt_walk_entry_check() {
    // keystone/capstone ground truth (real kernel bytes):
    //   cmp  x12, x8        ; 0xEB08019F
    //   ccmp x13, x8, #0, ls ; 0xFA4891A0
    //   b.lo +0x16c          ; 0x54000B63 → would jump to the panic
    let words = [0xEB08_019Fu32, 0xFA48_91A0, 0x5400_0B63, HLT];
    let (mut c, _) = ram(&words);
    c.x[12] = 0xFFFF_FFF0_09BA_D000; // DTRootNode
    c.x[8] = 0xFFFF_FFF0_09BA_D008; // entry+8
    c.x[13] = 0xFFFF_FFF0_09BE_2C2C; // DTEnd
    c.x[30] = 0x8888; // lr sentinel — branching must change pc, not lr
    let res = c.run(InterpBudget { max_insn: 4, max_ns: 1_000_000_000 });
    assert!(matches!(res.stop, StopReason::Halted), "{res:?}");
    // cmp: x12 < x8 → C=0 → `ls` true → ccmp performs cmp x13, x8:
    // x13 > x8 → C=1 → b.lo (C==0) must NOT be taken → pc = 12 (fell through).
    assert_eq!(c.pc, 12, "entry check must fall through (C=1 after ccmp), got nzcv={:04b}", c.nzcv);
    assert_eq!(c.nzcv & C_BIT, C_BIT, "ccmp x13,x8 with x13>x8 must set C");
}

/// CCMP register form must use the REGISTER VALUE, not the register number
/// as an immediate (`ccmp x13, x8` compares against x8's value). Found by
/// the real-kernel walk above.
#[test]
fn gap_ccmp_reg_uses_register_value() {
    // keystone: `ccmp x0, x1, #0, al` → compare x0 against x1's VALUE.
    // x0 = 0x2000_0000 (huge), x1 = 0x10 (small): x0 > x1 → C=1.
    // If the reg number (1) were used as the immediate instead, x0 > 1
    // also gives C=1 — so pick values where the two disagree:
    // x0 = 0x2 (reg number x1 = 1 → as-immediate compare 2 > 1 → C=1;
    // real compare 2 > 0x10 → C=0). The two interpretations differ.
    let w = keystone_ccmp_x0_x1_al();
    let (mut c, _) = ram(&[w, HLT]);
    c.x[0] = 2;
    c.x[1] = 0x10;
    let res = c.run(InterpBudget { max_insn: 2, max_ns: 1_000_000_000 });
    assert!(matches!(res.stop, StopReason::Halted), "{res:?}");
    assert_eq!(c.nzcv & C_BIT, 0, "ccmp x0,x1 must compare x0 against x1's VALUE (2 < 0x10 → C clear), got nzcv={:04b}", c.nzcv);
}

/// Keystone-assembled `ccmp x0, x1, #0, al` = 0xFA41E000 (capstone
/// round-trip verified: "ccmp x0, x1, #0, al" — reg form, cond=AL(0xE),
/// nzcv=0).
fn keystone_ccmp_x0_x1_al() -> u32 {
    0xFA41_E000
}
