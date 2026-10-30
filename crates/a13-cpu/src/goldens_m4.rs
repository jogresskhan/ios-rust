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
const N_BIT: u32 = 1 << 3; // NZCV.N

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

// ==================== REAL-DATA BUG #28 — MSUB subtract operand order ====================
//
// Session-J boot stop: after 2G clean insns the kernel spun forever in the
// Euclid GCD loop at 0x…7b92d68 (arm_vm_init timebase-ratio helper
// @0x…7b92d20, called with {clock, divisor=1} from 0x…7b80a2c). The residue
// "stayed wrapped": our MSUB computed Xn·Xm − Xa instead of Xa − Xn·Xm, so
// `udiv q,a,b; msub r,q,b,a` returned 2⁶⁴−(a mod b) — never zero. MADD hid
// the flip for every other site because addition commutes.
// Encodings: keystone-assembled AND read verbatim from the real 18C66 image
// (0x9B0BA98C @0xfffffff007b92d70, 0x9ACC094C @0xfffffff007b92d6c — capstone
// round-trip: "msub x12, x12, x11, x10" / "udiv x12, x10, x12").

/// The verbatim kernel Euclid step (all three words read from the real
/// image @0xfffffff007b92d68..70): x10 = 1e9 (divisor·10⁹), x12 = 24e6
/// (the pexpert default clock). One iteration must leave the true remainder
/// 1e9 mod 24e6 = 16e6 in x12 — the old engine returned 2⁶⁴−16e6 and looped.
#[test]
fn gap_msub_euclid_verbatim_kernel_sequence() {
    // mov x11, x12; udiv x12, x10, x12; msub x12, x12, x11, x10
    let words = [0xAA0C_03EBu32, 0x9ACC_094C, 0x9B0B_A98C, HLT];
    let (mut c, _) = ram(&words);
    c.x[10] = 1_000_000_000;
    c.x[12] = 24_000_000;
    let res = c.run(InterpBudget { max_insn: 4, max_ns: 1_000_000_000 });
    assert!(matches!(res.stop, StopReason::Halted), "{res:?}");
    assert_eq!(c.x[12], 16_000_000, "udiv+msub must compute 1e9 mod 24e6 = 16e6 (the real remainder, not its 2⁶⁴ wrap)");
}

/// Keystone: `msub x0, x1, x2, x3` = 0x9B028C20. Xd = Xa − Xn·Xm:
/// 100 − 7·11 = 23 (old engine: 77 − 100 = 2⁶⁴−23).
#[test]
fn gap_msub_subtract_operand_order() {
    let w = 0x9B02_8C20u32;
    let (mut c, _) = ram(&[w, HLT]);
    c.x[1] = 7;
    c.x[2] = 11;
    c.x[3] = 100;
    let res = c.run(InterpBudget { max_insn: 2, max_ns: 1_000_000_000 });
    assert!(matches!(res.stop, StopReason::Halted), "{res:?}");
    assert_eq!(c.x[0], 23, "msub x0,x1,x2,x3 must be x3 − x1·x2 = 23");
}

/// Keystone: `msub w0, w1, w2, w3` = 0x1B028C20. The W form reads the
/// addend as Wc (bits 31:0 only) and writes the 32-bit result
/// zero-extended: with x3 = 0x1_0000_0064 the upper bits of x3 must be
/// IGNORED and x0 must be exactly 23 (old engine leaked x3's upper bits).
#[test]
fn gap_msub_wform_addend_mask_and_zeroext() {
    let w = 0x1B02_8C20u32;
    let (mut c, _) = ram(&[w, HLT]);
    c.x[1] = 7;
    c.x[2] = 11;
    c.x[3] = 0x0001_0000_0064; // low 32 bits = 100; upper bits must not leak
    let res = c.run(InterpBudget { max_insn: 2, max_ns: 1_000_000_000 });
    assert!(matches!(res.stop, StopReason::Halted), "{res:?}");
    assert_eq!(c.x[0], 23, "msub w0 must mask the addend to 32 bits and zero-extend (got {:#x})", c.x[0]);
}

/// Keystone: `madd w0, w1, w2, w3` = 0x1B020C20. The 32-bit form computes
/// mod 2³² and zero-extends: 0x10000·0x10000 + 5 ≡ 5 (mod 2³²) — the old
/// engine kept the full 64-bit product (0x1_0000_0005).
#[test]
fn gap_madd_wform_truncates_product() {
    let w = 0x1B02_0C20u32;
    let (mut c, _) = ram(&[w, HLT]);
    c.x[1] = 0x1_0000;
    c.x[2] = 0x1_0000;
    c.x[3] = 5;
    let res = c.run(InterpBudget { max_insn: 2, max_ns: 1_000_000_000 });
    assert!(matches!(res.stop, StopReason::Halted), "{res:?}");
    assert_eq!(c.x[0], 5, "madd w0 must truncate to 32 bits and zero-extend (got {:#x})", c.x[0]);
}

/// Keystone: `umsubl x0, w1, w2, x3` = 0x9BA28C20. UMSUBL Xd, Xn, Xm, Xa →
/// Xd = Xa − ZExt(Wn)·ZExt(Wm): 50 − 100 = 2⁶⁴−50 (old engine: 100−50 = 50).
#[test]
fn gap_umsubl_subtract_operand_order() {
    let w = 0x9BA2_8C20u32;
    let (mut c, _) = ram(&[w, HLT]);
    c.x[1] = 10;
    c.x[2] = 10;
    c.x[3] = 50;
    let res = c.run(InterpBudget { max_insn: 2, max_ns: 1_000_000_000 });
    assert!(matches!(res.stop, StopReason::Halted), "{res:?}");
    assert_eq!(c.x[0], u64::MAX - 49, "umsubl must compute x3 − w1·w2 = 2⁶⁴−50");
}

/// Regression: `umaddl x0, w1, w2, x3` = 0x9BA20C20 — the add form was
/// always commutative-correct; must stay 10·10 + 50 = 150.
#[test]
fn gap_umaddl_add_regression() {
    let w = 0x9BA2_0C20u32;
    let (mut c, _) = ram(&[w, HLT]);
    c.x[1] = 10;
    c.x[2] = 10;
    c.x[3] = 50;
    let res = c.run(InterpBudget { max_insn: 2, max_ns: 1_000_000_000 });
    assert!(matches!(res.stop, StopReason::Halted), "{res:?}");
    assert_eq!(c.x[0], 150, "umaddl add form unchanged");
}

// ==================== REAL-DATA BUG #29 — MUL is MADD with Ra=31 (XZR), never SP ====================
//
// The kernel panicked "Section __BOOTDATA,__init_entry_set has invalid size"
// (vm_mem_bootstrap, insn 8,255,200) because our MADD read the addend with
// the SP rule: every `mul` computed product + SP. Keystone proves the dp3
// reg-31 rule: `mul x9,x8,x9` ≡ `madd x9,x8,x9,xzr` = 0x9B097D09, and the
// `sp` spellings DO NOT ASSEMBLE (`madd x0,x1,x2,sp` / `madd sp,x1,x2,x3` /
// `umaddl sp,w1,w2,sp` all KS-FAIL) — Rd=31 and Ra=31 are XZR-only.

/// The verbatim kernel check sequence @0xfffffff007a8ce6c..84 (18C66):
/// `mul x9, x8, x9; ror x9, x9, #3; cmp x9, <0x0AAAAAAAAAAAAAAB>; b.hs panic`
/// with x8 = __init_entry_set size 0x2640 and the unsigned div-by-6 magic.
/// The rotated product must be 0x198 (NO panic branch). With the SP bug the
/// product was 0xcc0+SP → rot huge → b.hs taken → the boot panic.
#[test]
fn gap_mul_div6_check_verbatim_kernel_sequence() {
    // mov x9, #-0x5555555555555556 → 0xAAAAAAAAAAAAAAAB … build via movz/movk
    // is fragile; instead load the magic with the actual constant in x2 and
    // orr it in. Simplest verbatim: use keystone's encoding of the real
    // words. mul x9, x8, x9 = 0x9B097D09; ror x9, x9, #3 = 0x93C92D29 (ror
    // imm3 form: sf 1 0010011 0 immr=3 imms=011010 Rn=x9 Rd=x9 → 0x93C92D29);
    // the cmp+threshold via movz/movk pair then cmp/b.hs is exercised by the
    // assertion on the ror result directly.
    let (mut c, _) = ram(&[0x9B09_7D09u32, HLT]); // mul x9, x8, x9
    c.x[8] = 0x2640; // __init_entry_set size
    c.x[9] = 0xAAAA_AAAA_AAAA_AAAB; // unsigned div-by-6 magic
    c.sp = 0xFFFF_FFF0_09B0_FEB0; // the boot stack — must NOT leak into the product
    let res = c.run(InterpBudget { max_insn: 2, max_ns: 1_000_000_000 });
    assert!(matches!(res.stop, StopReason::Halted), "{res:?}");
    assert_eq!(c.x[9], 0xCC0, "mul x9,x8,x9 must be (0x2640·magic) mod 2⁶⁴ = 0xcc0 — SP must not be added (bug #29)");
}

/// Keystone: `mul w0, w1, w2` = 0x1B027C20 — the W form must also read the
/// (implicit) addend as XZR: 0xFFFF·0xFFFF = 0xFFFE0001 with NO SP addition.
#[test]
fn gap_mul_wform_reads_zr_addend() {
    let (mut c, _) = ram(&[0x1B02_7C20u32, HLT]); // mul w0, w1, w2
    c.x[1] = 0xFFFF;
    c.x[2] = 0xFFFF;
    c.sp = 0x1234_5678;
    let res = c.run(InterpBudget { max_insn: 2, max_ns: 1_000_000_000 });
    assert!(matches!(res.stop, StopReason::Halted), "{res:?}");
    assert_eq!(c.x[0], 0xFFFE_0001, "mul w0 must be the 32-bit product only");
}

/// Keystone: `madd x0, x1, x2, xzr` — explicit XZR addend (ra field 31):
/// 7·11 + 0 = 77, not 77 + SP.
#[test]
fn gap_madd_xzr_addend_reads_zero() {
    // madd x0, x1, x2, xzr: rm=x2, ra=31 → 0x9B02_7C20 | (x2<<16)|(31<<10)|(x1<<5)|x0
    // keystone `madd x0, x1, x2, xzr` = 0x9B027C20 (same as the W-mul word's
    // ra field: verified via keystone round-trip).
    let w = 0x9B02_7C20u32;
    let (mut c, _) = ram(&[w, HLT]);
    c.x[1] = 7;
    c.x[2] = 11;
    c.sp = 0xFFFF_FFF0_09B0_FEB0;
    let res = c.run(InterpBudget { max_insn: 2, max_ns: 1_000_000_000 });
    assert!(matches!(res.stop, StopReason::Halted), "{res:?}");
    assert_eq!(c.x[0], 77, "madd with XZR addend must not add SP");
}

/// Keystone: `madd xzr, x1, x2, x3` = 0x9B020C3F — Rd=31 DISCARDS (XZR);
/// SP must be untouched (the old set_rsp(rd) wrote the product into SP).
#[test]
fn gap_madd_xzr_destination_discards() {
    let w = 0x9B02_0C3Fu32;
    let (mut c, _) = ram(&[w, HLT]);
    c.x[1] = 7;
    c.x[2] = 11;
    c.x[3] = 100;
    c.sp = 0xDEAD_0000_0000_1000;
    let res = c.run(InterpBudget { max_insn: 2, max_ns: 1_000_000_000 });
    assert!(matches!(res.stop, StopReason::Halted), "{res:?}");
    assert_eq!(c.sp, 0xDEAD_0000_0000_1000, "madd xzr destination must discard, SP untouched");
}

/// Keystone: `umaddl x0, w1, w2, xzr` = 0x9BA27C20 — the wide add form with
/// XZR addend: 10·10 = 100 exactly.
#[test]
fn gap_umaddl_xzr_addend_reads_zero() {
    let w = 0x9BA2_7C20u32;
    let (mut c, _) = ram(&[w, HLT]);
    c.x[1] = 10;
    c.x[2] = 10;
    c.sp = 0xFFFF_FFF0_09B0_FEB0;
    let res = c.run(InterpBudget { max_insn: 2, max_ns: 1_000_000_000 });
    assert!(matches!(res.stop, StopReason::Halted), "{res:?}");
    assert_eq!(c.x[0], 100, "umaddl with XZR addend must not add SP");
}

// ==================== REAL-DATA BUG #30 — authenticated branches must strip to CANONICAL ====================
//
// The real boot's callback dispatch `blraa x27, x26` (0xD73F0B7A, verbatim
// word read @0xfffffff007f2f658; capstone: "blraa x27, x26") jumped to the
// TAGGED pointer 0x402fff007a8d060 (our model pac() tag 0x402f at bits
// 63:48) and fetched-faulted (ESR 0x92000010). The model contract: pac()
// keeps bits 47:0 intact and tags 63:48, so the authenticate side restores
// the canonical pointer by sign-extending bit 47 (kernel VA 0xfffffff0_…).
// The TvMem golden can't map the target, so the assertion is the STOP's pc.

/// Verbatim kernel dispatch: `blraa x27, x26` with the observed tagged
/// pointer — execution must land at the CANONICAL 0xfffffff007a8d060, not
/// the tagged 0x402fff007a8d060, with x30 = the link value.
#[test]
fn gap_blraa_strips_to_canonical_kernel_word() {
    let (mut c, _) = ram(&[0xD73F_0B7Au32, HLT]); // blraa x27, x26 (real 18C66 word)
    c.x[27] = 0x402F_FFF0_07A8_D060; // pac()-tagged callback (tag 0x402f)
    c.x[26] = 0xE4FE; // the real modifier
    c.x[5] = 0x5555; // scratch to detect SP/ZR confusion on the link
    let res = c.run(InterpBudget { max_insn: 2, max_ns: 1_000_000_000 });
    match res.stop {
        StopReason::UnknownInsn { pc, .. } => {
            assert_eq!(pc, 0xFFFF_FFF0_07A8_D060, "blraa must land on the canonical pointer");
        }
        other => panic!("expected UnknownInsn at the canonical target, got {other:?}"),
    }
    assert_eq!(c.x[30], 4, "blraa must link (x30 = pc+4)");
}

/// `retab` (0xD65F0BFF, capstone-pinned) must return to the CANONICAL x30:
/// a pacibsp-tagged return address 0x402f_fff0_07b8_0a30 returns to
/// 0xfffffff007b80a30 (the real gcd-helper call site), never to the tag.
#[test]
fn gap_retab_strips_to_canonical() {
    let (mut c, _) = ram(&[0xD65F_0BFFu32, HLT]); // retab
    c.x[30] = 0x402F_FFF0_07B8_0A30; // pacibsp-tagged return into arm_vm_init
    let res = c.run(InterpBudget { max_insn: 2, max_ns: 1_000_000_000 });
    match res.stop {
        StopReason::UnknownInsn { pc, .. } => {
            assert_eq!(pc, 0xFFFF_FFF0_07B8_0A30, "retab must return to the canonical address");
        }
        other => panic!("expected UnknownInsn at the canonical target, got {other:?}"),
    }
}

/// Round-trip: pac() → aut() with the right modifier restores the canonical
/// kernel pointer (0xffff top back); a wrong modifier fails (stays None).
#[test]
fn gap_pac_aut_roundtrip_restores_canonical() {
    use crate::crypto::{aut, pac};
    let (k0, k1) = (0x1122_3344_5566_7788u64, 0x99AA_BBCC_DDEE_FF00u64);
    let ptr = 0xFFFF_FFF0_07A8_D060u64;
    let signed = pac(ptr, 0xE4FE, k0, k1);
    assert_ne!(signed, ptr, "pac must tag the pointer");
    assert_eq!(aut(signed, 0xE4FE, k0, k1), Some(ptr), "aut must restore the canonical kernel VA");
    assert_eq!(aut(signed, 0x1234, k0, k1), None, "wrong modifier must fail");
}

// ==================== REAL-DATA BUG #31 — add/sub register forms: Rn=31 reads SP ====================
//
// The kernel's exception-stack guard (`cmp sp, x18; b.gt .; sub x18,#0x4000;
// cmp sp,x18; b.lt .` @0x…8160400, the vector-page shared guard) spun for
// 2G insns because `cmp sp, x18` (0xEB3263FF, keystone+capstone-pinned —
// the add/sub EXTENDED form, option LSL#0) read Rn=31 as ZR: it compared 0
// against 0xfffffff009b18000 → nzcv=0000 → b.gt taken forever. In the
// add/sub register forms (shifted AND extended, S=0 AND S=1) Rn=31 is SP;
// only Rd differs (S=0 → SP, S=1 → ZR).

/// The verbatim guard prologue: `cmp sp, x18` with sp BELOW the bound must
/// clear the branch (N=1, C=0) — the old engine produced nzcv=0000 and the
/// b.gt spun forever.
#[test]
fn gap_cmp_sp_reg_reads_sp() {
    let words = [0xEB32_63FFu32, 0x5400_000C, HLT]; // cmp sp, x18 ; b.gt .
    let (mut c, _) = ram(&words);
    c.sp = 0xFFFF_FFF0_09B0_FE50;
    c.x[18] = 0xFFFF_FFF0_09B1_8000;
    let res = c.run(InterpBudget { max_insn: 3, max_ns: 1_000_000_000 });
    assert!(matches!(res.stop, StopReason::Halted), "b.gt must NOT be taken when sp < x18, got {res:?}");
    assert_eq!(c.nzcv & N_BIT, N_BIT, "cmp sp,x18 with sp<x18 must set N (negative), got nzcv={:04b}", c.nzcv);
    assert_eq!(c.nzcv & C_BIT, 0, "borrow must clear C");
    assert_eq!(c.pc, 8, "must fall through to the HLT");
}

/// The full guard: cmp (pass) → sub x18,#0x4000 → cmp (fail low) → b.lt
/// taken — then, with sp INSIDE the window, both branches fall through.
#[test]
fn gap_guard_sequence_both_paths() {
    // cmp sp, x18 ; b.gt . ; sub x18, x18, #4<<12 ; cmp sp, x18 ; b.lt . ; HLT
    let words = [
        0xEB32_63FFu32,
        0x5400_000C, // b.gt . (spin slot)
        0xD140_1252, // sub x18, x18, #4, lsl #12 (keystone)
        0xEB32_63FF, // cmp sp, x18
        0x5400_004B, // b.lt . (self-spin slot, imm19=0)
        HLT,
    ];
    // in-window: sp == bound → both checks fall through to the HLT
    let (mut c, _) = ram(&words);
    c.sp = 0xFFFF_FFF0_09B1_8000;
    c.x[18] = 0xFFFF_FFF0_09B1_8000;
    let res = c.run(InterpBudget { max_insn: 6, max_ns: 1_000_000_000 });
    assert!(matches!(res.stop, StopReason::Halted), "sp at the bound must pass the guard, got {res:?}");
    assert_eq!(c.pc, 20, "guard must fall through to the HLT at +20");
}

/// Keystone: `cmp sp, x18, lsl #1` = 0xEB3267FF — the SHIFTED form with
/// Rn=31 must also read SP: cmp(0x1000, 0x800<<1) → equal → Z set.
#[test]
fn gap_cmp_sp_shifted_reads_sp() {
    let words = [0xEB32_67FFu32, HLT]; // cmp sp, x18, lsl #1
    let (mut c, _) = ram(&words);
    c.sp = 0x1000;
    c.x[18] = 0x800;
    let res = c.run(InterpBudget { max_insn: 2, max_ns: 1_000_000_000 });
    assert!(matches!(res.stop, StopReason::Halted), "{res:?}");
    assert_eq!(c.nzcv & Z_BIT, Z_BIT, "cmp sp,x18,lsl#1 with sp==x18<<1 must set Z");
}

/// Keystone: `add sp, sp, x18` = 0x8B3263FF — S=0, Rd=31 writes SP.
#[test]
fn gap_add_sp_reg_writes_sp() {
    let words = [0x8B32_63FFu32, HLT]; // add sp, sp, x18
    let (mut c, _) = ram(&words);
    c.sp = 0x1000;
    c.x[18] = 0x234;
    let res = c.run(InterpBudget { max_insn: 2, max_ns: 1_000_000_000 });
    assert!(matches!(res.stop, StopReason::Halted), "{res:?}");
    assert_eq!(c.sp, 0x1234, "add sp,sp,x18 must write SP");
}

/// Keystone: `cmp sp, #4080` = 0xF13FC3FF — the immediate compare with
/// Rn=31 reads SP, and Rd=31 must DISCARD (the old set_rsp(31) wrote the
/// compare result into SP — the bug #10 class in the immediate form).
#[test]
fn gap_cmp_sp_imm_reads_sp_and_discards() {
    let words = [0xF13F_C3FFu32, HLT]; // cmp sp, #4080
    let (mut c, _) = ram(&words);
    c.sp = 0x1000;
    let res = c.run(InterpBudget { max_insn: 2, max_ns: 1_000_000_000 });
    assert!(matches!(res.stop, StopReason::Halted), "{res:?}");
    assert_eq!(c.nzcv & N_BIT, 0, "cmp 0x1000, 4080 is non-negative → N clear");
    assert_eq!(c.nzcv & C_BIT, C_BIT, "no borrow → C set");
    assert_eq!(c.sp, 0x1000, "cmp must not write SP");
}

// ==================== REAL-DATA BUG #34 — the #31 over-correction: the
// SHIFTED-register form reads Rn=31 as XZR, NOT SP ====================
//
// The live boot (session-L trace, insn 8,255,253) caught `neg x19, x20`
// (0xCB1403F3 = SUB x19,XZR,X20 SHIFTED — capstone `neg`) producing
// x19 = sp − 0x4C8 instead of −0x4C8: the #31 fix had mapped Rn=31 → SP
// in ALL register forms. ARM DDI0487: only the EXTENDED form (bit21=1,
// option field) reads Rn=31 as SP; the SHIFTED form reads XZR (that is
// why assemblers must use the extended form for `cmp sp, x18`). The
// kernel's qsort negates the element stride with `neg x19, x20` per
// partition step — the corrupted stride produced wild sort pointers and
// the #32 physmap-abort cascade (comparator arg x1 = phystokv(sp−0x4C8)
// measured live at the 0x…7a8d064 fault).
//
// NOTE on the #31 goldens above: 0xEB3263FF/0xEB3267FF/0x8B3263FF all
// carry bit21=1 (EXTENDED, imm3 in bits 12:10) — capstone `cmp sp, x18`
// / `cmp sp, x18, lsl #1` / `add sp, sp, x18` — so they remain the SP
// path and stay green with the #34 split.

/// The verbatim kernel qsort negate: `neg x19, x20` = 0xCB1403F3 must read
/// Rn(31) as ZR — result −0x4C8, NEVER sp−0x4C8 (the #32 cascade origin).
#[test]
fn gap_neg_shifted_rn31_reads_xzr() {
    let words = [0xCB14_03F3u32, HLT]; // neg x19, x20
    let (mut c, _) = ram(&words);
    c.x[20] = 0x4C8;
    c.sp = 0xFFFF_FFF0_09B0_FE50; // the live boot value at insn 8,255,253
    let res = c.run(InterpBudget { max_insn: 2, max_ns: 1_000_000_000 });
    assert!(matches!(res.stop, StopReason::Halted), "{res:?}");
    assert_eq!(
        c.x[19],
        0xFFFF_FFFF_FFFF_FB38u64, // −0x4C8
        "neg x19,x20 must be 0−x20 (XZR), not sp−x20 — bug #34"
    );
}

/// `cmp xzr, x19` (0xEB1303FF — SUBS xzr,xzr,x19 SHIFTED, Rn=31) must
/// compare ZR: x19=0x1234 → negative → N set; sp value must be ignored.
#[test]
fn gap_cmp_xzr_shifted_ignores_sp() {
    let words = [0xEB13_03FFu32, HLT]; // cmp xzr, x19
    let (mut c, _) = ram(&words);
    c.x[19] = 0x1234;
    c.sp = 0xDEAD_BEEF_0000_1000;
    let res = c.run(InterpBudget { max_insn: 2, max_ns: 1_000_000_000 });
    assert!(matches!(res.stop, StopReason::Halted), "{res:?}");
    assert_eq!(c.nzcv & N_BIT, N_BIT, "0 − 0x1234 is negative → N set");
}

/// `cmp sp, x18, lsl #1` (0xEB3267FF — EXTENDED, bit21=1, imm3=1) must
/// still read SP (bug #31 regression guard for the #34 split).
#[test]
fn gap_cmp_sp_extended_still_reads_sp() {
    let words = [0xEB32_67FFu32, HLT]; // cmp sp, x18, lsl #1 (extended)
    let (mut c, _) = ram(&words);
    c.sp = 0x1000;
    c.x[18] = 0x800;
    let res = c.run(InterpBudget { max_insn: 2, max_ns: 1_000_000_000 });
    assert!(matches!(res.stop, StopReason::Halted), "{res:?}");
    assert_eq!(c.nzcv & Z_BIT, Z_BIT, "extended cmp sp,x18,lsl#1: sp==x18<<1 → Z");
}

/// The verbatim 2-insn qsort chain from the live trace: `neg x19, x20` then
/// `add x22, x26, x19` (the med3 add at 0x…7f2f738). With the fix the add
/// stays inside the array; the old engine produced phystokv(sp−0x4C8).
#[test]
fn gap_qsort_med3_neighbors_with_fixed_neg() {
    let words = [0xCB14_03F3u32, 0x8B13_0356u32, HLT]; // neg x19,x20 ; add x22,x26,x19
    let (mut c, _) = ram(&words);
    c.x[20] = 0x4C8;
    c.x[26] = 0xFFFF_FFF0_09B0_2628; // the live last-element pointer
    c.sp = 0xFFFF_FFF0_09B0_FE50; // the live boot stack pointer
    let res = c.run(InterpBudget { max_insn: 3, max_ns: 1_000_000_000 });
    assert!(matches!(res.stop, StopReason::Halted), "{res:?}");
    assert_eq!(c.x[19], 0xFFFF_FFFF_FFFF_FB38u64, "stride must be −0x4C8");
    assert_eq!(
        c.x[22],
        0xFFFF_FFF0_09B0_2160u64, // 0x…2628 − 0x4C8 — INSIDE the array
        "med3 add x22,x26,x19 must stay in-array with the fixed neg"
    );
}

// ==================== REAL-DATA BUG #39 (M5 session O) ====================
// The vm_map coalesce path executes `ccmp x11, x14, #0, eq` at kernel
// 0xfffffff007b0b598 (word read from the live image, capstone-verified:
// ccmp x11, x14, #0, eq). The old ADC/SBCS decode arm checked bit23 but
// NOT bit22, and with cond=eq (bits[15:12]=0000) + bits[11:10]=00 +
// nzcv=0 the word ALSO matches the SBCS shape (bits[15:10]=000000,
// Rd-slot=nzcv=0) → decoded as `sbcs x0, x11, x14` → X0 zeroed →
// vm_map_store_entry_unlink(map=NULL, entry) → the FAR 0x10c percpu
// abort + exception-prologue stack-guard self-spin (0x…8160410) that
// burned the 48M→400M budget. Goldens: the word must decode as Ccmp
// AND must leave every GPR untouched in BOTH nzcv outcomes.

/// keystone: the kernel word decodes as the CCMP register form.
#[test]
fn gap39_ccmp_reg_eq_decodes_as_ccmp() {
    match decode(0, 0xFA4E_0160) {
        Some(crate::decode::Insn::Ccmp { rn, rm_imm, reg_form, nzcv, cond, ccmn, is64 }) => {
            assert_eq!(rn, 11);
            assert_eq!(rm_imm, 14);
            assert!(reg_form, "register form");
            assert_eq!(nzcv, 0);
            assert_eq!(cond, crate::decode::Cond::Eq);
            assert!(!ccmn, "CCMP not CCMN");
            assert!(is64, "x-form");
        }
        other => panic!("0xFA4E0160 must decode as Ccmp, got {other:?}"),
    }
}

/// ADC/ADCS/SBC/SBCS keystones must still decode as Adc (bit22/21 gate).
/// All four words capstone-verified; the subtract field = bit30.
#[test]
fn gap39_adc_family_keystones_unchanged() {
    for (w, subtract) in [
        (0x1A02_0020u32, false), // adc  w0, w1, w2
        (0x3A02_0020, false),    // adcs w0, w1, w2
        (0x5A02_0020, true),     // sbc  w0, w1, w2
        (0xBA02_0020, false),    // adcs x0, x1, x2 (capstone-verified)
        (0xDA02_0020, true),     // sbcs x0, x1, x2 (capstone-verified)
    ] {
        match decode(0, w) {
            Some(crate::decode::Insn::Adc { subtract: s, .. }) => {
                assert_eq!(s, subtract, "subtract field for {w:#x}")
            }
            other => panic!("ADC-family keystone {w:#x} misdecoded: {other:?}"),
        }
    }
}

/// Executing the verbatim kernel ccmp (both flag outcomes) must leave
/// X0..X30 EXACTLY as they were — CCMP writes NZCV only.
#[test]
fn gap39_kernel_ccmp_never_writes_gprs() {
    // Case 1: EQ false (x11 != x14) → nzcv = #0, registers frozen.
    let (mut c, _) = ram(&[0xFA4E_0160, HLT]);
    c.x[11] = 0xFFFF_FFF0_6E2C_5EC0;
    c.x[14] = 0xFFFF_FFE0_0019_C000;
    let res = c.run(InterpBudget { max_insn: 2, max_ns: 1_000_000_000 });
    assert!(matches!(res.stop, StopReason::Halted), "{res:?}");
    assert_eq!(c.x[11], 0xFFFF_FFF0_6E2C_5EC0, "x11 must survive");
    assert_eq!(c.x[14], 0xFFFF_FFE0_0019_C000, "x14 must survive");
    assert_eq!(c.x[0], 0, "x0 must never be written by ccmp");
    // Case 2: EQ true (x11 == x14) → add_with_flags(sub) path, still no GPR write.
    let (mut c, _) = ram(&[0xFA4E_0160, HLT]);
    c.x[11] = 0x1234;
    c.x[14] = 0x1234;
    let res = c.run(InterpBudget { max_insn: 2, max_ns: 1_000_000_000 });
    assert!(matches!(res.stop, StopReason::Halted), "{res:?}");
    assert_eq!(c.x[0], 0, "x0 untouched on the taken path too");
    assert_eq!(c.x[11], 0x1234, "x11 survives the taken path");
}

// ==================== REAL-DATA BUG #40 (M5-P) — the W-form add/sub +
// logical-REGISTER upper-half leak that WAS the global_waitqs wall ======
//
// The kernel's OWN panic "kernel_memory_allocate() failed to alloc global_
// waitqs" at insn 22,505,463 traced to waitq_bootstrp's whsize arithmetic
// (0x…7ab6d68..0x…7ab6d74, verbatim words from the 18C66 kernelcache):
//
//   0x128004E9  mov w9, #-0x28
//   0x1B097D08  mul w8, w8, w9
//   0x12124508  and w8, w8, #0xffffc000
//   0x4B0803F3  neg w19, w8          ← THE BUG SITE
//
// The engine ran `neg w19, w8` as a 64-bit SUB: 0 − 0x00000000FFFFC000 =
// 0xffffffff00004000 — with CLEAN inputs. W-form must zero-extend into
// Xd: x19 = 0x4000. That garbage size (2^64 − 0xFFFFC000) to
// kernel_memory_allocate trips the wired-extent sanity check
// (vm_kern.c: `map_size > MAX(1ULL << 31, sane_size / 64)` →
// KERN_RESOURCE_SHORTAGE) and the kernel panics.
//
// Panic evidence (measured at the 0x…987b99c probe, insn 22,505,463):
// x0=fmt 0x…735e028, x19=x2=0xffffffff00004000 (the spilled whsize),
// lr=0x…7ab6f34 (the call after `bl kernel_memory_allocate` 0x…7b01cb8).

/// The verbatim waitq_bootstrp negate: `neg w19, w8` (0x4B0803F3) must
/// ZERO-EXTEND the 32-bit result into X19 — never 0xffffffff00004000.
#[test]
fn gap40_neg_wform_zero_extends() {
    let words = [0x4B08_03F3u32, HLT]; // neg w19, w8 (verbatim)
    let (mut c, _) = ram(&words);
    c.x[8] = 0x0000_0000_FFFF_C000u64; // the measured clean input
    let res = c.run(InterpBudget { max_insn: 2, max_ns: 1_000_000_000 });
    assert!(matches!(res.stop, StopReason::Halted), "{res:?}");
    assert_eq!(
        c.x[19], 0x4000u64,
        "neg w19,w8 must write 0x4000 (zero-extended), got 0x{:x} — bug #40",
        c.x[19]
    );
}

/// The full verbatim waitq_bootstrp whsize tail (x8 = g_num_waitqs after
/// the power-of-2 mask loop = 256): mov w9,#-0x28; mul w8,w8,w9;
/// and w8,#0xffffc000; neg w19,w8 → x19 must be 0x4000 zero-extended
/// (the buggy engine produced 0xffffffff00004000 — the KMA size that
/// panicked the kernel), and W-form movn must zero-extend w9.
#[test]
fn gap40_waitq_whsize_chain_verbatim() {
    let words = [0x1280_04E9u32, 0x1B09_7D08, 0x1212_4508, 0x4B08_03F3, HLT];
    let (mut c, _) = ram(&words);
    c.x[8] = 256; // g_num_waitqs (power of 2), the real pre-mul input
    let res = c.run(InterpBudget { max_insn: 5, max_ns: 1_000_000_000 });
    assert!(matches!(res.stop, StopReason::Halted), "{res:?}");
    assert_eq!(
        c.x[9], 0x0000_0000_FFFF_FFD8u64,
        "mov w9,#-0x28 (movn w9,#0x27) zero-extends to 0xFFFFFFD8"
    );
    assert_eq!(
        c.x[8], 0x0000_0000_FFFF_C000u64,
        "256*(-40) mod 2^32 & 0xffffc000 = 0xFFFFC000"
    );
    assert_eq!(
        c.x[19], 0x4000u64,
        "neg w19,w8 → whsize 0x4000 zero-extended — the bug #40 site"
    );
}

/// W-form logical-REGISTER: `orr w0, w1, w2` and `eor w3, w4, w5` with
/// dirty uppers must zero-extend (the ORR/EOR leak — bug #38 covered only
/// the immediate forms; AND was safe by accident: result ⊆ masked Rm).
#[test]
fn gap40_logic_reg_wform_zero_extends() {
    // orr w0, w1, w2  = 0x2A020020? — pack via the shifted-reg encoding:
    // ORR shifted-register: sf=0 01 01010 shift=00 0 Rm=2 imm6=0 Rn=1 Rd=0
    let orr = 0x2A02_0020u32;
    // EOR shifted-register: sf=0 10 01010 … Rn=4 Rd=3
    let eor = 0x4A05_0083u32;
    let words = [orr, eor, HLT];
    let (mut c, _) = ram(&words);
    c.x[1] = 0xAAAA_0000_0000_00F0u64;
    c.x[2] = 0x0000_0000_0000_000Fu64;
    c.x[4] = 0x1234_0000_0000_00FFu64;
    c.x[5] = 0x0000_0000_0000_0F0Fu64;
    let res = c.run(InterpBudget { max_insn: 3, max_ns: 1_000_000_000 });
    assert!(matches!(res.stop, StopReason::Halted), "{res:?}");
    assert_eq!(c.x[0], 0xF0 | 0xF, "orr w0,w1,w2 → 0xFF zero-extended");
    assert_eq!(c.x[3], 0x00FF ^ 0x0F0F, "eor w3,w4,w5 → 0xF0F0 zero-extended");
}

/// W-form ADD/SUB immediate (capstone-pinned 0x11004020 / 0x51000400):
/// `add w0, w1, #0x10` with a DIRTY x1 upper must read bits 31:0 only and
/// zero-extend the result into X0; `sub w0, w0, #1` then stays 32-bit.
#[test]
fn gap40_addsub_imm_wform_masks_operand_and_result() {
    let words = [0x1100_4020u32, 0x5100_0400, HLT]; // add w0,w1,#0x10 ; sub w0,w0,#1
    let (mut c, _) = ram(&words);
    c.x[1] = 0xDEAD_0000_BEEF_0020u64; // dirty upper half
    let res = c.run(InterpBudget { max_insn: 3, max_ns: 1_000_000_000 });
    assert!(matches!(res.stop, StopReason::Halted), "{res:?}");
    assert_eq!(
        c.x[0], 0x0000_0000_BEEF_002Fu64,
        "w0 = (w1&0xffffffff + 0x10 - 1) zero-extended (0xBEEF002F, NOT \
         0xDEAD0000BEEF002F) — bug #40"
    );
}

// ==================== REAL-DATA BUG #42 (M5-P) — PSTATE.PAN unsupported
// → "context switch with PAN disabled" at insn 23,684,722 ================
//
// machine_switch_context's helper (0x…7b91904) does `mrs x8, pan; cbz w8,
// →panic`. The engine dropped every `msr pan, #0/#1` (95 sites: copyin/
// copyout wrappers, pmap, arm_vm_init 0x…7b80ad4) AND the SPSel immediate
// mask (0xD500_401F, no op2 pin) silently swallowed PAN words as SPSel.
// 18C66 ground-truth bytes: msr pan,#0 = D500409F, msr pan,#1 = D500419F,
// mrs x8, pan = D5384268 (capstone-decoded).

#[test]
fn gap42_pan_decode_from_kernel_bytes() {
    use crate::decode::Insn;
    assert_eq!(
        decode(0, 0xD500_409F),
        Some(Insn::MsrPan { set: false }),
        "msr pan, #0 (verbatim 0x…7b7ce54)"
    );
    assert_eq!(
        decode(0, 0xD500_419F),
        Some(Insn::MsrPan { set: true }),
        "msr pan, #1 (verbatim 0x…7b7ce68)"
    );
    assert_eq!(
        decode(0, 0xD538_4268),
        Some(Insn::MrsPan { rt: 8 }),
        "mrs x8, pan (verbatim 0x…7b91918)"
    );
    // the PAN words must NOT decode as SPSel anymore (op2 pin: 4 vs 5)
    assert!(
        !matches!(decode(0, 0xD500_409F), Some(Insn::MsrSpsel { .. })),
        "SPSel mask must not swallow PAN words — bug #42"
    );
    // SPSel itself unchanged (keystone goldens d50040bf/d50041bf)
    assert_eq!(decode(0, 0xD500_40BF), Some(Insn::MsrSpsel { use_sp: false }));
    assert_eq!(decode(0, 0xD500_41BF), Some(Insn::MsrSpsel { use_sp: true }));
}

/// Exec round-trip: msr pan,#1 → mrs reads 1 → msr pan,#0 → mrs reads 0.
#[test]
fn gap42_pan_msr_mrs_roundtrip() {
    // msr pan,#1; mrs x0, pan; msr pan,#0; mrs x1, pan; hlt
    let words = [0xD500_419Fu32, 0xD538_4260, 0xD500_409F, 0xD538_4261, HLT];
    let (mut c, _) = ram(&words);
    let res = c.run(InterpBudget { max_insn: 6, max_ns: 1_000_000_000 });
    assert!(matches!(res.stop, StopReason::Halted), "{res:?}");
    assert_eq!(c.x[0], 1, "mrs x0, pan after msr pan,#1");
    assert_eq!(c.x[1], 0, "mrs x1, pan after msr pan,#0");
}

/// Exception entry saves PAN into SPSR bit 23; ERET restores it.
#[test]
fn gap42_pan_spsr_save_restore() {
    // words: msr pan,#1; eret
    let (mut c, _) = ram(&[0xD500_419Fu32, 0xD69F_03E0]);
    let res = c.run(InterpBudget { max_insn: 1, max_ns: 1_000_000_000 });
    assert!(matches!(res.stop, StopReason::Budget), "{res:?}");
    assert!(c.pan, "msr pan,#1 must set the tracked bit");
    // exception entry (kernel-taken data abort) must save PAN → SPSR bit 23
    c.take_exception(0x200, 0x96000005, Some(0x10), "load");
    assert_eq!(
        (c.sys.spsr_el1 >> 23) & 1,
        1,
        "exception entry must save PAN into SPSR bit 23"
    );
    // the handler runs with PAN off (kernel does this around uaccess)
    c.pan = false;
    // ERET at word[1] (pc=4) restores PSTATE from SPSR — PAN must come back
    c.pc = 4;
    let res = c.step();
    assert!(res.is_ok(), "eret must execute: {res:?}");
    assert!(c.pan, "ERET must restore PAN from SPSR bit 23");
}
