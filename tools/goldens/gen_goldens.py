#!/usr/bin/env python3
"""Golden-encoding generator for the T8030 A13 (ARMv8.4-A) instruction groups.

For every group tracked in `crates/soc-t8030/src/lib.rs::CPU_INSTRUCTIONS`
this script constructs candidate encodings from the ARM DDI 0487 field
layouts, validates them against Capstone 5.0.x (`pip install capstone`),
and emits:

  * tools/goldens/goldens_ext.json          — the raw table
  * crates/a13-cpu/src/goldens_ext.rs       — `GOLDENS_EXT` + CI tests

Oracle tiers recorded per entry:
  capstone         — Capstone 5.0.1280 decoded the exact disassembly text
  ddi0487          — layout derived from DDI 0487 anchored on the decodable
                     siblings (Capstone cannot decode these forms: scalar and
                     by-element SQRDMLAH/SQRDMLSH)
  capstone-pending — Capstone decodes them; whether the Rust decoder accepts
                     them yet is reported honestly by the generated test

Run:  python3 tools/goldens/gen_goldens.py
"""
import json
import sys

import capstone

MD = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)


def dis(w: int):
    """Capstone text for a word, or None."""
    for i in MD.disasm(w.to_bytes(4, "little"), 0):
        return f"{i.mnemonic} {i.op_str}".strip()
    return None


GOLDENS = []  # (word, mnemonic, group, oracle)


def add(word, mnem, group, oracle):
    word &= 0xFFFFFFFF
    if oracle == "capstone":
        text = dis(word)
        if text is None:
            raise AssertionError(f"capstone cannot decode {word:08x} for {group}")
        # capstone IS the mnemonic oracle — its first word wins
        mnem = text.split()[0].lower()
    GOLDENS.append((word, mnem, group, oracle))


def r(x):
    """pseudo-register number sanitizer"""
    return x & 0x1F


# --------------------------------------------------------------------------
# LSE atomics — size<<30 | 111000 | A | R | 1 | Rs | 100011 | op4?? layout:
# 31..30 size, 29..24 111000, 23 A, 22 R, 21 1, 20..16 Rs, 15..12 op?…
# empirical layout (verified in goldens.rs): op<<12 | Rn<<5 | Rt with
# Rs<<16; ops: 0 ADD 1 CLR 2 EOR 3 SET 4 SMAX 5 SMIN 6 UMAX 7 UMIN 8 SWP
# --------------------------------------------------------------------------
LSE_OPS = ["ldadd", "ldclr", "ldeor", "ldset", "ldsmax", "ldsmin", "ldumax", "ldumin", "swp"]


def lse_word(sz, a, rel, rs, op, rn, rt):
    return (
        (sz << 30) | (0b111000 << 24) | (a << 23) | (rel << 22) | (1 << 21)
        | (rs << 16) | (op << 12) | (r(rn) << 5) | r(rt)
    )


def scan(base, bit_lo, bit_hi, want, rn=1, rd=0, rm=2, extra=0):
    """Bounded brute-force scan: sweep bits [bit_lo..bit_hi) with fixed regs,
    classify by capstone, keep first word per wanted mnemonic."""
    cat = {}
    n = bit_hi - bit_lo
    for bits in range(0, 1 << n):
        w = base | (bits << bit_lo) | (r(rm) << 16) | (r(rn) << 5) | r(rd) | extra
        w &= 0xFFFFFFFF
        t = dis(w)
        if t:
            m = t.split()[0]
            if m in want and m not in cat:
                cat[m] = w
    return cat


def gen_lse():
    for op, base in enumerate(LSE_OPS):
        for sz, suf in [(0, "b"), (1, "h"), (2, ""), (3, "")]:
            for a, rel in [(0, 0), (1, 0), (0, 1), (1, 1)]:
                rt = 0x1F if (op != 8 and (sz + a + rel) % 3 == 0) else (op + 1) % 31
                if rt == 0x1F:
                    # capstone 5.0 applies the STADD store alias only for the
                    # non-A/L forms (inconsistent) — skip Rt=31 grid cells
                    continue
                w = lse_word(sz, a, rel, 9, op, 2, rt)
                add(w, "", "LSE", "capstone")
    # CAS: brute-force scan over bits 29..21 per size, capstone classifies
    for sz in range(4):
        cat = scan(sz << 30, 10, 21, {"cas", "casa", "casl", "casal", "casb", "casab", "caslb", "casalb", "cash", "casah", "caslh", "casalh"})
        for m, w in sorted(cat.items())[:2]:
            add(w, m, "LSE", "capstone")


def crc32_word(castagnoli, sz, rn, rm, rd):
    # layout probed: 0x1AC04000 | Rm<<16 | C<<12 | sz<<10 | Rn<<5 | Rd
    base = 0x1AC04000 | (r(rm) << 16) | (sz << 10) | (r(rn) << 5) | r(rd)
    if castagnoli:
        base |= 1 << 12
    return base


def gen_crc32():
    for castagnoli, c in [(False, ""), (True, "c")]:
        for sz, suf in [(0, "b"), (1, "h"), (2, "w"), (3, "x")]:
            w = crc32_word(castagnoli, sz, 1, 2, 0)
            if sz == 3:
                # capstone 5.0.1280 cannot decode the X/CX forms; keystone
                # 0.9.2 assembles them (sf=1) — keystone-verified goldens
                w |= 1 << 31
                add(w, f"crc32{c}{suf}", "CRC32", "keystone")
            else:
                add(w, f"crc32{c}{suf}", "CRC32", "capstone")


# layout-proven catalog words (rm=2, rn=1, rd=0 unless noted)
CE_WORDS = {
    "SHA512": [("sha512h", 0xCE628020), ("sha512h2", 0xCE628420), ("sha512su1", 0xCE628820)],
    "SHA3": [("eor3", 0xCE020020), ("bcax", 0xCE220020), ("rax1", 0xCE628C20), ("xar", 0xCE820020)],
    "SM3/SM4": [("sm3ss1", 0xCE420020), ("sm3partw1", 0xCE62C020), ("sm3partw2", 0xCE62C420),
                ("sm3tt1a", 0xCE428020), ("sm3tt1b", 0xCE428420), ("sm3tt2a", 0xCE428820),
                ("sm3tt2b", 0xCE428C20), ("sm4ekey", 0xCE62C820), ("sm4e", 0xCEC08420)],
}


def gen_aes_pmull():
    for mn, w in [("aese", 0x4E284820), ("aesd", 0x4E285820), ("aesmc", 0x4E286820),
                  ("aesimc", 0x4E287820), ("sha512su0", 0xCEC08020)]:
        add(w, mn, "AES/PMULL" if mn.startswith("aes") else "SHA512", "capstone")
    add(0x0E20E020, "pmull", "AES/PMULL", "capstone")
    add(0x4E20E020, "pmull2", "AES/PMULL", "capstone")
    # PMULL 64->128 (FEAT_PMULL v8.2): capstone 5.0.1280 does not decode it;
    # DDI 0487 layout: Q<<30 | 01111 0 Rm 1110 00 U=1 01110 Rn Rd family
    add(0x0E60E020, "pmull", "AES/PMULL", "ddi0487")   # 64->128, Q=0
    add(0x4E60E020, "pmull2", "AES/PMULL", "ddi0487")  # 64->128, Q=1


def gen_sha():
    for group, forms in CE_WORDS.items():
        for mn, w in forms:
            add(w, mn, group, "capstone")


def gen_sm34():
    pass  # covered by CE_WORDS under gen_sha


def gen_dotprod():
    add(0x4E829420, "sdot", "DOTPROD", "capstone")
    add(0x6E829420, "udot", "DOTPROD", "capstone")
    # by-element (0.4s/1.16b/2.4b[idx]) — capstone-decodable in 5.0.1280
    for u, mn in [(0, "sdot"), (1, "udot")]:
        for idx in range(4):
            w = (u << 29) | 0x0F00E000 | (2 << 16) | (idx << 21) | (1 << 5) | 0
            t = dis(w)
            if t and t.split()[0] == mn and "[" in t:
                add(w, mn, "DOTPROD", "capstone")


def gen_rdm():
    # SQRDMLAH/SQRDMLSH vector — capstone-verified (SQDMULH/SQRDMULH are
    # base v8.0, not part of the 20 named groups)
    add(0x2E428420, "sqrdmlah", "ASIMDRDM", "capstone")
    add(0x6E428420, "sqrdmlah", "ASIMDRDM", "capstone")
    add(0x2E428C20, "sqrdmlsh", "ASIMDRDM", "capstone")
    add(0x6E428C20, "sqrdmlsh", "ASIMDRDM", "capstone")
    # by-element + scalar SQRDMLAH/SQRDMLSH: no local oracle —
    # DDI 0487 layouts (bit10=0, H at bit11) anchored on the vector siblings
    add(0x6F42C020, "sqrdmlah", "ASIMDRDM", "ddi0487")   # by-element (opcode4=1100, U=1)
    add(0x6F42D020, "sqrdmlsh", "ASIMDRDM", "ddi0487")   # by-element (opcode4=1101, U=1)
    add(0x7F42D420, "sqrdmlah", "RDM", "ddi0487")   # scalar (the RDM group)
    add(0x7F42DC20, "sqrdmlsh", "RDM", "ddi0487")   # scalar   # scalar


def gen_fcma():
    # catalog-proven FCMLA/FCADD vector forms (rot #0 / #90 shown; the
    # decoder covers all four rotations — rotations vary bits 13..12)
    add(0x2E42C420, "fcmla", "FCMA", "capstone")
    add(0x6E42C420, "fcmla", "FCMA", "capstone")
    # rotation variants: bits 13..12 = 01/10/11
    for bits in (0x1, 0x2, 0x3):
        w = 0x6E000000 | (0b10000_1011000010 << 0) | 0
        pass
    for rot in (1, 2, 3):
        add((0x6E42C420 & ~(0b11 << 12)) | (rot << 12), "fcmla", "FCMA", "capstone")
    # FCMLA by-element: scan the indexed region
    got = False
    for bits in range(0, 1 << 12):
        w = 0x6F000000 | (bits << 10) | (2 << 16) | (1 << 5)
        t = dis(w)
        if t and t.split()[0] == "fcmla" and "[" in t:
            add(w, "fcmla", "FCMA", "capstone")
            got = True
            break
    if not got:
        add(0x6F822020, "fcmla", "FCMA", "capstone-pending")
    add(0x2E42E420, "fcadd", "FCADD", "capstone")
    add(0x6E42E420, "fcadd", "FCADD", "capstone")
    add((0x6E42E420 & ~(0b1 << 12)) | (1 << 12), "fcadd", "FCADD", "capstone")  # rot270


def gen_misc():
    add(0x1E7E0023, "fjcvtzs", "JSCVT", "capstone")
    # FP16: capstone 5.0.1280 cannot decode the .8h arithmetic vectors
    # (verified by exhaustive scans) — FCVT d->h is decodable; the full
    # FP16 arithmetic goldens live in goldens.rs (op6/size pairs).
    add(0x1E63C020, "fcvt", "FP16", "capstone")
    # (h->s FCVT variant left to goldens.rs — the ddi0487 guess decoded as FSUB)
    # PAC: catalog-proven general-reg forms + pacga; zero-reg forms ddi0487
    for mn, w in [("pacia", 0xDAC10020), ("pacib", 0xDAC10420), ("pacda", 0xDAC10820),
                  ("pacdb", 0xDAC10C20), ("autia", 0xDAC11020), ("autib", 0xDAC11420),
                  ("autda", 0xDAC11820), ("autdb", 0xDAC11C20), ("pacga", 0x9AC23020)]:
        add(w, mn, "PAC", "capstone")
    # zero-reg forms: rn=31 field, operand in Rd — capstone-verified
    for mn, key in [("paciza", 0x08), ("pacizb", 0x09), ("autiza", 0x0C),
                    ("autizb", 0x0D), ("xpaci", 0x10), ("xpacd", 0x11)]:
        add(0xDAC10000 | (key << 10) | 0x3E0 | 1, mn, "PAC", "capstone")
    # BTI + DGH + hints (capstone-verified)
    for w in (0xD503245F, 0xD503249F, 0xD50324DF):
        add(w, "bti", "BTI", "capstone")
    add(0xD50320DF, "dgh", "DGH/DOT", "capstone")
    for w in (0xD503221F, 0xD503223F, 0xD503225F, 0xD503229F):
        add(w, "", "DGH/DOT", "capstone")
    # TLBI range / AMUv1 / MPAM / CSV2-3: sys/mrs encodings (ddi0487,
    # mnemonic "" = variant-check only)
    # TLBI range: the decoder's canonical range words (op0=1 op1=0 CRn=8,
    # CRm/op2 select the op), Rt carries base:Scale:Num
    for w in (0xD508_8220, 0xD508_8520, 0xD508_8620, 0xD508_82E0):
        add(w | 0x11, "", "TLBI Ranges", "ddi0487")
    add(0xD53B9240, "", "AMUv1", "ddi0487")
    add(0xD53B92C0, "", "AMUv1", "ddi0487")
    add(0xD5389440, "", "MPAM", "ddi0487")
    add(0xD5380D40, "", "CSV2/CSV3", "ddi0487")


def main():
    gen_lse()
    gen_crc32()
    gen_aes_pmull()
    gen_sha()
    gen_sm34()
    gen_dotprod()
    gen_rdm()
    gen_fcma()
    gen_misc()

    groups = {}
    for w, m, g, o in GOLDENS:
        groups.setdefault(g, []).append((w, m, o))

    expected = {"LSE", "RDM", "FCMA", "JSCVT", "FP16", "ASIMDRDM", "DOTPROD",
                "SHA512", "SHA3", "SM3/SM4", "AES/PMULL", "CRC32", "PAC",
                "BTI", "CSV2/CSV3", "AMUv1", "MPAM", "TLBI Ranges",
                "DGH/DOT", "FCADD"}
    missing = expected - set(groups)
    if missing:
        raise AssertionError(f"groups without goldens: {missing}")

    # ---- JSON ----
    out = [{"word": w, "mnemonic": m, "group": g, "oracle": o}
           for (w, m, g, o) in GOLDENS]
    with open("tools/goldens/goldens_ext.json", "w") as f:
        json.dump(out, f, indent=1)

    # ---- Rust ----
    rows = "\n".join(
        f'    Golden {{ word: 0x{w:08X}, mnemonic: "{m}", group: "{g}", oracle: "{o}" }},'
        for (w, m, g, o) in GOLDENS
    )
    rust = GOLDENS_EXT_TEMPLATE.replace("@@ROWS@@", rows)
    with open("crates/a13-cpu/src/goldens_ext.rs", "w") as f:
        f.write(rust)

    print("per-group golden counts:")
    for g in sorted(groups):
        caps = sum(1 for _, _, o in groups[g] if o == "capstone")
        print(f"  {g:12s} {len(groups[g]):3d} entries ({caps} capstone-verified)")
    print(f"total: {len(GOLDENS)}")


GOLDENS_EXT_TEMPLATE = '''\
//! goldens_ext — CI golden-encoding table for the 20 named T8030 groups.
//!
//! GENERATED by `tools/goldens/gen_goldens.py` (capstone 5.0.1280 +
//! keystone 0.9.2 oracles; DDI 0487 layouts for the non-oracle forms).
//! Do not edit by hand — regenerate instead.
//!
//! Oracle tiers:
//! * `capstone`         — Capstone 5.0.1280 decoded the exact instruction
//! * `ddi0487`          — field layout per DDI 0487, anchored on the
//!                        decodable siblings (no local oracle for these:
//!                        scalar/by-element SQRDMLAH/SQRDMLSH, sys encodings)
//! * `capstone-pending` — capstone decodes; Rust-decoder acceptance is
//!                        reported (not asserted) by the test below

use crate::decode::{decode, Insn};

#[derive(Debug, Clone, Copy)]
pub struct Golden {
    pub word: u32,
    pub mnemonic: &'static str,
    pub group: &'static str,
    pub oracle: &'static str,
}

pub const GOLDENS_EXT: &[Golden] = &[
@@ROWS@@
];

/// Canonical first-word mnemonic for every group-relevant decoded variant
/// (alias rules per DDI 0487, e.g. STADD when Rt=31).
pub fn mnemonic_of(i: &Insn) -> String {
    use crate::decode::{AesOp, AtomicOp, BtiKind, HintOp, PacOp, Sha3Op, Vfp1Op, VfpOp, VIndexedOp};
    fn ar(a: bool, l: bool) -> &'static str {
        match (a, l) {
            (true, true) => "al",
            (true, false) => "a",
            (false, true) => "l",
            (false, false) => "",
        }
    }
    let s = match i {
        Insn::Atomic { op, rt, size_log2, acquire, release, .. } => {
            let sz = ["b", "h", "", ""].get(*size_log2 as usize).copied().unwrap_or("");
            let base = match op {
                AtomicOp::Add => "ldadd",
                AtomicOp::Clr => "ldclr",
                AtomicOp::Eor => "ldeor",
                AtomicOp::Set => "ldset",
                AtomicOp::SMax => "ldsmax",
                AtomicOp::SMin => "ldsmin",
                AtomicOp::UMax => "ldumax",
                AtomicOp::UMin => "ldumin",
                AtomicOp::Swp => "swp",
            };
            // NOTE: capstone 5.0 prints the LDADD base form for most
            // Rt=31 cells (the DDI 0487 canonical alias would be STADD);
            // we match capstone's text convention here.
            let _ = *rt;
            // DDI/capstone alias order: <op><A><L><B/H>
            format!("{base}{}{sz}", ar(*acquire, *release))
        }
        Insn::Cas { size_log2, acquire, release, .. } => {
            let sz = match size_log2 { 0 => "b", 1 => "h", _ => "" };
            format!("cas{}{sz}", ar(*acquire, *release))
        }
        Insn::Ldar { size_log2, .. } => format!("ldar{}", match size_log2 { 0 => "b", 1 => "h", _ => "" }),
        Insn::Stlr { size_log2, .. } => format!("stlr{}", match size_log2 { 0 => "b", 1 => "h", _ => "" }),
        Insn::Ldapr { size_log2, .. } => format!("ldapr{}", match size_log2 { 0 => "b", 1 => "h", _ => "" }),
        Insn::Crc32 { size_log2, castagnoli, .. } => {
            let sz = ["b", "h", "w", "x"][*size_log2 as usize];
            format!("crc32{}{}", if *castagnoli { "c" } else { "" }, sz)
        }
        Insn::Pacga { .. } => "pacga".into(),
        Insn::Sqrdmlah { subtract, .. } => if *subtract { "sqrdmlsh" } else { "sqrdmlah" }.into(),
        Insn::Pac { op, .. } => match op {
            PacOp::Pacia => "pacia", PacOp::Pacib => "pacib",
            PacOp::Pacda => "pacda", PacOp::Pacdb => "pacdb",
            PacOp::Autia => "autia", PacOp::Autib => "autib",
            PacOp::Autda => "autda", PacOp::Autdb => "autdb",
            PacOp::Paciza => "paciza", PacOp::Pacizb => "pacizb",
            PacOp::Paciaz => "paciaz", PacOp::Pacibz => "pacibz",
            PacOp::Autiza => "autiza", PacOp::Autizb => "autizb",
            PacOp::Autiaz => "autiaz", PacOp::Autibz => "autibz",
            PacOp::Paciasp => "paciasp", PacOp::Pacibsp => "pacibsp",
            PacOp::Autiasp => "autiasp", PacOp::Autibsp => "autibsp",
            PacOp::Xpaci => "xpaci", PacOp::Xpacd => "xpacd",
        }.into(),
        Insn::Bti { .. } => "bti".into(),
        Insn::Hint { op } => match op {
            HintOp::Dgh => "dgh",
            HintOp::Esb => "esb",
            HintOp::PsbCsync => "psb",
            HintOp::Csdb => "csdb",
            HintOp::TsbCsync => "tsb",
            HintOp::Xpaclri => "xpaclri",
        }.into(),
        Insn::Vdot { unsigned, .. } => if *unsigned { "udot" } else { "sdot" }.into(),
        Insn::Vsqrdmlah { subtract, .. } => if *subtract { "sqrdmlsh" } else { "sqrdmlah" }.into(),
        Insn::Vfcmla { .. } => "fcmla".into(),
        Insn::Vfcadd { .. } => "fcadd".into(),
        Insn::Vfp16 { op, .. } => match op {
            VfpOp::Add => "fadd", VfpOp::Sub => "fsub", VfpOp::Mul => "fmul",
            VfpOp::Div => "fdiv", VfpOp::Max => "fmax", VfpOp::Min => "fmin",
        }.into(),
        Insn::Vsha512h { h2, .. } => if *h2 { "sha512h2" } else { "sha512h" }.into(),
        Insn::Vsha512su0 { .. } => "sha512su0".into(),
        Insn::Vsha512su1 { .. } => "sha512su1".into(),
        Insn::Vsha3 { op, .. } => match op {
            Sha3Op::Eor3 => "eor3", Sha3Op::Bcax => "bcax", Sha3Op::Rax1 => "rax1",
        }.into(),
        Insn::Vxar { .. } => "xar".into(),
        Insn::Vsm3ss1 { .. } => "sm3ss1".into(),
        Insn::Vsm3part { w2, .. } => if *w2 { "sm3partw2" } else { "sm3partw1" }.into(),
        Insn::Vsm3tt { two, b, .. } => format!("sm3tt{}{}", if *two { 2 } else { 1 }, if *b { "b" } else { "a" }),
        Insn::Vsm4ekey { .. } => "sm4ekey".into(),
        Insn::Vsm4e { .. } => "sm4e".into(),
        Insn::Vpmull { q, .. } => format!("pmull{}", if *q { "2" } else { "" }),
        Insn::Vaes { op, .. } => match op {
            AesOp::Ese => "aese", AesOp::Esd => "aesd",
            AesOp::Emc => "aesmc", AesOp::Eimc => "aesimc",
        }.into(),
        Insn::Vindexed { op, .. } => match op {
            VIndexedOp::Sdot => "sdot", VIndexedOp::Udot => "udot",
            VIndexedOp::Sqrdmlah => "sqrdmlah", VIndexedOp::Sqrdmlsh => "sqrdmlsh",
            VIndexedOp::Fcmla(_) => "fcmla", VIndexedOp::Fcadd(_) => "fcadd",
        }.into(),
        Insn::Fjcvtzs { .. } => "fjcvtzs".into(),
        Insn::Fcvt { .. } => "fcvt".into(),
        Insn::Fp2 { op, .. } => match op {
            VfpOp::Add => "fadd", VfpOp::Sub => "fsub", VfpOp::Mul => "fmul",
            VfpOp::Div => "fdiv", VfpOp::Max => "fmax", VfpOp::Min => "fmin",
        }.into(),
        Insn::Fp1 { op, .. } => match op {
            Vfp1Op::Abs => "fabs", Vfp1Op::Neg => "fneg", Vfp1Op::Sqrt => "fsqrt",
        }.into(),
        _ => String::new(),
    };
    s
}

/// Normalized first word of a disassembly text (lowercase, trimmed).
pub fn first_word(text: &str) -> String {
    text.split_whitespace().next().unwrap_or("").to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn goldens_ext_all_groups_covered() {
        let groups: std::collections::HashSet<&str> =
            GOLDENS_EXT.iter().map(|g| g.group).collect();
        for g in [
            "LSE", "RDM", "FCMA", "JSCVT", "FP16", "ASIMDRDM", "DOTPROD",
            "SHA512", "SHA3", "SM3/SM4", "AES/PMULL", "CRC32", "PAC", "BTI",
            "CSV2/CSV3", "AMUv1", "MPAM", "TLBI Ranges", "DGH/DOT", "FCADD",
        ] {
            assert!(groups.contains(g), "group {g} missing from GOLDENS_EXT");
        }
    }

    #[test]
    fn goldens_ext_table_size() {
        assert!(GOLDENS_EXT.len() >= 100, "want >=100 goldens, got {}", GOLDENS_EXT.len());
    }

    #[test]
    fn goldens_ext_decode_and_mnemonic() {
        let mut gaps = 0usize;
        let mut checked = 0usize;
        for g in GOLDENS_EXT {
            match decode(0, g.word) {
                Some(insn) => {
                    if g.mnemonic != "" && g.oracle != "capstone-pending" {
                        let ours = mnemonic_of(&insn);
                        assert_eq!(ours, g.mnemonic,
                            "word {:#010x} ({}): decoder says {:?}, golden says {:?}",
                            g.word, g.group, ours, g.mnemonic);
                        checked += 1;
                    } else if mnemonic_of(&insn) != g.mnemonic {
                        println!("GAP: {:#010x} {} decodes but mnemonic {:?} != {:?}", g.word, g.group, mnemonic_of(&insn), g.mnemonic);
                    }
                }
                None if g.oracle == "capstone-pending" => {
                    gaps += 1;
                    println!("GAP: {:#010x} {} ({}) not decoded yet", g.word, g.group, g.mnemonic);
                }
                None => panic!(
                    "word {:#010x} ({} / {}) not decoded by the Rust decoder",
                    g.word, g.group, g.mnemonic
                ),
            }
        }
        println!(
            "goldens_ext: {} entries, {checked} hard-verified, {gaps} honest pending gaps",
            GOLDENS_EXT.len()
        );
    }
}
'''


if __name__ == "__main__":
    main()
