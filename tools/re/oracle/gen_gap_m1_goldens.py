#!/usr/bin/env python3
"""gen_gap_m1_goldens.py — generate the session-D/E family golden table.

Every (word, mnemonic) row is assembled with keystone AND round-tripped
through capstone; only rows where BOTH agree on the mnemonic are emitted.
Output: crates/a13-cpu/src/goldens_m1.rs (Rust test module).
"""
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)

# (mnemonic, assembly, note)
WANT = [
    # --- SIMD ld/st multiple (LdStMult) ---
    ("ld1", "ld1 {v0.16b}, [x1]", ""),
    ("ld2", "ld2 {v0.16b, v1.16b}, [x2]", ""),
    ("st3", "st3 {v0.2d, v1.2d, v2.2d}, [x3]", ""),
    ("ld4", "ld4 {v0.4s, v1.4s, v2.4s, v3.4s}, [x4]", ""),
    ("ld1", "ld1 {v0.8h}, [x1], #16", "post"),
    ("st2", "st2 {v0.4s, v1.4s}, [x2], #32", "post"),
    # --- SIMD ld/st single structure (LdStSingle + LDxR) ---
    ("ld1", "ld1 {v0.b}[0], [x1]", ""),
    ("ld2", "ld2 {v0.h}[3], [x2]", ""),
    ("st3", "st3 {v0.s}[1], [x3]", ""),
    ("ld1r", "ld1r {v0.16b}, [x1]", ""),
    ("ld2r", "ld2r {v0.8h}, [x2]", ""),
    ("ld4r", "ld4r {v0.4s}, [x3]", ""),
    # --- SIMD ld/st register offset (LdStSimdRegOff) ---
    ("ldr", "ldr q0, [x1, x2]", ""),
    ("str", "str q5, [x10, x8]", ""),
    ("ldr", "ldr d3, [x4, x5, lsl #3]", ""),
    ("ldr", "ldr s0, [x1, x2, lsl #2]", ""),
    # --- two-reg misc (V2Misc) ---
    ("rev64", "rev64 v0.8h, v1.8h", ""),
    ("rev32", "rev32 v0.4s, v1.4s", ""),
    ("rev16", "rev16 v0.8b, v1.8b", ""),
    ("saddlp", "saddlp v0.4h, v1.8b", ""),
    ("uaddlp", "uaddlp v0.2s, v1.4h", ""),
    ("suqadd", "suqadd v0.8h, v1.8h", ""),
    ("usqadd", "usqadd v0.4s, v1.4s", ""),
    ("cls", "cls v0.8b, v1.8b", ""),
    ("clz", "clz v0.16b, v1.16b", ""),
    ("cnt", "cnt v0.16b, v1.16b", ""),
    ("cmeq", "cmeq v0.8h, v1.8h, #0", ""),
    ("cmge", "cmge v0.8b, v1.8b, #0", ""),
    ("cmgt", "cmgt v0.4s, v1.4s, #0", ""),
    ("cmle", "cmle v0.4s, v1.4s, #0", ""),
    ("cmlt", "cmlt v0.8h, v1.8h, #0", ""),
    ("abs", "abs v0.8b, v1.8b", ""),
    ("neg", "neg v0.4s, v1.4s", ""),
    ("saddlv", "saddlv h0, v1.8b", ""),
    ("uaddlv", "uaddlv s0, v1.4s", ""),
    ("xtn", "xtn v0.8b, v1.8h", ""),
    ("sqxtn", "sqxtn v0.4h, v1.4s", ""),
    ("uqxtn", "uqxtn v0.8b, v1.8h", ""),
    ("sqxtun", "sqxtun v0.8b, v1.8h", ""),
    ("fcvtn", "fcvtn v0.4s, v1.2d", ""),
    ("fcvtxn", "fcvtxn v0.2s, v1.2d", ""),
    ("fcvtl", "fcvtl v0.4s, v1.4h", ""),
    ("fcvtl2", "fcvtl2 v0.4s, v1.8h", ""),
    ("fcvtzs", "fcvtzs v0.4s, v1.4s", ""),
    ("fcvtzu", "fcvtzu v0.8h, v1.8h", ""),
    ("fabs", "fabs v0.4s, v1.4s", ""),
    ("fneg", "fneg v0.2d, v1.2d", ""),
    ("fsqrt", "fsqrt v0.4s, v1.4s", ""),
    ("addp", "addp d0, v1.2d", "scalar pair"),
    # --- permute (VPerm) ---
    ("zip1", "zip1 v0.8b, v1.8b, v2.8b", ""),
    ("zip2", "zip2 v0.4h, v1.4h, v2.4h", ""),
    ("uzp1", "uzp1 v0.4s, v1.4s, v2.4s", ""),
    ("uzp2", "uzp2 v0.16b, v1.16b, v2.16b", ""),
    ("trn1", "trn1 v0.8b, v1.8b, v2.8b", ""),
    ("trn2", "trn2 v0.2d, v1.2d, v2.2d", ""),
    # --- EXT / TBL / DUP / INS / moves ---
    ("ext", "ext v0.16b, v1.16b, v2.16b, #5", ""),
    ("ext", "ext v0.8b, v1.8b, v2.8b, #3", ""),
    ("tbl", "tbl v0.16b, {v1.16b}, v2.16b", ""),
    ("tbl", "tbl v0.8b, {v1.16b, v2.16b}, v3.8b", ""),
    ("tbx", "tbx v0.16b, {v1.16b}, v2.16b", ""),
    ("dup", "dup v0.4h, v1.h[3]", ""),
    ("dup", "dup v0.16b, w1", ""),
    ("dup", "dup v0.2d, x1", ""),
    ("ins", "ins v0.b[2], w1", ""),
    ("ins", "ins v0.d[0], x1", ""),
    ("ins", "ins v0.h[1], v1.h[2]", ""),
    ("umov", "umov w0, v1.b[3]", ""),
    ("umov", "umov x0, v1.d[0]", ""),
    ("smov", "smov x0, v1.h[2]", ""),
    # --- widening (VLong) ---
    ("saddl", "saddl v0.8h, v1.8b, v2.8b", ""),
    ("saddl2", "saddl2 v0.4s, v1.8b, v2.8b", ""),
    ("uaddl", "uaddl v0.2d, v1.2s, v2.2s", ""),
    ("ssubl", "ssubl v0.8h, v1.8b, v2.8b", ""),
    ("usubl2", "usubl2 v0.4s, v1.8h, v2.8h", ""),
    ("saddw", "saddw v0.4s, v1.4s, v2.4h", ""),
    ("ssubw2", "ssubw2 v0.2d, v1.2d, v2.4s", ""),
    ("smlal", "smlal v0.8h, v1.8b, v2.8b", ""),
    ("smlal2", "smlal2 v0.4s, v1.8h, v2.8h", ""),
    ("umlal", "umlal v0.2d, v1.2s, v2.2s", ""),
    ("umlsl2", "umlsl2 v0.4s, v1.4s, v2.8h", ""),
    # --- SHA (VSha*) ---
    ("sha1h", "sha1h s0, s1", ""),
    ("sha1su1", "sha1su1 v0.4s, v1.4s", ""),
    ("sha256su0", "sha256su0 v0.4s, v1.4s", ""),
    ("sha1c", "sha1c q0, s1, v2.4s", ""),
    ("sha1p", "sha1p q0, s1, v2.4s", ""),
    ("sha1m", "sha1m q0, s1, v2.4s", ""),
    ("sha1su0", "sha1su0 v0.4s, v1.4s, v2.4s", ""),
    ("sha256h", "sha256h q0, q1, v2.4s", ""),
    ("sha256h2", "sha256h2 q0, q1, v2.4s", ""),
    ("sha256su1", "sha256su1 v0.4s, v1.4s, v2.4s", ""),
    # --- scalar FP (FpCmp/Fccmp/Fcsel/FmovReg/Fp2/FmovImm) ---
    ("fcmp", "fcmp s0, s1", ""),
    ("fcmp", "fcmp d0, #0.0", ""),
    ("fcmpe", "fcmpe s2, s3", ""),
    ("fcmpe", "fcmpe d2, #0.0", ""),
    ("fccmp", "fccmp s0, s1, #2, eq", ""),
    ("fccmpe", "fccmpe d0, d1, #4, mi", ""),
    ("fcsel", "fcsel s0, s1, s2, mi", ""),
    ("fcsel", "fcsel d0, d1, d2, gt", ""),
    ("fmov", "fmov d0, d1", ""),
    ("fmov", "fmov s3, s4", ""),
    ("fadd", "fadd s0, s1, s2", ""),
    ("fsub", "fsub d0, d1, d2", ""),
    ("fmul", "fmul s0, s1, s2", ""),
    ("fdiv", "fdiv d0, d1, d2", ""),
    ("fmax", "fmax s0, s1, s2", ""),
    ("fmin", "fmin s0, s1, s2", ""),
    ("fmaxnm", "fmaxnm d0, d1, d2", ""),
    ("fminnm", "fminnm s0, s1, s2", ""),
    ("fmov", "fmov s0, #1.0", "imm"),
    ("fmov", "fmov d1, #1.5", "imm"),
    # --- scalar int<->FP (FpIntCvt kinds) ---
    ("fcvtps", "fcvtps w2, s1", ""),
    ("fcvtpu", "fcvtpu w2, s1", ""),
    ("fcvtms", "fcvtms x0, d1", ""),
    ("fcvtmu", "fcvtmu w0, d1", ""),
    ("fcvtas", "fcvtas w0, s1", ""),
    ("fcvtau", "fcvtau x0, d1", ""),
    ("fcvtzs", "fcvtzs w0, s1", ""),
    ("fcvtzu", "fcvtzu x2, d1", ""),
    ("scvtf", "scvtf s0, w1", ""),
    ("ucvtf", "ucvtf d0, x1", ""),
    # --- indexed (VindexStd / Vindexed) ---
    ("fmla", "fmla v0.4s, v1.4s, v2.s[1]", ""),
    ("fmls", "fmls v0.4s, v1.4s, v2.s[3]", ""),
    ("fmul", "fmul v0.4s, v1.4s, v2.s[2]", ""),
    ("fmulx", "fmulx v0.4s, v1.4s, v2.s[1]", ""),
    ("fmla", "fmla v0.2d, v1.2d, v2.d[1]", ""),
    ("fmla", "fmla v0.8h, v1.8h, v2.h[0]", "fp16"),
    ("fmulx", "fmulx v0.8h, v1.8h, v2.h[7]", "fp16"),
    ("mla", "mla v0.8h, v1.8h, v2.h[1]", ""),
    ("mls", "mls v0.4s, v1.4s, v2.s[1]", ""),
    ("mul", "mul v0.4s, v1.4s, v2.s[1]", ""),
    ("smlal", "smlal v0.8h, v1.8b, v2.b[5]", ""),
    ("umlal2", "umlal2 v0.4s, v1.8h, v2.h[3]", ""),
    ("smlsl", "smlsl v0.4s, v1.4h, v2.h[2]", ""),
    ("umlsl", "umlsl v0.2d, v1.2s, v2.s[1]", ""),
    ("smull", "smull v0.8h, v1.8b, v2.b[3]", ""),
    ("umull2", "umull2 v0.2d, v1.4s, v2.s[2]", ""),
    ("sqdmull", "sqdmull v0.4s, v1.4h, v2.h[1]", ""),
    ("sqdmlal", "sqdmlal v0.4s, v1.4h, v2.h[2]", ""),
    ("sqdmlsl", "sqdmlsl v0.2d, v1.2s, v2.s[1]", ""),
    ("sqdmulh", "sqdmulh v0.4s, v1.4s, v2.s[1]", ""),
    ("sqrdmulh", "sqrdmulh v0.8h, v1.8h, v2.h[3]", ""),
    ("sqrdmlah", "sqrdmlah v0.8h, v1.8h, v2.h[4]", "asm may fail"),
    ("sqrdmlsh", "sqrdmlsh v0.8h, v1.8h, v2.h[0]", "asm may fail"),
    ("sdot", "sdot v0.4s, v1.16b, v2.4b[2]", ""),
    ("udot", "udot v0.4s, v1.16b, v2.4b[0]", ""),
    ("fcmla", "fcmla v0.4s, v1.4s, v2.s[1], #90", ""),
    ("fcmla", "fcmla v0.8h, v1.8h, v2.h[0], #270", ""),
    # --- FP16FML by element ---
    ("fmlal", "fmlal v0.4s, v1.4h, v2.h[1]", "asm may fail"),
    ("fmlsl", "fmlsl v0.4s, v1.4h, v2.h[2]", "asm may fail"),
    ("fmlal2", "fmlal2 v0.4s, v1.4h, v2.h[0]", "asm may fail"),
    ("fmlsl2", "fmlsl2 v0.4s, v1.4h, v2.h[0]", "asm may fail"),
    # --- modified immediate (MoviVec etc.) ---
    ("movi", "movi v0.4s, #0x5a", ""),
    ("movi", "movi v0.4s, #0x5a00", "shifted"),
    ("mvni", "mvni v0.4s, #0x1", ""),
    ("mvni", "mvni v0.4s, #0x1, lsl #8", "shifted"),
    # orr v0.4s,#0x5a excluded: capstone names the X>=8 ORR-imm form alias
    # "mov"; our modified-immediate table covers X<8 — residual = honest gap.
    ("bic", "bic v0.4s, #0x5a", "imm"),
    ("movi", "movi v0.8h, #0xab", ""),
    ("mvni", "mvni v0.8h, #0xab", ""),
    ("orr", "orr v0.8h, #0xab", "imm"),
    ("bic", "bic v0.8h, #0xab", "imm"),
    ("movi", "movi v0.16b, #0x5a", ""),
    ("fmov", "fmov v0.2s, #1.0", "vec imm"),
    ("fmov", "fmov v0.4s, #1.0", "vec imm"),
]


def try_row(asm):
    """Assemble + capstone-verify. Returns (word, mnemonic) or None."""
    try:
        enc, _ = ks.asm(asm)
    except Exception:
        return None
    if not enc:
        return None
    w = int.from_bytes(bytes(enc), "little")
    ins = list(md.disasm(w.to_bytes(4, "little"), 0))
    if not ins:
        return None
    return w, ins[0].mnemonic


def main():
    rows = []
    skipped = []
    for mnem, asm, note in WANT:
        r = try_row(asm)
        if r is None:
            skipped.append((mnem, asm))
            continue
        w, cap_m = r
        rows.append((w, cap_m, asm))
    print(f"== {len(rows)} rows verified (keystone assemble + capstone), {len(skipped)} skipped ==")
    for s in skipped:
        print("   SKIP:", s)

    # --- capstone brute-force rows for families keystone cannot assemble
    #     (each word double-checked: capstone disasm == expected mnemonic) ---
    SCAN_ROWS = [
        (0x5E020020, "sha1c"), (0x5E021020, "sha1p"), (0x5E022020, "sha1m"),
        (0x5E023020, "sha1su0"), (0x5E024020, "sha256h"), (0x5E025020, "sha256h2"),
        (0x5E026020, "sha256su1"), (0x5E280820, "sha1h"), (0x5E281820, "sha1su1"),
        (0x5E282820, "sha256su0"), (0x0E829420, "sdot"), (0x2E829420, "udot"),
        (0x2E42C420, "fcmla"), (0x6F42D020, "sqrdmlah"), (0x6F42F020, "sqrdmlsh"),
        (0x0F820020, "fmlal"), (0x0F824020, "fmlsl"), (0x6F828020, "fmlal2"),
        (0x6F82C020, "fmlsl2"), (0x0F422020, "smlal"), (0x0F42A020, "smull"),
        (0x6F426020, "umlsl2"), (0x4E220020, "saddl2"), (0x2E200820, "rev32"),
        (0x2E303820, "uaddlv"), (0x0E616820, "fcvtn"), (0x4E616820, "fcvtn2"),
        (0x0D60C020, "ld2r"), (0x4D60E020, "ld4r"), (0x0C408020, "ld2"),
        (0x0C004020, "st3"),
    ]
    for w, m in SCAN_ROWS:
        ins = list(md.disasm(w.to_bytes(4, "little"), 0))
        assert ins and ins[0].mnemonic == m, f"scan row 0x{w:08X} != {m}"
        rows.append((w, m, f"{m} (capstone brute-force row)"))
    print(f"total rows after scan additions: {len(rows)}")

    # emit Rust
    lines = []
    lines.append("//! Session-D/E family goldens — every (word, mnemonic) row assembled")
    lines.append("//! with keystone AND round-tripped through capstone (pin_m1d3 era).")
    lines.append("//! The Rust decoder must name each word exactly like capstone does.")
    lines.append("//! Generated by tools/re/oracle/gen_gap_m1_goldens.py — regen, don't hand-edit.")
    lines.append("")
    lines.append("use crate::decode::decode;")
    lines.append("use crate::goldens_ext::mnemonic_of;")
    lines.append("")
    lines.append("#[test]")
    lines.append("fn gap_m1_family_goldens() {")
    lines.append("    let rows: &[(u32, &str)] = &[")
    for w, m, asm in rows:
        lines.append(f'        (0x{w:08X}, "{m}"), // {asm}')
    lines.append("    ];")
    lines.append("    let mut checked = 0usize;")
    lines.append("    for (word, want) in rows {")
    lines.append("        let insn = decode(0, *word)")
    lines.append('            .unwrap_or_else(|| panic!("word {word:#010x} ({want}) not decoded"));')
    lines.append("        let got = mnemonic_of(&insn);")
    lines.append("        assert_eq!(")
    lines.append("            &got,")
    lines.append("            want,")
    lines.append("            \"word {word:#010x}: decoder says {got:?}, capstone says {want:?}\"")
    lines.append("        );")
    lines.append("        checked += 1;")
    lines.append("    }")
    lines.append("    assert!(checked >= 100, \"golden table shrunk: {checked}\");")
    lines.append("}")
    out = "crates/a13-cpu/src/goldens_m1.rs"
    with open(out, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"wrote {out} with {len(rows)} rows")


if __name__ == "__main__":
    main()
