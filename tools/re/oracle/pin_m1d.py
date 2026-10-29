#!/usr/bin/env python3
"""pin_m1d.py — keystone-driven field maps for the M1 session-D families.
For each family: assemble a designed grid, print word -> asm, diff fields.
This is the ONLY source of field-map truth (campaign rule: no hand-derivation).
"""
from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN
import itertools, capstone

ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)

def asm(text):
    enc, _ = ks.asm(text)
    return int.from_bytes(bytes(enc), "little")

def bits(w, hi, lo):
    return (w >> lo) & ((1 << (hi - lo + 1)) - 1)

def show(title, items):
    print(f"\n===== {title} =====")
    for text in items:
        try:
            w = asm(text)
        except Exception as e:
            print(f"  {text:44s} ASM-FAIL {e}")
            continue
        ci = next(md.disasm(w.to_bytes(4, "little"), 0), None)
        cs = f"{ci.mnemonic} {ci.op_str}" if ci else "?"
        print(f"  {text:44s} {w:08X}  b23={bits(w,23,23)} b22={bits(w,22,22)} b21={bits(w,21,21)} b20_16={bits(w,20,16):05b} op15_10={bits(w,15,10):06b} b11={bits(w,11,11)} b10={bits(w,10,10)} | {cs}")

# ---------------- F1: SIMD ld/st register offset (S/D/Q) ----------------
show("F1 SIMD reg-offset", [
    "str q5, [x10, x8]", "ldr q0, [x9, x8]",
    "str s1, [x11, x10, lsl #2]", "ldr s2, [x1, x9, lsl #2]",
    "str d0, [x19, x13]", "ldr d0, [x9, x10]",
    "str q0, [x8, w9, sxtw #4]", "ldr s1, [x9, w8, uxtw #2]",
    "str d7, [x10, x8, lsl #3]", "ldr q0, [x8, w11, sxtw #4]",
])

# ---------------- F2: SIMD ld/st multiple structures ----------------
show("F2 multiple structures", [
    "ld1 {v0.8b}, [x0]", "ld1 {v0.16b}, [x0]",
    "ld1 {v0.4s}, [x0]", "ld1 {v0.2d}, [x0]",
    "st1 {v0.4s}, [x0]",
    "ld1 {v0.4s, v1.4s}, [x0]", "st1 {v0.4s, v1.4s}, [x0]",
    "ld1 {v0.4s, v1.4s, v2.4s}, [x0]", "st1 {v0.4s, v1.4s, v2.4s}, [x0]",
    "ld1 {v0.4s, v1.4s, v2.4s, v3.4s}, [x0]",
    "st1 {v0.4s, v1.4s, v2.4s, v3.4s}, [x0]",
    "st1 {v0.4s, v1.4s, v2.4s}, [x0], #48",
    "ld2 {v0.4s, v1.4s}, [x0]", "st2 {v0.4s, v1.4s}, [x0]",
    "ld3 {v0.4s, v1.4s, v2.4s}, [x0]", "st3 {v0.4s, v1.4s, v2.4s}, [x0]",
    "ld4 {v0.4s, v1.4s, v2.4s, v3.4s}, [x0]",
    "st4 {v0.4s, v1.4s, v2.4s, v3.4s}, [x0]",
    "ld1 {v0.8h, v1.8h}, [x0]", "ld1 {v0.2s, v1.2s}, [x0]",
    "ld1 {v0.4s, v1.4s}, [x0], #32",
    "ld1 {v0.4s, v1.4s}, [x0], x5",
    "st2 {v0.2d, v1.2d}, [x0]", "ld2 {v0.2d, v1.2d}, [x0], #32",
])

# ---------------- F3: single structure (one lane) ----------------
show("F3 single structure", [
    "ld1 {v0.b}[0], [x0]", "ld1 {v0.b}[4], [x0]", "ld1 {v0.h}[2], [x0]",
    "ld1 {v0.s}[1], [x0]", "ld1 {v0.d}[1], [x0]", "ld1 {v0.s}[3], [x0]",
    "st1 {v0.d}[1], [x0]", "st1 {v0.s}[3], [x0]",
    "ld1 {v0.s}[1], [x0], #4", "ld1 {v0.s}[1], [x0], x3",
    "st1 {v0.h}[1], [x0], #2",
    "ld1r {v0.4s}, [x0]", "ld1r {v0.2d}, [x0]", "ld1r {v0.8b}, [x0]",
    "ld2r {v0.4s, v1.4s}, [x0]", "ld3r {v0.4s, v1.4s, v2.4s}, [x0]",
    "ld4r {v0.4s, v1.4s, v2.4s, v3.4s}, [x0]",
    "ld1 {v0.16b, v1.16b}, [x0]",  # ld1 2reg 16b = single-struct? no — multiple. check
])

# ---------------- F4: FP/INT by-element (indexed) ----------------
show("F4 indexed FP", [
    "fmul v0.4s, v1.4s, v2.s[0]", "fmul v0.4s, v1.4s, v2.s[1]",
    "fmul v0.4s, v1.4s, v2.s[3]", "fmul v0.2d, v1.2d, v2.d[0]",
    "fmul v0.2d, v1.2d, v2.d[1]", "fmul v0.2s, v1.2s, v2.s[1]",
    "fmla v0.4s, v1.4s, v2.s[0]", "fmls v0.4s, v1.4s, v2.s[0]",
    "fmla v0.2d, v1.2d, v2.d[1]", "fmulx v0.4s, v1.4s, v2.s[0]",
    "fmul v0.8h, v1.8h, v2.h[0]", "fmul v0.8h, v1.8h, v2.h[7]",
    "fmul v0.4h, v1.4h, v2.h[1]",
    "fmla v0.8h, v1.8h, v2.h[0]",
])
show("F4 indexed INT", [
    "mla v0.4s, v1.4s, v2.s[0]", "mls v0.4s, v1.4s, v2.s[1]",
    "smull v0.2d, v1.2s, v2.s[0]", "smull v0.2d, v1.2s, v2.s[1]",
    "smull2 v0.4d, v1.4s, v2.s[3]", "umull v0.2d, v1.2s, v2.s[0]",
    "umlal v0.2d, v1.2s, v2.s[0]", "umlal2 v0.4d, v1.4s, v2.s[1]",
    "smlal v0.2d, v1.2s, v2.s[0]", "smlsl v0.2d, v1.2s, v2.s[0]",
    "umlsl v0.2d, v1.2s, v2.s[0]", "sqdmull v0.2d, v1.2s, v2.s[0]",
    "sqdmulh v0.4s, v1.4s, v2.s[0]", "sqrdmulh v0.4s, v1.4s, v2.s[0]",
    "sqdmulh v0.4h, v1.4h, v2.h[1]", "sqdmull v0.2s, v1.2h, v2.h[1]",
    "sqdmlal v0.2d, v1.2s, v2.s[0]", "sqdmlsl v0.2d, v1.2s, v2.s[0]",
    "mul v0.8b, v1.8b, v2.b[0]", "mla v0.8h, v1.8h, v2.h[0]",
])

# ---------------- F5: scalar FP ----------------
show("F5 scalar FP cmp/mov/sel", [
    "fcmp s0, s1", "fcmp s0, #0.0", "fcmpe s0, s1", "fcmpe s0, #0.0",
    "fcmp d0, d1", "fcmp d0, #0.0",
    "fccmp s0, s1, #0, eq", "fccmp s0, s1, #15, ne", "fccmpe d0, d1, #4, le",
    "fcsel s0, s1, s2, eq", "fcsel d3, d4, d5, mi",
    "fmov s0, s1", "fmov d0, d1", "fmov v0.d[0], x1", "fmov x1, v0.d[0]",
    "fmov s0, w1", "fmov w1, s0", "fmov d0, x1", "fmov x1, d0",
    "fmov s5, #1.00000000", "fmov d5, #1.00000000", "fmov d5, #-1.00000000",
    "fmov s5, #0.5", "fmov d5, #31.0",
])
show("F5 scalar FP 2-source + conversions", [
    "fmaxnm s0, s1, s2", "fminnm d0, d1, d2", "fmax s0, s1, s2",
    "fnmul s0, s1, s2",
    "fcvtzs w0, s1, #16", "fcvtzs w0, d1, #16", "fcvtzu w0, s1, #8",
    "fcvtzs x0, d1, #1",
    "scvtf s0, w1", "scvtf s0, x1", "ucvtf d0, w1", "ucvtf d0, x1",
    "scvtf s0, w1, #8", "ucvtf s0, x1, #4",
    "fcvt s0, d1", "fcvt d0, s1", "fcvt h0, s1",
    "fjcvtzs w0, d1",
    "fmov s0, #0.0",  # alias
])
show("F5 vector conversions (2-reg-misc FP)", [
    "ucvtf v0.4s, v0.4s", "ucvtf v0.2d, v0.2d", "scvtf v0.4s, v0.4s",
    "fcvtn v0.4s, v0.2d", "fcvtn2 v0.4s, v1.2d", "fcvtl v0.2d, v0.2s",
    "fcvtl2 v0.2d, v0.4s", "fcvtxn v0.2s, v0.2d",
    "faddp d0, v0.2d", "fmaxp d0, v0.2d",
])

# ---------------- F6: permute / 2-reg-misc / dup / ins / ext / tbl ----------------
show("F6 permute", [
    "zip1 v0.4s, v1.4s, v2.4s", "zip2 v0.4s, v1.4s, v2.4s",
    "uzp1 v0.4s, v1.4s, v2.4s", "uzp2 v0.4s, v1.4s, v2.4s",
    "trn1 v0.4s, v1.4s, v2.4s", "trn2 v0.4s, v1.4s, v2.4s",
    "zip1 v0.16b, v1.16b, v2.16b", "zip1 v0.8b, v1.8b, v2.8b",
])
show("F6 ext / tbl / dup / ins", [
    "ext v0.16b, v0.16b, v1.16b, #8", "ext v0.8b, v0.8b, v1.8b, #3",
    "tbl v0.16b, {v0.16b}, v1.16b", "tbl v0.16b, {v0.16b, v1.16b}, v2.16b",
    "tbl v0.8b, {v0.16b}, v1.8b", "tbx v0.16b, {v0.16b}, v1.16b",
    "tbl v0.16b, {v0.16b, v1.16b, v2.16b}, v3.16b",
    "tbl v0.16b, {v0.16b, v1.16b, v2.16b, v3.16b}, v4.16b",
    "dup v0.4s, v1.s[0]", "dup v0.4s, v1.s[1]", "dup v0.2d, v1.d[0]",
    "dup v0.8b, v1.b[0]", "dup v0.8h, v1.h[1]", "dup v0.4h, v1.h[2]",
    "dup v0.2d, x9", "dup v0.4s, w9", "dup v0.16b, w9",
    "mov v1.s[1], w13", "mov w8, v0.s[1]", "mov w9, v0.b[0]",
    "mov v2.s[0], v1.s[1]", "mov v0.h[3], v1.h[2]",
    "smov w8, v0.b[1]", "smov x8, v0.b[1]",
    "ins v0.b[2], w1", "ins v0.d[0], x1",
])
show("F6 2-reg-misc data + reduce + shift-reg", [
    "rev64 v0.8b, v0.8b", "rev32 v0.16b, v0.16b", "rev16 v0.8h, v0.8h",
    "rev64 v0.4h, v0.4h", "rev32 v0.4s, v0.4s", "rev16 v0.16b, v0.16b",
    "abs v0.4s, v1.4s", "neg v0.4s, v1.4s", "sqneg v0.4s, v1.4s",
    "addv s0, v1.4s", "addv h0, v1.8b", "saddlv h0, v1.8b",
    "saddlv s0, v1.4h", "uaddlv h0, v0.8b", "uaddlv s0, v0.4h",
    "smaxv h0, v0.8b", "uminv h0, v0.8b",
    "saddlp v0.4s, v1.8h", "addp v0.4s, v1.4s, v2.4s",
    "ushl v4.4s, v2.4s, v1.4s", "sshl v0.4s, v1.4s, v2.4s",
    "urshl v0.4s, v1.4s, v2.4s", "srshl v0.4s, v1.4s, v2.4s",
    "sqshl v0.4s, v1.4s, v2.4s", "sqrshl v0.4s, v1.4s, v2.4s",
    "uqshl v0.4s, v1.4s, v2.4s", "uqrshl v0.4s, v1.4s, v2.4s",
    "suqadd v0.4s, v1.4s", "usqadd v0.4s, v1.4s",
    "cls v0.4s, v1.4s", "clz v0.4s, v1.4s", "cnt v0.16b, v1.16b",
    "cmeq v0.4s, v1.4s, #0", "cmge v0.4s, v1.4s, #0",
    "cmgt v0.4s, v1.4s, #0", "cmle v0.4s, v1.4s, #0",
    "cmlt v0.4s, v1.4s, #0", "cmeq v0.4s, v1.4s, #0",
    "fcvtzs v0.4s, v1.4s", "fcvtzu v0.4s, v1.4s",
    "scvtf v0.4s, v1.4s", "ucvtf v0.4s, v1.4s",
    "frintx v0.4s, v1.4s", "frinti v0.4s, v1.4s",
    "fabs v0.4s, v1.4s", "fneg v0.4s, v1.4s", "fsqrt v0.4s, v1.4s",
    "fmaxnmv h0, v0.8h", "fminnmv h0, v0.8h",
    "faddp v0.4s, v1.4s", "fmlal v0.4s, v1.4s, v2.4s",
    "faddp s0, v0.2s",
])
show("F6 2-reg-misc FP scalar-ish + crypto misc", [
    "sha1h s19, s20", "sha1su1 v0.4s, v3.4s", "sha256su0 v0.4s, v1.4s",
    "sha1su0 v0.4s, v1.4s, v2.4s", "sha1c q0, s1, v2.4s",
    "sha1p q0, s1, v2.4s", "sha1m q0, s1, v2.4s",
    "sha256h q0, q1, v2.4s", "sha256h2 q0, q1, v2.4s",
    "sha256su1 v0.4s, v1.4s, v2.4s",
])
