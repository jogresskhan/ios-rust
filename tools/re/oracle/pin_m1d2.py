#!/usr/bin/env python3
"""pin_m1d2.py — second round: index matrices + collision checks + SHA maps.
Every field map printed here is keystone/capstone-derived, read off directly.
"""
from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN
import capstone

ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)

def asm(text):
    enc, _ = ks.asm(text)
    return int.from_bytes(bytes(enc), "little")

def bits(w, hi, lo):
    return (w >> lo) & ((1 << (hi - lo + 1)) - 1)

def fields(w):
    return (f"Q={bits(w,30,30)} sz={bits(w,23,22):02b} b21={bits(w,21,21)} "
            f"rm={bits(w,20,16):05b} op1512={bits(w,15,12):04b} "
            f"b1110={bits(w,11,10):02b} op1510={bits(w,15,10):06b} "
            f"b14_11={bits(w,14,11):04b} imm5={bits(w,20,16):05b} b12={bits(w,12,12)} b11={bits(w,11,11)} b10={bits(w,10,10)}")

def show(title, items):
    print(f"\n===== {title} =====")
    for text in items:
        try:
            w = asm(text)
        except Exception as e:
            print(f"  {text:48s} ASM-FAIL")
            continue
        ci = next(md.disasm(w.to_bytes(4, "little"), 0), None)
        cs = f"{ci.mnemonic} {ci.op_str}" if ci else "?"
        print(f"  {text:48s} {w:08X}  {fields(w)} | {cs}")

# --- F3 single-structure index matrix ---
ss = []
for idx in range(0, 16, 4):
    ss.append(f"ld1 {{v0.b}}[{idx}], [x0]")
for idx in range(4):
    ss.append(f"ld1 {{v0.h}}[{idx}], [x0]")
    ss.append(f"ld1 {{v0.s}}[{idx}], [x0]")
for idx in range(2):
    ss.append(f"ld1 {{v0.d}}[{idx}], [x0]")
ss += ["st1 {v0.b}[3], [x0]", "st1 {v0.s}[1], [x0]", "st1 {v0.d}[0], [x0]"]
ss += ["ld1r {v0.8b}, [x0]", "ld1r {v0.4h}, [x0]", "ld1r {v0.2s}, [x0]", "ld1r {v0.1d}, [x0]",
       "ld2r {v0.2s, v1.2s}, [x0]", "ld3r {v0.2s, v1.2s, v2.2s}, [x0]",
       "ld4r {v0.2s, v1.2s, v2.2s, v3.2s}, [x0]",
       "ld2 {v0.s, v1.s}, [x0]",  # not valid, skip if fails
       ]
show("F3 single-structure indices", ss)

# --- dup/ins index matrix ---
di = []
for idx in range(4):
    di.append(f"dup v0.4s, v1.s[{idx}]")
for idx in range(2):
    di.append(f"dup v0.2d, v1.d[{idx}]")
for idx in [0, 1, 7, 15]:
    di.append(f"dup v0.16b, v1.b[{idx}]")
for idx in range(4):
    di.append(f"ins v0.s[{idx}], v1.s[0]")
di += ["ins v0.b[3], v1.b[0]", "ins v0.h[5], v1.h[0]", "ins v0.d[1], v1.d[0]",
       "mov v0.s[1], v1.s[2]"]
show("dup-elem / ins indices", di)

# --- tbl/tbx ---
show("tbl/tbx reg-count", ["tbl v0.8b, {v0.16b}, v1.8b", "tbx v0.8b, {v0.16b}, v1.8b"])

# --- fmov-imm imm8 decode ---
import struct
def f32(bits_):
    return struct.unpack("<f", struct.pack("<I", bits_))[0]
def f64(bits_):
    return struct.unpack("<d", struct.pack("<Q", bits_))[0]
print("\n===== FMOV-imm imm8 map =====")
for t, vals in [("s", ["#1.0", "#0.5", "#2.0", "#-1.0", "#16.0", "#31.0", "#-31.0", "#1.9375"]),
                ("d", ["#1.0", "#0.5", "#2.0", "#-1.0", "#16.0", "#31.0", "#-31.0", "#1.9375"])]:
    for v in vals:
        w = asm(f"fmov {t}0, {v}")
        imm8 = bits(w, 20, 13)
        print(f"  fmov {t}0, {v:8s} {w:08X} imm8={imm8:02x} type={bits(w,23,22):02b}")

# --- collision checks ---
show("collision: RDM vs long-class", [
    "sqrdmlah v0.4s, v1.4s, v2.4s", "sqrdmlsh v0.4s, v1.4s, v2.4s",
    "umlal2 v0.8h, v1.16b, v2.16b", "saddl2 v0.4s, v1.8h, v2.8h",
    "umlal v0.2s, v1.4h, v2.4h",
    "sqrdmlah v0.4s, v1.4s, v17.4s",
])

# --- scalar FP remaining ---
show("scalar FP: plain converts + gpr", [
    "fcvtzs w0, s1", "fcvtzu w0, s1", "fcvtzs x0, d1", "fcvtzu x0, d1",
    "fcvtas w0, s1", "fcvtps w0, s1", "fcvtns w0, s1",
    "scvtf s0, w1", "ucvtf s0, x1", "scvtf d0, w1",
    "fmov s0, w1", "fmov w1, s0", "fmov d0, x1", "fmov x1, d0",
    "fjcvtzs w0, d1",
])

# --- SHA/crypto from REAL census words (capstone truth) ---
print("\n===== SHA family (real census words) =====")
real = {
    "sha1h":   0x5E280A93, "sha1su1": 0x5E281860, "sha1su0": 0x5E023020,
    "sha256h": 0x5E044272, "sha256h2": 0x5E045293, "sha1p": 0x5E051272,
    "sha256su0": 0x5E282800, "sha256su1": 0x5E046820, "sha1c": 0x5E001020,
    "sha1m": 0x5E005020,
}
for name, w in real.items():
    ci = next(md.disasm(w.to_bytes(4, "little"), 0), None)
    cs = f"{ci.mnemonic} {ci.op_str}" if ci else "?"
    print(f"  {name:10s} {w:08X}  Q={bits(w,30,30)} U={bits(w,29,29)} sz={bits(w,23,22):02b} "
          f"b21={bits(w,21,21)} rm={bits(w,20,16):05b} op1512={bits(w,15,12):04b} "
          f"b11={bits(w,11,11)} b10={bits(w,10,10)} op1510={bits(w,15,10):06b} | {cs}")

# --- 2-reg-misc full op matrix (the F6 class) ---
show("2-reg-misc matrix", [
    "rev64 v0.8b, v0.8b", "rev32 v0.8b, v0.8b", "rev16 v0.8b, v0.8b",
    "saddlp v0.4h, v0.8b", "uaddlp v0.4h, v0.8b",
    "suqadd v0.8b, v0.8b", "usqadd v0.8b, v0.8b",
    "cls v0.8b, v0.8b", "clz v0.8b, v0.8b", "cnt v0.8b, v0.8b",
    "cmgt v0.8b, v0.8b, #0", "cmge v0.8b, v0.8b, #0",
    "cmeq v0.8b, v0.8b, #0", "cmle v0.8b, v0.8b, #0", "cmlt v0.8b, v0.8b, #0",
    "abs v0.8b, v0.8b", "neg v0.8b, v0.8b", "sqneg v0.8b, v0.8b",
    "xtn v0.8b, v0.8h", "sqxtn v0.8b, v0.8h", "sqxtn2 v0.16b, v0.8h", "uqxtn v0.8b, v0.8h",
    "fcvtn v0.4s, v0.2d", "fcvtxn v0.2s, v0.2d", "fcvtl v0.8h, v0.8b",
    "fcvtzs v0.8b, v0.8b", "fcvtzu v0.8b, v0.8b",
    "scvtf v0.8b, v0.8b", "ucvtf v0.8b, v0.8b",
    "frintn v0.8h, v0.8h", "frinta v0.8h, v0.8h",
    "faddp v0.4s, v0.4s", "fadd v0.4s, v0.4s", "fmla v0.4s, v0.4s",
    "sha1h v0.4s, v1.4s", "sha1su1 v0.4s, v1.4s", "sha256su0 v0.4s, v1.4s",
    "addv v0.4s, v0.4s", "smaxlv s0, v0.4h",
])
