#!/usr/bin/env python3
"""Probe capstone 5.0.x text formats for the T8030 golden sweep (task 2-a).

Answers: exact disassembly text (mnemonic + op_str) for every instruction
class we intend to pin in goldens_ext, so fmt.rs can mirror the oracle.
"""
import capstone

md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)


def dis(word):
    for i in md.disasm(word.to_bytes(4, "little"), 0):
        return f"{i.mnemonic} {i.op_str}".strip()
    return "<UNDECODED>"


def show(label, words):
    print(f"--- {label}")
    for w in words:
        print(f"  {w:08X}  {dis(w)}")


# --- move-wide aliases -------------------------------------------------
show("movz/movn/movk", [
    0xD2800040,  # movz x0, #2
    0xD2820040,  # movz x0, #0x100, lsl #16
    0xD2C20040,  # movz x0, #0x100, lsl #32
    0x52800021,  # movz w1, #1
    0x12800002,  # movn w0, #1 -> mov w0, #-2
    0xD2A00000,  # ?
    0xF2A00001,  # movk x0, #0, lsl #16?
    0xF2C00001,
])

# --- add/sub/logic shifted-register shift text -------------------------
show("addsub reg shift", [
    0x8B020020,  # add x0, x1, x2
    0x8B020C20,  # add x0, x1, x2, lsl #3
    0x8B020820,  # add x0, x1, x2, lsr #2? (sh=01 imm6=2)
    0x8B021020,  # asr?
    0xEB02003F,  # cmp x1, x2
    0xEB02143F,  # cmp x1, x2, lsl #5?
    0x8A020020,  # and x0, x1, x2
    0x8A020C20,  # and ... lsl #3
    0x8A220020,  # bic
    0xEA020020,  # ands x0? -> tst? (rd=0)
    0xEB02001F,  # ands xzr, x1, x2 -> tst x1, x2
])

# --- logical immediate text (hex vs dec) --------------------------------
show("logic imm", [
    0x92400420,  # and x0, x1, #0xff?
    0x9243FC21,  # ?
    0xB2400021,  # orr x1, x1, #1?
    0x92C00000,
])

# --- LSE atomics grid ---------------------------------------------------
def lse(sz, a, r, op4, rn=2, rt=1, rs=0):
    return (sz << 30) | (0b111000 << 24) | (a << 23) | (r << 22) | (1 << 21) | (rs << 16) | (op4 << 12) | (rn << 5) | rt


show("lse ops w/x", [
    lse(3, 0, 0, op) for op in range(9)
] + [lse(2, 0, 0, 0), lse(1, 0, 0, 0), lse(0, 0, 0, 0),
     lse(2, 1, 0, 0), lse(2, 0, 1, 0), lse(2, 1, 1, 0),
     lse(3, 1, 1, 8), lse(0, 1, 1, 3)])

# --- CAS grid -----------------------------------------------------------
def cas(sz, a, r, rs=1, rn=2, rt=3):
    return (sz << 30) | (0b001000 << 27) | (0b1 << 21) | (a << 22) | (rs << 16) | (r << 15) | (0b11111 << 10) | (rn << 5) | rt


show("cas", [cas(s, 0, 0) for s in range(4)] + [cas(2, 1, 0), cas(2, 0, 1), cas(2, 1, 1)])

# --- CRC32 --------------------------------------------------------------
show("crc32", [
    0x1AC24020, 0x1AC24420, 0x1AC24820, 0x9AC24C20,
    0x1AC25020, 0x1AC25420, 0x1AC25820, 0x9AC25C20,
])

# --- SIMD crypto --------------------------------------------------------
show("aes/pmull", [0x4E284800, 0x4E285800, 0x4E286800, 0x4E287800,
                   0x0E22E020, 0x4E22E020, 0x0EE2E020, 0x4EE2E020])
show("sha512", [0xCE628020, 0xCE628420, 0xCEC08020, 0xCE628820])
show("sha3", [0xCE020C20, 0xCE220C20, 0xCE628C20, 0xCE821C20])
show("sm3/sm4", [0xCE420C20, 0xCE62C020, 0xCE62C420, 0xCE42C020,
                 0xCE428020, 0xCE428420, 0xCE428820, 0xCE428C20,
                 0xCE429020, 0xCEC08420, 0xCE62C820])

# --- 3-same: DOT / RDM / FCMLA / FCADD / FP16 ---------------------------
show("dotprod vector", [0x0E829420, 0x2E829420, 0x4E829420, 0x6E829420])
show("rdm vector", [0x2E428420, 0x6E428C20, 0x6E828420, 0x2E428C20, 0x6E828C20, 0x2E828420])
show("fcmla vector", [0x6E82C420, 0x6E82CC20, 0x6E82D420, 0x6E82DC20, 0x2E42CC20, 0x4E82C420, 0x6E42C420])
show("fcadd vector", [0x6E82E420, 0x6E82F420, 0x2E42E420, 0x4E82E420, 0x4E42E420])
show("fp16 vector", [0x4E421420, 0x4EC21420, 0x6E421C20, 0x2E423C20, 0x4E423420, 0x4EC23420, 0x2E421420, 0x6E421420])

# --- indexed (by-element) ------------------------------------------------
def idx(q, u, size, l, m, rm, op4, h, rn=1, rd=0):
    return (q << 30) | (u << 29) | (0b01111 << 24) | (size << 22) | (l << 21) | (m << 20) | (rm << 16) | (op4 << 12) | (h << 11) | (0 << 10) | (rn << 5) | rd


show("sdot/udot by-elem", [
    idx(1, 0, 2, 0, 0, 2, 0xE, 0),  # sdot v0.4s, v1.16b, v2.4b[0]
    idx(1, 0, 2, 1, 0, 2, 0xE, 0),
    idx(1, 0, 2, 0, 0, 2, 0xE, 1),
    idx(1, 0, 2, 1, 1, 2, 0xE, 1),
    idx(1, 1, 2, 0, 0, 2, 0xE, 0),  # udot
    idx(0, 0, 2, 0, 0, 2, 0xE, 0),  # sdot .2s
    idx(0, 1, 2, 0, 0, 2, 0xE, 0),
])
show("sqrdmlah by-elem probe (expect UNDECODED)", [
    idx(1, 1, 2, 0, 0, 2, 0xC, 0),
    idx(1, 1, 2, 0, 0, 2, 0xD, 0),
])
show("fcmla by-elem", [
    idx(1, 0, 1, 0, 0, 2, 0xC, 0),
    idx(1, 0, 1, 0, 0, 2, 0xC, 1),
    idx(1, 0, 1, 1, 0, 2, 0xC, 0),
    idx(1, 0, 1, 0, 0, 2, 0xD, 0),  # fcadd by-elem
    idx(1, 0, 1, 0, 0, 2, 0xD, 1),
    idx(0, 0, 1, 0, 0, 2, 0xC, 0),  # fcmla .2h?
])
# fcmla rot in size field (bits 23:22 when opcode=1100)
show("fcmla by-elem rot", [
    idx(1, 0, 0, 0, 0, 2, 0xC, 0),
    idx(1, 0, 1, 0, 0, 2, 0xC, 0),
    idx(1, 0, 2, 0, 0, 2, 0xC, 0),
    idx(1, 0, 3, 0, 0, 2, 0xC, 0),
])
# USDOT probes: by-element U=1 opcode 0xE size 00; vector 3-same opcode 0x2A?
show("usdot probes", [
    idx(1, 1, 0, 0, 0, 2, 0xE, 0),
    idx(0, 1, 0, 0, 0, 2, 0xE, 0),
])
def threesame(q, u, size, opcode, rn=1, rd=0, vm=2):
    return (q << 30) | (u << 29) | (0b01110 << 24) | (size << 22) | (vm << 16) | (0 << 21) | (opcode << 10) | (rn << 5) | rd


# USDOT vector (i8mm): 0 Q U 01110 00 Rm 000111 0 Rn Rd? try opcode=0x0E with bit10=1 variants
for op6 in (0x0E, 0x0F, 0x2A, 0x2E):
    for u in (0, 1):
        for size in (0,):
            w = threesame(1, u, size, op6)
            t = dis(w)
            if t != "<UNDECODED>":
                print(f"  threesame q=1 u={u} size={size} op6={op6:#x}: {w:08X}  {t}")
show("usdot vec probe 2", [0x6E808400, 0x6E808C00, 0x6EA08400, 0x6EA08C00, 0x6E80A400])

# --- FP16 scalar / JSCVT -------------------------------------------------
show("fp16 scalar", [
    0x1EE24020,  # fcvt s0, h1
    0x1E23C020,  # fcvt h0, s1
    0x1E63C020,  # fcvt h0, d1
    0x1EE2C020,  # fcvt d0, h1
    0x1E604020,  # fcvt? h0, s1? (opc 11)
    0x1EE22820,  # fadd h0, h1, h2
    0x1EE20820,  # fmul
    0x1EE00820,  # fmul s0, s1, s2? (ty=00)
    0x5EE20820,
    0xDEE20820,
    0x1EE0C020,  # fabs h0, h1
    0x1E60C020,  # fabs s0, s1
    0x1E704020,  # ?
    0x1EE40020,  # scvtf h0, w1?
    0x9EE30020,  # scvtf h0, x1
    0x1EE22020,  # ?
    0x1E7E0020,  # fjcvtzs w0, d1
])

# --- PAC / BTI / hints ----------------------------------------------------
show("pac", [
    0xDAC10020, 0xDAC10420, 0xDAC10820, 0xDAC10C20,
    0xDAC11020, 0xDAC11420, 0xDAC11820, 0xDAC11C20,
    0xDAC123E0,  # paciza x0
    0xDAC12BE0,  # pacizb x0
    0xDAC143E0,  # xpaci x0
    0xDAC147E0,  # xpacd x0
    0xDAC10BE0,  # pacia x0, sp?
    0xD503231F, 0xD503233F, 0xD503235F, 0xD503237F,
    0xD503239F,  # autiaz x30?
    0x9AC53002,  # pacga x2, x0, x5
])
show("braa/blraa/retaa probes", [
    0xD71F0820, 0xD73F0820, 0xD65F0BFF,
    0xD71F0C20, 0xD73F0C20, 0xD65F0FFF,
    0xD69F0BFF, 0xD69F0FFF,
])
show("bti/dgh/hints", [
    0xD503245F, 0xD503249F, 0xD50324DF, 0xD503241F,
    0xD50320DF, 0xD503221F, 0xD503223F, 0xD503229F, 0xD50320FF,
])

# --- TLBI range ------------------------------------------------------------
show("tlbi range", [0xD5088220, 0xD5088520, 0xD5088620, 0xD50882E0, 0xD50885E0,
                    0xD50886E0, 0xD5088260, 0xD5088560, 0xD5088660, 0xD5088223])

# --- AMU/MPAM/ID sysreg sweep ---------------------------------------------
print("--- sysreg sweep (mrs, names matching am/mpam/id_aa64)")
found = {}
for w in range(0xD5380000, 0xD53C0000, 1 << 5):
    t = dis(w)
    if t != "<UNDECODED>":
        mn = t.split()[1]
        if any(k in mn for k in ("am", "mpam", "id_aa64pfr0", "gxf")):
            found.setdefault(mn, []).append(w)
for k in sorted(found):
    print(f"  {k:20s} {[hex(x) for x in found[k][:4]]}")
