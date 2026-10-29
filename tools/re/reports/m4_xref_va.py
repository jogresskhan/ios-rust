#!/usr/bin/env python3
"""Robust ADRP+ADD xref scan (prefilter + per-word capstone confirm, no stream
state) — find every code site materializing a target VA. Ground truth stays
capstone; the prefilter only skips non-ADRP-shaped words (m4a_xref.py style).
"""
import capstone, struct, sys

KC = "/tmp/kc18c66.macho"
data = open(KC, "rb").read()
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)

SEGS = [("TEXT_EXEC", 0xfffffff007a18000, 0xa14000, 0x1e68000),
        ("TEXT", 0xfffffff007004000, 0x0, 0x6e4000)]

def scan(target):
    hits = []
    for name, VM, FO, SZ in SEGS:
        words = struct.unpack_from(f"<{SZ//4}I", data, FO)
        # prefilter: adrp-shaped (op0 1xx1000: bit31=1, bits28-24=10000)
        adrp = []  # (idx, reg, page)
        for i, w in enumerate(words):
            if (w & 0x9F000000) == 0x90000000:
                va = VM + i * 4
                ok = md.disasm(struct.pack("<I", w), va)
                ins = next(ok, None)
                if ins is None or ins.mnemonic != "adrp":
                    continue
                parts = ins.op_str.split(",")
                reg = parts[0].strip()
                page = int(parts[1].strip().lstrip("#"), 16)
                adrp.append((i, reg, page, va))
        # forward scan for add reg, reg, #imm hitting target
        for i, reg, page, va in adrp:
            for j in range(i + 1, min(i + 24, len(words))):
                w2 = words[j]
                if (w2 & 0x1F000000) != 0x11000000:  # add imm 32/64-bit
                    continue
                va2 = VM + j * 4
                ins = next(md.disasm(struct.pack("<I", w2), va2), None)
                if ins is None:
                    continue
                parts = [p.strip() for p in ins.op_str.split(",")]
                if len(parts) >= 3 and parts[0] == reg and parts[1] == reg and parts[2].startswith("#"):
                    try:
                        imm = int(parts[2].lstrip("#"), 16)
                    except ValueError:
                        continue
                    if page + imm == target:
                        hits.append((name, va2))
    return hits

if __name__ == "__main__":
    for arg in sys.argv[1:]:
        t = int(arg, 16)
        h = scan(t)
        print(f"target {t:#x}: {[(n, hex(a)) for n, a in h]}")
