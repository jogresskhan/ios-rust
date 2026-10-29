#!/usr/bin/env python3
"""pin_m1d3.py — capstone-authoritative census of the AdvSIMD by-element
group (bits 28:24 == 01111, group word 0x0F/0x2F/0x4F/0x6F).

Enumerates (opcode4[15:12], U[29], size[23:22], q[30]) and records every
mnemonic capstone accepts, plus index-bit verification for (L[21], M[20],
H[11]). Output: tools/re/oracle/pin_m1d3_map.json

Rule: this replaces ALL hand-derived bit tables (the old
indexed_structural goldens had wrong entries — 0x6F82C020 is fmlsl2, not
sqrdmlah; 0x4F42C020 is sqdmulh, not fcmla — capstone is the referee).
"""
import json
import itertools
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)


def word(q, u, size, L, M, op4, H, vm=2, vn=1, vd=0):
    return (
        (q << 30) | (u << 29) | (0b01111 << 24) | (size << 22) | (L << 21)
        | (M << 20) | (vm << 16) | (op4 << 12) | (H << 11) | (vn << 5) | vd
    )


def dis(w):
    ins = list(md.disasm(w.to_bytes(4, "little"), 0))
    if not ins:
        return None
    return (ins[0].mnemonic, ins[0].op_str)


def parse_index(op_str):
    """Extract the trailing [N] lane index from 'v2.h[3]' style operand."""
    if "[" not in op_str:
        return None
    tail = op_str.rsplit("[", 1)[1].split("]")[0]
    try:
        return int(tail)
    except ValueError:
        return None


def main():
    # ---- 1. opcode map: (op4, u, size) -> mnemonic ----------------------
    omap = {}
    for op4, u, size in itertools.product(range(16), (0, 1), range(4)):
        w = word(1, u, size, 0, 0, op4, 0)
        d = dis(w)
        if d:
            omap[f"{op4:04b}|u={u}|size={size}"] = {
                "op4": op4, "u": u, "size": size,
                "mnemonic": d[0], "operands": d[1],
                "sample_word": f"0x{w:08X}",
            }
    # q=0 variants may reject some ops that q=1 accepts (and vice versa);
    # scan q=0 for anything new.
    for op4, u, size in itertools.product(range(16), (0, 1), range(4)):
        w = word(0, u, size, 0, 0, op4, 0)
        d = dis(w)
        if d:
            k = f"{op4:04b}|u={u}|size={size}"
            if k not in omap:
                omap[k] = {
                    "op4": op4, "u": u, "size": size, "mnemonic": d[0],
                    "operands": d[1], "sample_word": f"0x{w:08X}", "q0_only": True,
                }
    print(f"== opcode map: {len(omap)} valid (op4,u,size) combos ==")
    for k in sorted(omap, key=lambda x: (omap[x]["op4"], omap[x]["u"], omap[x]["size"])):
        v = omap[k]
        print(f"  op4={v['op4']:04b} U={v['u']} size={v['size']}  {v['mnemonic']:10s} {v['operands']}  ({v['sample_word']})")

    # ---- 2. index-bit verification --------------------------------------
    print("\n== index verification (does idx == formula?) ==")
    formulas = {
        0: lambda h, l, m: h,                       # D: index = H
        1: lambda h, l, m: (h << 2) | (l << 1) | m, # H: index = H:L:M
        2: lambda h, l, m: (h << 1) | l,            # S: index = H:L
        3: lambda h, l, m: h,                       # D: index = H
    }
    bad = []
    checked = 0
    for op4, u, size in itertools.product(range(16), (0, 1), range(4)):
        base = omap.get(f"{op4:04b}|u={u}|size={size}")
        if not base:
            continue
        mn = base["mnemonic"]
        for L, M, H, q in itertools.product((0, 1), (0, 1), (0, 1), (0, 1)):
            w = word(q, u, size, L, M, op4, H)
            d = dis(w)
            if not d or d[0] != mn:
                continue  # invalid combo or different mnemonic (cross-family)
            idx = parse_index(d[1])
            if idx is None:
                continue
            expect = formulas[size](H, L, M)
            checked += 1
            if idx != expect:
                bad.append((mn, f"0x{w:08X}", f"idx={idx} expect={expect} (H={H} L={L} M={M} q={q} size={size})"))
    print(f"   checked {checked} index extractions, {len(bad)} mismatches")
    for b in bad[:10]:
        print("   MISMATCH:", b)

    # ---- 3. M-bit validity for FP S/D and dot families ------------------
    print("\n== M/L acceptance quirks (fp s/d + dot) ==")
    quirks = []
    for mn_filter, sizes in (("fmla", (2, 3)), ("sdot", (2,)), ("fcmla", (0, 1, 2, 3))):
        for op4, u, size in itertools.product(range(16), (0, 1), range(4)):
            base = omap.get(f"{op4:04b}|u={u}|size={size}")
            if not base or base["mnemonic"] != mn_filter or size not in sizes:
                continue
            for M in (0, 1):
                w = word(1, u, size, 0, M, op4, 0)
                d = dis(w)
                ok = d and d[0] == mn_filter
                quirks.append((mn_filter, f"op4={op4:04b} U={u} size={size} M={M}", "OK" if ok else "INVALID"))
    for qk in quirks:
        print("   ", qk)

    out = {"map": omap, "index_mismatches": bad}
    path = "tools/re/oracle/pin_m1d3_map.json"
    with open(path, "w") as f:
        json.dump(out, f, indent=1)
    print(f"\nwrote {path}")


if __name__ == "__main__":
    main()
