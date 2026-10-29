#!/usr/bin/env python3
"""mask_discover.py — derive hardware encoding masks for A64 instruction
classes by brute-forcing the encoding space through capstone.

For each target mnemonic this finds every 32-bit word in a scan range that
capstone decodes to it, then intersects their bits to produce the fixed-bit
mask/value pair you can paste into `crates/a13-cpu/src/decode.rs`.

Usage:
  mask_discover.py --range 0xd6000000:0xd8000000 --want retaa,retab,braa,brab,blraa,blrab,brk,drps,dcps1
  mask_discover.py --words 0xd65f0bff,0xd65f0fff,0xd73f0909   # classify examples
"""
import sys
import capstone

md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)


def decode(w: int):
    try:
        i = next(md.disasm(w.to_bytes(4, "little"), 0))
        return i.mnemonic
    except StopIteration:
        return None


def scan(lo: int, hi: int, want: set, step: int = 4):
    hits = {}
    for w in range(lo, hi, step):
        m = decode(w)
        if m in want:
            hits.setdefault(m, []).append(w)
    return hits


def masks(hits):
    out = {}
    for m, ws in hits.items():
        if len(ws) < 2:
            out[m] = (ws[0], 0xFFFFFFFF, len(ws))
            continue
        fixed = 0xFFFFFFFF
        for w in ws[1:]:
            fixed &= ~(w ^ ws[0]) & 0xFFFFFFFF
        out[m] = (ws[0] & fixed, fixed, len(ws))
    return out


def main():
    want, lo, hi, words = set(), 0xD6000000, 0xD8000000, None
    argv = sys.argv[1:]
    for i, a in enumerate(argv):
        if a == "--range":
            lo, hi = (int(x, 16) for x in argv[i + 1].split(":"))
        if a == "--want":
            want = set(argv[i + 1].split(","))
        if a == "--words":
            words = [int(x, 16) for x in argv[i + 1].split(",")]
    if words:
        for w in words:
            print(f"0x{w:08x} -> {decode(w)}")
        return
    hits = scan(lo, hi, want)
    for m, (val, mask, n) in sorted(masks(hits).items()):
        print(f"{m:8} if (w & 0x{mask:08X}) == 0x{val:08X}   # {n} distinct encodings in range")


if __name__ == "__main__":
    main()
