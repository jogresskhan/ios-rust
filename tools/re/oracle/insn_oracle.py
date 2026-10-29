#!/usr/bin/env python3
"""insn_oracle.py — the ARM64 decode oracle for ios-rust a13-cpu work.

Assembles A64 mnemonics with keystone, decodes them back with capstone,
and prints the exact 32-bit encodings. Use it to (a) derive hardware masks
before implementing a new instruction class in `crates/a13-cpu/src/decode.rs`,
and (b) cross-check an implemented class field-by-field.

Usage:
  insn_oracle.py 'retaa' 'ldur x1, [x2, #-8]' 'stp q0, q3, [sp, #-0x80]!'
  insn_oracle.py --fuzz RETAA RETAB BRAA BLRAA     # enumerate register fields
Output: one line per encoding:  <hex insn>  <capstone mnemonic> <operands>
"""
import sys

import capstone
import keystone


def assemble(text: str) -> int:
    ks = keystone.Ks(keystone.KS_ARCH_ARM64, keystone.KS_MODE_LITTLE_ENDIAN)
    enc, _ = ks.asm(text)
    if len(enc) != 4:
        raise ValueError(f"not one 4-byte A64 insn: {text!r} -> {enc.hex()}")
    return int.from_bytes(enc, "little")


def show(words):
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    md.detail = False
    for w in words:
        try:
            ins = next(md.disasm(w.to_bytes(4, "little"), 0))
            print(f"  0x{w:08x}  {ins.mnemonic:10} {ins.op_str}")
        except StopIteration:
            print(f"  0x{w:08x}  <capstone cannot decode>")
        print(f"            binary: {w:032b}")


def fuzz(mnemonics):
    """Enumerate register-field encodings of a mnemonic via keystone."""
    words = []
    regs = ["x0", "x1", "x15", "x30", "sp"]
    combos = {
        "RETAA": ["retaa"], "RETAB": ["retab"],
        "BRAA": [f"braa x{n}" for n in (0, 1, 30)], "BRAB": [f"brab x{n}" for n in (0, 1)],
        "BLRAA": [f"blraa x{n}" for n in (0, 1, 30)], "BLRAB": [f"blrab x{n}" for n in (0, 1)],
        "PACIA": ["pacia x30", "paciasp", "pacia x0, sp"],
        "PACIB": ["pacib x30", "pacibsp"], "AUTIA": ["autia x30", "autiasp"],
        "AUTIB": ["autib x30", "autibsp"], "PACGA": ["pacga x0, x30"],
        "BRK": ["brk #0", "brk #0x8e20"], "DRPS": ["drps"],
        "DCPS1": ["dcps1 0x0"], "DCPS2": ["dcps2 0x0"], "DCPS3": ["dcps3 0x0"],
    }
    for m in mnemonics:
        up = m.upper()
        if up in combos:
            words += [assemble(c) for c in combos[up]]
    show(sorted(set(words)))


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if "--fuzz" in sys.argv[1:]:
        fuzz([m for m in sys.argv[2:] if not m.startswith("-")] or
             ["RETAA", "RETAB", "BRAA", "BRAB", "BLRAA", "BLRAB",
              "PACIA", "PACIB", "AUTIA", "AUTIB", "BRK", "DRPS", "DCPS1"])
        return
    if not args:
        print(__doc__)
        return
    show([assemble(a) for a in args])


if __name__ == "__main__":
    main()
