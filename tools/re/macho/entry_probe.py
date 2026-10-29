#!/usr/bin/env python3
"""entry_probe — disassemble the XNU entry path of the real 18C66 kernelcache.

Answers, from the real binary (not from memory):
  * which boot_args offsets start.s loads (the struct layout the kernel expects)
  * which system registers the first window touches
  * the branch flow (start → start_first_cpu → …)
"""
import struct
import sys

from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs

KC = sys.argv[1] if len(sys.argv) > 1 else "/tmp/kernel-decompressed.bin"
ENTRY = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0xFFFFFFF0081644E8
N = int(sys.argv[3]) if len(sys.argv) > 3 else 200

img = open(KC, "rb").read()

# map a VA to file offset using the top-level __TEXT segment mapping:
# segment vmaddr 0xfffffff007004000 fileoff 0 → base = vmaddr - fileoff
BASE = 0xFFFFFFF007004000


def va2off(va: int) -> int:
    return va - BASE


md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = False

off = va2off(ENTRY)
code = img[off : off + N * 4]
msr_mrs = []
ldr_imm = []
branches = []
for i in md.disasm(code, ENTRY):
    tag = f"{i.address:#x}  {i.mnemonic:12s}{i.op_str}"
    print(tag)
    if i.mnemonic in ("msr", "mrs"):
        msr_mrs.append((i.address, i.mnemonic, i.op_str))
    if i.mnemonic.startswith("ldr") or i.mnemonic.startswith("ldp"):
        # immediate loads from a register base — boot args candidates
        ldr_imm.append((i.address, i.op_str))
    if i.mnemonic[0] in "bc" or i.mnemonic.startswith("tb") or i.mnemonic.startswith("ret"):
        branches.append((i.address, i.mnemonic, i.op_str))

print("\n=== system register accesses in window ===")
for a, m, o in msr_mrs:
    print(f"  {a:#x}  {m} {o}")
print("\n=== branch flow ===")
for a, m, o in branches:
    print(f"  {a:#x}  {m} {o}")
