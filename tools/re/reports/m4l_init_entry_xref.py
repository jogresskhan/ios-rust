#!/usr/bin/env python3
"""M4-L #32 RE part 7: locate the __init_entry_set runner via string xref,
then census its callers."""
import sys, struct
sys.path.insert(0, '/home/z/my-project/s3-work/ios-rust/tools/re/extraction')
from m4a_common import _mm, seg_by_name, va2off, off2va, cstr_va, dis
import capstone

md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)

# 1. find the panic string "invalid size" near init_entry_set
needle = b'__init_entry_set'
pos = []
i = 0
while True:
    i = _mm.find(needle, i)
    if i < 0:
        break
    pos.append(i)
    i += 1
print(f"strings with '__init_entry_set': {len(pos)}")
for p in pos[:6]:
    # back up to string start
    s = p
    while s > 0 and 0x20 <= _mm[s-1] < 0x7f:
        s -= 1
    va = off2va(s)
    print(f"  @{s:#x} VA {va:#x}: {_mm[s:p+len(needle)+8].decode('ascii', errors='replace')[:90]!r}")

# 2. xref: adrp+add pairs producing those VAs
targets = set()
for p in pos[:6]:
    s = p
    while s > 0 and 0x20 <= _mm[s-1] < 0x7f:
        s -= 1
    va = off2va(s)
    if va:
        targets.add(va & ~0xFFF)

def bl_census(target_func):
    out = []
    for segname in ('__TEXT', '__TEXT_EXEC', '__PPLTEXT'):
        seg = seg_by_name(segname)
        o = seg.off(seg.vmaddr)
        code = _mm[o:o + seg.filesize]
        va = seg.vmaddr
        n = 0
        while n < len(code):
            got = False
            for insn in md.disasm(code[n:n + 16], va):
                got = True
                if insn.mnemonic == 'bl':
                    try:
                        tgt = int(insn.op_str.lstrip('#'), 16)
                        if tgt == target_func:
                            out.append(insn.address)
                    except ValueError:
                        pass
                va = insn.address + insn.size
                n = insn.address - seg.vmaddr + insn.size
                break
            if not got:
                n += 4
                va += 4
    return out

# 3. scan executable code for adrp to the string pages
print("\n=== adrp xrefs to string pages ===")
tex = seg_by_name('__TEXT_EXEC')
o = tex.off(tex.vmaddr)
code = _mm[o:o + tex.filesize]
va = tex.vmaddr
n = 0
last_adrp = {}
while n < len(code):
    got = False
    for insn in md.disasm(code[n:n + 16], va):
        got = True
        if insn.mnemonic == 'adrp':
            parts = insn.op_str.split(', ')
            if len(parts) == 2:
                try:
                    last_adrp[parts[0]] = (int(parts[1].lstrip('#'), 16), insn.address)
                except ValueError:
                    pass
        elif insn.mnemonic == 'add' and last_adrp:
            # add xN, xN, #imm
            parts = insn.op_str.split(', ')
            if len(parts) == 3 and parts[0] == parts[1] and parts[0] in last_adrp:
                try:
                    imm = int(parts[2].lstrip('#'), 16)
                    full = last_adrp[parts[0]][0] + imm
                    if any((full & ~0xFFF) == t for t in targets):
                        print(f"  {insn.address:#x}: adrp+add -> string VA {full:#x}")
                except ValueError:
                    pass
        va = insn.address + insn.size
        n = insn.address - tex.vmaddr + insn.size
        break
    if not got:
        n += 4
        va += 4
