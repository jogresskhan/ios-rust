#!/usr/bin/env python3
"""M4-L #32 RE part 9: full call-chain census — who calls 0x7b82e34 (the
never-executed physmap function) and 0x7b80xxx (the live one)?"""
import sys
sys.path.insert(0, '/home/z/my-project/s3-work/ios-rust/tools/re/extraction')
from m4a_common import seg_by_name, _mm, va2off
import capstone, struct

md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)

def bl_census(target):
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
                        if int(insn.op_str.lstrip('#'), 16) == target:
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

def find_func_start(va, max_back=0x8000):
    off = va2off(va)
    o = off - 4
    while o > max(off - max_back, 0):
        w = struct.unpack_from('<I', _mm, o)[0]
        if w == 0xD503237F:
            return va - (off - o)
        o -= 4
    return None

live_fs = find_func_start(0xfffffff007b80a3c)
print(f"live function start (contains 0x7b80a3c): {live_fs:#x}")
print(f"BL callers of {live_fs:#x}: {[hex(c) for c in bl_census(live_fs)]}")
print()
print(f"BL callers of 0x7b82e34 (never-executed physmap fn): {[hex(c) for c in bl_census(0xfffffff007b82e34)]}")
