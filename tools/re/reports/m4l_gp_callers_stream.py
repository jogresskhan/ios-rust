#!/usr/bin/env python3
"""M4-L #32 RE part 5b: STREAMING census of BL callers of granular_prot
(0xfffffff007b825d0) — generator-based, restart-on-invalid, memory-light."""
import sys
import capstone
sys.path.insert(0, '/home/z/my-project/s3-work/ios-rust/tools/re/extraction')
from m4a_common import _mm, seg_by_name, va2off

TARGET = 0xfffffff007b825d0
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)

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
                except ValueError:
                    tgt = None
                if tgt == TARGET:
                    print(f"{segname} {insn.address:#x}: bl granular_prot", flush=True)
            va = insn.address + insn.size
            n = insn.address - seg.vmaddr + insn.size
            break
        if not got:
            n += 4
            va += 4
print("census done", flush=True)
