#!/usr/bin/env python3
"""M4-L #32 RE part 3b: robust census of [0x7701d10] (L2-table array ptr)
and [0x7702460] (L2 bump cursor) writers across all executable segments."""
import sys
sys.path.insert(0, '/home/z/my-project/s3-work/ios-rust/tools/re/extraction')
from m4a_common import _mm, SEGS, seg_by_name, dis

TARGETS = {
    0xd10: "L2-table-array ptr  [0x7701d10]",
    0x460: "L2 bump cursor     [0x7702460]",
    0xcf8: "L2 free-list/head  [0x7701cf8]",
}

for segname in ('__TEXT', '__TEXT_EXEC', '__PPLTEXT'):
    seg = seg_by_name(segname)
    insns = dis(seg.vmaddr, 10_000_000, stop_at_ret=False, va_end=seg.vmaddr + seg.vmsize)
    # window-track last adrp per register
    last_adrp = {}
    for va, sz, text, insn in insns:
        if insn.mnemonic == 'adrp':
            parts = insn.op_str.split(', ')
            if len(parts) == 2:
                try:
                    tgt = int(parts[1].lstrip('#'), 16)
                    last_adrp[parts[0]] = (tgt, va)
                except ValueError:
                    pass
        elif insn.mnemonic in ('ldr', 'str', 'ldur', 'stur') and last_adrp:
            op = insn.op_str
            for reg, (tgt, ava) in list(last_adrp.items()):
                if tgt == 0xfffffff007701000 or tgt == 0xfffffff007702000:
                    for off, label in TARGETS.items():
                        if f'[{reg}, #0x{off:x}]' in op or (f'[{reg}]' == op.split(', ', 1)[-1].strip() and False):
                            if insn.mnemonic in ('str', 'stur') or True:
                                print(f"{segname} {va:#x}: {insn.mnemonic} {op}   <- {label} (adrp @{ava:#x})")
            # don't clear: adrp is persistent until reg overwritten (approximation)
