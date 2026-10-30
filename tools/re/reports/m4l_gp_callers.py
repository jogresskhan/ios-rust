#!/usr/bin/env python3
"""M4-L #32 RE part 5: census of BL callers of arm_vm_page_granular_prot
(0xfffffff007b825d0) across all executable segments."""
import sys
sys.path.insert(0, '/home/z/my-project/s3-work/ios-rust/tools/re/extraction')
from m4a_common import seg_by_name, dis

TARGET = 0xfffffff007b825d0
for segname in ('__TEXT', '__TEXT_EXEC', '__PPLTEXT'):
    seg = seg_by_name(segname)
    insns = dis(seg.vmaddr, 10_000_000, stop_at_ret=False, va_end=seg.vmaddr + seg.vmsize)
    for va, sz, text, insn in insns:
        if insn.mnemonic == 'bl' and insn.op_str.lstrip('#') == f'{TARGET:#x}':
            print(f"{segname} {va:#x}: bl granular_prot")
