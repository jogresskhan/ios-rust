#!/usr/bin/env python3
"""M4-M: memory-lean BL xref scanner for __TEXT_EXEC (chunked capstone)."""
import sys
sys.path.insert(0, '/home/z/my-project/s3-work/ios-rust/tools/re/extraction')
from m4a_common import seg_by_name, va2off, _mm
import capstone

TARGET = int(sys.argv[1], 16)
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
seg = seg_by_name('__TEXT_EXEC')
CHUNK = 1 << 20
hits = []
lo = seg.vmaddr
while lo < seg.vmaddr + seg.vmsize:
    hi = min(lo + CHUNK + 0x100, seg.vmaddr + seg.vmsize)
    off = va2off(lo)
    if off is None:
        lo += CHUNK
        continue
    code = _mm[off:off + (hi - lo)]
    for insn in md.disasm(code, lo):
        if len(hits) >= 64:
            break
        if insn.mnemonic == 'bl' and insn.op_str.lstrip('#') == f'{TARGET:#x}':
            hits.append(insn.address)
    lo += CHUNK
    if len(hits) >= 64:
        break
print(f'{len(hits)} BL callers of {TARGET:#x}:')
for h in hits:
    print(f'  {h:#x}')
