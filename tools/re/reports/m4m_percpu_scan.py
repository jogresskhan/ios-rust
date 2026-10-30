#!/usr/bin/env python3
"""M4-M: scan __TEXT_EXEC for `ldr xN, [xM, #0x4f0]` (xnu percpu base load)
and report the enclosing context + nearby str sites."""
import sys
sys.path.insert(0, '/home/z/my-project/s3-work/ios-rust/tools/re/extraction')
from m4a_common import seg_by_name, va2off, _mm
import capstone

md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
md.detail = False
seg = seg_by_name('__TEXT_EXEC')
CHUNK = 1 << 20
lo = seg.vmaddr
total = 0
sites = []
while lo < seg.vmaddr + seg.vmsize:
    hi = min(lo + CHUNK + 0x100, seg.vmaddr + seg.vmsize)
    off = va2off(lo)
    if off is None:
        lo += CHUNK
        continue
    code = _mm[off:off + (hi - lo)]
    for insn in md.disasm(code, lo):
        if insn.mnemonic == 'ldr' and '#0x4f0]' in insn.op_str and 'tpidr' not in insn.op_str:
            sites.append((insn.address, insn.op_str))
            total += 1
            if total >= 200:
                break
    lo += CHUNK
    if total >= 200:
        break
print(f'{len(sites)} `ldr x?, [x?, #0x4f0]` sites (percpu-base loads):')
for a, ops in sites:
    print(f'  {a:#x}: ldr {ops}')
