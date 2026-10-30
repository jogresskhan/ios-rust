#!/usr/bin/env python3
"""M4-M: robust chunked scanner — resumes past undecodable bytes (literal pools).
Usage: m4m_robust_scan.py <pattern-name>
  percpu   → `ldr x?, [x?, #0x4f0]` sites
  bl:<TGT> → BL to target
"""
import sys
sys.path.insert(0, '/home/z/my-project/s3-work/ios-rust/tools/re/extraction')
from m4a_common import seg_by_name, va2off, _mm
import capstone

md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
seg = seg_by_name('__TEXT_EXEC')
mode = sys.argv[1]
tgt = int(sys.argv[2], 16) if ':' in mode else None

def scan(lo, hi, want):
    """disasm [lo,hi) resuming past invalid bytes; yield (addr, insn)."""
    off = va2off(lo)
    if off is None:
        return
    code = _mm[off:off + (hi - lo)]
    pos = 0
    base = lo
    while pos + 4 <= len(code):
        got = False
        for insn in md.disasm(code[pos:], base + pos):
            got = True
            yield insn
            pos = insn.address - base + insn.size
        if not got:
            pos += 4  # skip undecodable word

mode_name = mode.split(':')[0]
hits = []
CHUNK = 1 << 21
lo = seg.vmaddr
end = seg.vmaddr + seg.vmsize
while lo < end:
    hi = min(lo + CHUNK, end)
    for insn in scan(lo, hi, tgt):
        if mode_name == 'percpu':
            if insn.mnemonic == 'ldr' and insn.op_str.endswith('#0x4f0]'):
                hits.append((insn.address, 'ldr ' + insn.op_str))
        elif mode_name == 'bl':
            if insn.mnemonic == 'bl' and insn.op_str.lstrip('#') == f'{tgt:#x}':
                hits.append((insn.address, f'bl {tgt:#x}'))
        if len(hits) >= 120:
            break
    lo = hi
    if len(hits) >= 120:
        break
print(f'{len(hits)} hits for {mode}:')
for a, t in hits:
    print(f'  {a:#x}: {t}')
