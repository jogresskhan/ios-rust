#!/usr/bin/env python3
import sys
sys.path.insert(0, '/home/z/my-project/download/ios-rust/tools/re/extraction')
import m4a_common as M

def dr(va, nbytes):
    for a, sz, t, _ in M.dis(va, nbytes // 4 + 8, stop_at_ret=False):
        print(f'{a:#x}: {t}')
        if a >= va + nbytes:
            break

for site in (0xfffffff0081687a0, 0xfffffff008168a1c, 0xfffffff008168df8):
    print(f'== context {site:#x} (raw words) ==')
    start = site - 0x30
    for k in range(0x30, 0x60, 4):
        va = start + k
        w = M.u32va(va)
        print(f'  {va:#x}: {w:08x}')
    print(f'== disasm from {site - 0x10:#x} ==')
    dr(site - 0x10, 0x40)
    print()
