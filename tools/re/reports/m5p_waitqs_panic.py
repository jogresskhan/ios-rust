#!/usr/bin/env python3
"""M5-P part 1: decode the global_waitqs panic call — what does the kernel
actually pass at 0x…7ab6f30 (bl 0x…987b99c), and where does kret come from?
Also disasms the panic wrapper 0x…987b99c and the brk site 0x…7a584fc."""
import sys
sys.path.insert(0, '/home/z/my-project/s3-work/ios-rust/tools/re/extraction')
from m4a_common import dis, u32va

RANGES = [
    ('waitq_bootstrp tail (panic call site)', 0xfffffff007ab6dc0, 0xfffffff007ab6f60),
    ('panic wrapper 0x…987b99c', 0xfffffff00987b980, 0xfffffff00987ba40),
    ('brk site (post-panic loop)', 0xfffffff007a584d0, 0xfffffff007a58530),
]
for name, lo, hi in RANGES:
    print('=' * 78)
    print(f'{name}: {lo:#x}..{hi:#x}')
    for a, sz, t, insn in dis(lo, hi - lo, stop_at_ret=False, va_end=hi):
        print(f'   {a:#x}: {t}')

print('=' * 78)
print('words at fmt 0x…735e028 region check (should be the panic string)')
