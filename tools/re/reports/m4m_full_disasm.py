#!/usr/bin/env python3
"""M4-M part 2: full disasm of arm_vm_init (0x…7b82e34..0x…7b84914) and the
three helpers: phystokv 0x…7b818a0, allocator 0x…7b72f88, func 0x…8169574."""
import sys
sys.path.insert(0, '/home/z/my-project/s3-work/ios-rust/tools/re/extraction')
from m4a_common import seg_by_name, dis

RANGES = [
    ('arm_vm_init', 0xfffffff007b82e34, 0xfffffff007b84914),
    ('phystokv?', 0xfffffff007b818a0, 0xfffffff007b81980),
    ('allocator', 0xfffffff007b72f88, 0xfffffff007b73060),
    ('func_8169574', 0xfffffff008169574, 0xfffffff008169640),
]
for name, lo, hi in RANGES:
    print('=' * 78)
    print(f'{name}: {lo:#x}..{hi:#x}')
    for a, sz, t, insn in dis(lo, hi - lo, stop_at_ret=False, va_end=hi):
        print(f'   {a:#x}: {t}')
