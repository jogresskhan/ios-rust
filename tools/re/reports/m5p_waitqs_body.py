#!/usr/bin/env python3
"""M5-P part 2: main body of waitq_bootstrp — the kernel_memory_allocate call,
the kret test, and the packed-args setup for the panic block (x19=0xffffffff00004000)."""
import sys
sys.path.insert(0, '/home/z/my-project/s3-work/ios-rust/tools/re/extraction')
from m4a_common import dis

# scan backwards for the function prologue, then disasm to the panic block
for name, lo, hi in [
    ('waitq_bootstrp body', 0xfffffff007ab6a80, 0xfffffff007ab6dc4),
]:
    print('=' * 78)
    print(f'{name}: {lo:#x}..{hi:#x}')
    for a, sz, t, insn in dis(lo, hi - lo, stop_at_ret=False, va_end=hi):
        print(f'   {a:#x}: {t}')
