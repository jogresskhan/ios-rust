#!/usr/bin/env python3
"""M4 bug #28 RE (task 3-a): the diverging Euclid GCD loop @0x7b92d68-78
called from arm_vm_init (lr 0x7b80a30). Capstone-only (oracle rule).
Windows: call site +/-0x200, the gcd helper function (pacibsp scan-back),
argument provenance readers, global values. Output: /tmp/m4_gcd_clock.out.
Companion to tools/re/notes/m4-gcd-clock-re.md."""
import sys
sys.path.insert(0, '/home/z/work/ios-rust/tools/re/extraction')
import m4a_common as M
import capstone, struct

LINK_BASE = 0xFFFFFFF007004000
def kva(trunc):
    """0x…7b92d68-style truncated log addresses are FULL KVAs:
    0xfffffff0_07b92d68 (the ellipsis hides ffffff00)."""
    return 0xFFFFFFF000000000 + trunc

def section(t):
    print(f'\n==== {t} ====')

def dump(va, n, label, va_end=None, stop_at_ret=False):
    section(label)
    M.show(va, n, stop_at_ret=stop_at_ret, va_end=va_end)

GCD_LOOP = kva(0x7b92d68)
CALLSITE = kva(0x7b80a30)          # lr value => bl at 0x7b80a2c

# ---- 0. sanity: the loop itself ----
section('[0] the diverging loop @0x7b92d68 (trace ring stop point)')
M.show(GCD_LOOP - 0x40, 24, stop_at_ret=False)

# ---- 1. helper function start: scan back for pacibsp (0xd503237f) ----
section('[1] pacibsp scan-back from the loop head')
scan_va = GCD_LOOP & ~0x3
starts = []
for d in range(4, 0x4000, 4):
    va = GCD_LOOP - d
    if M.u32va(va) == 0xd503237f:
        starts.append(va)
print(f'  pacibsp candidates below {GCD_LOOP:#x}: '
      + ', '.join(f'{v:#x} (-{GCD_LOOP-v:#x})' for v in starts[:12]))
helper = starts[0] if starts else None
print(f'  helper start = {helper:#x}' if helper else '  NO pacibsp found in 16K')

# ---- 2. full helper function (both paths: fast path + the b.hi escape) ----
if helper:
    section('[2] helper function from pacibsp (fast path + escape path)')
    M.show(helper, 160, stop_at_ret=False, va_end=helper + 0x2a0)
    section('[2b] helper escape path 0x7b92dc4.. (b.hi target)')
    M.show(GCD_LOOP + 0x5c, 90, stop_at_ret=False, va_end=GCD_LOOP + 0x300)

# ---- 3. call site window: bl at lr-4 = 0x7b80a2c ----
section('[3] call site window 0x7b80a2c-0x200 .. +0x200 (lr=0x7b80a30)')
M.show(CALLSITE - 0x200, 170, stop_at_ret=False, va_end=CALLSITE + 0x210)

