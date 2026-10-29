#!/usr/bin/env python3
"""M4 text-zeroing RE (task 2-a): why does PA 0x80216c458 (VA 0xfffffff00816c458)
read ZERO at the 10.9M-insn stop, and where does the warped SP 0xfffffff00816c220
come from? Capstone-only, /tmp/kc18c66.macho via m4a_common. Output archived at
/tmp/m4_text_zeroing.out. Companion to tools/re/notes/m4-text-zeroing-re.md."""
import sys
sys.path.insert(0, '/home/z/work/ios-rust/tools/re/extraction')
import m4a_common as M
import capstone

def section(t):
    print(f'\n==== {t} ====')

def dump(va, n, label):
    section(label)
    M.show(va, n, stop_at_ret=False)

def words(va, n, label):
    section(label)
    for i in range(n):
        a = va + 4 * i
        w = M.u32va(a)
        print(f'  {a:#x}: {w:08x}' if w is not None else f'  {a:#x}: <no file backing>')

# 1. file truth at the stop pc and the whole damaged window
words(0xfffffff00816c200, 0x70, 'FILE WORDS 0x816c200..0x816c3c0 (stop pc 0x816c458 below)')
words(0xfffffff00816c3c0, 0x30, 'FILE WORDS 0x816c3c0..0x816c480 (stop pc 0x816c458)')
print(f"\n  insn @0x816c458 (stop pc): ", end='')
M.show(0xfffffff00816c458, 3, stop_at_ret=False)
print(f"  insn @0x816c38c (storm fault pc): ", end='')
M.show(0xfffffff00816c38c, 4, stop_at_ret=False)

# 2. panic arg string + x3
section('panic arg strings (x0=0xfffffff0073adec0, x3=0xfffffff007744a89)')
print('  0x73adec0:', repr(M.cstr_va(0xfffffff0073adec0)))
print('  0x744a89: (near __DATA, offset into a struct?)')
print('  string search "Device tree pointer outside":', M.find_str('Device tree pointer outside')[:3])

# 3. VBAR early vector entries
dump(0xfffffff008165200, 16, 'VBAR early +0x200 (sync, current EL SPx) entry 0x8165200')
dump(0xfffffff008165000, 12, 'VBAR early +0x000 entry 0x8165000')
dump(0xfffffff008165300, 12, 'VBAR early +0x300 (FIQ) entry')

# 4. the fatal save fn from its top (pacibsp back-scan)
section('pacibsp back-scan for 0x816c38c / 0x816c458')
def fn_top(va, maxback=0x400):
    best = None
    start = (va - maxback) & ~3
    for a, sz, t, _ in M.dis(start, maxback // 4, stop_at_ret=False):
        if a >= va:
            break
        if t.startswith('pacibsp'):
            best = a
    return best
top = fn_top(0xfffffff00816c38c)
print(f'  fn top candidate: {top:#x}' if top else '  none found in 0x400 back-scan')

# 5. full disasm of the fatal fn window and the storm-handler window
dump(0xfffffff00816c1e0, 0x120, 'DISASM 0x816c1e0..0x816c660 area (fatal save fn + stop pc)')
dump(0xfffffff00801606a0 if False else 0xfffffff0081606a0, 0x90,
     'DISASM 0x81606a0..0x81608e0 (covers SP-warp site 0x81607c8)')

# 6. prologue save sites
dump(0xfffffff008160400, 0x18, 'DISASM prologue save sites 0x8160400..0x8160460')

# 7. every SP-writing insn in the two windows
section('SP-writing insns, 0x8160000..0x8161000 and 0x816c000..0x816c800')
for lo, hi in ((0xfffffff008160000, 0xfffffff008161000),
               (0xfffffff00816c000, 0xfffffff00816c800)):
    seg = M.seg_by_name('__TEXT_EXEC')
    o = seg.off(lo)
    code = M._mm[o:o + (hi - lo)]
    for insn in M._md.disasm(code, lo):
        if 'sp' in insn.op_str.split(',')[0] or insn.mnemonic in ('mov', 'add', 'sub') and (
                insn.op_str.startswith('sp,')):
            ops0 = insn.op_str.split(',')[0].strip()
            if ops0 == 'sp':
                print(f'  {insn.address:#x}: {insn.mnemonic} {insn.op_str}')

# 8. who computes 0x8137198 (SecureDTLookupEntry) / 0x816c220 / touches page 0x98a4000
section('adrp+add/ldr origin scan: targets = SecureDTLookupEntry, 0x816c220, PPL stack table page')
targets = [0xfffffff008137198, 0xfffffff00816c220, 0xfffffff0098a4180,
           0xfffffff0098a4190, 0xfffffff0098a4000]
for segname in ('__TEXT_EXEC', '__TEXT'):
    hits, count = M.adrp_add_scan(segname, targets)
    print(f'  [{segname}] scanned {count} insns')
    for a, t, addr in hits[:40]:
        print(f'    {a:#x}: {t}   -> {addr:#x}')

# 9. PPL stack-table readers: any site loading sp from [x, #0x10] after adrp 0x98a4000?
section('PPL stack table (0x98a4180 stride 0x180 sp@+0x10): file backing?')
print(f'  u64 @0x98a4190 = {M.u64va(0xfffffff0098a4190)}  (None = no segment file backing)')
print(f'  u64 @0x98a4180 = {M.u64va(0xfffffff0098a4180)}')
for s in M.SEGS:
    if s.contains(0xfffffff0098a4180):
        print(f'  contained in seg: {s}')
print('  (gap between __PPLTEXT end 0x989c000 and __DATA start 0x98ac000 means the')
print('   table lives in unmapped-at-file-time space; runtime-allocated by PPL boot)')
