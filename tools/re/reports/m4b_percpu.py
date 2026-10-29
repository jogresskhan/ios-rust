#!/usr/bin/env python3
"""M4-b: the TPIDR_EL1/percpu blocker — static evidence from the real 18C66
kernel. Companion to tools/re/notes/m4-percpu-blocker.md.

Dumps (capstone-only, no hand bit-splitting):
  * the exception-vector prologue windows that appear in the boot storm
    (0x81601e0 / 0x816041c / 0x81607b8 / 0x816c35c..0x816c470),
  * both VBAR tables (early 0x8165000, post-reloc 0x815f000),
  * the tpidr/msr sites (0x8160c24 restore-from-C9_1, 0x816858c msr xzr),
  * the FIRST abort site 0x7a58678 with a pacibsp back-scan to function top,
  * arm_init's store at 0x7b80844 and the kext-parse window 0x7a81190,
  * a census of `ldr/str xN, [xM, #0x4f8]` (ACT_CPUDATAP) across __TEXT_EXEC,
  * a census of msr/mrs TPIDR_EL1 across __TEXT_EXEC + __PPLTEXT.
"""
import sys
sys.path.insert(0, '/home/z/my-project/download/ios-rust/tools/re/extraction')
import m4a_common as M
import capstone

md = M._md

def dis_range(va, nbytes, prefix=''):
    out = []
    for a, sz, t, _ in M.dis(va, nbytes // 4 + 8, stop_at_ret=False):
        out.append(f'{prefix}{a:#x}: {t}')
        if a >= va + nbytes:
            break
    return out

def fn_top(va, maxback=0x800):
    """pacibsp back-scan: find the function top by walking back to the
    pacibsp/stp x29 prologue."""
    best = None
    start = va - maxback & ~3
    for a, sz, t, _ in M.dis(start, maxback // 4, stop_at_ret=False):
        if a >= va:
            break
        if t.startswith('pacibsp') or t.startswith('stp\tx29') or t == 'stp x29, x30, [sp, #-0x10]!':
            best = a
    return best

def section_header():
    print('=== KEY WINDOW DUMPS ===')

print('== VBAR early (0x8165000) sync entry (+0x200) ==')
for l in M.dis(0xfffffff008165200, 24, stop_at_ret=False):
    print(f'{l[0]:#x}: {l[2]}')
print()
print('== VBAR post-reloc (0x815f000) sync entry (+0x200) ==')
for l in M.dis(0xfffffff00815f200, 24, stop_at_ret=False):
    print(f'{l[0]:#x}: {l[2]}')
print()
print('== FIQ entry post-reloc (+0x300) ==')
for l in M.dis(0xfffffff00815f300, 12, stop_at_ret=False):
    print(f'{l[0]:#x}: {l[2]}')
print()
print('== storm prologue window 0x81601c0..0x8160210 ==')
for l in dis_range(0xfffffff0081601c0, 0x50 // 4):
    print(l)
print()
print('== storm window 0x81603e0..0x8160460 (the tpidr prologue + saves) ==')
for l in dis_range(0xfffffff0081603e0, 0x80 // 4):
    print(l)
print()
print('== storm window 0x8160790..0x81607e0 (tpidr save + bl) ==')
for l in dis_range(0xfffffff008160790, 0x50 // 4):
    print(l)
print()
print('== 0x816c350..0x816c4a0 (the fatal save fn incl. "zeros" site 0x816c458) ==')
for l in dis_range(0xfffffff00816c350, 0x150 // 4):
    print(l)
print()
print('== msr tpidr site 0x8160c24 window ==')
for l in dis_range(0xfffffff008160c00, 0x100 // 4):
    print(l)
print()
print('== msr tpidr_el1, xzr site 0x816858c window (function top back-scan) ==')
top = fn_top(0xfffffff00816858c)
print('fn top:', hex(top) if top else None)
for l in dis_range(0xfffffff008168560, 0x60 // 4):
    print(l)
print()
print('== FIRST abort ELR 0x7a58678 (function context) ==')
top = fn_top(0xfffffff007a58678)
print('fn top:', hex(top) if top else None)
if top:
    for l in dis_range(top, 0x140 // 4):
        print(l)
print()
print('== arm_init store site 0x7b80844 window ==')
for l in dis_range(0xfffffff007b80800, 0x60 // 4):
    print(l)
print()
print('== kext-parse window 0x7a81170..0x7a811c0 ==')
for l in dis_range(0xfffffff007a81170, 0x50 // 4):
    print(l)
print()

print('=== CENSUS: ldr/str xN, [xM, #0x4f8] (ACT_CPUDATAP) in __TEXT_EXEC ===')
seg = M.seg_by_name('__TEXT_EXEC')
code = M._mm[seg.off(seg.vmaddr):seg.off(seg.vmaddr) + seg.filesize]
hits = []
for insn in md.disasm(code, seg.vmaddr):
    if insn.mnemonic in ('ldr', 'str') and '#0x4f8' in insn.op_str.replace(']', ', #0x4f8]'):
        hits.append((insn.address, insn.mnemonic + ' ' + insn.op_str))
for a, t in hits[:60]:
    print(f'{a:#x}: {t}')
print('total:', len(hits))
print()
print('=== CENSUS: msr/mrs tpidr_el1 (enc 0xd518d084 / 0xd538d084) in __TEXT_EXEC+__PPLTEXT ===')
for sname in ('__TEXT_EXEC', '__PPLTEXT', '__TEXT'):
    seg = M.seg_by_name(sname)
    code = M._mm[seg.off(seg.vmaddr):seg.off(seg.vmaddr) + seg.filesize]
    for insn in md.disasm(code, seg.vmaddr):
        w = M.u32va(insn.address)
        if w in (0xd518d084, 0xd538d084, 0xd518d088, 0xd538d088):
            print(f'{sname} {insn.address:#x}: {insn.mnemonic} {insn.op_str} (word {w:#x})')
print()
print('=== CENSUS: MSR/MRS s3_6_c15_c9_1 (GXF ctx: 0xd538c9xx?) — op0=6 op1=6? ===')
# GXF_CTX = enc(1,6,15,9,1) canonical 15-bit; the raw msr word for MRS x, s3_6_c15_c9_1
# = 0xd53c0000 | (6<<16... op1=6) hmm: MRS = 0xd5380000 | op1<<16 | CRn<<12 | CRm<<8 | op2<<5 | Rt
def mrs_word(op1, crn, crm, op2, rt=0):
    return 0xd5380000 | (op1 << 16) | (crn << 12) | (crm << 8) | (op2 << 5) | rt
def msr_word(op1, crn, crm, op2, rt=0):
    return 0xd5180000 | (op1 << 16) | (crn << 12) | (crm << 8) | (op2 << 5) | rt
gxf_read = mrs_word(6, 15, 9, 1) & ~0x1F
gxf_write = msr_word(6, 15, 9, 1) & ~0x1F
print(f'gxf ctx mrs mask {gxf_read:#x} msr mask {gxf_write:#x}')
for sname in ('__TEXT_EXEC', '__PPLTEXT'):
    seg = M.seg_by_name(sname)
    code = M._mm[seg.off(seg.vmaddr):seg.off(seg.vmaddr) + seg.filesize]
    for insn in md.disasm(code, seg.vmaddr):
        w = M.u32va(insn.address)
        if (w & ~0x1F) in (gxf_read, gxf_write):
            print(f'{sname} {insn.address:#x}: {insn.mnemonic} {insn.op_str} (word {w:#x})')
