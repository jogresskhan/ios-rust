#!/usr/bin/env python3
"""M4-M: RE the physmap L2 allocation path that aborts at insn 8514106
(ELR 0xfffffff007b82fec, FAR 0xffffffe806000000 = phystokv(0)).

Targets:
  A. function containing 0x…7b82fec (the aborting phystokv/ptov_lookup call site)
  B. function at 0x…7b72f88 (session-L "L2 free-list allocation" ptr target)
  C. xrefs (adrp+add / adr) to globals: 0x7702128 (ptov_table?), 0x7701cf8,
     0x7701d10, 0x7702460, 0x7702450, 0x7702458
  D. BL xrefs to both target functions
Cross-check against osfmk/arm/arm_vm_init.c (xnu-7195.121.3, in-tree source).
"""
import sys
sys.path.insert(0, '/home/z/my-project/s3-work/ios-rust/tools/re/extraction')
from m4a_common import seg_by_name, dis, va2off, u64, read, SEGS
import capstone

md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
md.detail = True

GLOBAL_ADDRS = [0xfffffff007702128, 0xfffffff007701cf8, 0xfffffff007701d10,
                0xfffffff007702460, 0xfffffff007702450, 0xfffffff007702458]
TARGET_FUNCS = [0xfffffff007b72f88]

def func_start(va, maxback=0x4000):
    """Walk back to the preceding `stp x29/x28… ` prologue or pacibsp."""
    seg = seg_by_name('__TEXT_EXEC')
    if seg is None:
        seg = seg_by_name('__TEXT')
    start = max(seg.vmaddr, va - maxback)
    insns = list(dis(start, va - start + 0x100, stop_at_ret=False))
    best = None
    for a, sz, t, insn in insns:
        if a >= va:
            break
        if insn.mnemonic in ('pacibsp', 'pacisp') or \
           (insn.mnemonic == 'stp' and 'x29' in insn.op_str and 'x28' in insn.op_str and
            insn.op_str.startswith('x29')):
            best = a
    return best or start

def disasm_range(lo, hi):
    seg = None
    for s in SEGS:
        if s.contains(lo):
            seg = s
            break
    out = []
    for a, sz, t, insn in dis(lo, hi - lo, stop_at_ret=False, va_end=hi):
        out.append((a, t))
    return out

def annotate(vals, globals_hit, calls):
    extra = []
    if vals:
        extra.append(f'; ← GLOBAL {vals}')
    if calls:
        extra.append(f'; CALL {calls}')
    return ' '.join(extra)

# ---------- A. abort site function ----------
print('=' * 78)
print('A. function containing abort site 0x…7b82fec')
fs = func_start(0xfffffff007b82fec)
print(f'   function start = {fs:#x}')
for a, t in disasm_range(fs, 0xfffffff007b83110):
    mark = ' <== ABORT ELR' if a == 0xfffffff007b82fec else ''
    print(f'   {a:#x}: {t}{mark}')

# ---------- B. allocator function ----------
print('=' * 78)
print('B. function at 0x…7b72f88 (session-L L2 free-list allocation target)')
fs2 = func_start(0xfffffff007b72f88)
print(f'   function start = {fs2:#x}')
for a, t in disasm_range(fs2, 0xfffffff007b73200):
    mark = ' <== TARGET' if a == 0xfffffff007b72f88 else ''
    print(f'   {a:#x}: {t}{mark}')

# ---------- C+D. global xrefs + BL xrefs across exec segments ----------
print('=' * 78)
print('C/D. xref census')
for segname in ('__TEXT', '__TEXT_EXEC', '__PPLTEXT'):
    seg = seg_by_name(segname)
    if seg is None:
        continue
    print(f'-- {segname} va={seg.vmaddr:#x} size={seg.vmsize:#x}')
    adrp_seen = {}
    insns = dis(seg.vmaddr, min(seg.vmsize, 12_000_000), stop_at_ret=False,
                va_end=seg.vmaddr + seg.vmsize)
    prev_adrp = {}
    for va, sz, t, insn in insns:
        # track adrp pairs
        if insn.mnemonic == 'adrp':
            try:
                reg = insn.operands[0].reg
                imm = insn.operands[1].imm
                prev_adrp[reg] = (va, imm)
            except Exception:
                pass
            continue
        # add Xn, Xn, #imm → candidate global address
        if insn.mnemonic == 'add' and len(insn.operands) == 3 and \
           insn.operands[0].type == capstone.arm64.ARM64_OP_REG and \
           insn.operands[1].type == capstone.arm64.ARM64_OP_REG and \
           insn.operands[2].type == capstone.arm64.ARM64_OP_IMM:
            src = insn.operands[1].reg
            if src in prev_adrp:
                _, base = prev_adrp[src]
                addr = base + insn.operands[2].imm
                if addr in GLOBAL_ADDRS:
                    print(f'   {segname} {va:#x}: add → global {addr:#x} (adrp@{prev_adrp[src][0]:#x})')
        # bl targets
        if insn.mnemonic in ('bl', 'b') and insn.operands and \
           insn.operands[0].type == capstone.arm64.ARM64_OP_IMM:
            tgt = insn.operands[0].imm
            if tgt in TARGET_FUNCS:
                print(f'   {segname} {va:#x}: {insn.mnemonic} → allocator {tgt:#x}')
        # keep adrp regs alive only for ~64 insns
        if len(prev_adrp) > 8 and (va & 0x3f) == 0:
            pass
