#!/usr/bin/env python3
"""M4 text-zeroing investigation — Task 2-a (RESEARCH ONLY).
Adjudicate WHY text PA 0x80216c458 (VA 0xfffffff00816c458) reads zero at the
10,921,780-insn stop. All instruction text is capstone-derived; no hand bit-splitting.

Usage: python3 tools/re/reports/m4_text_zero_re.py <section>
Sections: strings, panic, vectors, fn07b8, fn0c38c, spscan, poison, all
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'extraction'))
import m4a_common as M
import capstone
import struct

def dis_window(va_start, va_end, label=''):
    print(f'== {label} {va_start:#x}..{va_end:#x} ==')
    for a, sz, t, _ in M.dis(va_start, 100000, stop_at_ret=False, va_end=va_end):
        print(f'{a:#x}: {t}')
    print()

def find_func_start(va):
    """Back-scan for pacibsp / stp prologue: return the nearest plausible fn start."""
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    best = None
    for back in range(0, 0x800, 4):
        cand = va - back
        b = M.read(cand, 4)
        if b is None:
            continue
        w = struct.unpack('<I', b)[0]
        ins = next(md.disasm(b, cand), None)
        if ins is None:
            continue
        if ins.mnemonic in ('pacibsp', 'paciasp') or \
           (ins.mnemonic == 'stp' and '[sp, #' in ins.op_str and '#-' in ins.op_str):
            best = cand
            if back > 0x400:
                break
    return best

def scan_sp_writers(va_start, va_end, label):
    """Capstone scan for instructions that WRITE sp: mov sp, add sp, sub sp,
    ldr sp-like (ldr with Rt=31 in post/pre-index), msr spsel."""
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    seg = None
    for s in M.SEGS:
        if s.contains(va_start):
            seg = s
    if seg is None:
        print('no seg'); return
    o = seg.off(va_start)
    code = M._mm[o: seg.off(va_end)]
    hits = []
    for insn in md.disasm(code, va_start):
        ops = insn.operands
        w_sp = False
        for i, op in enumerate(ops):
            if op.type == capstone.arm64.ARM64_OP_REG and op.access & capstone.CS_AC_WRITE:
                if insn.reg_name(op.reg) == 'sp':
                    w_sp = True
        if w_sp or insn.mnemonic in ('msr',) and 'spsel' in insn.op_str:
            hits.append((insn.address, insn.mnemonic + ' ' + insn.op_str))
    print(f'== SP writers {label} {va_start:#x}..{va_end:#x} ==')
    for a, t in hits:
        print(f'{a:#x}: {t}')
    print()

def strings():
    for va in (0xfffffff0073adec0, 0xfffffff007744a89, 0xfffffff0073ade9b):
        print(f'str @ {va:#x}: {M.cstr_va(va)!r}')
    # locate the "m/apple." bytes as a substring anywhere in the image
    needle = b'm/apple.'
    start = 0
    while True:
        o = M._mm.find(needle, start)
        if o < 0: break
        va = M.off2va(o)
        if va is not None:
            lo = max(0, o - 40)
            print(f'"m/apple." @ file {o:#x} va {va:#x}: ...{M._mm[lo:o+24].decode("utf-8","replace")!r}')
        start = o + 1
    print()

def file_bytes_at_stop():
    va = 0xfffffff00816c458
    b = M.read(va, 64)
    print(f'== file bytes @ {va:#x} (stop site) ==')
    for k in range(0, 64, 16):
        print(f'  {va+k:#x}: ' + ' '.join(f'{x:02x}' for x in b[k:k+16]))
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    for ins in md.disasm(b, va):
        print(f'  file-decode {ins.address:#x}: {ins.mnemonic} {ins.op_str}')
    print()

if __name__ == '__main__':
    sec = sys.argv[1] if len(sys.argv) > 1 else 'all'
    if sec in ('strings', 'all'):
        strings()
    if sec in ('stop', 'all'):
        file_bytes_at_stop()
    if sec in ('sp', 'all'):
        scan_sp_writers(0xfffffff00815f000, 0xfffffff008167000, 'vector-area')
        scan_sp_writers(0xfffffff008167000, 0xfffffff00816d000, 'handler-area')
