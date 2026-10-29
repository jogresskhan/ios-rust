#!/usr/bin/env python3
"""M5: per-driver MMIO offset measurement for the real 18C66 T8030 kernelcache
(/tmp/kc18c66.macho). Complements tools/re/notes/m5-peripheral-queue.md.

Method (capstone-only, no hand bit-splitting):
  1. locate driver C strings in the kernel's const-string data (exact + substring),
  2. linear-scan __TEXT_EXEC/__PPLTEXT/__TEXT with ADRP-state tracking to find
     code xrefs to those string VAs (adrp_add_scan from m4a_common),
  3. pacibsp back-scan to function top, disassemble the function,
  4. print every ldr/str [reg, #imm] MMIO-candidate op with context.

Usage: python3 m5_kext_mmio.py <driver-key>
  driver-key in {pmgr, sart, ans, smc, wdt, gpio, dart, aic}
"""
import sys, re
sys.path.insert(0, '/home/z/work/ios-rust/tools/re/extraction')
import m4a_common as M
import capstone

STRINGS = {
    'pmgr':  ['AppleT8030PMGR'],
    'sart':  ['AppleSARTMarconi', 'AppleSART'],
    'ans':   ['AppleANS2NVMeController'],
    'smc':   ['AppleSMC::', 'AppleSMCFamily'],
    'wdt':   ['IOWatchdogEmbedded', 'WatchdogEmbedded'],
    'gpio':  ['AppleGPIOICController', 'AppleGPIODevice'],
    'dart':  ['AppleT8020DART'],
    'aic':   ['AppleInterruptController'],
}

def str_vas(needle):
    """All VAs of needle (substring, not exact) mapped into the image."""
    res = []
    mm = M._mm
    start = 0
    while True:
        i = mm.find(needle.encode(), start)
        if i < 0:
            break
        va = M.off2va(i)
        if va is not None:
            res.append((va, i))
        start = i + 1
    return res

def xref_code(target_vas, segs=('__TEXT_EXEC', '__PPLTEXT')):
    tset = set(target_vas)
    hits = []
    for segname in segs:
        h, _ = M.adrp_add_scan(segname, tset)
        hits += [(segname,) + x for x in h]
    return hits

def fn_top(va, maxback=0x1000):
    best = None
    start = (va - maxback) & ~3
    for a, sz, t, insn in M.dis(start, maxback // 4, stop_at_ret=False):
        if a >= va:
            break
        if insn.mnemonic == 'pacibsp' or (insn.mnemonic == 'stp' and insn.op_str.startswith('x29, x30, [sp, #-')):
            best = a
    return best

def fn_end(va, maxlen=0x2000):
    """First ret/retab after va."""
    for a, sz, t, insn in M.dis(va, maxlen // 4, stop_at_ret=False):
        if insn.mnemonic in ('ret', 'retab'):
            return a + sz
    return va + maxlen

def mmio_ops(fstart, fend):
    """Collect ldr/str [reg, #imm] + their immediates inside [fstart, fend)."""
    ops = []
    for a, sz, t, insn in M.dis(fstart, (fend - fstart) // 4 + 8, stop_at_ret=False):
        if a >= fend:
            break
        if insn.mnemonic in ('ldr', 'str', 'ldrb', 'strb', 'ldrsw'):
            for op in insn.operands:
                if op.type == capstone.arm64.ARM64_OP_MEM and op.mem.base != 0 and op.mem.index == 0:
                    if op.mem.disp:
                        ops.append((a, f'{insn.mnemonic} {insn.op_str}'))
                    break
    return ops

def main(key):
    strs = STRINGS[key]
    all_xrefs = []
    for s in strs:
        for va, fo in str_vas(s):
            x = xref_code([va])
            for segname, code_va, text, addr in x:
                all_xrefs.append((s, va, code_va, text))
    seen = set()
    fns = []
    for s, sva, cva, text in sorted(all_xrefs, key=lambda t: t[2]):
        top = fn_top(cva)
        if top is None:
            top = cva
        if top not in seen:
            seen.add(top)
            fns.append((top, s, cva, text))
    print(f'== {key}: {len(fns)} distinct referencing functions ==')
    for top, s, cva, text in fns[:40]:
        end = fn_end(top)
        ops = mmio_ops(top, min(end, top + 0x600))
        imms = sorted(set(int(m) for (_, txt) in ops
                          for m in re.findall(r'#(0x[0-9a-f]+|\d+)', txt)
                          for m in [m if m.startswith('0x') else hex(int(m))]))
        print(f'\nfn {top:#x} (end {min(end, top+0x600):#x}) via str "{s}" @xref {cva:#x}: {text}')
        print(f'  imm set: {[i for i in imms if 0 < i < 0x100000][:28]}')
        for a, t in ops[:36]:
            print(f'  {a:#x}: {t}')

if __name__ == '__main__':
    main(sys.argv[1])
