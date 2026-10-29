#!/usr/bin/env python3
"""M4-a full linear scan (low-mem, disasm_lite) of an exec segment tracking
ADRP(+ADD) state; report ldr/str whose resolved VA is in a target set."""
import sys, struct, re
import m4a_common as K
import capstone

RE_IMM = re.compile(r'#(0x[0-9a-f]+|\d+)')
RE_MEM = re.compile(r'\[(x\d+|sp|xzr)(?:, #(0x[0-9a-f]+|\d+))?\]')

def parse_num(s):
    if not s: return 0
    return int(s.lstrip('#'), 0)

def scan(segname, targets, chunk=0x40000):
    seg = K.seg_by_name(segname)
    o = seg.off(seg.vmaddr)
    code = K._mm[o:o + seg.filesize]
    md = K._md
    md.detail = False
    tset = set(targets)
    state = {}
    hits = []
    pos = 0
    base = seg.vmaddr
    while pos < len(code):
        c = code[pos:pos + chunk]
        for addr, size, mnem, ops in md.disasm_lite(c, base + pos):
            pos_next = addr + size - base
            parts = ops.split(', ')
            if mnem == 'adrp':
                rd = parts[0]
                tgt = parse_num(parts[1].lstrip('#'))
                state[rd] = [tgt, False]
            elif mnem == 'add' and len(parts) == 3 and parts[2].startswith('#'):
                rd, rn = parts[0], parts[1]
                if rn in state and not state[rn][1]:
                    a = state[rn][0] + parse_num(parts[2])
                    state[rd] = [a, True]
                    if a in tset:
                        hits.append((addr, mnem + ' ' + ops, a))
                elif rd in state and rd != rn:
                    del state[rd]
            elif mnem.startswith(('ldr', 'ldur', 'str', 'stur', 'stlr', 'ldlar')):
                m = RE_MEM.search(ops)
                if m:
                    breg = m.group(1)
                    disp = parse_num(m.group(2))
                    if breg in state:
                        a = state[breg][0] + disp
                        if a in tset:
                            hits.append((addr, mnem + ' ' + ops, a))
            # invalidate dest reg if written by non-load, non-adrp, non-store
            if parts and not mnem.startswith(('ldr', 'ldur', 'str', 'adrp', 'stlr')):
                rd = parts[0]
                if rd in state and mnem != 'add' and rd[0] == 'x':
                    del state[rd]
        pos = (base + pos) - base + len(c)  # move by chunk; disasm_lite may stop early on bad data
    return hits

if __name__ == '__main__':
    targets = [0xfffffff007744988, 0xfffffff007744990, 0xfffffff007744998, 0xfffffff0077449a0,
               0xfffffff007744ad0, 0xfffffff007744ae0]
    hits = scan('__TEXT_EXEC', targets)
    print(f'{len(hits)} hits')
    for va, txt, addr in sorted(hits):
        kind = 'W' if txt.startswith(('str', 'stur', 'stlr')) else 'R'
        print(f'  {va:#x} [{kind}] {txt}   -> {addr:#x}')
