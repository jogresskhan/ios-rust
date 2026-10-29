#!/usr/bin/env python3
"""M4-a: find all BL/B call sites targeting given VAs within a segment."""
import sys, struct
import m4a_common as K

def bl_scan(segname, targets):
    seg = K.seg_by_name(segname)
    o = seg.off(seg.vmaddr)
    code = K._mm[o:o + seg.filesize]
    base = seg.vmaddr
    tset = set(targets)
    hits = {t: [] for t in targets}
    n = len(code) // 4
    for i in range(n):
        w = struct.unpack_from('<I', code, i * 4)[0]
        if (w & 0xFC000000) == 0x94000000:  # BL
            imm = w & 0x03FFFFFF
            if imm & (1 << 25): imm -= (1 << 26)
            tgt = base + i * 4 + (imm << 2)
            if tgt in tset:
                hits[tgt].append(base + i * 4)
        elif (w & 0xFC000000) == 0x14000000:  # B
            imm = w & 0x03FFFFFF
            if imm & (1 << 25): imm -= (1 << 26)
            tgt = base + i * 4 + (imm << 2)
            if tgt in tset:
                hits[tgt].append(('B', base + i * 4))
    return hits

if __name__ == '__main__':
    targets = [int(x, 16) for x in sys.argv[1:]]
    hits = bl_scan('__TEXT_EXEC', targets)
    for t in targets:
        print(f'== callers of {t:#x}: {len(hits[t])} ==')
        for h in hits[t]:
            print(f'   {h:#x}')
