#!/usr/bin/env python3
"""M4-a: scan __TEXT_EXEC (and optionally other exec segs) for ADRP+reg-offset
accesses to specific (page, disp) pairs. Raw-byte ADRP prefilter, capstone confirm."""
import sys, struct
import m4a_common as K
import capstone

def scan_adrp_disp(segname, page, disps, show_readers=False):
    seg = K.seg_by_name(segname)
    o = seg.off(seg.vmaddr)
    code = K._mm[o:o + seg.filesize]
    base = seg.vmaddr
    n = len(code) // 4
    hits = []
    md = K._md
    page_lo = page & ~0xFFF
    for i in range(n):
        w = struct.unpack_from('<I', code, i * 4)[0]
        # ADRP: op=1, bits[28:24]=10000 -> (w & 0x9F000000) == 0x90000000
        if (w & 0x9F000000) != 0x90000000:
            continue
        rd = w & 0x1F
        immlo = (w >> 29) & 3
        immhi = (w >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & (1 << 20): imm -= (1 << 21)
        pc_page = (base + i * 4) & ~0xFFF
        tgt = pc_page + (imm << 12)
        if tgt != page_lo:
            continue
        # disassemble adrp + next few insns with capstone to find consumer
        for insn in md.disasm(code[i*4:(i+6)*4], base + i * 4):
            pass
        # simpler: decode next up to 12 insns
        chunk = code[i*4:(i+14)*4]
        va = base + i * 4
        reg = 'x%d' % rd if rd != 31 else 'sp'
        got_adrp = False
        for insn in md.disasm(chunk, va):
            if not got_adrp:
                if insn.mnemonic == 'adrp':
                    got_adrp = True
                    reg = insn.reg_name(insn.operands[0].reg)
                continue
            if insn.mnemonic in ('add', 'ldr', 'ldrb', 'ldrh', 'ldrsw', 'str', 'strb', 'strh',
                                 'ldur', 'stur', 'ldurb', 'ldrsb', 'ldrh', 'stlr', 'ldlar'):
                ops = insn.operands
                for op in ops:
                    if op.type == capstone.arm64.ARM64_OP_MEM and insn.reg_name(op.mem.base) == reg:
                        d = op.mem.disp
                        if d in disps:
                            hits.append((insn.address, f'{insn.mnemonic} {insn.op_str}', d))
                        break
            # stop tracking if the reg is overwritten
            if insn.operands and insn.operands[0].type == capstone.arm64.ARM64_OP_REG \
               and insn.reg_name(insn.operands[0].reg) == reg and insn.mnemonic not in ('ldr',):
                break
            if insn.mnemonic == 'adrp':
                break
    return hits

if __name__ == '__main__':
    page = int(sys.argv[1], 16)
    disps = set(int(x, 16) for x in sys.argv[2:])
    for segname in ('__TEXT_EXEC',):
        hits = scan_adrp_disp(segname, page, disps)
        print(f'== {segname}: {len(hits)} hits for page {page:#x} disps {[hex(d) for d in sorted(disps)]} ==')
        for va, txt, d in hits:
            print(f'  {va:#x}: {txt}   (-> {page + d:#x})')
