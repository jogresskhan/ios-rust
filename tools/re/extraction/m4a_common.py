#!/usr/bin/env python3
"""M4-a common helpers: VA<->fileoff mapping + capstone disassembly for kc18c66.
Pattern copied from m2_fixup_census.py segment walk. Capstone is the ONLY
instruction authority."""
import struct, bisect

MACHO = '/tmp/kc18c66.macho'
_mm = open(MACHO, 'rb').read()
SZ = len(_mm)

LC_SEGMENT_64 = 0x19
def u32(o): return struct.unpack_from('<I', _mm, o)[0]
def u64(o): return struct.unpack_from('<Q', _mm, o)[0]
def u16(o): return struct.unpack_from('<H', _mm, o)[0]

# ---- parse segments (top-level kernel Mach-O) ----
class Seg:
    def __init__(s, name, vmaddr, vmsize, fileoff, filesize):
        s.name, s.vmaddr, s.vmsize, s.fileoff, s.filesize = name, vmaddr, vmsize, fileoff, filesize
    def contains(s, va): return s.vmaddr <= va < s.vmaddr + s.vmsize
    def has_file(s, va): return s.vmaddr <= va < s.vmaddr + s.filesize
    def off(s, va): return s.fileoff + (va - s.vmaddr)
    def __repr__(s):
        return f'{s.name} va={s.vmaddr:#x} sz={s.vmsize:#x} fo={s.fileoff:#x}'

SEGS = []
ncmds = u32(16); off = 32
for _ in range(ncmds):
    cmd, cs = u32(off), u32(off + 4)
    if cmd == LC_SEGMENT_64:
        name = _mm[off+8:off+24].rstrip(b'\0').decode()
        SEGS.append(Seg(name, u64(off+24), u64(off+32), u64(off+40), u64(off+48)))
    off += cs

def seg_by_name(n):
    for s in SEGS:
        if s.name == n: return s
    return None

def va2off(va):
    for s in SEGS:
        if s.has_file(va): return s.off(va)
    return None

def off2va(fo):
    for s in SEGS:
        if s.fileoff <= fo < s.fileoff + s.filesize: return s.vmaddr + (fo - s.fileoff)
    return None

def read(va, n):
    o = va2off(va)
    if o is None or o + n > SZ: return None
    return _mm[o:o+n]

def u32va(va):
    b = read(va, 4)
    return struct.unpack('<I', b)[0] if b else None

def u64va(va):
    b = read(va, 8)
    return struct.unpack('<Q', b)[0] if b else None

def cstr_va(va, maxlen=256):
    o = va2off(va)
    if o is None: return None
    e = _mm.find(b'\0', o, o + maxlen)
    if e < 0: e = o + maxlen
    return _mm[o:e].decode('utf-8', 'replace')

# ---- capstone ----
import capstone
_md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
_md.detail = True
_md.skipdata = True

def dis(va_start, n_insns=200, stop_at_ret=True, va_end=None):
    """Disassemble from va_start. Returns list of (va, size, text, insn).
    Stops after RET (unless stop_at_ret=False) or n_insns or va_end."""
    out = []
    va = va_start
    while len(out) < n_insns:
        if va_end is not None and va >= va_end: break
        o = va2off(va)
        if o is None: break
        got = False
        for insn in _md.disasm(_mm[o:o+16], va):
            out.append((insn.address, insn.size, insn.mnemonic + (' ' + insn.op_str if insn.op_str else ''), insn))
            va = insn.address + insn.size
            got = True
            if stop_at_ret and insn.mnemonic == 'ret':
                return out
            break
        if not got:
            va += 4
    return out

def show(va_start, n_insns=100, stop_at_ret=True, va_end=None, prefix=''):
    for a, sz, t, _ in dis(va_start, n_insns, stop_at_ret, va_end):
        print(f'{prefix}{a:#x}: {t}')

def find_str(s, segname=None):
    """Find a C string in file, return VA(s)."""
    res = []
    needle = s.encode() + b'\0'
    start = 0
    while True:
        o = _mm.find(needle, start)
        if o < 0: break
        va = off2va(o)
        if va is not None and (segname is None or (seg_by_name(segname) and seg_by_name(segname).has_file(va))):
            res.append((va, o))
        start = o + 1
    return res

def adrp_add_scan(segname, targets, limit=None):
    """Linear-scan a segment's executable text with capstone, tracking ADRP
    register state; report every ADRP+ADD that materializes an address in
    `targets` (set of VAs). Also reports ADRP+LDR whose page matches."""
    seg = seg_by_name(segname)
    assert seg
    hits = []
    tset = set(targets)
    tpset = set(t & ~0xFFF for t in targets)
    adrp_state = {}
    o = seg.off(seg.vmaddr)
    code = _mm[o:o + seg.filesize]
    base = seg.vmaddr
    count = 0
    for insn in _md.disasm(code, base):
        count += 1
        if limit and count > limit: break
        m = insn.mnemonic
        if m == 'adrp':
            ops = insn.operands
            reg = insn.reg_name(ops[0].reg)
            adrp_state[reg] = ops[1].imm
        elif m in ('add', 'ldr', 'ldrb', 'ldrsb', 'ldrsw', 'str', 'strb', 'ldur', 'stur', 'ldrsw'):
            ops = insn.operands
            if ops and ops[0].type == capstone.arm64.ARM64_OP_REG and len(ops) >= 2:
                # find base reg operand
                for op in ops[1:]:
                    if op.type == capstone.arm64.ARM64_OP_MEM and op.mem.base != 0:
                        breg = insn.reg_name(op.mem.base)
                        if breg in adrp_state:
                            page = adrp_state[breg]
                            addr = page + op.mem.disp
                            if m == 'add':
                                if ops[1].type == capstone.arm64.ARM64_OP_IMM:
                                    addr = page + ops[1].imm
                            if addr in tset or (page & ~0xFFF) in tpset or (page) in tpset:
                                hits.append((insn.address, f'{m} {insn.op_str}', addr))
                            break
        elif m in ('b', 'br', 'ret', 'blr'):
            # heuristic: clear state on hard control flow boundaries is too
            # aggressive for kext-style code; keep state (xnu is flat).
            pass
    return hits, count

if __name__ == '__main__':
    for s in SEGS: print(s)
