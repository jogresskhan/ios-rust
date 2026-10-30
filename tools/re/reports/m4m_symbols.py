#!/usr/bin/env python3
"""M4-M part 3: symbol lookup for the physmap globals + __auth_ptr census.
Uses the kernelcache LC_SYMTAB (nlist_64) directly."""
import sys, struct
sys.path.insert(0, '/home/z/my-project/s3-work/ios-rust/tools/re/extraction')
from m4a_common import _mm, u32, SEGS, seg_by_name

# ---- LC_SYMTAB ----
LC_SYMTAB = 0x2
ncmds = u32(16); off = 32
symoff = nsyms = stroff = strsize = 0
for _ in range(ncmds):
    cmd, cs = u32(off), u32(off + 4)
    if cmd == LC_SYMTAB:
        symoff, nsyms = u32(off + 8), u32(off + 12)
        stroff, strsize = u32(off + 16), u32(off + 20)
        break
    off += cs
print(f'symtab: nsyms={nsyms} symoff={symoff:#x} stroff={stroff:#x}')

def cstr(o):
    e = _mm.index(b'\0', o)
    return _mm[o:e].decode('utf8', 'replace')

syms = []
for i in range(nsyms):
    o = symoff + i * 16
    n_strx, n_type, n_sect, n_desc = struct.unpack_from('<IBBh', _mm, o)
    n_value = struct.unpack_from('<Q', _mm, o + 8)[0]
    name = cstr(stroff + n_strx) if n_strx else ''
    syms.append((n_value, name, n_type, n_sect))

syms.sort()
import bisect
addrs = [s[0] for s in syms]

def lookup(va):
    i = bisect.bisect_right(addrs, va) - 1
    if i >= 0 and syms[i][0] != 0:
        return syms[i]
    return None

for va in (0xfffffff007701cf8, 0xfffffff007701d10, 0xfffffff007704000,
           0xfffffff007702128, 0xfffffff007702440, 0xfffffff007702450,
           0xfffffff007702458, 0xfffffff00774c000, 0xfffffff0098a4ac0,
           0xfffffff007b72f88, 0xfffffff007b818a0, 0xfffffff008169574,
           0xfffffff007b6eeb0, 0xfffffff00987c440, 0xfffffff0080108f0,
           0xfffffff008168000, 0xfffffff007702460, 0xfffffff007702578,
           0xfffffff007702580, 0xfffffff009a67f68, 0xfffffff007724000):
    s = lookup(va)
    # section for VA
    sect = ''
    for sg in SEGS:
        if sg.contains(va):
            sect = sg.name
            break
    print(f'{va:#x} [{sect:14}] → {s[1] if s else "?? (no symbol)"}  (sym@{s[0]:#x})' if s else f'{va:#x} [{sect:14}] → ?? (no symbol)')

# ---- symbols in __BOOTDATA-ish range window around the globals ----
print()
print('--- symbols in [0x7701000, 0x7705000) ---')
for v, n, t, sec in syms:
    if 0xfffffff007701000 <= v < 0xfffffff007705000:
        print(f'  {v:#x} type={t:#x} sect={sec} {n}')
print('--- symbols in [0x98a4000, 0x98a6000) ---')
for v, n, t, sec in syms:
    if 0xfffffff0098a4000 <= v < 0xfffffff0098a6000:
        print(f'  {v:#x} type={t:#x} sect={sec} {n}')
