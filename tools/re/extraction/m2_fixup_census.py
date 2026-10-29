#!/usr/bin/env python3
"""M2 census: locate + decode DYLD_CHAINED fixups in the real 18C66 kernelcache.
Empirical: every layout decision is validated from the bytes (chain termination,
target-range membership). Re-runnable: python3 m2_fixup_census.py [fixture]"""
import sys, struct, mmap, collections

path = sys.argv[1] if len(sys.argv) > 1 else '/home/z/work/ios-rust/fixtures/kernelcache.release.iphone12b'
f = open(path, 'rb')
mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
SZ = len(mm)
def u32(o): return struct.unpack_from('<I', mm, o)[0]
def u16(o): return struct.unpack_from('<H', mm, o)[0]
def u64(o): return struct.unpack_from('<Q', mm, o)[0]
def cstr(o):
    e = mm.find(b'\0', o)
    return mm[o:e].decode('utf-8', 'replace')

MH = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
LC_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = 0x80000022
LC_DYLD_EXPORTS_TRIE = 0x80000033
LC_DYLD_CHAINED_FIXUPS = 0x80000034
LC_FILESET_ENTRY = 0x80000035

class Seg:
    def __init__(s, name, vmaddr, vmsize, fileoff, filesize, initprot):
        s.name, s.vmaddr, s.vmsize, s.fileoff, s.filesize, s.initprot = name, vmaddr, vmsize, fileoff, filesize, initprot
    def __repr__(s):
        return f'{s.name} va={s.vmaddr:#x} sz={s.vmsize:#x} fo={s.fileoff:#x} prot={s.initprot:#x}'

def parse_segments(hdr_off):
    """parse one Mach-O header (top-level or component)"""
    assert u32(hdr_off) == MH, hex(u32(hdr_off))
    ncmds = u32(hdr_off + 16)
    off = hdr_off + 32
    cmds = collections.Counter(); segs = []; fs = []; fx = None; di = None; ex = None
    for _ in range(ncmds):
        cmd, cs = u32(off), u32(off + 4)
        if cs < 8 or off + cs > SZ: break
        cmds[hex(cmd)] += 1
        if cmd == LC_SEGMENT_64:
            name = mm[off + 8:off + 24].rstrip(b'\0').decode()
            segs.append(Seg(name, u64(off + 24), u64(off + 32), u64(off + 40), u64(off + 48), u32(off + 60)))
        elif cmd == LC_FILESET_ENTRY:
            fs.append(dict(eid=cstr(off + 8 + u32(off + 12)), ivm=u64(off + 16), off=off, cs=cs))
        elif cmd == LC_DYLD_CHAINED_FIXUPS:
            fx = dict(dataoff=u32(off + 8), datasize=u32(off + 12), import_off=u32(off + 16),
                      import_size=u32(off + 20), sym_off=u32(off + 24), sym_size=u32(off + 28))
        elif cmd in (LC_DYLD_INFO, LC_DYLD_INFO_ONLY):
            di = dict(rebase=(u32(off + 8), u32(off + 12)), bind=(u32(off + 16), u32(off + 20)),
                      weak=(u32(off + 24), u32(off + 28)), lazy=(u32(off + 32), u32(off + 36)),
                      export=(u32(off + 40), u32(off + 44)))
        elif cmd == LC_DYLD_EXPORTS_TRIE:
            ex = (u32(off + 8), u32(off + 12))
        off += cs
    return cmds, segs, fs, fx, di, ex

# ---------- top level ----------
cmds, segs, fs, fx, di, ex = parse_segments(0)
print(f'== TOP-LEVEL (ncmds={u32(16)}) ==')
for k, v in sorted(cmds.items()): print(f'   {k} x{v}')
print('segments:'); [print('  ', s) for s in segs]
print(f'fileset entries ({len(fs)}):'); [print(f'   [{i}] {e["eid"]} ivm={e["ivm"]:#x} cmd@{e["off"]:#x} cs={e["cs"]}') for i, e in enumerate(fs)]
print(f'fixups_cmd(top)={fx} dyld_info={di} exports={ex}')

# ---------- components ----------
comp = []
for i, e in enumerate(fs):
    guess = e['off'] + e['cs']
    hdr = guess if (guess + 4 <= SZ and u32(guess) == MH) else None
    if hdr is None:
        for o in range(guess, min(guess + 0x100000, SZ - 4)):
            if u32(o) == MH: hdr = o; break
    if hdr is not None:
        ccmds, csegs, cfs, cfx, cdi, cex = parse_segments(hdr)
        comp.append(dict(i=i, hdr=hdr, segs=csegs, fx=cfx, di=cdi, cmds=ccmds, e=e))
    else:
        comp.append(dict(i=i, hdr=None, segs=[], fx=None, di=None, cmds={}, e=e))

print(f'== COMPONENTS ({len(comp)}) ==')
for c in comp:
    hdr = c['hdr']
    loc = f'hdr@{hdr:#x}' if hdr else 'NO-HEADER'
    adj = ' (right-after-cmd)' if hdr == c['e']['off'] + c['e']['cs'] else ''
    print(f'[{c["i"]}] {c["e"]["eid"]}: {loc}{adj} nseg={len(c["segs"])} '
          f'fixups={"Y" if c["fx"] else "-"} dyld_info={"Y" if c["di"] else "-"}')
    if c['fx']: print(f'     fixups: {c["fx"]}')
    if c['di']: print(f'     dyld_info: {c["di"]}')

# ---------- fixups decode ----------
def decode_fixups(fx, segs_for_id):
    d = fx['dataoff']
    fv, so, ssz, io, isz, syo, sysz, icnt, ifmt, sfmt = struct.unpack_from('<10I', mm, d)
    print(f'  fixups_header@{d:#x}: ver={fv} starts_off={so} starts_sz={ssz} imports_off={io} imports_sz={isz} '
          f'syms_off={syo} syms_sz={sysz} imports_count={icnt} imports_format={ifmt} symbols_format={sfmt}')
    img = d + so
    seg_count = u32(img)
    offs = [u32(img + 4 + 4 * i) for i in range(seg_count)]
    print(f'  starts_in_image@{img:#x}: seg_count={seg_count} offsets={offs}')
    total = 0
    for si, soff in enumerate(offs):
        s = img + soff
        size = u32(s); page_size = u16(s + 4); seg_id = u16(s + 6); psc = u32(s + 8)
        ps = [u16(s + 12 + 2 * i) for i in range(psc)]
        after = s + 12 + 2 * psc
        pfmt = u16(after)
        segoff = u64(after + 2)
        mvp = u32(after + 10)
        page_count = u16(after + 14)
        own = segs_for_id[seg_id] if seg_id < len(segs_for_id) else None
        own_name = own.name if own else f'seg{seg_id}'
        print(f'  [seg{seg_id} {own_name}] size={size} page_size={page_size:#x} psc={psc} '
              f'starts[:8]={ps[:8]}{"..." if psc > 8 else ""} pointer_format={pfmt} '
              f'segment_offset={segoff:#x} max_valid={mvp:#x} page_count={page_count}')
        if own is None:
            print('     (no matching segment — skip walk)'); continue
        n_heads = 0; n_fix = 0; brk = 0; samples = []
        tgt_min = (1 << 64); tgt_max = 0
        nxt_hist = collections.Counter()
        for pi in range(page_count):
            start = ps[pi] if pi < psc else 0xFFFF
            if start == 0: continue          # explicit no-fixups page
            cur = 0 if start == 0xFFFF else start * 4
            page_va = own.vmaddr + pi * page_size
            va = page_va + cur
            fo = own.fileoff + (va - own.vmaddr)
            steps = 0
            while True:
                if fo < 0 or fo + 8 > SZ: brk += 1; break
                raw = u64(fo)
                n_heads += (steps == 0); n_fix += 1
                if steps == 0 and len(samples) < 6:
                    samples.append((va, raw))
                next_f = (raw >> 51) & 0x7FF
                bind_f = (raw >> 63) & 1
                nxt_hist[next_f] += 1
                lo36 = raw & ((1 << 36) - 1)
                t = lo36 * 4
                if t:
                    tgt_min = min(tgt_min, t); tgt_max = max(tgt_max, t)
                if next_f == 0: break
                va += next_f * 4
                fo += next_f * 4
                steps += 1
                if steps > 200000: brk += 1; break
        total += n_fix
        print(f'     walk: heads={n_heads} fixups={n_fix} broken={brk} '
              f'lo36*4 target range=[{tgt_min:#x}..{tgt_max:#x}] next_hist_top={nxt_hist.most_common(4)}')
        print(f'     samples: ' + ' '.join(f'({va:#x},{r:#018x})' for va, r in samples))
    if icnt and ifmt == 1:
        ib = d + io
        print(f'  imports ({icnt}, fmt {ifmt}): first 4 raw:')
        for i in range(min(4, icnt)):
            v = u32(ib + 4 * i)
            print(f'    imp[{i}]={v:#010x} ord24={v & 0xFFFFFF:#x} lib={(v >> 24) & 0xFF} flags={(v >> 31) & 1}')
    elif icnt:
        print(f'  imports: count={icnt} format={ifmt}')
    print(f'  TOTAL fixups: {total}')

if fx:
    print('== FIXUPS (top-level) ==')
    decode_fixups(fx, segs)
for c in comp:
    if c['fx']:
        print(f'== FIXUPS (component [{c["i"]}] {c["e"]["eid"]}) ==')
        decode_fixups(c['fx'], c['segs'])

print('== MAIN KERNEL COMPONENT SEGMENTS ==')
for c in comp:
    if c['segs'] and ('kernel' in c['e']['eid'].lower() or c['e']['ivm'] == max((x['e']['ivm'] for x in comp if x['segs']), default=0)):
        print(f' [{c["i"]}] {c["e"]["eid"]}:')
        for s in c['segs']: print('  ', s)
print('done.')
