#!/usr/bin/env python3
"""M4-B capstone scan over /tmp/kc18c66.macho (iOS 14.3 18C66 T8030 kernelcache).

Ground-truth sweeps (no hand-split bits; capstone/keystone only):
  - linear disasm (restart at undecodable words) over executable segments
  - every msr/mrs sysreg op (full op_str kept)
  - wfi / wfe sites: keystone-encoded word scan, each hit confirmed by capstone
  - ADRP+ADD / ADR literal-resolution state -> xref hits for chosen string VAs
  - `disasm` mode: dump a window at any VA

Usage:
  python3 m4_b_scan.py scan            # full pass, caches results in /tmp/m4b_scan.json
  python3 m4_b_scan.py strings <pat>   # find cstrings matching pattern (VA list)
  python3 m4_b_scan.py sysreg <name>   # list msr/mrs sites of a sysreg
  python3 m4_b_scan.py wfi             # list confirmed wfi sites
  python3 m4_b_scan.py xref <va>       # ADRP+ADD/ADR refs to a target VA
  python3 m4_b_scan.py disasm <va> <n> # disassemble n insns at va
"""
import capstone, keystone, struct, sys, json, os, re

KC = "/tmp/kc18c66.macho"
CACHE = "/tmp/m4b_scan.json"
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
md.detail = False

with open(KC, "rb") as f:
    data = f.read()

def load_segments():
    ncmds = struct.unpack_from("<I", data, 16)[0]
    off = 32
    segs = []
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", data, off)
        if cmd == 0x19:
            name = data[off+8:off+24].rstrip(b"\0").decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, off+24)
            segs.append((name, vmaddr, vmsize, fileoff, filesize))
        off += size
    return segs

SEGS = load_segments()
EXEC_SEGS = [s for s in SEGS if s[0] in ("__TEXT", "__TEXT_EXEC", "__PPLTEXT", "__KLD", "__PLK_TEXT_EXEC")]

def va2off(va):
    for name, vm, vmsz, fo, fsz in SEGS:
        if vm <= va < vm + vmsz:
            d = va - vm
            if d < fsz:
                return name, fo + d
            return name, None
    return None, None

# ---------------- linear disasm with restart ----------------
def disasm_segment(seg):
    """Yield (addr, mnem, op_str) across a segment, restarting at bad words."""
    name, vm, vmsz, fo, fsz = seg
    n = fsz & ~3
    pos = 0
    code = data[fo:fo+n]
    while pos < n:
        got = False
        for a, sz, mnem, ops in md.disasm_lite(code[pos:], vm + pos):
            got = True
            yield (a, mnem, ops)
            pos = a - vm + sz
        if not got:
            pos += 4

def scan_all():
    sysregs = []   # (va, seg, mnem, op_str)
    wfis = []      # (va, seg)
    xrefs = {}     # target_va -> [(va, seg, kind, val)]  (adrp+add / adr resolved)
    pending = {}   # reg -> (page_va, at_va)  ADRP state per segment run
    for seg in EXEC_SEGS:
        name, vm, vmsz, fo, fsz = seg
        if vmsz == 0:
            continue
        lastadrp = {}
        for a, mnem, ops in disasm_segment(seg):
            if mnem == "adrp":
                parts = ops.replace("#", "").split(", ")
                if len(parts) == 2:
                    lastadrp[parts[0]] = int(parts[1], 16)
            elif mnem == "adr":
                m = re.match(r"^(x\d+|w\d+|xzr|sp), (#?0x[0-9a-f]+)$", ops.replace("#", "", 0))
                if m:
                    tgt = int(m.group(2).lstrip("#"), 16)
                    xrefs.setdefault(tgt, []).append((a, name, "adr", m.group(1)))
            elif mnem in ("add", "sub"):
                m = re.match(r"^(x\d+), (x\d+), (#?0x[0-9a-f]+)$", ops)
                if m and m.group(1) == m.group(2) and m.group(2) in lastadrp:
                    page = lastadrp[m.group(2)]
                    imm = int(m.group(3).lstrip("#"), 16)
                    tgt = page + imm if mnem == "add" else page - imm
                    xrefs.setdefault(tgt, []).append((a, name, mnem, ops))
                    lastadrp.pop(m.group(2), None)
            elif mnem in ("ldr", "str", "ldrb", "strb", "ldrw", "strw"):
                pass
            elif mnem in ("msr", "mrs"):
                sysregs.append((a, name, mnem, ops))
            elif mnem == "wfi":
                wfis.append((a, name))
    return {"sysregs": sysregs, "wfis": wfis, "xrefs": {hex(k): v for k, v in xrefs.items()}}

# ---------------- wfi word scan (keystone encode + capstone confirm) ----------------
def wfi_scan():
    ks = keystone.Ks(keystone.KS_ARCH_ARM64, keystone.KS_MODE_LITTLE_ENDIAN)
    enc, _ = ks.asm("wfi")
    word = int.from_bytes(bytes(enc), "little")
    print(f"keystone wfi encoding: {bytes(enc).hex()} (word {word:#010x})")
    hits = []
    for seg in EXEC_SEGS:
        name, vm, vmsz, fo, fsz = seg
        if vmsz == 0:
            continue
        n = fsz & ~3
        for o in range(0, n, 4):
            if struct.unpack_from("<I", data, fo + o)[0] == word:
                va = vm + o
                ok = next(md.disasm(data[fo+o:fo+o+4], va), None)
                if ok is not None and ok.mnemonic == "wfi":
                    hits.append((va, name))
    return hits

# ---------------- cstring scan ----------------
def find_strings(pat):
    rx = re.compile(pat.encode())
    out = []
    for name, vm, vmsz, fo, fsz in SEGS:
        if name in ("__LINKEDIT",):
            continue
        blob = data[fo:fo+fsz]
        for m in rx.finditer(blob):
            va = vm + m.start()
            # extend to the cstring boundaries
            s = m.start()
            while s > 0 and 0x20 <= blob[s-1] < 0x7f:
                s -= 1
            e = m.end()
            while e < len(blob) and 0x20 <= blob[e] < 0x7f:
                e += 1
            if e - s < 256:
                out.append((va, name, blob[s:e].decode()))
    # dedup
    seen = set(); res = []
    for va, seg, s in out:
        if va not in seen:
            seen.add(va); res.append((va, seg, s))
    return res

# ---------------- CLI ----------------
def cache_or_scan():
    if os.path.exists(CACHE):
        with open(CACHE) as f:
            return json.load(f)
    r = scan_all()
    r["xrefs"] = {k: v for k, v in r["xrefs"].items()}
    with open(CACHE, "w") as f:
        json.dump(r, f)
    return r

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "help"
    if cmd == "scan":
        r = cache_or_scan()
        print(f"sysregs: {len(r['sysregs'])}  wfis: {len(r['wfis'])}  xref targets: {len(r['xrefs'])}")
    elif cmd == "wfi":
        for va, seg in wfi_scan():
            print(f"{va:#x} {seg}")
        print(f"total: {len(wfi_scan())}")
    elif cmd == "strings":
        pat = sys.argv[2]
        for va, seg, s in find_strings(pat):
            print(f"{va:#x} {seg:12s} {s!r}")
    elif cmd == "sysreg":
        want = sys.argv[2].lower()
        r = cache_or_scan()
        n = 0
        for va, seg, mnem, ops in r["sysregs"]:
            if want in ops.lower():
                print(f"{va:#x} {seg:12s} {mnem} {ops}")
                n += 1
        print(f"-- {n} sites for /{want}/")
    elif cmd == "xref":
        tgt = int(sys.argv[2], 16)
        r = cache_or_scan()
        for a, seg, kind, val in r["xrefs"].get(hex(tgt), []):
            print(f"{a:#x} {seg:12s} {kind} {val}")
    elif cmd == "disasm":
        va = int(sys.argv[2], 16); n = int(sys.argv[3])
        seg, o = va2off(va)
        print(f"== seg {seg} off {o:#x}" if o is not None else "== unmapped")
        if o is not None:
            for a, sz, mnem, ops in md.disasm_lite(data[o:o+4*n], va):
                print(f"{a:#x}: {mnem:8s} {ops}")
    else:
        print(__doc__)
