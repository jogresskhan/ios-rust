#!/usr/bin/env python3
"""adr_string_scan.py — string xref scanner for Apple ARM64 Mach-O binaries
that reference strings with plain `adr` instead of `adrp+add`.

WHY THIS EXISTS
---------------
Apple's restored_external (iOS 14 restore ramdisk, T8030) compiles its
string references as single PC-relative `adr` instructions (7,793 of them)
rather than the textbook `adrp` (page) + `add` pair. Standard IDA/Ghidra/
radare adrp-xref strategies report zero string xrefs, which makes static
triage of the restore engine look impossible. It isn't — every string is
exactly one `adr` away.

Encoding (ARMv8, fixed-width 32-bit):
  ADR  Xd, label : 0b0 immlo(2) 10000 immhi(19) Rd(5)   -> op bit31 = 0
  ADRP Xd, label : 0b1 immlo(2) 10000 immhi(19) Rd(5)   -> op bit31 = 1
  imm21 = sign_extend(immhi:immlo);  ADR target = PC + imm21
                                     ADRP target = page(PC) + imm21 * 4096

USAGE
-----
  python3 adr_string_scan.py BIN                          # triage summary
  python3 adr_string_scan.py BIN --strings                # dump all strings
  python3 adr_string_scan.py BIN --xref RESTORE-OUTCOME   # who references it
  python3 adr_string_scan.py BIN --addr 0x10000dfe0       # string at addr
  python3 adr_string_scan.py BIN --json OUT.json          # machine-readable

Works on arm64/arm64e MH_EXECUTE/DYLIB, local symbols stripped or not.
stdlib-only (no LIEF/capstone needed) so it runs anywhere, incl. CI.
"""
import struct
import sys
import json

MH_MAGIC_64 = 0xFEEDFACF
CPU_TYPE_ARM64 = 0x0100000C
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_DYSYMTAB = 0xB
S_CSTRING_LITERALS = 2  # section flag bit pattern for cstring sections
SECT_TEXT = "__text"
SECT_STRING_NAMES = {"__cstring", "__oslogstring", "__constg_swifttstring"}


class MachO:
    def __init__(self, data: bytes):
        self.data = data
        magic, cputype, _, filetype, ncmds, sizeofcmds, flags, _ = struct.unpack_from(
            "<IIIIIIII", data, 0)
        if magic != MH_MAGIC_64:
            raise ValueError(f"not a 64-bit little-endian Mach-O (magic {magic:#x})")
        self.cputype, self.filetype, self.ncmds, self.flags = cputype, filetype, ncmds, flags
        self.segments = []      # (name, vmaddr, vmsize, fileoff, filesize, sections)
        self.symbols = []       # (addr, name)
        self.entry = None
        off = 32
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from("<II", data, off)
            if cmd == LC_SEGMENT_64:
                name = data[off + 8:off + 24].split(b"\0")[0].decode()
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, off + 24)
                nsects = struct.unpack_from("<I", data, off + 64)[0]
                sects = []
                so = off + 72
                for _ in range(nsects):
                    sname = data[so:so + 16].split(b"\0")[0].decode("utf-8", errors="replace")
                    seg2 = data[so + 16:so + 32].split(b"\0")[0].decode("utf-8", errors="replace")
                    addr, size = struct.unpack_from("<QQ", data, so + 32)
                    sflags = struct.unpack_from("<I", data, so + 64)[0]
                    sects.append((sname, seg2, addr, size, sflags))
                    so += 80
                self.segments.append((name, vmaddr, vmsize, fileoff, filesize, sects))
            elif cmd == LC_SYMTAB:
                symoff, nsyms, stroff, strsize = struct.unpack_from("<IIII", data, off + 8)
                for i in range(nsyms):
                    so = symoff + i * 16
                    n_strx, n_type, n_sect, n_desc, n_value = struct.unpack_from(
                        "<IBBHQ", data, so)
                    if n_type & 0x0E:  # defined symbol with address
                        end = data.index(b"\0", stroff + n_strx)
                        nm = data[stroff + n_strx:end].decode("utf-8", errors="replace")
                        if nm.startswith("__Z"):
                            nm = self._demangle_light(nm)
                        self.symbols.append((n_value, nm))
            elif cmd == 0x80000028:  # LC_MAIN
                self.entry = struct.unpack_from("<Q", data, off + 8)[0]
            off += cmdsize
        self.symbols.sort()

    @staticmethod
    def _demangle_light(m):
        return m  # hook for a real demangler later; keep names raw for now

    def section(self, segname, sectname):
        for _, _, _, _, _, sects in self.segments:
            for sname, seg2, addr, size, sflags in sects:
                if sname == sectname and seg2 == segname:
                    return addr, size, sflags
        return None

    def text(self):
        for name, vmaddr, vmsize, fileoff, filesize, sects in self.segments:
            if name == "__TEXT":
                for sname, _, addr, size, _ in sects:
                    if sname == SECT_TEXT:
                        return addr, size
        # fallback: biggest executable section
        best = None
        for name, vmaddr, vmsize, fileoff, filesize, sects in self.segments:
            for sname, _, addr, size, sflags in sects:
                if sflags & 0x80000400:  # S_ATTR_PURE_INSTRUCTIONS|some exec bits
                    if best is None or size > best[1]:
                        best = (addr, size)
        return best

    def strings(self):
        """[(addr, s)] from cstring-type sections. A string is a maximal run
        of printable bytes (or \\t \\n \\r) NUL-terminated, length >= 4."""
        out = []
        for name, vmaddr, vmsize, fileoff, filesize, sects in self.segments:
            for sname, _, addr, size, sflags in sects:
                if sname in SECT_STRING_NAMES or (sflags & 0x2):
                    blob = self.data[fileoff + (addr - vmaddr):fileoff + (addr - vmaddr) + size]
                    start = None
                    for i, b in enumerate(blob):
                        ok = 32 <= b < 127 or b in (9, 10, 13)
                        if b == 0:
                            if start is not None and i - start >= 4:
                                s = blob[start:i]
                                try:
                                    out.append((addr + start, s.decode("ascii")))
                                except UnicodeDecodeError:
                                    pass
                            start = None
                        elif ok:
                            if start is None:
                                start = i
                        else:
                            start = None
        return out

    def fileoff_for(self, addr):
        for name, vmaddr, vmsize, fileoff, filesize, _ in self.segments:
            if vmaddr <= addr < vmaddr + vmsize:
                return fileoff + (addr - vmaddr)
        return None

    def func_of(self, addr):
        best = None
        for sa, nm in self.symbols:
            if sa <= addr and (best is None or sa > best[0]):
                best = (sa, nm)
        return best


def decode_adr(word, pc):
    """Return ('adr'|'adrp', target) or None."""
    op = word >> 31
    if (word >> 24) & 0x9F != 0x10:
        return None
    immlo = (word >> 29) & 0x3
    immhi = (word >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= 1 << 21
    if op:
        return ("adrp", (pc & ~0xFFF) + imm * 4096)
    return ("adr", pc + imm)


def scan(m: MachO):
    """{string_addr: [insn_addr, ...]} for every ADR/ADRP in __text."""
    addr, size = m.text() or (None, None)
    if addr is None:
        raise ValueError("no __text section found")
    fo = m.fileoff_for(addr)
    xrefs = {}
    n_adr = n_adrp = 0
    for i in range(0, size - 3, 4):
        word = struct.unpack_from("<I", m.data, fo + i)[0]
        d = decode_adr(word, addr + i)
        if d:
            kind, target = d
            if kind == "adr":
                n_adr += 1
            else:
                n_adrp += 1
            xrefs.setdefault(target, []).append(addr + i)
    return xrefs, n_adr, n_adrp


def main():
    ap = sys.argv[1:]
    if not ap or ap[0] in ("-h", "--help"):
        print(__doc__)
        return
    binpath = ap[0]
    args = ap[1:]
    m = MachO(open(binpath, "rb").read())
    xrefs, n_adr, n_adrp = scan(m)
    strings = m.strings()

    if "--strings" in args:
        for a, s in sorted(strings):
            print(f"{a:#x}  {s}")
        return

    if "--json" in args:
        out = {
            "binary": binpath, "cputype": hex(m.cputype),
            "entry": hex(m.entry) if m.entry else None,
            "adr_count": n_adr, "adrp_count": n_adrp,
            "strings": {hex(a): s for a, s in strings},
            "xrefs": {hex(a): [hex(x) for x in xl] for a, xl in sorted(xrefs.items())},
        }
        open(args[args.index("--json") + 1], "w").write(json.dumps(out, indent=1))
        print(f"wrote {args[args.index('--json') + 1]}")
        return

    # default: triage summary + optional queries
    print(f"{binpath}: {len(m.segments)} segments, {len(m.symbols)} symbols, "
          f"entry {m.entry and hex(m.entry)}")
    print(f"{len(strings)} strings | {n_adr} ADR insns (xref-capable), "
          f"{n_adrp} ADRP")
    n_x = sum(1 for a, _ in strings if a in xrefs)
    print(f"{n_x}/{len(strings)} strings have direct ADR xrefs")

    if "--xref" in args:
        needle = args[args.index("--xref") + 1]
        hits = [(a, s) for a, s in strings if needle.lower() in s.lower()]
        for a, s in hits:
            print(f"\n{a:#x}: {s!r}")
            fn = m.func_of(a)
            if fn:
                print(f"   defined inside: {fn[1]} @ {fn[0]:#x}")
            for x in xrefs.get(a, []):
                f = m.func_of(x)
                who = f"{f[1]}+{x - f[0]:#x} ({f[0]:#x})" if f else "?"
                print(f"   <- {x:#x}  in {who}")
    if "--addr" in args:
        tgt = int(args[args.index("--addr") + 1], 16)
        for x in xrefs.get(tgt, []):
            f = m.func_of(x)
            who = f"{f[1]}+{x - f[0]:#x}" if f else "?"
            print(f"{tgt:#x} <- {x:#x} in {who}")


if __name__ == "__main__":
    main()
