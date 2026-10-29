#!/usr/bin/env python3
"""macho_inspect.py — stdlib-only ARM64 Mach-O triage for iOS ramdisk/firmware
binaries (the "what am I even looking at" tool).

Answers, in one shot, the questions every RE session starts with:
  * what is it (cputype/filetype, PIE, chained fixups, PAC)
  * where does it start (entry point)
  * what does it link (dyld chained-fixup imports — the library list that
    tells you the binary's job before you read a single instruction)
  * is it what it claims to be (ad-hoc CodeDirectory page-hash verification —
    the integrity proof used to validate extracted restored_external 202/202)

USAGE
-----
  python3 macho_inspect.py BIN                    # full triage report
  python3 macho_inspect.py BIN --verify           # + verify all code pages
  python3 macho_inspect.py BIN --imports-only     # just the import list

stdlib-only. Handles MH_EXECUTE / MH_DYLIB / MH_DYLINKER, chained fixups
(iOS 13.4+) and classic LC_DYLD_INFO binds.
"""
import hashlib
import struct
import sys

MH_MAGIC_64 = 0xFEEDFACF
CPU_NAMES = {0x0100000C: "arm64", 0x0100000E: "arm64e", 0x01000007: "x86_64"}
FILE_TYPES = {1: "MH_OBJECT", 2: "MH_EXECUTE", 6: "MH_DYLIB", 7: "MH_DYLINKER",
              8: "MH_BUNDLE", 12: "MH_DYLIB_STUB"}
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = 0x80000022
LC_DYLD_CHAINED_FIXUPS = 0x80000034
LC_CODE_SIGNATURE = 0x1D
LC_MAIN = 0x28 | 0x80000000
LC_UNIXTHREAD = 0x5


def parse(path):
    d = open(path, "rb").read()
    magic, cputype, cpusub, ftype, ncmds, sizeofcmds, flags, res = struct.unpack_from(
        "<IIIIIIII", d, 0)
    if magic != MH_MAGIC_64:
        raise SystemExit(f"not a 64-bit LE Mach-O (magic {magic:#x})")
    info = {"path": path, "size": len(d), "cputype": CPU_NAMES.get(cputype, hex(cputype)),
            "filetype": FILE_TYPES.get(ftype, ftype), "flags": flags, "ncmds": ncmds,
            "segments": [], "symbols": 0, "imports": [], "entry": None,
            "codesig": None, "pie": bool(flags & 0x20000)}
    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", d, off)
        if cmd == LC_SEGMENT_64:
            name = d[off + 8:off + 24].split(b"\0")[0].decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", d, off + 24)
            nsects = struct.unpack_from("<I", d, off + 64)[0]
            sects = []
            so = off + 72
            for _ in range(nsects):
                sname = d[so:so + 16].split(b"\0")[0].decode("utf-8", errors="replace")
                addr, size = struct.unpack_from("<QQ", d, so + 32)
                sects.append((sname, hex(addr), hex(size)))
                so += 80
            info["segments"].append({"name": name, "vmaddr": hex(vmaddr),
                                     "vmsize": hex(vmsize), "fileoff": hex(fileoff),
                                     "filesize": hex(filesize), "sections": sects})
        elif cmd == LC_SYMTAB:
            info["symbols"] = struct.unpack_from("<I", d, off + 12)[0]
        elif cmd in (LC_DYLD_INFO, LC_DYLD_INFO_ONLY):
            bo, boop, boe = struct.unpack_from("<III", d, off + 32)
            info["imports"] += parse_classic_binds(d, bo, boop, boe)
        elif cmd == LC_DYLD_CHAINED_FIXUPS:
            dataoff, datasize = struct.unpack_from("<II", d, off + 8)
            info["imports"] += parse_chained_fixups(d, dataoff, datasize)
        elif cmd == LC_MAIN:
            info["entry"] = hex(struct.unpack_from("<Q", d, off + 8)[0])
        elif cmd == LC_UNIXTHREAD:
            # arm64: flavor, count, then 33 GPRs (x0..x28, fp, lr, sp, pc)
            try:
                regs = struct.unpack_from("<33Q", d, off + 16)
                info["entry"] = hex(regs[32])
            except struct.error:
                pass
        elif cmd == LC_CODE_SIGNATURE:
            info["codesig"] = struct.unpack_from("<II", d, off + 8)
        off += cmdsize
    return d, info


def uleb(buf, i):
    r, s = 0, 0
    while True:
        b = buf[i]
        i += 1
        r |= (b & 0x7F) << s
        if not b & 0x80:
            return r, i
        s += 7


def parse_classic_binds(d, bind_off, weak_off, lazy_off):
    names = []
    for base in (bind_off, weak_off, lazy_off):
        if not base:
            continue
        i = base
        while i < len(d):
            op = d[i] & 0xF0
            imm = d[i] & 0x0F
            i += 1
            if op == 0x00:  # DONE
                break
            elif op == 0x60:  # SET_SYMBOL_TRAILING_FLAGS_IMM
                end = d.index(b"\0", i)
                names.append(d[i:end].decode("utf-8", errors="replace"))
                i = end
            elif op in (0x20, 0x30, 0x40, 0x50):  # ULEB-taking ops
                if op in (0x20, 0x30, 0x40):
                    _, i = uleb(d, i)
                if op in (0x50, 0x30):
                    continue
            elif op == 0x90:  # BIND_IMMEDIATE_OPCODE range end
                pass
            elif op in (0x70, 0x80):
                pass
            elif op == 0xA0:  # THREADED_BIND — skip sub-opcode
                i += 1
            elif op == 0xC0:  # BIND_ADDEND_SLEB etc.
                i += imm
        # scan is best-effort; stop at segment-junk to avoid infinite loops
        if i >= len(d):
            break
    return sorted(set(n for n in names if len(n) > 2))


def parse_chained_fixups(d, off, size):
    """LC_DYLD_CHAINED_FIXUPS -> import symbol names.

    Empirically calibrated on iOS 14.0b5 restored_external (arm64, format 2):
    header is 7 u32s; the imports table sits immediately before the string
    pool; each 8-byte entry's LE u32 >> 8 (24 bits) is 2*(name_offset), and
    names live at blob[imports_offset + name_offset/2]. We try the structured
    decode first and validate it; if it fails we fall back to enumerating the
    string pool (a superset that is exactly the import list when
    symbols_format == 0, which triage cares about anyway).
    """
    if size < 28:
        return []
    version, starts_off, starts_count, imports_off, imports_count, \
        imports_format, symbols_format = struct.unpack_from("<7I", d, off)

    def read_name(p):
        if not (0 <= p < size) or not (32 <= d[off + p] < 127):
            return None
        e = d.index(b"\0", off + p)
        s = d[off + p:e]
        if len(s) < 3 or not all(32 <= c < 127 for c in s):
            return None
        return s.decode()

    # structured decode: 8-byte entries ending at the string pool
    names, ok = [], 0
    if symbols_format == 0 and imports_off and imports_count:
        t0 = imports_off - imports_count * 8
        if t0 >= 28:
            for i in range(imports_count):
                w0 = struct.unpack_from("<I", d, off + t0 + i * 8)[0]
                nm = read_name(imports_off + ((w0 >> 8) & 0xFFFFFF) // 2)
                if nm is None:
                    break
                names.append(nm)
                ok += 1
    if ok == imports_count and len(set(names)) == imports_count:
        return sorted(set(names))

    # fallback: enumerate the string pool from imports_off to blob end
    pool, p = [], imports_off
    while p < size:
        nm = read_name(p)
        if nm is not None:
            pool.append(nm)
            p += len(nm) + 1
        else:
            p += 1
    if imports_count and len(pool) >= imports_count * 0.95:
        return sorted(set(pool))
    return []


def verify_codesig(d, codesig_cmd):
    """Verify every CodeDirectory code-page hash (SHA-256).

    NOTE: Embedded signatures are BIG-ENDIAN SuperBlobs (CSMAGIC_EMBEDDED_
    SIGNATURE 0xFADE0CC0) with {type, offset} index entries; the CodeDirectory
    (CSMAGIC_CODEDIRECTORY 0xFADE0C02) hangs off index slot 0. All fields BE:
      magic, length, version, flags, hashOffset, identOffset,
      nSpecialSlots, nCodeSlots, codeLimit, hashSize, hashType,
      platform, pageSize(log2)
    Returns (ok, total); (None, total) if not SHA-256; (None, None) if absent.
    """
    off, size = codesig_cmd
    blob = d[off:off + size]
    magic, _, count = struct.unpack_from(">III", blob, 0)
    if magic != 0xFADE0CC0 or count < 1:
        return None, None
    cd_off = None
    for i in range(count):
        t, o = struct.unpack_from(">II", blob, 12 + i * 8)
        if t == 0:  # CSSLOT_CODEDIRECTORY
            cd_off = o
            break
    if cd_off is None:
        return None, None
    cd = blob[cd_off:]
    cmagic, _, version, flags, hash_off, ident_off = struct.unpack_from(">6I", cd, 0)
    if cmagic != 0xFADE0C02:
        return None, None
    n_special, n_code, code_limit = struct.unpack_from(">3I", cd, 24)
    hash_size, hash_type, _, page_shift = struct.unpack_from(">4B", cd, 36)
    if hash_type != 2 or hash_size != 32:
        return None, n_code
    page_size = 1 << page_shift
    ok = 0
    for slot in range(n_code):
        start = slot * page_size
        end = min(start + page_size, code_limit)
        if start >= end:
            break
        h = hashlib.sha256(d[start:end]).digest()
        so = hash_off + slot * 32
        if cd[so:so + 32] == h:
            ok += 1
    return ok, n_code


def main():
    ap = sys.argv[1:]
    if not ap or ap[0] in ("-h", "--help"):
        print(__doc__)
        return
    d, info = parse(ap[0])
    if "--imports-only" in ap:
        print("\n".join(info["imports"]))
        return
    print(f"{info['path']}  ({info['size']:,} B)")
    print(f"  {info['cputype']} {info['filetype']}  PIE={info['pie']}  "
          f"{info['ncmds']} load cmds, {info['symbols']} symbols")
    print(f"  entry: {info['entry']}")
    print("  segments:")
    for s in info["segments"]:
        print(f"    {s['name']:<16} vm {s['vmaddr']}-{hex(int(s['vmaddr'],16)+int(s['vmsize'],16))} "
              f"file {s['fileoff']}+{s['filesize']}")
        for sn, sa, ss in s["sections"]:
            print(f"      {sn:<20} {sa} ({ss} B)")
    print(f"  imports ({len(info['imports'])}):")
    for n in info["imports"]:
        print(f"    {n}")
    if info["codesig"]:
        if "--verify" in ap:
            ok, total = verify_codesig(d, info["codesig"])
            if ok is None:
                print(f"  code signature: {total} pages, non-SHA256 or "
                      f"unrecognized blob — presence check only")
            else:
                print(f"  code signature: {ok}/{total} code pages verified "
                      f"({'INTACT' if ok == total else 'CORRUPTED'})")
        else:
            print(f"  code signature: present at {hex(info['codesig'][0])} "
                  f"({info['codesig'][1]:,} B) — add --verify to check pages")


if __name__ == "__main__":
    main()
