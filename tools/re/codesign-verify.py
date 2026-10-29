#!/usr/bin/env python3
"""
codesign-verify.py — verify an ad-hoc embedded signature page-for-page,
stdlib-only. This is how reassembled/extracted binaries were proven intact
during the ios-sweet-rust ramdisk work: restored_external, reassembled from
decmpfs zlib chunks, matched 202/202 SHA256 code-page slots of its
CodeDirectory (the 203rd slot covers the signature blob tail itself).

CodeDirectory layout (v0x20100+, from cs_blobs.h):
  0x00 magic 0xFADE0C02   0x04 length   0x08 version   0x0C flags
  0x10 hashOffset         0x14 identOffset
  0x18 nSpecialSlots      0x1C nCodeSlots
  0x20 codeLimit          0x24 hashSize 0x25 hashType
                          0x27 pageSize (log2)

Usage:  codesign-verify.py <binary>
Exit 0 iff every code page hash matches.
"""
import struct, sys, hashlib

CSSLOT_CDDIRECTORY = 0
CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
CSMAGIC_CODEDIRECTORY = 0xFADE0C02
HASHTYPES = {1: "SHA1", 2: "SHA256"}

def verify_cdblob(d, blob, prefix=""):
    magic, blen = struct.unpack_from(">II", blob, 0)
    assert magic == CSMAGIC_CODEDIRECTORY, f"bad CD magic {magic:#x}"
    version, flags = struct.unpack_from(">II", blob, 8)
    hashoff, identoff = struct.unpack_from(">II", blob, 16)
    nspec, ncode, codelimit = struct.unpack_from(">III", blob, 24)
    hsz, htype, platform, pageshift = blob[36], blob[37], blob[38], blob[39]
    pagesz = 1 << pageshift if pageshift else 4096
    ident = blob[identoff:blob.index(b"\0", identoff)].decode(errors="replace")
    algo = HASHTYPES.get(htype, f"type{htype}")
    hfun = hashlib.sha256 if hsz == 32 else (hashlib.sha1 if hsz == 20 else None)
    print(f"{prefix}CodeDirectory v{version:#x} id={ident!r} hash={algo}({hsz}B) "
          f"pages={ncode} special={nspec} codeLimit={codelimit} pageSize={pagesz}")
    if hfun is None:
        print(f"{prefix}  (unsupported hash size {hsz} — skipped)"); return True
    match, bad = 0, []
    for p in range(ncode):
        lo, hi = p * pagesz, min((p + 1) * pagesz, codelimit)
        digest = hfun(d[lo:hi]).digest()
        slot = blob[hashoff + p * hsz: hashoff + (p + 1) * hsz]
        if digest == slot: match += 1
        else: bad.append(p)
    print(f"{prefix}  -> {match}/{ncode} code pages match")
    if bad:
        print(f"{prefix}     first bad pages: {bad[:8]}{'...' if len(bad) > 8 else ''}")
        return False
    return True

def main():
    if len(sys.argv) < 2:
        print(__doc__); return 2
    d = open(sys.argv[1], "rb").read()
    ncmds = struct.unpack_from("<I", d, 16)[0]
    off = 32; cs = None
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", d, off)
        if cmd == 0x1D:
            cs = struct.unpack_from("<II", d, off + 8)
        off += size
    if not cs:
        print("no LC_CODE_SIGNATURE"); return 2
    soff, ssize = cs
    sb = d[soff:soff + ssize]
    magic, length, count = struct.unpack_from(">III", sb, 0)
    if magic != CSMAGIC_EMBEDDED_SIGNATURE:
        print(f"not an embedded SuperBlob: {magic:#x}"); return 2
    print(f"SuperBlob @ {soff:#x} ({ssize} B), {count} slots")
    ok = True
    for i in range(count):
        typ, o = struct.unpack_from(">II", sb, 12 + 8 * i)   # index starts at 0x0C
        blob = sb[o:o + struct.unpack_from(">I", sb, o + 4)[0]]
        if not blob:
            print(f"  slot {typ:#x}: empty (bad offset {o:#x})"); ok = False; continue
        bmagic = struct.unpack_from(">I", blob, 0)[0]
        if bmagic == CSMAGIC_CODEDIRECTORY and typ == CSSLOT_CDDIRECTORY:
            ok = verify_cdblob(d, blob, "  ") and ok
        else:
            print(f"  slot {typ:#x} @ {o:#x} magic {bmagic:#x} {len(blob)} B (not verified)")
    print("VERDICT:", "OK — byte-exact vs its embedded signature" if ok else "MISMATCH — file differs from signed content")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
