#!/usr/bin/env python3
"""bootstop_probe.py — decode the real 18C66 stop loop with capstone.

Uses the real LC_SEGMENT_64 table for VA→file-offset mapping (never a
naive `va - link_base`), then disassembles the failing loop and dumps
the walked data. Ground truth: capstone + the real segment table.
"""
import struct
import sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

KC = "fixtures/kernelcache.release.iphone12b"
LINK_BASE = 0xFFFFFFF007004000
FAULT_PC = 0xFFFFFFF007B80350

LC_SEGMENT_64 = 0x19
LC_UNIXTHREAD = 0x5


def parse_segments(img: bytes):
    """Return [(name, vmaddr, vmsize, fileoff, filesize)], entry."""
    ncmds = struct.unpack_from("<I", img, 16)[0]
    off = 32
    segs, entry = [], 0
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", img, off)
        if cmd == LC_SEGMENT_64:
            name = img[off + 8 : off + 24].split(b"\0")[0].decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", img, off + 24)
            segs.append((name, vmaddr, vmsize, fileoff, filesize))
        elif cmd == LC_UNIXTHREAD:
            if cmdsize >= 0x118:
                entry = struct.unpack_from("<Q", img, off + 0x110)[0]
        off += cmdsize
    return segs, entry


def va2off(segs, va: int):
    for name, vmaddr, vmsize, fileoff, filesize in segs:
        if vmaddr <= va < vmaddr + max(vmsize, filesize):
            return fileoff + (va - vmaddr), name
    return None, None


def main() -> None:
    with open(KC, "rb") as f:
        img = f.read()
    segs, entry = parse_segments(img)
    print("=== LC_SEGMENT_64 table (real) ===")
    for name, vmaddr, vmsize, fileoff, filesize in segs:
        print(f"  {name:<16} vm {vmaddr:#x} size {vmsize:#x}  file {fileoff:#x} size {filesize:#x}")
    print(f"  entry {entry:#x}")

    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

    # the failing loop: trace showed PCs 0x7b802b8..0x7b80360
    start, end = FAULT_PC - 0x98, FAULT_PC + 0x18
    off, seg = va2off(segs, start)
    print(f"\n=== loop {start:#x}..{end:#x} (seg {seg}, file off {off:#x}) ===")
    blob = img[off : off + (end - start)]
    for insn in md.disasm(blob, start):
        mark = "  <== FAULT PC" if insn.address == FAULT_PC else ""
        print(f"  {insn.address:#x}: {insn.bytes.hex():<12} {insn.mnemonic:<10} {insn.op_str}{mark}")

    # walked data: x10 = 0xfffffff0076e7ef0, x8 = 0xfffffff0076e7ef8
    print("\n=== walked data (real file bytes) ===")
    for va in range(0xFFFFFFF0076E7EC0, 0xFFFFFFF0076E7F20, 8):
        o, seg = va2off(segs, va)
        q = int.from_bytes(img[o:o+8], "little") if o is not None else -1
        print(f"  {va:#x} ({seg}, off {o:#x}): {q:#018x}" if o is not None else f"  {va:#x}: NOT IN FILE")

    # thread_starts neighborhood (boot-real mem_probe reads PA 0x8016e7b8c)
    print("\n=== thread_starts region (va 0xfffffff0076e7b8c..) ===")
    for va in range(0xFFFFFFF0076E7B8C, 0xFFFFFFF0076E7BD0, 8):
        o, seg = va2off(segs, va)
        q = int.from_bytes(img[o:o+8], "little") if o is not None else -1
        print(f"  {va:#x}: {q:#018x}")


if __name__ == "__main__":
    sys.exit(main())
