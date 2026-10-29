#!/usr/bin/env python3
"""M4 stop-site context: disassemble around pc=0xfffffff0081377b4 (DT-globals
TranslationFault stop) and the suspected gate fn 0x…8136f10, plus find xrefs
to the gate. Uses capstone only — no hand-split bits (per tools/re/README.md).
"""
import capstone, struct, sys

KC = "/tmp/kc18c66.macho"
BASE = 0xFFFFFFF008000000  # kernel VA base (slide 0 pre-linked __TEXT)

with open(KC, "rb") as f:
    data = f.read()

# Parse mach-O segments to map VA->file offset
assert data[:4] == b"\xcf\xfa\xed\xce" or data[:4] == b"\xcf\xfa\xed\xfe", data[:4].hex()
magic = data[:4]
if magic == b"\xcf\xfa\xed\xce":  # 32 LE
    ncmds = struct.unpack_from("<I", data, 16)[0]
    off = 32
    fmt = "<II"
else:  # 64
    ncmds = struct.unpack_from("<I", data, 16)[0]
    off = 32
    fmt = "<II"
# it's actually MH_MAGIC_64 for arm64; re-read properly:
is64 = magic == b"\xcf\xfa\xed\xfe"
ncmds = struct.unpack_from("<I", data, 16)[0]
off = 32 if is64 else 28
segs = []
for _ in range(ncmds):
    cmd, size = struct.unpack_from("<II", data, off)
    if cmd == 0x19:  # LC_SEGMENT_64
        name = data[off+8:off+24].rstrip(b"\0").decode()
        vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, off+24)
        segs.append((name, vmaddr, vmsize, fileoff, filesize))
    off += size

def va2off(va):
    for name, vmaddr, vmsize, fileoff, filesize in segs:
        if vmaddr <= va < vmaddr + vmsize:
            delta = va - vmaddr
            if delta < filesize:
                return name, fileoff + delta
            return name, None
    return "?", None

md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
md.detail = False

def dump(va_start, n, label):
    seg, o = va2off(va_start)
    if o is None:
        print(f"== {label}: va {va_start:#x} in seg {seg} but beyond file size")
        return
    print(f"== {label}: va {va_start:#x} (seg {seg}, file off {o:#x})")
    code = data[o:o+n*4]
    for i in md.disasm(code, va_start):
        print(f"  {i.address:#x}: {i.mnemonic:10s} {i.op_str}")

print("== segment map")
for name, vmaddr, vmsize, fileoff, filesize in segs:
    print(f"  {name:16s} vm {vmaddr:#x}..{vmaddr+vmsize:#x} file {fileoff:#x}..{fileoff+filesize:#x}")

dump(0xFFFFFFF0081377B4 - 0x40, 28, "stop site window (pc=0x…377b4 fault va=4)")
dump(0xFFFFFFF0081376F10 - 0x10, 48, "gate fn 0x…376f10")
dump(0xFFFFFFF007B83F80, 20, "store-site window 0x…7b83fa0 (M2 notes)")
