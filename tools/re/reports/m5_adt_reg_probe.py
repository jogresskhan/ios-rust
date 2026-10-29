#!/usr/bin/env python3
"""Inspect reg property encodings in the REAL DeviceTree.n104ap flat blob.
Format (crates/adt parse_flat): node = {u32 nprops, u32 nchildren} LE,
props = {char name[32], u32 len(bit31=placeholder), data[pad4]}, children pre-order.
"""
import struct, sys, hashlib

path = sys.argv[1] if len(sys.argv) > 1 else "/tmp/adt-n104ap.bin"
buf = open(path, "rb").read()
print(f"{path}: {len(buf)} B sha256={hashlib.sha256(buf).hexdigest()[:16]}…")

def parse_node(off, depth=0, pathstr=""):
    nprops, nchildren = struct.unpack_from("<II", buf, off)
    p = off + 8
    name = "?"
    props = {}
    for _ in range(nprops):
        nm = buf[p:p+32].split(b"\0")[0].decode(errors="replace")
        ln = struct.unpack_from("<I", buf, p+32)[0]
        ln &= 0x7FFFFFFF
        data = buf[p+36:p+36+ln]
        props[nm] = data
        if nm == "name":
            name = data.rstrip(b"\0").decode(errors="replace")
        p = (p + 36 + ln + 3) & ~3
    full = f"{pathstr}/{name}"
    if "reg" in props and depth <= 4:
        r = props["reg"]
        desc = []
        if len(r) % 16 == 0 and len(r) > 0:
            for i in range(0, len(r), 16):
                a, s = struct.unpack_from("<QQ", r, i)
                desc.append(f"{a:#x}/{s:#x}")
        elif len(r) % 8 == 0:
            for i in range(0, len(r), 8):
                a, s = struct.unpack_from("<II", r, i)
                desc.append(f"u32 {a:#x}/{s:#x}")
        else:
            desc.append(f"raw{len(r)}B:{r[:16].hex()}")
        interesting = depth <= 2 or name in ("aic","pmgr","wdt","uart0","ans","ans2","dart","sart","sgx") or full=="/cpus"
        if interesting:
            print(f"  {full:34s} reg[{len(r):2d}B] {' '.join(desc)}")
    kids = []
    q = p
    for _ in range(nchildren):
        c, q = parse_node(q, depth+1, full)
        kids.append(c)
    return full, q

# top-level: {u32 nprops, u32 nchildren} then props then children (root name prop = "device-tree")
_, end = parse_node(0)
print(f"parsed {end}/{len(buf)} B")
