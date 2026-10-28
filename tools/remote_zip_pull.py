#!/usr/bin/env python3
"""remote_zip_pull.py — pull individual members out of a remote ZIP (IPSW)
using HTTP Range requests, without downloading the whole file.

Usage: remote_zip_pull.py <url> <output_dir> [name_regex ...]
"""
import io, os, re, struct, sys, urllib.request

def http(url, start=None, end=None, method="GET"):
    req = urllib.request.Request(url, method=method)
    if start is not None:
        req.add_header("Range", f"bytes={start}-{end}")
    req.add_header("User-Agent", "ios-rust-fixtures/1.0")
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read()

def head(url):
    req = urllib.request.Request(url, method="HEAD")
    req.add_header("User-Agent", "ios-rust-fixtures/1.0")
    with urllib.request.urlopen(req, timeout=60) as r:
        return int(r.headers["Content-Length"])

def find_eocd(url, size):
    # EOCD is in the last 64KB (usually)
    tail_start = max(0, size - 65536)
    tail = http(url, tail_start, size - 1)
    idx = tail.rfind(b"PK\x05\x06")
    if idx < 0:
        raise RuntimeError("EOCD not found")
    eocd = tail[idx:idx + 22]
    disk_no, cd_disk, n_disk, n_total, cd_size, cd_off, cl = struct.unpack("<HHHHIIH", eocd[4:])
    if cd_off == 0xFFFFFFFF or n_total == 0xFFFF:  # zip64
        loc = tail.rfind(b"PK\x06\x07")
        if loc < 0:
            raise RuntimeError("zip64 EOCD locator not found")
        z64_off = struct.unpack("<Q", tail[loc + 8:loc + 16])[0]
        z64 = http(url, z64_off, z64_off + 55)
        cd_size, cd_off = struct.unpack("<QQ", z64[40:56])
        n_total = struct.unpack("<Q", z64[24:32])[0]
    return cd_size, cd_off, n_total

def parse_central_directory(url, cd_off, cd_size, n_total):
    cd = http(url, cd_off, cd_off + cd_size - 1)
    entries = []
    pos = 0
    while pos < len(cd) and len(entries) < n_total:
        if cd[pos:pos + 4] != b"PK\x01\x02":
            break
        (sig, vmade, vneed, flags, method, mtime, mdate, crc, csize, usize,
         nlen, elen, clen, disk, iattr, eattr, lho) = struct.unpack("<IHHHHHHIIIHHHHHII", cd[pos:pos + 46])
        name = cd[pos + 46:pos + 46 + nlen].decode("utf-8", "replace")
        extra = cd[pos + 46 + nlen:pos + 46 + nlen + elen]
        if csize == 0xFFFFFFFF or usize == 0xFFFFFFFF or lho == 0xFFFFFFFF:
            ep = 0
            while ep + 4 <= len(extra):
                hid, hsz = struct.unpack("<HH", extra[ep:ep + 4])
                data = extra[ep + 4:ep + 4 + hsz]
                if hid == 0x0001:
                    dp = 0
                    if usize == 0xFFFFFFFF:
                        usize = struct.unpack("<Q", data[dp:dp + 8])[0]; dp += 8
                    if csize == 0xFFFFFFFF:
                        csize = struct.unpack("<Q", data[dp:dp + 8])[0]; dp += 8
                    if lho == 0xFFFFFFFF:
                        lho = struct.unpack("<Q", data[dp:dp + 8])[0]; dp += 8
                ep += 4 + hsz
        entries.append({"name": name, "method": method, "csize": csize,
                        "usize": usize, "lho": lho})
        pos += 46 + nlen + elen + clen
    return entries

def pull_member(url, e, out_path):
    lfh = http(url, e["lho"], e["lho"] + 29)
    if lfh[:4] != b"PK\x03\x04":
        raise RuntimeError(f"bad LFH for {e['name']}")
    nlen, elen = struct.unpack("<HH", lfh[26:30])
    data_start = e["lho"] + 30 + nlen + elen
    data_end = data_start + e["csize"] - 1
    blob = http(url, data_start, data_end)
    if e["method"] == 0:
        raw = blob
    elif e["method"] == 8:
        raw = __import__("zlib").decompressobj(-15).decompress(blob)
    else:
        raise RuntimeError(f"unsupported method {e['method']} for {e['name']}")
    with open(out_path, "wb") as f:
        f.write(raw)
    return len(raw)

def main():
    url, outdir = sys.argv[1], sys.argv[2]
    patterns = sys.argv[3:] or [r"kernelcache", r"devicetree", r"BuildManifest"]
    os.makedirs(outdir, exist_ok=True)
    size = head(url)
    print(f"remote size: {size // 1024 // 1024} MB", flush=True)
    cd_size, cd_off, n_total = find_eocd(url, size)
    print(f"central directory: {cd_size // 1024} KB, {n_total} entries", flush=True)
    entries = parse_central_directory(url, cd_off, cd_size, n_total)
    print(f"parsed {len(entries)} entries", flush=True)
    rx = [re.compile(p, re.I) for p in patterns]
    done = set()
    for e in entries:
        for r in rx:
            if r.search(e["name"]) and r.pattern not in done:
                out = os.path.join(outdir, os.path.basename(e["name"]))
                print(f"pulling {e['name']} ({e['usize'] // 1024} KB) -> {out}", flush=True)
                n = pull_member(url, e, out)
                print(f"  wrote {n // 1024} KB", flush=True)
                done.add(r.pattern)
    missing = [p.pattern for p in rx if p.pattern not in done]
    if missing:
        print("MISSING patterns:", missing)
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
