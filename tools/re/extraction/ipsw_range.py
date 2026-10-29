#!/usr/bin/env python3
"""Stream specific members out of the big restore IPSW over HTTP ranges.
Only the requested members land on disk (each <100 MB)."""
import struct, sys, urllib.request, zlib

IPSW = ("https://updates.cdn-apple.com/2020SummerSeed/fullrestores/001-35886/"
        "5FE9BE2E-17F8-41C8-96BB-B76E2B225888/"
        "iPhone11,8,iPhone12,1_14.0_18A5351d_Restore.ipsw")


class HttpRange:
    def __init__(self, url):
        self.url = url
        r = urllib.request.urlopen(urllib.request.Request(url, method="HEAD"))
        self.size = int(r.headers["Content-Length"])

    def read(self, off, n):
        end = min(off + n, self.size) - 1
        req = urllib.request.Request(self.url, headers={"Range": f"bytes={off}-{end}"})
        return urllib.request.urlopen(req).read()


def find_eocd(f):
    # comment-free zips: EOCD is exactly the last 22 bytes; else scan
    tail = f.read(f.size - 66000, 66000) if f.size > 66000 else f.read(0, f.size)
    n = len(tail)
    idx = n - 22
    if tail[idx:idx + 4] != b"PK\x05\x06":
        idx = tail.rfind(b"PK\x05\x06")
        while idx >= 0 and idx + 22 > n:
            idx = tail.rfind(b"PK\x05\x06", 0, idx)
    if idx < 0:
        raise RuntimeError("EOCD not found")
    return struct.unpack_from("<IHHHHIIH", tail, idx)[:7]  # sig,disk,cd_disk,n_disk,n_total,cd_size,cd_off,clen


def central_dir(f):
    _, _, _, n_total, cd_size, cd_off = find_eocd(f)[1:]
    # zip64: if cd_off == 0xFFFFFFFF, need zip64 locator
    if cd_off == 0xFFFFFFFF or n_total == 0xFFFF:
        win = min(f.size, 131072); tail = f.read(f.size - win, win)
        li = tail.rfind(b"PK\x06\x07")
        if li < 0:
            raise RuntimeError("zip64 locator not found")
        z64_off = struct.unpack_from("<Q", tail, li + 8)[0]
        rec = f.read(z64_off, 56)
        n_total = struct.unpack_from("<Q", rec, 32)[0]
        cd_size = struct.unpack_from("<Q", rec, 40)[0]
        cd_off = struct.unpack_from("<Q", rec, 48)[0]
    data = f.read(cd_off, cd_size)
    entries = []
    p = 0
    while p < len(data) and data[p:p + 4] == b"PK\x01\x02":
        (sig, vmade, vneed, flags, method, mtime, mdate, crc, csize, usize,
         nlen, elen, clen, disk, iattr, eattr, lho) = struct.unpack_from("<IHHHHHHIIIHHHHHII", data, p)
        name = data[p + 46:p + 46 + nlen].decode("utf-8", "replace")
        extra = data[p + 46 + nlen:p + 46 + nlen + elen]
        # parse zip64 extra if needed
        if csize == 0xFFFFFFFF or usize == 0xFFFFFFFF or lho == 0xFFFFFFFF:
            q = 0
            while q + 4 <= len(extra):
                hid, hsz = struct.unpack_from("<HH", extra, q)
                if hid == 1:
                    vals = []
                    o = q + 4
                    for cur in ("usize", "csize", "lho"):
                        if (cur == "usize" and usize == 0xFFFFFFFF) or \
                           (cur == "csize" and csize == 0xFFFFFFFF) or \
                           (cur == "lho" and lho == 0xFFFFFFFF):
                            vals.append(struct.unpack_from("<Q", extra, o)[0])
                            o += 8
                    it = iter(vals)
                    if usize == 0xFFFFFFFF:
                        usize = next(it)
                    if csize == 0xFFFFFFFF:
                        csize = next(it)
                    if lho == 0xFFFFFFFF:
                        lho = next(it)
                q += 4 + hsz
        entries.append((name, method, csize, usize, lho))
        p += 46 + nlen + elen + clen
    return entries


def extract(f, e, out):
    name, method, csize, usize, lho = e
    # read local header to get data offset (extra may differ)
    lh = f.read(lho, 30)
    nlen, elen = struct.unpack_from("<HH", lh, 26)
    data_off = lho + 30 + nlen + elen
    comp = f.read(data_off, csize)
    if method == 0:
        raw = comp
    elif method == 8:
        d = zlib.decompressobj(-15)
        raw = d.decompress(comp, usize)
    else:
        raise RuntimeError(f"method {method}")
    assert len(raw) == usize, f"{len(raw)} != {usize}"
    with open(out, "wb") as g:
        g.write(raw)
    print("extracted", out, len(raw))


if __name__ == "__main__":
    f = HttpRange(IPSW)
    print("ipsw size:", f.size)
    ents = central_dir(f)
    for e in ents:
        print(f"{e[0]:70s} method={e[1]} csize={e[2]:>12,} usize={e[3]:>12,}")
    want = sys.argv[1:] if len(sys.argv) > 1 else []
    for e in ents:
        base = e[0].rsplit("/", 1)[-1]
        if any(w in e[0] for w in want):
            extract(f, e, "/tmp/" + base)
