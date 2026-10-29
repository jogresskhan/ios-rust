#!/usr/bin/env python3
# Extract the restore-ramdisk userland (restored_external, asr, keystorectl, ...)
# straight from the official IPSW over HTTP ranges — no LZFSE needed, no 6 GB
# download, no hdiutil, runs anywhere python3 runs.
#
# Why this exists (ios14-ramdisk-diag / re-restore-ramdisk CI, 2026-10-28):
#   * The ramdisk IM4P payload (type 'rdsk') is a RAW, UNCOMPRESSED HFSX volume
#     — the only compression is the zip deflate of the IPSW member itself. All
#     the "im4p -> mountable HFS image" legs failed because they expected bvx2.
#   * Almost every binary inside is HFS+ transparently compressed (decmpfs):
#     empty data fork, compressed bytes in a chunked resource fork (zlib).
#     hdiutil/APFS tools choke on that; this parser just decodes it.
#   * Binaries extracted this way verify page-for-page against their embedded
#     ad-hoc code signature (202/203 SHA256 page slots for restored_external).
#
# Usage:
#   python3 tools/extract-ramdisk-userland.py <IPSW-URL-or-path> [outdir]
#
# Requires nothing but python3 stdlib. Output files land in <outdir> flat,
# named after their volume path.
import struct, sys, os, zlib, urllib.request

DEFAULT_IPSW = ("https://updates.cdn-apple.com/2020SummerSeed/fullrestores/"
                "001-35886/5FE9BE2E-17F8-41C8-96BB-B76E2B225888/"
                "iPhone11,8,iPhone12,1_14.0_18A5351d_Restore.ipsw")
MEMBERS = ("038-44135-124.dmg", "038-44087-125.dmg")   # restore + update ramdisks
TARGETS = ("restored_external", "restored_update", "/asr", "keystorectl",
           "configdarwinbootargs")


class LocalFile:
    def __init__(self, path):
        self.f = open(path, "rb")
        self.f.seek(0, 2)
        self.size = self.f.tell()

    def read(self, off, n):
        self.f.seek(off)
        return self.f.read(n)


class HttpFile:
    def __init__(self, url):
        self.url = url
        r = urllib.request.urlopen(urllib.request.Request(url, method="HEAD"))
        self.size = int(r.headers["Content-Length"])

    def read(self, off, n):
        end = min(off + n, self.size) - 1
        req = urllib.request.Request(self.url, headers={"Range": f"bytes={off}-{end}"})
        return urllib.request.urlopen(req).read()


def find_member(f, want):
    """Locate a zip member via EOCD/zip64 + central directory (range reads)."""
    win = min(f.size, 66000)
    tail = f.read(f.size - win, win)
    idx = len(tail) - 22
    if tail[idx:idx + 4] != b"PK\x05\x06":
        idx = tail.rfind(b"PK\x05\x06")
    _, _, _, n_total, cd_size, cd_off, _ = struct.unpack_from("<IHHHHIIH", tail, idx)[:7]
    li = tail.rfind(b"PK\x06\x07")                       # zip64 locator wins
    if li >= 0:
        z64 = struct.unpack_from("<Q", tail, li + 8)[0]
        zrec = f.read(z64, 56)
        n_total = struct.unpack_from("<Q", zrec, 32)[0]
        cd_size = struct.unpack_from("<Q", zrec, 40)[0]
        cd_off = struct.unpack_from("<Q", zrec, 48)[0]
    cd = f.read(cd_off, cd_size)
    p = 0
    while p < len(cd) and cd[p:p + 4] == b"PK\x01\x02":
        (_, _, _, _, method, _, _, _, csize, usize,
         nlen, elen, clen2, _, _, _, lho) = struct.unpack_from("<IHHHHHHIIIHHHHHII", cd, p)
        name = cd[p + 46:p + 46 + nlen].decode("utf-8", "replace")
        if csize == 0xFFFFFFFF or usize == 0xFFFFFFFF or lho == 0xFFFFFFFF:
            extra = cd[p + 46 + nlen:p + 46 + nlen + elen]
            q, vals = 0, []
            while q + 4 <= len(extra):
                hid, hsz = struct.unpack_from("<HH", extra, q)
                if hid == 1:
                    o = q + 4
                    for field, cur in (("usize", usize), ("csize", csize), ("lho", lho)):
                        if cur == 0xFFFFFFFF:
                            vals.append((field, struct.unpack_from("<Q", extra, o)[0]))
                            o += 8
                q += 4 + hsz
            for k, v in vals:
                if k == "usize": usize = v
                elif k == "csize": csize = v
                else: lho = v
        if want in name:
            lh = f.read(lho, 30)
            nl, el = struct.unpack_from("<HH", lh, 26)
            data_off = lho + 30 + nl + el
            comp = f.read(data_off, csize)
            raw = comp if method == 0 else zlib.decompressobj(-15).decompress(comp, usize)
            assert len(raw) == usize, f"{name}: {len(raw)} != {usize}"
            return name, raw
        p += 46 + nlen + elen + clen2
    return None, None


def im4p_payload(img4):
    """DER IM4P -> (type, payload)."""
    def der(off):
        tag = img4[off]; l = img4[off + 1]; o = off + 2
        if l & 0x80:
            k = l & 0x7F
            l = int.from_bytes(img4[o:o + k], "big"); o += k
        return tag, l, o
    _, _, o = der(0)                 # SEQUENCE
    _, L, o = der(o); o += L         # 'IM4P'
    _, L, o = der(o); rtype = img4[o:o + L]; o += L   # 'rdsk'
    _, L, o = der(o); o += L         # version
    _, L, o = der(o)                 # OCTET STRING payload
    return rtype, img4[o:o + L]


def decompress_resource(fb):
    """decmpfs chunked resource fork -> original bytes (zlib chunks)."""
    if len(fb) < 300:
        return None
    doff = struct.unpack_from(">I", fb, 0)[0]
    if doff < 256 or doff >= len(fb):
        return None
    d = fb[doff:]
    try:
        n = struct.unpack_from("<I", d, 4)[0]
        if n == 0 or n > 100000 or 8 + 8 * n > len(d):
            return None
        out = bytearray()
        for i in range(n):
            off, ln = struct.unpack_from("<II", d, 8 + 8 * i)
            out += zlib.decompress(d[4 + off: 4 + off + ln])
        return bytes(out)
    except Exception:
        return None


class HFSX:
    """Minimal HFSX/HFS+ catalog walker with decmpfs support."""

    def __init__(self, blob):
        self.blob = blob
        base = 0
        for b in range(64):
            if blob[b + 1024:b + 1026] in (b"HX", b"H+"):
                base = b
                break
        self.base = base
        vh = blob[base + 1024: base + 1024 + 512]
        self.bs = struct.unpack_from(">I", vh, 40)[0]
        cat_size = struct.unpack_from(">Q", vh, 272)[0]
        exts = [struct.unpack_from(">II", vh, 288 + 8 * i)
                for i in range(8) if struct.unpack_from(">II", vh, 288 + 8 * i)[1]]
        self.cat = self.fork_bytes(cat_size, exts)
        (self.depth, self.root, self.leafrec, self.first_leaf, self.last_leaf,
         self.nsz, self.maxkey, self.totnodes, self.freenodes) = \
            struct.unpack_from(">HIIIIHHII", self.cat, 14)

    def fork_bytes(self, size, exts):
        out, rem = bytearray(), size
        for sb, bc in exts:
            k = min(bc * self.bs, rem)
            if k <= 0:
                break
            o = self.base + sb * self.bs
            out += self.blob[o:o + k]
            rem -= k
        return bytes(out)

    def node(self, i):
        return self.cat[i * self.nsz:(i + 1) * self.nsz]

    def recs(self, buf):
        nrec = struct.unpack_from(">H", buf, 10)[0]
        raw = struct.unpack_from(f">{nrec + 1}H", buf, self.nsz - 2 * (nrec + 1))
        o = tuple(reversed(raw))                     # table is last-record-first
        return [(o[i], o[i + 1]) for i in range(nrec)]

    def leaves(self):
        out = []
        def rec(i):
            b = self.node(i)
            kind = struct.unpack_from(">b", b, 8)[0]
            if kind == -1:
                out.append(i); return
            if kind == 0:
                for s, e in self.recs(b):
                    if e - s >= 4 and s + 8 <= len(b):
                        klen = struct.unpack_from(">H", b, s)[0]
                        nlen = struct.unpack_from(">H", b, s + 6)[0]
                        vo = s + 516 if klen == 516 else s + 8 + 2 * nlen
                        if vo + 4 <= len(b):
                            c = struct.unpack_from(">I", b, vo)[0]
                            if 0 <= c < self.totnodes:
                                rec(c)
        rec(self.root)
        return out

    def files(self):
        """{path: bytes} for every regular file (decmpfs decoded)."""
        files, folders = {}, {}
        for ln in self.leaves():
            b = self.node(ln)
            for s, e in self.recs(b):
                if e - s < 8:
                    continue
                klen = struct.unpack_from(">H", b, s)[0]
                parent = struct.unpack_from(">I", b, s + 2)[0]
                nlen = struct.unpack_from(">H", b, s + 6)[0]
                name = b[s + 8:s + 8 + 2 * nlen].decode("utf-16-be", "replace")
                r = s + 516 if klen == 516 else s + 8 + 2 * nlen
                if r + 2 > len(b):
                    continue
                rt = struct.unpack_from(">H", b, r)[0]
                if rt == 3:      # thread record: key.parent = own cnid
                    vp = struct.unpack_from(">I", b, r + 4)[0]
                    nl2 = struct.unpack_from(">H", b, r + 8)[0]
                    folders[parent] = (vp, b[r + 10:r + 10 + nl2 * 2]
                                       .decode("utf-16-be", "replace"))
                elif rt == 1:
                    folders[struct.unpack_from(">I", b, r + 8)[0]] = (parent, name)
                elif rt == 2:
                    fid = struct.unpack_from(">I", b, r + 8)[0]
                    lsz = struct.unpack_from(">Q", b, r + 88)[0]
                    if lsz:      # plain data fork
                        exts = [struct.unpack_from(">II", b, r + 104 + 8 * i)
                                for i in range(8)
                                if struct.unpack_from(">II", b, r + 104 + 8 * i)[1]]
                        files[fid] = (parent, name, self.fork_bytes(lsz, exts))
                    else:        # decmpfs: compressed bytes in resource fork
                        rsz = struct.unpack_from(">Q", b, r + 168)[0]
                        rext = [struct.unpack_from(">II", b, r + 184 + 8 * i)
                                for i in range(8)
                                if struct.unpack_from(">II", b, r + 184 + 8 * i)[1]]
                        if rsz:
                            content = decompress_resource(self.fork_bytes(rsz, rext))
                            if content is not None:
                                files[fid] = (parent, name, content)

        def path_of(cnid):
            parts, seen, cur = [], set(), cnid
            while cur not in (1, 2, 0) and cur not in seen:
                seen.add(cur)
                pp, nn = folders.get(cur, (None, None))
                if pp is None:
                    break
                if nn:
                    parts.append(nn)
                cur = pp
            return "/" + "/".join(reversed(parts))

        return {path_of(par) + "/" + nm: data
                for fid, (par, nm, data) in files.items()}


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_IPSW
    outdir = sys.argv[2] if len(sys.argv) > 2 else "ramdisk-userland"
    f = HttpFile(src) if src.startswith("http") else LocalFile(src)
    os.makedirs(outdir, exist_ok=True)
    for member in MEMBERS:
        name, raw = find_member(f, member)
        if raw is None:
            print(f"{member}: not in IPSW"); continue
        rtype, payload = im4p_payload(raw)
        print(f"{member}: IM4P type={rtype.decode()} payload={len(payload):,} "
              f"(raw HFSX — no LZFSE)")
        vol = HFSX(payload)
        paths = vol.files()
        print(f"  {len(paths):,} files decoded")
        n = 0
        for p, data in sorted(paths.items()):
            if any(t in p for t in TARGETS):
                out = os.path.join(outdir, p.strip("/").replace("/", "_"))
                with open(out, "wb") as g:
                    g.write(data)
                print(f"  -> {out} ({len(data):,} bytes)")
                n += 1
        if n == 0:
            print("  (no targets matched)")


if __name__ == "__main__":
    main()
