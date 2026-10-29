#!/usr/bin/env python3
"""In-memory pipeline: IPSW range-request -> member -> HFSX volume -> binaries.
Writes ONLY the requested target files to disk."""
import struct, sys, urllib.request, zlib

IPSW = ("https://updates.cdn-apple.com/2020SummerSeed/fullrestores/001-35886/"
        "5FE9BE2E-17F8-41C8-96BB-B76E2B225888/"
        "iPhone11,8,iPhone12,1_14.0_18A5351d_Restore.ipsw")
OUT = "/tmp/bin"


class HttpRange:
    def __init__(self, url):
        self.url = url
        r = urllib.request.urlopen(urllib.request.Request(url, method="HEAD"))
        self.size = int(r.headers["Content-Length"])

    def read(self, off, n):
        end = min(off + n, self.size) - 1
        req = urllib.request.Request(self.url, headers={"Range": f"bytes={off}-{end}"})
        return urllib.request.urlopen(req).read()


def member_blob(f, want):
    """Return (name, uncompressed_bytes) for first member containing `want`."""
    win = min(f.size, 66000)
    tail = f.read(f.size - win, win) if f.size > win else f.read(0, f.size)
    n = len(tail)
    idx = n - 22
    if tail[idx:idx + 4] != b"PK\x05\x06":
        idx = tail.rfind(b"PK\x05\x06")
    disk, cd_disk, n_disk, n_total, cd_size, cd_off, clen = \
        struct.unpack_from("<IHHHHIIH", tail, idx)[:7]
    li = tail.rfind(b"PK\x06\x07")          # zip64 locator wins if present
    if li >= 0:
        z64_off = struct.unpack_from("<Q", tail, li + 8)[0]
        zrec = f.read(z64_off, 56)
        n_total = struct.unpack_from("<Q", zrec, 32)[0]
        cd_size = struct.unpack_from("<Q", zrec, 40)[0]
        cd_off = struct.unpack_from("<Q", zrec, 48)[0]
    cd = f.read(cd_off, cd_size)
    p = 0
    while p < len(cd) and cd[p:p + 4] == b"PK\x01\x02":
        (sig, vmade, vneed, flags, method, mt, md, crc, csize, usize,
         nlen, elen, clen2, dsk, iattr, eattr, lho) = struct.unpack_from("<IHHHHHHIIIHHHHHII", cd, p)
        name = cd[p + 46:p + 46 + nlen].decode("utf-8", "replace")
        if csize == 0xFFFFFFFF or usize == 0xFFFFFFFF or lho == 0xFFFFFFFF:
            extra = cd[p + 46 + nlen:p + 46 + nlen + elen]
            q = 0
            vals = {}
            while q + 4 <= len(extra):
                hid, hsz = struct.unpack_from("<HH", extra, q)
                if hid == 1:
                    o = q + 4
                    for key in ("usize", "csize", "lho"):
                        if key in ("usize",) and usize == 0xFFFFFFFF:
                            vals[key] = struct.unpack_from("<Q", extra, o)[0]; o += 8
                        elif key in ("csize",) and csize == 0xFFFFFFFF:
                            vals[key] = struct.unpack_from("<Q", extra, o)[0]; o += 8
                        elif key in ("lho",) and lho == 0xFFFFFFFF:
                            vals[key] = struct.unpack_from("<Q", extra, o)[0]; o += 8
                q += 4 + hsz
            usize = vals.get("usize", usize)
            csize = vals.get("csize", csize)
            lho = vals.get("lho", lho)
        if want in name:
            lh = f.read(lho, 30)
            nl, el = struct.unpack_from("<HH", lh, 26)
            doff = lho + 30 + nl + el
            comp = f.read(doff, csize)
            raw = comp if method == 0 else zlib.decompressobj(-15).decompress(comp, usize)
            assert len(raw) == usize
            return name, raw
        p += 46 + nlen + elen + clen2
    return None, None


def im4p_payload(img4):
    """DER IM4P -> (type, payload_bytes)."""
    def der(off):
        tag = img4[off]
        l = img4[off + 1]
        o = off + 2
        if l & 0x80:
            k = l & 0x7F
            l = int.from_bytes(img4[o:o + k], "big")
            o += k
        return tag, l, o
    t, L, o = der(0)                    # top SEQUENCE
    t, L, o = der(o)                    # PrintableString 'IM4P'
    o += L
    t, L, o = der(o)                    # PrintableString type ('rdsk')
    rtype = img4[o:o + L]
    o += L
    t, L, o = der(o)                    # PrintableString version
    o += L
    t, L, o = der(o)                    # OCTET STRING payload
    return rtype, img4[o:o + L]


class HFSXMem:
    def __init__(self, blob):
        self.blob = blob
        base = 0
        for b in range(64):
            if blob[b + 1024:b + 1026] in (b"HX", b"H+"):
                base = b
                break
        self.base = base
        vh = blob[base + 1024:base + 1024 + 512]
        self.block_size = struct.unpack_from(">I", vh, 40)[0]
        cat_size = struct.unpack_from(">Q", vh, 272)[0]
        exts = [(struct.unpack_from(">II", vh, 288 + 8 * i))
                for i in range(8) if struct.unpack_from(">II", vh, 288 + 8 * i)[1]]
        self.cat = self._read_fork(cat_size, exts)
        (self.depth, self.root, self.leaf_records, self.first_leaf, self.last_leaf,
         self.node_size, self.max_key, self.total_nodes, self.free_nodes) = \
            struct.unpack_from(">HIIIIHHII", self.cat, 14)

    def _read_fork(self, size, exts):
        out = bytearray()
        rem = size
        for sb, bc in exts:
            k = min(bc * self.block_size, rem)
            if k <= 0:
                break
            out += self.blob[self.base + sb * self.block_size: self.base + sb * self.block_size + k]
            rem -= k
        return bytes(out)

    def node(self, i):
        return self.cat[i * self.node_size:(i + 1) * self.node_size]

    def recs(self, buf):
        nrec = struct.unpack_from(">H", buf, 10)[0]
        raw = struct.unpack_from(f">{nrec + 1}H", buf, self.node_size - 2 * (nrec + 1))
        o = tuple(reversed(raw))
        return [(o[i], o[i + 1]) for i in range(nrec)]

    def leaves(self):
        out = []
        def rec(i):
            b = self.node(i)
            kind = struct.unpack_from(">b", b, 8)[0]
            if kind == -1:
                out.append(i)
                return
            if kind == 0:
                for s, e in self.recs(b):
                    if e - s >= 4 and s + 8 <= len(b):
                        klen = struct.unpack_from(">H", b, s)[0]
                        nlen = struct.unpack_from(">H", b, s + 6)[0]
                        vo = s + 516 if klen == 516 else s + 8 + 2 * nlen
                        if vo + 4 <= len(b):
                            c = struct.unpack_from(">I", b, vo)[0]
                            if 0 <= c < self.total_nodes:
                                rec(c)
        rec(self.root)
        return out

    def walk(self):
        files, folders, content = {}, {}, {}
        def decompress_resource(fb):
            import zlib
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
                if rt == 3:
                    vp = struct.unpack_from(">I", b, r + 4)[0]
                    nl2 = struct.unpack_from(">H", b, r + 8)[0]
                    nm = b[r + 10:r + 10 + nl2 * 2].decode("utf-16-be", "replace")
                    folders[parent] = (vp, nm)
                elif rt == 1:
                    folders[struct.unpack_from(">I", b, r + 8)[0]] = (parent, name)
                elif rt == 2:
                    fid = struct.unpack_from(">I", b, r + 8)[0]
                    lsz = struct.unpack_from(">Q", b, r + 88)[0]
                    exts = [(struct.unpack_from(">II", b, r + 104 + 8 * i))
                            for i in range(8) if struct.unpack_from(">II", b, r + 104 + 8 * i)[1]]
                    if lsz == 0:
                        rsz = struct.unpack_from(">Q", b, r + 168)[0]
                        rext = [(struct.unpack_from(">II", b, r + 184 + 8 * i))
                                for i in range(8) if struct.unpack_from(">II", b, r + 184 + 8 * i)[1]]
                        if rsz:
                            c = decompress_resource(self._read_fork(rsz, rext))
                            if c is not None:
                                content[fid] = c
                                lsz = len(c)
                    files[fid] = (parent, name, lsz, exts)

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

        return {path_of(par) + "/" + nm: (fid, sz, ex)
                for fid, (par, nm, sz, ex) in files.items()}, content


def main():
    import os
    targets = sys.argv[1:] or ["restored", "/asr", "restored_update",
                               "configdarwinbootargs", "keystorectl"]
    os.makedirs(OUT, exist_ok=True)
    f = HttpRange(IPSW)
    for member in ("038-44135-124.dmg", "038-44087-125.dmg"):
        name, raw = member_blob(f, member)
        if raw is None:
            print(f"{member}: not found"); continue
        rtype, payload = im4p_payload(raw)
        print(f"{member}: im4p type={rtype} payload={len(payload):,}")
        vol = HFSXMem(payload)
        paths, content = vol.walk()
        print(f"  {len(paths)} files")
        for p, (fid, sz, ex) in paths.items():
            if any(t in p for t in targets):
                data = content.get(fid)
                if data is None:
                    data = vol._read_fork(sz, ex)
                out = OUT + p.replace("/", "_")
                with open(out, "wb") as g:
                    g.write(data)
                print(f"  -> {out} ({len(data):,} bytes)")


if __name__ == "__main__":
    main()
