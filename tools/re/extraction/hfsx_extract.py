#!/usr/bin/env python3
"""Minimal HFSX/HFS+ volume reader: list all files, extract by path.
TN1150 semantics, empirical fork offsets for this volume layout."""
import struct, sys, os

VOL = sys.argv[1] if len(sys.argv) > 1 else "/tmp/038-44087-125.dmg"
MODE = sys.argv[2] if len(sys.argv) > 2 else "list"       # list | extract
PREFIX = sys.argv[3] if len(sys.argv) > 3 else "/usr/local"
OUTDIR = sys.argv[4] if len(sys.argv) > 4 else "/tmp/rd-root"

_base_cache = {}
def rd(off, n):
    with open(VOL, "rb") as f:
        f.seek(off)
        return f.read(n)

# auto-detect DER/IMG4 prefix (VH at base+1024)
BASE = 0
head = rd(0, 4096)
for b in range(0, 64):
    if head[b + 1024:b + 1026] in (b"HX", b"H+"):
        BASE = b
        break
vh = rd(BASE + 1024, 512)
sig = vh[:2]
assert sig in (b"H+", b"HX"), f"not HFS+/HFSX: {sig!r}"
block_size = struct.unpack_from(">I", vh, 40)[0]
print(f"base={BASE} vol={sig.decode()} blockSize={block_size}")

def fork(forkdata):
    logical_size = struct.unpack_from(">Q", forkdata, 0)[0]
    extents = []
    for i in range(8):
        sb, bc = struct.unpack_from(">II", forkdata, 16 + i * 8)
        if bc:
            extents.append((sb, bc))
    return logical_size, extents

def read_fork(logical_size, extents):
    out = bytearray()
    remaining = logical_size
    for sb, bc in extents:
        n = min(bc * block_size, remaining)
        if n <= 0:
            break
        out += rd(BASE + sb * block_size, n)
        remaining -= n
    return bytes(out)

def decompress_resource(forkdata_bytes):
    """decmpfs chunked resource fork -> original bytes (zlib chunks)."""
    import zlib
    if len(forkdata_bytes) < 300:
        return None
    data_off = struct.unpack_from(">I", forkdata_bytes, 0)[0]
    if data_off < 256 or data_off >= len(forkdata_bytes):
        return None
    data = forkdata_bytes[data_off:]
    try:
        dlen = struct.unpack_from(">I", data, 0)[0]          # BE total length
        n = struct.unpack_from("<I", data, 4)[0]             # LE chunk count
        if n == 0 or n > 100000 or 8 + 8 * n > len(data):
            return None
        pairs = [struct.unpack_from("<II", data, 8 + 8 * i) for i in range(n)]
        out = bytearray()
        for off, ln in pairs:
            chunk = data[4 + off: 4 + off + ln]
            out += zlib.decompress(chunk)
        return bytes(out)
    except Exception:
        return None


# fork fields (empirical for this volume): alloc@112 extents@192 catalog@272
cat_size, cat_ext = fork(vh[272:272 + 80])
cat = read_fork(cat_size, cat_ext)
print(f"catalog fork: {cat_size:,} bytes, extents {cat_ext}")

depth, root_node, leaf_records, first_leaf, last_leaf, node_size, max_key, total_nodes, free_nodes = \
    struct.unpack_from(">HIIIIHHII", cat, 14)
print(f"btree: depth={depth} root={root_node} leafRec={leaf_records:,} nodeSize={node_size}")

def node(i):
    return cat[i * node_size:(i + 1) * node_size]

def records(buf):
    nrec = struct.unpack_from(">H", buf, 10)[0]
    raw = struct.unpack_from(f">{nrec + 1}H", buf, node_size - 2 * (nrec + 1))
    ordered = tuple(reversed(raw))          # table is stored last-record-first
    return [(ordered[i], ordered[i + 1]) for i in range(nrec)]

def descend(i):
    buf = node(i)
    kind = struct.unpack_from(">b", buf, 8)[0]    # signed: -1 leaf, 0 index, 1 header, 2 map
    if kind == -1:
        return [i]
    if kind == 0:
        out = []
        for s, e in records(buf):
            if e - s >= 4 and s + 8 <= len(buf):
                klen = struct.unpack_from(">H", buf, s)[0]
                nlen = struct.unpack_from(">H", buf, s + 6)[0]
                vo = s + 516 if klen == 516 else s + 8 + 2 * nlen
                if vo + 4 <= len(buf):
                    child = struct.unpack_from(">I", buf, vo)[0]
                    if 0 <= child < total_nodes:
                        out.extend(descend(child))
        return out
    raise RuntimeError(f"unexpected node kind {kind} at {i}")

leaves = descend(root_node)
print(f"leaf nodes: {len(leaves)}")

files, folders, file_content = {}, {}, {}

def parse_key(buf, s):
    klen = struct.unpack_from(">H", buf, s)[0]
    parent = struct.unpack_from(">I", buf, s + 2)[0]
    nlen = struct.unpack_from(">H", buf, s + 6)[0]
    name = buf[s + 8:s + 8 + nlen * 2].decode("utf-16-be", "replace")
    return parent, name, klen

for ln in leaves:
    buf = node(ln)
    for s, e in records(buf):
        if e - s < 8:
            continue
        parent, name, klen = parse_key(buf, s)
        nlen_k = struct.unpack_from(">H", buf, s + 6)[0]
        r = s + 516 if klen == 516 else s + 8 + 2 * nlen_k   # value offset (empirical)
        if r + 2 > len(buf):
            continue
        rt = struct.unpack_from(">H", buf, r)[0]
        if rt == 3:                        # folder/file thread: key.parentID = own cnid
            vparent = struct.unpack_from(">I", buf, r + 4)[0]
            nlen = struct.unpack_from(">H", buf, r + 8)[0]
            nm = buf[r + 10:r + 10 + nlen * 2].decode("utf-16-be", "replace")
            folders[parent] = (vparent, nm)
        elif rt == 1:                      # folder record
            cid = struct.unpack_from(">I", buf, r + 8)[0]
            folders[cid] = (parent, name)
        elif rt == 2:                      # file record
            file_id = struct.unpack_from(">I", buf, r + 8)[0]
            logical, ext = fork(buf[r + 88:r + 88 + 80])
            files[file_id] = (parent, name, logical, ext)
            if logical == 0:
                rf = buf[r + 168:r + 168 + 80]
                rsz, rext = fork(rf)
                if rsz:
                    content = decompress_resource(read_fork(rsz, rext))
                    if content is not None:
                        file_content[file_id] = content
                        files[file_id] = (parent, name, len(content), ext)

def path_of(cnid):
    parts, seen, cur = [], set(), cnid
    while cur not in (1, 2, 0) and cur not in seen:
        seen.add(cur)
        p, n = folders.get(cur, (None, None))
        if p is None:
            break
        if n:
            parts.append(n)
        cur = p
    return "/" + "/".join(reversed(parts))

paths = {path_of(parent) + "/" + name: (fid, size, ext)
         for fid, (parent, name, size, ext) in files.items()}

if MODE == "list":
    hits = sorted(p for p in paths if PREFIX == "/" or p.startswith(PREFIX))
    for p in hits:
        fid, size, ext = paths[p]
        print(f"{size:>12,}  {p}")
    print(f"({len(hits)} of {len(paths)} files shown)")
else:
    os.makedirs(OUTDIR, exist_ok=True)
    n = plain = decomp = 0
    for p, (fid, size, ext) in paths.items():
        if not p.startswith(PREFIX):
            continue
        # need the raw record for resource forks: re-walk (store raw later)
        data = file_content.get(fid)
        if data is None:
            data = read_fork(size, ext)
        else:
            decomp += 1
        out = os.path.join(OUTDIR, p.lstrip("/"))
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "wb") as g:
            g.write(data)
        n += 1
    print(f"extracted {n} files ({decomp} via decmpfs resource chunks) -> {OUTDIR}")
