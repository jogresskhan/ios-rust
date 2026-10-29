#!/usr/bin/env python3
"""M4-A: /cpus contents of the real DeviceTree fixture.

Decodes fixtures/DeviceTree.n104ap.im4p (IM4P -> LZFSE bvx2) independently
(liblzfse), verifies it matches the session copy /tmp/adt-n104ap.bin by
sha256, parses the Apple flat tree (LE), and dumps /cpus + every cpu child
with raw property bytes so the enumerator's view is on record.
"""
import sys, struct, hashlib

FIXTURE = '/home/z/my-project/download/ios-rust/fixtures/DeviceTree.n104ap.im4p'
SESSION = '/tmp/adt-n104ap.bin'

raw = open(FIXTURE, 'rb').read()
i = raw.find(b'IM4P')
assert i >= 0, 'no IM4P fourcc'
print(f'IM4P container: fourcc at 0x{i:x}, type={raw[i+4:i+8]!r}, '
      f'description={raw[i+8:i+8+0x20].rstrip(b"\0")!r}')
# DER OCTET STRING holding the LZFSE payload: find 0x04 0x82 <len hi> <len lo>
j = raw.find(b'\x04\x82', i)
ln = struct.unpack_from('>H', raw, j + 2)[0]
payload = raw[j + 4: j + 4 + ln]
print(f'LZFSE payload: DER OCTET STRING len={ln:#x}, magic={payload[:4]!r}')

import liblzfse
dt = liblzfse.decompress(payload)
print(f'decompressed: {len(dt)} bytes')

sha_f = hashlib.sha256(dt).hexdigest()
sess = open(SESSION, 'rb').read()
sha_s = hashlib.sha256(sess).hexdigest()
print(f'sha256 fixture-decoded = {sha_f}')
print(f'sha256 /tmp copy       = {sha_s}')
print(f'MATCH: {sha_f == sha_s}')

# ---- flat tree parse (Apple format, little-endian per M5 finding) ----
def u32(b, o):
    return struct.unpack_from('<I', b, o)[0]

class Node:
    def __init__(s, off):
        s.off = off
        s.nprops = u32(dt, off)
        s.nchildren = u32(dt, off + 4)
        s.props = {}
        s.prop_order = []
        o = off + 8
        for _ in range(s.nprops):
            name = dt[o:o + 32].rstrip(b'\0').decode('ascii', 'replace')
            plen = u32(dt, o + 32)
            data = dt[o + 36: o + 36 + plen]
            s.props[name] = data
            s.prop_order.append(name)
            o += 36 + ((plen + 3) & ~3)
        s.child_off = o
        s.children = []
        s.parent = None
        s.path = '?'

    def walk(s, path):
        s.path = path
        o = s.child_off
        for _ in range(s.nchildren):
            c = Node(o)
            c.parent = s
            s.children.append(c)
            o = c.walk_end(o)

    def walk_end(s, start):
        s.walk_start = start
        c = Node(start)
        c.parent = s
        s.children.append(c)
        o = c.end_after_parse(start)
        for k in range(len(s.children) - 1, -1, -1):
            pass
        return o

    def end_after_parse(s, start):
        # parse node at start fully (props then children recursively)
        s2 = Node(start)
        s2.walk_done = True
        s.children = s2.children
        s.props = s2.props
        s.prop_order = s2.prop_order
        s.nprops, s.nchildren = s2.nprops, s2.nchildren
        o = s2.child_off
        for _ in range(s2.nchildren):
            child = Node.__new__(Node)
            child.props = {}
            child.prop_order = []
            child.parent = s
            o = end_after_parse(child, o)
            s.children[_] = child
        return o

# simpler recursive parser (returns node dict + end offset)
def parse_node(off, path, name_hint=''):
    nprops, nchildren = u32(dt, off), u32(dt, off + 4)
    o = off + 8
    props = {}
    order = []
    for _ in range(nprops):
        name = dt[o:o + 32].rstrip(b'\0').decode('ascii', 'replace')
        plen = u32(dt, o + 32) & 0x7fffffff   # bit31 = placeholder flag (M5 finding)
        props[name] = dt[o + 36:o + 36 + plen]
        order.append(name)
        o += 36 + ((plen + 3) & ~3)
    node = dict(path=path, props=props, order=order, children=[], off=off)
    for k in range(nchildren):
        child, o = parse_node(o, path + '/?')
        node['children'].append(child)
    return node, o

def name_of(node):
    n = node['props'].get('name', b'?').decode('ascii', 'replace')
    return n.rstrip('\x00')

def fix_names(node, parent_path):
    nm = name_of(node)
    path = parent_path + '/' + nm
    node['path'] = path
    for c in node['children']:
        fix_names(c, path)

def find(node, path):
    if node['path'] == path:
        return node
    for c in node['children']:
        r = find(c, path)
        if r:
            return r
    return None

root, _end = parse_node(0, '/')
fix_names(root, '')
print(f'tree parsed: root props={list(root["props"])[:6]} … children={[name_of(c) for c in root["children"]]}')
print(f'parse consumed { _end } of {len(dt)} bytes')

def dump(node, full=True):
    p = node['props']
    print(f'== {node["path"]} ==  (nprops={len(p)})')
    for k in node['order']:
        v = p[k]
        if len(v) <= 32:
            hx = v.hex()
        else:
            hx = v[:32].hex() + '…'
        print(f'   {k} = [{len(v)} B] {hx}')

root_name = root['props'].get('name', b'').decode().rstrip('\x00')
tree_root = '/device-tree' if root_name == 'device-tree' else ''
cpus = find(root, tree_root + '/cpus')
print()
print('### /cpus node + children (full raw property dump, LE) ###')
dump(cpus)
for c in cpus['children']:
    dump(c)

# known-property interpretations
print()
print('### interpreted ###')
for c in cpus['children']:
    p = c['props']
    nm = name_of(c)
    reg = p.get('reg')
    regv = struct.unpack(f'<{len(reg)//4}I', reg) if reg else None
    compat = p.get('compatible', b'').decode('ascii', 'replace')
    state = p.get('state', b'').decode('ascii', 'replace')
    irst = struct.unpack(f'<{len(p["interrupts"])//4}I', p['interrupts']) if 'interrupts' in p else None
    print(f'{nm}: reg(LE u32)={regv} compatible={compat!r} state={state!r} '
          f'interrupts={list(irst) if irst else None} cluster-type={p.get("cluster-type", b"").decode()}')

# timebase / clock frequency probes anywhere in the tree
print()
probes = ('timebase-frequency', 'fixed-frequency', 'clock-frequency', 'bus-frequency')
for probe in probes:
    hits = []
    def scan(n):
        if probe in n['props']:
            hits.append((n['path'], n['props'][probe].hex()))
        for c in n['children']:
            scan(c)
    scan(root)
    print(f'"{probe}": {len(hits)} node(s)' + (' — ' + ', '.join(f'{p}={h}' for p, h in hits[:8]) if hits else ''))

# /chosen quick facts (memory-map presence matters for later boot stages)
for want in (tree_root + '/chosen', tree_root + '/memory', tree_root + '/chosen/memory-map'):
    n = find(root, want)
    if n:
        print(f'{want}: props={n["order"][:24]}')
    else:
        print(f'{want}: NOT FOUND')
