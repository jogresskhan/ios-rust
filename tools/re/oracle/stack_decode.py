#!/usr/bin/env python3
"""Decode a staged-stop log's stack region: label the known buffers
(x22 struct, ws, V2, msg, frame, r VLA, x24 struct) and dump qwords."""
import re, sys, struct

def parse(path):
    mem = {}
    for m in re.finditer(r'M5-S stop-dump (0x[0-9a-f]+) \(0x[0-9a-f]+ B\):\n((?:    \+[0-9a-f]+:(?: [0-9a-f]{2})+\n?)*)', open(path).read()):
        va = int(m.group(1), 16)
        for line in m.group(2).splitlines():
            mm = re.match(r'    \+([0-9a-f]+):((?: [0-9a-f]{2})+)', line)
            if mm:
                off = int(mm.group(1), 16)
                data = bytes.fromhex(mm.group(2).replace(' ', ''))
                for i, b in enumerate(data):
                    mem[va + off + i] = b
    return mem

def q(mem, va):
    return struct.unpack('<Q', bytes(mem[va + i] for i in range(8)))[0]

def be256(mem, va):
    return int.from_bytes(bytes(mem[va + i] for i in range(32)), 'big')

LABELS = {
    0xffffffe802fab550: 'x22 struct',
    0xffffffe802fab560: 'x20 / r-LE',
    0xffffffe802fab580: 'ws (x25 after init)',
    0xffffffe802fab5b0: 'A (MUL#1 out)',
    0xffffffe802fab5c0: 'V2',
    0xffffffe802fab5e0: 'msg [x29-0x78]',
    0xffffffe802fab608: 'frame[-0x98] pair lo',
    0xffffffe802fab610: 'frame[-0x98] pair hi',
    0xffffffe802fab618: 'frame[-0x88]',
    0xffffffe802fab630: 'r VLA ptr [x29-0x70]',
    0xffffffe802fab638: 'ctx [x29-0x68]',
    0xffffffe802fab640: 'key ctx [x29-0x60]',
    0xffffffe802fab6a0: 'x29 frame',
    0xffffffe802fab6b0: 'x24 struct',
    0xffffffe802fab6d0: 'r VLA',
    0xffffffe802fab870: 'key ctx copy (d)',
    0xffffffe802fab620: 'frame[-0x80]',
}

if __name__ == '__main__':
    path = sys.argv[1]
    lo = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0xffffffe802fab500
    hi = int(sys.argv[3], 16) if len(sys.argv) > 3 else 0xffffffe802fab7c0
    mem = parse(path)
    va = lo
    while va < hi:
        if va in LABELS:
            print(f'---- {LABELS[va]} ----')
        if all(va + i in mem for i in range(8)):
            v = q(mem, va)
            note = ''
            if 0xfffffff000000000 < v < 0xfffffff010000000:
                note = ' (KVA)'
            elif 0xffffffe000000000 < v < 0xffffffe800000000:
                note = ' (stack/heap VA)'
            print(f'{va:#x}: {v:016x}{note}')
            va += 8
        else:
            va += 8
