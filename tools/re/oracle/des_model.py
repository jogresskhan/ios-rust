#!/usr/bin/env python3
"""BUG #54: exact python model of the kernel's 3DES block fn 0x82e2fd0
(the SP-table DES with folded IP/FP), driven with the CAPTURED scheduled
keys (ws @0xffffffe802fab598, boot stop at the ECB call) — decides whether
the ws (key schedule) or the engine's execution diverges."""

import re, struct, sys
sys.path.insert(0, '/home/z/my-project/scripts/re')
import kc

BASE = 0xfffffff000000000
M32 = 0xFFFFFFFF

def ror(v, n):
    return ((v >> n) | (v << (32 - n))) & M32

# SP tables from the kernel file (verified == runtime)
SP = []
for t in range(8):
    off = kc.va2off(BASE + 0x7051e30 + t * 0x100)
    SP.append(struct.unpack('<64I', kc._mm[off:off + 256]))

# the captured scheduled keys: parse the boot log's stop-dump
def parse_dump(path, want_va):
    mem = {}
    for m in re.finditer(r'M5-S stop-dump (0x[0-9a-f]+) \(0x[0-9a-f]+ B\):\n((?:    \+[0-9a-f]+:(?: [0-9a-f]{2})+\n?)*)', open(path).read()):
        va = int(m.group(1), 16)
        if va != want_va:
            continue
        for line in m.group(2).splitlines():
            mm = re.match(r'    \+([0-9a-f]+):((?: [0-9a-f]{2})+)', line)
            if mm:
                off = int(mm.group(1), 16)
                data = bytes.fromhex(mm.group(2).replace(' ', ''))
                for i, b in enumerate(data):
                    mem[va + off + i] = b
    return mem

mem = parse_dump('/tmp/boot-V-des.log', 0xffffffe802fab580)
ws = bytes(mem[0xffffffe802fab598 + i] for i in range(0x180))
print('ws[0:16] :', ws[:16].hex())
print('ws[0x80:0x90]:', ws[0x80:0x90].hex())
print('ws[0x100:0x110]:', ws[0x100:0x110].hex())

# inputs
pin = bytes.fromhex('88137a562beab0e2')
iv = bytes.fromhex('b90969d0503f61f3')
block = bytes(a ^ b for a, b in zip(pin, iv))
print('block (in^iv):', block.hex())

def run(block, ws):
    # the caller BE-loaded the block into the 8-byte buffer: sp[0:4] = rev32(block[0:4]) etc.
    # ldp w8, w9 reads them back as the BE values.
    w8 = int.from_bytes(block[0:4], 'big')
    w9 = int.from_bytes(block[4:8], 'big')
    # ---- initial permutation (0x82e2fec..0x82e303c) ----
    w10 = (w9 ^ (w8 >> 4)) & 0x0F0F0F0F
    w9 ^= w10
    w8 ^= (w10 << 4) & M32
    w10 = (w9 & 0xFFFF) ^ (w8 >> 16)
    w9 ^= w10
    w8 ^= (w10 << 16) & M32
    w10 = (w8 ^ (w9 >> 2)) & 0x33333333
    w8 ^= w10
    w9 ^= (w10 << 2) & M32
    w10 = (w8 ^ (w9 >> 8)) & 0x00FF00FF
    w9 ^= (w10 << 8) & M32
    w8 ^= w10
    w10 = (w8 ^ ((w9 << 1) & M32)) & 0xAAAAAAAA
    w4 = w10 ^ ror(w9, 31)
    w8 ^= w10
    w5 = ror(w8, 31)

    def sround(klo, khi, R, acc):
        t = klo ^ ror(R, 4)
        u = khi ^ R
        s = (SP[0][t & 0x3F] ^ SP[1][(t >> 8) & 0x3F] ^ SP[2][(t >> 16) & 0x3F] ^ SP[3][(t >> 24) & 0x3F]
             ^ SP[4][u & 0x3F] ^ SP[5][(u >> 8) & 0x3F] ^ SP[6][(u >> 16) & 0x3F] ^ SP[7][(u >> 24) & 0x3F])
        return acc ^ s

    def pass_loop(base, first_to_w5):
        nonlocal w4, w5
        for i in range(0, 0x80, 16):
            k = struct.unpack_from('<4I', ws, base + i)
            if first_to_w5:
                w5 = sround(k[0], k[1], w4, w5)
                w4 = sround(k[2], k[3], w5, w4)
            else:
                w4 = sround(k[0], k[1], w5, w4)
                w5 = sround(k[2], k[3], w4, w5)

    pass_loop(0x000, first_to_w5=True)    # K1 encrypt
    pass_loop(0x080, first_to_w5=False)   # K2 (reversed schedule = decrypt)
    pass_loop(0x100, first_to_w5=True)    # K3 encrypt

    # ---- final permutation (0x82e3358..0x82e33ac) ----
    m11, m9, m8, m10 = 0xAAAAAAAA, 0x33333333, 0x0F0F0F0F, 0x00FF00FF
    w12 = w5 ^ ror(w4, 1)
    w11 = w12 & m11
    w12 = w11 ^ w5
    w11 = w11 ^ ror(w4, 1)
    w12 = ((w5 << 31) | (w12 >> 1)) & M32          # extr w12, w5, w12, #1
    w13 = w11 ^ (w12 >> 8)
    w10b = w13 & m10
    w11 = w10b ^ w11
    w10b = w12 ^ ((w10b << 8) & M32)
    w12 = w11 ^ (w10b >> 2)
    w9b = w12 & m9
    w11 = w9b ^ w11
    w9b = w10b ^ ((w9b << 2) & M32)
    w10c = w9b & 0xFFFF
    w10c = w10c ^ (w11 >> 16)
    w9b = w10c ^ w9b
    w10d = w11 ^ ((w10c << 16) & M32)
    w11 = w9b ^ (w10d >> 4)
    w8b = w11 & m8
    w9b = w8b ^ w9b
    w8b = w10d ^ ((w8b << 4) & M32)
    return w8b.to_bytes(4, 'big') + w9b.to_bytes(4, 'big')

out = run(block, ws)
print()
print('model out (captured ws):', out.hex())
print('engine out (wrong)     :', 'a83c81282d62a782')
print('true 3DES-CBC          :', '68c06c8af772abff')

# also: is the model itself sane? run with a PYTHON-GENERATED schedule
# (the ws format = 16 rounds x 8 bytes x 3 keys, IP/FP-folded — we cannot
# generate it without the schedule fn, so this is ws-as-captured only).
