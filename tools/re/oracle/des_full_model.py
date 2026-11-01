#!/usr/bin/env python3
"""BUG #54: the FULL python model of the kernel's 3DES chain —
schedule (PC1/rot/PC2/spread) -> NEON repack -> SP-table block fn —
validated against pycryptodome. Then diff each stage against the engine."""

import struct, sys
sys.path.insert(0, '/home/z/my-project/scripts/re')
import kc

BASE = 0xfffffff000000000
M32 = 0xFFFFFFFF

def rd(va, n):
    o = kc.va2off(BASE + va)
    return kc._mm[o:o+n]

pc1 = rd(0x7051d38, 56)
bitmask = struct.unpack('<8I', rd(0x7051d70, 32))
shifts = rd(0x7051d90, 16)
pc2 = rd(0x7051da0, 48)
spread = struct.unpack('<24I', rd(0x7051dd0, 96))
SP = []
for t in range(8):
    o = kc.va2off(BASE + 0x7051e30 + t*0x100)
    SP.append(struct.unpack('<64I', kc._mm[o:o+256]))

def ror(v, n):
    return ((v >> n) | (v << (32 - n))) & M32

def schedule_raw(key8, decrypt):
    """returns [(klo, khi) * 16] — the pre-repack spread-format subkeys"""
    CD = []
    for i in range(56):
        v = pc1[i]
        byte = key8[v >> 3]
        mask = bitmask[v & 7]
        CD.append(1 if (byte & mask) == mask else 0)
    out = []
    for r in range(16):
        rr = (15 - r) if decrypt else r
        C = [CD[(shifts[r] + j) % 28] for j in range(28)]
        D = [CD[28 + ((shifts[r] + j) % 28)] for j in range(28)]
        CDw = C + D
        klo = khi = 0
        for j in range(24):
            if CDw[pc2[j]]:
                klo |= spread[j]
            if CDw[pc2[j + 24]]:
                khi |= spread[j]
        out.append((klo, khi))
    return out

def repack(raw):
    """the NEON repack (0x82e2d10..58): (klo,khi) -> (klo', khi')"""
    out = []
    for klo, khi in raw:
        # v5 = [0x3f, 0x3f00], v6 = [0x3f00, 0x3f] (the file constants)
        klop = (((klo << 6) & M32) & 0x3F000000) | (((klo << 10) & M32) & 0x003F0000) \
             | ((khi >> 10) & 0x00003F00) | ((khi >> 6) & 0x3F)
        khip = (((klo << 12) & M32) & 0x3F000000) | (((klo << 16) & M32) & 0x003F0000) \
             | ((khi >> 4) & 0x00003F00) | (khi & 0x3F)
        out.append((klop, khip))
    return out

def run_block(block, ws):
    w8 = int.from_bytes(block[0:4], 'big'); w9 = int.from_bytes(block[4:8], 'big')
    w10 = (w9 ^ (w8 >> 4)) & 0x0F0F0F0F; w9 ^= w10; w8 ^= (w10 << 4) & M32
    w10 = (w9 & 0xFFFF) ^ (w8 >> 16); w9 ^= w10; w8 ^= (w10 << 16) & M32
    w10 = (w8 ^ (w9 >> 2)) & 0x33333333; w8 ^= w10; w9 ^= (w10 << 2) & M32
    w10 = (w8 ^ (w9 >> 8)) & 0x00FF00FF; w9 ^= (w10 << 8) & M32; w8 ^= w10
    w10 = (w8 ^ ((w9 << 1) & M32)) & 0xAAAAAAAA
    w4 = w10 ^ ror(w9, 31); w8 ^= w10; w5 = ror(w8, 31)
    def sround(klo, khi, R, acc):
        t = klo ^ ror(R, 4); u = khi ^ R
        return acc ^ (SP[0][t & 0x3F] ^ SP[1][(t>>8)&0x3F] ^ SP[2][(t>>16)&0x3F] ^ SP[3][(t>>24)&0x3F]
                      ^ SP[4][u & 0x3F] ^ SP[5][(u>>8)&0x3F] ^ SP[6][(u>>16)&0x3F] ^ SP[7][(u>>24)&0x3F])
    # 3 passes over the ws segments (K1 enc, K2 dec, K3 enc)
    for base, f25 in ((0, True), (8, False), (16, True)):
        for i in range(8):
            klo, khi = ws[base + i]
            if f25:
                w5 = sround(klo, khi, w4, w5)
                klo, khi = ws[base + 8 + i]
                w4 = sround(klo, khi, w5, w4)
            else:
                w4 = sround(klo, khi, w5, w4)
                klo, khi = ws[base + 8 + i]
                w5 = sround(klo, khi, w4, w5)
    # final permutation
    m11, m9, m8, m10 = 0xAAAAAAAA, 0x33333333, 0x0F0F0F0F, 0x00FF00FF
    w12 = w5 ^ ror(w4, 1); w11 = w12 & m11; w12 = w11 ^ w5
    w11 = w11 ^ ror(w4, 1)
    w12 = ((w5 << 31) | (w12 >> 1)) & M32
    w13 = w11 ^ (w12 >> 8); w10b = w13 & m10; w11 = w10b ^ w11
    w10b = w12 ^ ((w10b << 8) & M32); w12 = w11 ^ (w10b >> 2)
    w9b = w12 & m9; w11 = w9b ^ w11; w9b = w10b ^ ((w9b << 2) & M32)
    w10c = w9b & 0xFFFF; w10c ^= (w11 >> 16); w9b = w10c ^ w9b
    w10d = w11 ^ ((w10c << 16) & M32); w11 = w9b ^ (w10d >> 4)
    w8b = w11 & m8; w9b = w8b ^ w9b; w8b = w10d ^ ((w8b << 4) & M32)
    return w8b.to_bytes(4, 'big') + w9b.to_bytes(4, 'big')

key = bytes.fromhex('5ee4db0cdfdf719e40fc962d2f31f416d9aa0f228d89e07f')
K1, K2, K3 = key[0:8], key[8:16], key[16:24]
block = bytes.fromhex('311a13867bd5d111')

raw1 = schedule_raw(K1, False)
raw2 = schedule_raw(K2, True)
raw3 = schedule_raw(K3, False)
ws = repack(raw1) + repack(raw2) + repack(raw3)
out = run_block(block, ws)
print('full python chain:', out.hex())
print('pycryptodome     : 68c06c8af772abff')

from Crypto.Cipher import DES3
true = DES3.new(key, DES3.MODE_ECB).encrypt(block)
print('pycryptodome ECB:', true.hex(), 'MATCH' if true.hex() == out.hex() else 'DIFFER')
# stage dumps for the engine diff
print()
print('raw K1 round0 :', f'{raw1[0][0]:08x} {raw1[0][1]:08x}')
print('repack K1 r0  :', f'{ws[0][0]:08x} {ws[0][1]:08x}')
print('repack K1 r0 bytes:', struct.pack('<II', ws[0][0], ws[0][1]).hex())
