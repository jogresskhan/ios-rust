#!/usr/bin/env python3
"""derive_sha1_arm.py — reconstruct the ARMv8 SHA-1 crypto-instruction
semantics EMPIRICALLY (the only accepted authority: python hashlib).

The engine's VSha1Cpm (sha1c/p/m) models ONE round per lane-0 operand and
never writes Vn; the kernel FIPS HMAC-SHA1 KAT diverges completely, so the
4-round-group semantics (with the Vd/Vn lane writeback) must be pinned.
This oracle brute-forces the small candidate space:
  * sha1c/p/m: per-round Vn writeback variants + the ROR(2) folding
  * sha1su0:   3-term vs sliding-window vs 2-term
  * sha1su1:   3-term variants
and reports which combination reproduces SHA-1 end-to-end.
"""
import hashlib, itertools

M32 = 0xFFFFFFFF
ror = lambda x, n: ((x >> (n % 32)) | (x << (32 - (n % 32)))) & M32

def cho(b, c, d): return (b & c) | ((~b) & M32 & d)
def par(b, c, d): return b ^ c ^ d
def maj(b, c, d): return (b & c) | (b & d) | (c & d)

FNS = [cho, par, maj, par]  # rounds 0-19 cho, 20-39 par, 40-59 maj, 60-79 par
KS  = [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6]

def pad(msg):
    ml = len(msg) * 8
    return msg + b'\x80' + b'\x00' * ((55 - len(msg)) % 64) + ml.to_bytes(8, 'big')

def su0_variant(v, idx, din, nin, min_):
    # din/nin/min: 4-lane lists read BEFORE any write
    if idx == 0:  # sliding window (2-term, ARM-sliding)
        return [din[2] ^ min_[0], din[3] ^ min_[1], nin[0] ^ min_[2], nin[1] ^ min_[3]]
    if idx == 1:  # 3-term xor
        return [min_[i] ^ din[(i+2) % 4] ^ ror(nin[i], 2) for i in range(4)]
    if idx == 2:  # 2-term xor
        return [din[(i+2) % 4] ^ min_[i] for i in range(4)]
    if idx == 3:  # sliding window alt (Vn window)
        return [din[2] ^ min_[0], din[3] ^ min_[1], nin[2] ^ min_[2], nin[3] ^ min_[3]]

def su1_variant(v, idx, din, nin):
    if idx == 0:
        return [din[i] ^ nin[(i+1) % 4] ^ ror(nin[i], 2) for i in range(4)]
    if idx == 1:
        return [din[i] ^ nin[(i+3) % 4] ^ ror(nin[i], 2) for i in range(4)]
    if idx == 2:
        return [din[i] ^ ror(nin[(i+1) % 4], 2) ^ nin[i] for i in range(4)]
    if idx == 3:
        return [din[i] ^ nin[(i+1) % 4] ^ ror(din[i], 2) for i in range(4)]

def cpm_variant(v, idx, vd_in, vn_in, vm, op):
    """sha1c/p/m 4-round-group variants. Returns (Vd_out, Vn_out)."""
    f = FNS[op]
    A, B, C, D = list(vd_in)
    E = vn_in[0]
    T = []
    for r in range(4):
        t = (E + vm[r] + f(B, C, D) + ror(A, 2)) & M32
        T.append(t)
        A, B, C, D, E = t, A, B, C, D
    return T, list(vn_in)

def cpm_variant2(v, idx, vd_in, vn_in, vm, op):
    """variant: the K-addend folded via the sha1h E-rotation."""
    f = FNS[op]
    A, B, C, D = list(vd_in)
    E = vn_in[0]
    T = []
    for r in range(4):
        t = (E + vm[r] + f(B, C, D) + ror(A, 2) + KS[op]) & M32
        T.append(t)
        A, B, C, D, E = t, A, B, C, D
    return T, list(vn_in)

def cpm_variant3(v, idx, vd_in, vn_in, vm, op):
    """variant: software-style ROTL(A,5), E as plain state."""
    f = FNS[op]
    A, B, C, D = list(vd_in)
    E = vn_in[0]
    T = []
    for r in range(4):
        rotl5 = ((A << 5) | (A >> 27)) & M32
        t = (rotl5 + vm[r] + f(B, C, D) + E + KS[op]) & M32
        T.append(t)
        A, B, C, D, E = t, A, B, C, D
    return T, list(vn_in)

CPM = [cpm_variant, cpm_variant2, cpm_variant3]

def sha1_arm(msg, su0_i, su1_i, cpm_i, vn_wb):
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    data = pad(msg)
    for off in range(0, len(data), 64):
        blk = data[off:off+64]
        W = [int.from_bytes(blk[i:i+4], 'big') for i in range(0, 64, 4)]
        groups = [W[0:4], W[4:8], W[8:12], W[12:16]]
        vd = h[0:4]
        vn = [h[4], 0, 0, 0]
        # schedule: W4 from W0..W3 via su0/su1 (the ARM loop:
        #   for each new group: sha1su0; sha1su1)
        sched = [g[:] for g in groups]
        for g in range(4):
            wg = sched[g]
            # schedule the NEXT group (if any)
            if g < 3:
                if g == 0:
                    nxt = su0_variant(0, su0_i, sched[3], sched[g+1] if g+1 < 4 else [0]*4, wg)
                    # cand A expects (din=W3, nin=?, m=Wg): for g=0 the ARM asm is
                    # sha1su0 vW4, vW2, vW0 then sha1su1 vW4, vW1
                    nxt = su0_variant(0, su0_i, sched[3], sched[2], wg)
                    nxt = su1_variant(0, su1_i, nxt, sched[1])
                else:
                    base = [sched[(g+k) % 4] for k in range(4)]
                    nxt = su0_variant(0, su0_i, base[3], base[2], wg)
                    nxt = su1_variant(0, su1_i, nxt, base[1])
                sched[(g+3) % 4] = nxt
            # 4 rounds: op pattern per absolute round t = g*4+r
            op = 0 if g == 0 else 1 if g in (1, 3) else 2
            T, vn_out = CPM[cpm_i](0, 0, vd, vn, wg, op)
            if vn_wb:
                vn_out = [T[0], T[1], T[2], T[3]]
            vd = T
            vn = vn_out
        # finalize: the 5th state word + the sha1h chain
        e_final = h[4]
        # the engine-equivalent end: h' = {vd, e'} — accumulate
        h = [vd[0], vd[1], vd[2], vd[3], vn[0]]
    return b''.join(x.to_bytes(4, 'big') for x in h)

target = hashlib.sha1(b'abc').digest()
print('sha1(abc) =', target.hex())
best = None
for su0_i in range(4):
    for su1_i in range(4):
        for cpm_i in range(3):
            for vn_wb in (False, True):
                try:
                    got = sha1_arm(b'abc', su0_i, su1_i, cpm_i, vn_wb)
                except Exception as ex:
                    continue
                if got == target:
                    print(f'MATCH: su0={su0_i} su1={su1_i} cpm={cpm_i} vn_wb={vn_wb}')
                    best = (su0_i, su1_i, cpm_i, vn_wb)
if best is None:
    print('no combination matched — need more candidates')
