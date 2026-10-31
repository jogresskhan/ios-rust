#!/usr/bin/env python3
"""Debug the sha1_arm caller: compare per-group state vs reference SHA-1."""
import sys
sys.path.insert(0, 'tools/re/oracle')
from derive_sha1_arm import (sha1_cpm, sha1h, sha1su0, sha1su1, lanes, pack, K1, M32, rol, ror)

def ref_sha1_states(msg):
    """Reference SHA-1 with per-group (every 4 rounds) state snapshots."""
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    ml = len(msg) * 8
    data = msg + b'\x80' + b'\x00' * ((55 - len(msg)) % 64) + ml.to_bytes(8, 'big')
    cho = lambda b, c, d: (b & c) | (~b & d)
    par = lambda b, c, d: b ^ c ^ d
    maj = lambda b, c, d: (b & c) | (b & d) | (c & d)
    out = []
    for off in range(0, len(data), 64):
        blk = data[off:off + 64]
        W = [int.from_bytes(blk[i:i + 4], 'big') for i in range(0, 64, 4)]
        W += [0] * 64
        for t in range(16, 80):
            W[t] = rol(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1)
        a, b, c, d, e = h
        for g in range(20):
            f = (cho, par, maj, par)[g // 5]
            k = K1[g // 5]
            for r in range(4):
                t = g * 4 + r
                T = (rol(a, 5) + f(b, c, d) + e + W[t] + k) & M32
                e, d, c, b, a = d, c, rol(b, 30), a, T
            out.append((g, a, b, c, d, e))
        h = [(x + y) & M32 for x, y in zip(h, [a, b, c, d, e])]
    return out

def arm_states(msg):
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    ml = len(msg) * 8
    data = msg + b'\x80' + b'\x00' * ((55 - len(msg)) % 64) + ml.to_bytes(8, 'big')
    out = []
    for off in range(0, len(data), 64):
        blk = data[off:off + 64]
        W = [int.from_bytes(blk[i:i + 4], 'big') for i in range(0, 64, 4)]
        msg_regs = [pack(W[0:4]), pack(W[4:8]), pack(W[8:12]), pack(W[12:16])]
        abcd = pack(h[0:4])
        e = h[4]
        e_next = sha1h(abcd & M32)
        for grp in range(20):
            fn = (0, 1, 2, 1)[grp // 5]
            ki = K1[grp // 5]
            w_plus_k = pack([(x + ki) & M32 for x in lanes(msg_regs[0])])
            abcd, _ = sha1_cpm(abcd, e, w_plus_k, fn)
            e = e_next
            e_next = sha1h(abcd & M32)
            if grp < 19:
                msg_regs[0] = sha1su0(msg_regs[0], msg_regs[1], msg_regs[2])
                msg_regs[0] = sha1su1(msg_regs[0], msg_regs[3])
                msg_regs.append(msg_regs.pop(0))
            out.append((grp,) + tuple(lanes(abcd)) + (e,))
    return out

ref = ref_sha1_states(b'abc')
arm = arm_states(b'abc')
for (g, a, b, c, d, e), (g2, A, B, C, D, E) in zip(ref, arm):
    mark = "OK " if (a, b, c, d, e) == (A, B, C, D, E) else "BAD"
    if mark == "BAD" or g < 3:
        print(f"{mark} group {g:2}: ref=({a:08x},{b:08x},{c:08x},{d:08x},{e:08x}) arm=({A:08x},{B:08x},{C:08x},{D:08x},{E:08x})")
    if mark == "BAD":
        break
