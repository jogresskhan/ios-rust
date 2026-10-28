#!/usr/bin/env python3
"""Independent XTS-AES-128-CTS reference oracle (IEEE P1619 draft CTS scheme).

Pins the ciphertext-stealing constants used in
crates/devices/src/aes_engine.rs tests. AES-128 primitive comes from the
`cryptography` package (OpenSSL-backed); the XTS composition (little-endian
tweak schedule, GF(2^128) doubling with 0x87, P1619-draft ciphertext
stealing: C_m = CC[..b], C_{m-1} = ENC(P_m || CC[b..] ^ T_m) ^ T_m) is
implemented here from the spec, independently of the Rust code.

Usage: python3 xts_cts_ref.py   (prints the pinned vectors)
"""
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def E(k: bytes, b: bytes) -> bytes:
    c = Cipher(algorithms.AES(k), modes.ECB())
    e = c.encryptor()
    return e.update(b) + e.finalize()


def le(x: int) -> bytes:
    return x.to_bytes(16, "little")


def mul2(t: int) -> int:
    t <<= 1
    if t & (1 << 128):
        t ^= (1 << 128) | 0x87
    return t


def xts_cts_encrypt_128(dk: bytes, tk: bytes, tweak_u128: int, data: bytes) -> bytes:
    t = int.from_bytes(E(tk, le(tweak_u128)), "little")
    full, rem = divmod(len(data), 16)
    data = bytearray(data)
    for i in range(full - (1 if rem else 0)):
        x = le(t)
        blk = bytearray(data[i * 16:(i + 1) * 16])
        for j in range(16):
            blk[j] ^= x[j]
        e = E(dk, bytes(blk))
        data[i * 16:(i + 1) * 16] = bytes([e[j] ^ x[j] for j in range(16)])
        t = mul2(t)
    if rem:
        split = full * 16
        pm = bytes(data[split:])
        last = bytes(data[split - 16:split])
        x = le(t)
        cc = E(dk, bytes([last[j] ^ x[j] for j in range(16)]))
        data[split:] = cc[:rem]
        b2 = bytearray(pm + cc[rem:])
        x2 = le(mul2(t))
        for j in range(16):
            b2[j] ^= x2[j]
        e2 = E(dk, bytes(b2))
        data[split - 16:split] = bytes([e2[j] ^ x2[j] for j in range(16)])
    return bytes(data)


if __name__ == "__main__":
    KEY = bytes.fromhex(
        "6f1ef55a0d2b5c14a9a5239c9c6b4d3ee4c898a2c9f0b4ad0b1e6cf3d84a1b0b"
    )
    PT = bytes.fromhex(
        "000306090c0f1215181b1e2124272a2d303336393c3f4245484b4e5154575a5d"
        "606366696c6f7275787b7e8184878a8d90939699"
    )
    print("xts128-cts 52B tweak=5 CT:",
          xts_cts_encrypt_128(KEY[:16], KEY[16:], 5, PT).hex())
