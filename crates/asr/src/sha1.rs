//! SHA-1 (FIPS 180-1) — the checksum ASR appends to payload chunks when the
//! device asks for `Checksum Chunks` (upstream: `sha1(data, size, data+size)`
//! from libimobiledevice-glue). Self-contained pure-Rust implementation.

const H_INIT: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

fn rol(x: u32, n: u32) -> u32 {
    x.rotate_left(n)
}

fn process_block(h: &mut [u32; 5], block: &[u8]) {
    debug_assert_eq!(block.len(), 64);
    let mut w = [0u32; 80];
    for (i, word) in w.iter_mut().take(16).enumerate() {
        *word = u32::from_be_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
    }
    for t in 16..80 {
        w[t] = rol(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1);
    }
    let [mut a, mut b, mut c, mut d, mut e] = *h;
    for (t, &wt) in w.iter().enumerate() {
        let (f, k) = match t {
            0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
            20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
            40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
            _ => (b ^ c ^ d, 0xCA62C1D6),
        };
        let tmp = rol(a, 5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(wt);
        e = d;
        d = c;
        c = rol(b, 30);
        b = a;
        a = tmp;
    }
    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
}

/// SHA-1 of a byte slice (single-shot; ASR chunks are ≤ 131072 bytes).
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h = H_INIT;
    let full = data.len() / 64;
    for i in 0..full {
        process_block(&mut h, &data[i * 64..i * 64 + 64]);
    }
    // tail block(s): message + 0x80 + zeros + u64 BE bit-length
    let tail = &data[full * 64..];
    let mut last = [0u8; 128];
    last[..tail.len()].copy_from_slice(tail);
    last[tail.len()] = 0x80;
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let padded_len = if tail.len() < 56 { 64 } else { 128 };
    last[padded_len - 8..padded_len].copy_from_slice(&bit_len.to_be_bytes());
    process_block(&mut h, &last[..64]);
    if padded_len == 128 {
        process_block(&mut h, &last[64..128]);
    }
    let mut out = [0u8; 20];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::sha1;

    fn hex(d: &[u8]) -> String {
        d.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn fips_vectors() {
        assert_eq!(hex(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(hex(&sha1(b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(
            hex(&sha1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
        assert_eq!(
            hex(&sha1(&[b'a'; 1_000_000])),
            "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
        );
    }

    #[test]
    fn block_boundary_cases() {
        // padding switches to the second block at tail len 56..=63
        assert_eq!(hex(&sha1(&[b'a'; 55])), "c1c8bbdc22796e28c0e15163d20899b65621d65a");
        assert_eq!(hex(&sha1(&[b'a'; 56])), "c2db330f6083854c99d4b5bfb6e8f29f201be699");
        assert_eq!(hex(&sha1(&[b'a'; 63])), "03f09f5b158a7a8cdad920bddc29b81c18a551f5");
        assert_eq!(hex(&sha1(&[b'a'; 64])), "0098ba824b5c16427bd7a1122a5a442a25ec644d");
        assert_eq!(hex(&sha1(&[b'a'; 65])), "11655326c708d70319be2610e8a57d9a5b959d3b");
        assert_eq!(hex(&sha1(&[b'a'; 999])), "d8e4b5c1594d2e9c1c4154eb8ea5715cfe9dd055");
        assert_eq!(hex(&sha1(&[b'a'; 1000])), "291e9a6c66994949b57ba5e650361e98fc36b1ba");
    }
}
