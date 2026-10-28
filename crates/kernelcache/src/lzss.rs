//! lzss — the iBoot/XNU kernelcache LZSS decoder (`complzss`).
//!
//! The decompressor is a faithful port of Apple's `decompress_lzss`
//! (Haruhiko Okumura's LZSS, N=4096, F=18, THRESHOLD=2) as it appears in
//! xnu `libkern/mkext.c` — verified against the vendored xnu-7195.141.2
//! tree and against blacktop/lzss `Decompress`.
//!
//! The file header is big-endian (ipsw reads `lzss.Header` with
//! `binary.BigEndian`) and self-describing:
//!
//! ```text
//! 0x000: u32 "comp"           CompressionType
//! 0x004: u32 "lzss"           Signature        (together: "complzss")
//! 0x008: u32 CheckSum         (adler32 of the uncompressed bytes)
//! 0x00C: u32 UncompressedSize
//! 0x010: u32 CompressedSize
//! 0x014: u32 Version
//! 0x018: 360 bytes reserved   (Padding — blacktop/lzss `Padding [360]byte`)
//! 0x180: LZSS stream          (the well-known kernelcache 0x180 offset)
//! ```
//!
//! Total header = 384 (0x180) bytes. Parity: blacktop/lzss `Header`
//! (github.com/blacktop/lzss `lzss.go`), consumed by ipsw
//! `pkg/kernelcache/kernelcache.go` (`binary.Read` + `buffer.Next
//! (CompressedSize)`).

/// Ring buffer size (must be a power of 2) — Okumura N.
const N: usize = 4096;
/// Upper limit for match length — Okumura F.
const F: usize = 18;
/// Encode string as position+length when match_length > THRESHOLD.
const THRESHOLD: usize = 2;

/// The `complzss` header fields (big-endian).
#[derive(Debug, Clone, Copy, Default)]
pub struct LzssHeader {
    pub compression_type: u32,
    pub signature: u32,
    pub checksum: u32,
    pub uncompressed_size: u32,
    pub compressed_size: u32,
    pub version: u32,
    /// 0x180 when the 360-byte Padding block is present (the real
    /// kernelcache layout), 28 for the legacy field-only layout.
    pub stream_offset: usize,
}

impl LzssHeader {
    /// `"comp"` big-endian.
    pub const COMPRESSION_TYPE: u32 = 0x636f_6d70;
    /// `"lzss"` big-endian.
    pub const SIGNATURE: u32 = 0x6c7a_7373;
}

/// True when `data` starts with the `comp` magic (ipsw checks only
/// `bytes.Contains(magic, "comp")`).
pub fn is_lzss(data: &[u8]) -> bool {
    data.len() >= 4 && data[0..4] == *b"comp"
}

/// Parse + validate the header.
///
/// The canonical kernelcache layout has the 360-byte Padding block
/// (stream at 0x180). Files too small for that fall back to the legacy
/// field-only layout (stream at 28). Validation: `compressed_size` must
/// fit in the file and `uncompressed_size` must be a sane kernel size.
pub fn parse_header(data: &[u8]) -> Result<LzssHeader, String> {
    if !is_lzss(data) {
        return Err("lzss: no complzss magic".into());
    }
    const MAX_KERNEL: u32 = 256 * 1024 * 1024;
    let be32 = |o: usize| -> u32 {
        if o + 4 <= data.len() {
            u32::from_be_bytes(data[o..o + 4].try_into().unwrap())
        } else {
            0
        }
    };
    let fields = |stream_offset: usize| LzssHeader {
        compression_type: be32(0),
        signature: be32(4),
        checksum: be32(8),
        uncompressed_size: be32(12),
        compressed_size: be32(16),
        version: be32(20),
        stream_offset,
    };
    let valid = |h: &LzssHeader| {
        h.compressed_size > 0
            && h.stream_offset as u64 + h.compressed_size as u64 <= data.len() as u64
            && h.uncompressed_size > 0
            && h.uncompressed_size < MAX_KERNEL
    };

    // Canonical: 0x180 stream offset (360-byte Padding block).
    let canonical = fields(0x180);
    if canonical.compression_type == LzssHeader::COMPRESSION_TYPE
        && canonical.signature == LzssHeader::SIGNATURE
        && valid(&canonical)
    {
        return Ok(canonical);
    }
    // Legacy field-only layout (stream at 28).
    let legacy = fields(28);
    if valid(&legacy) {
        return Ok(legacy);
    }
    // Fall back to canonical (with signature check relaxed) and let the
    // caller see the raw values — mirrors ipsw's permissive "comp" gate.
    Ok(canonical)
}

/// Apple's `decompress_lzss` from xnu `libkern/mkext.c`, verbatim logic:
/// flag-bit LZSS over a 4096-byte ring buffer initialized to spaces.
///
/// * `src` — compressed stream (after the 0x180-byte header).
/// * `dst_len_hint` — `UncompressedSize` when known (bounds the output).
pub fn decompress(src: &[u8], dst_len_hint: Option<usize>) -> Vec<u8> {
    let mut text_buf = [b' '; N + F - 1];
    let cap = dst_len_hint.unwrap_or(src.len() * 4).max(1024);
    let mut dst: Vec<u8> = Vec::with_capacity(cap);
    let mut r = N - F;
    let mut flags: u32 = 0;
    let mut si = 0usize;

    loop {
        // C: if (((flags >>= 1) & 0x100) == 0) { load new flag byte }
        // The shift happens every iteration; the sentinel bit at 0x100
        // counts the eight flag bits (c | 0xFF00 trick).
        flags >>= 1;
        if flags & 0x100 == 0 {
            if si >= src.len() {
                break;
            }
            let c = src[si] as u32;
            si += 1;
            flags = c | 0xFF00;
        }
        if flags & 1 != 0 {
            if si >= src.len() {
                break;
            }
            let c = src[si];
            si += 1;
            dst.push(c);
            text_buf[r] = c;
            r = (r + 1) & (N - 1);
        } else {
            if si + 2 > src.len() {
                break;
            }
            let mut i = src[si] as usize;
            let mut j = src[si + 1] as usize;
            si += 2;
            i |= (j & 0xF0) << 4;
            j = (j & 0x0F) + THRESHOLD;
            for k in 0..=j {
                let c = text_buf[(i + k) & (N - 1)];
                dst.push(c);
                text_buf[r] = c;
                r = (r + 1) & (N - 1);
            }
        }
        // The C code caps at dstlen; we grow unbounded but honor the hint
        // as a sanity stop to mirror `dst >= dstend` termination.
        if let Some(hint) = dst_len_hint {
            if dst.len() >= hint {
                break;
            }
        }
    }
    dst
}

/// RFC 1950 adler32 — the routine xnu uses beside LZSS
/// (`libkern/mkext.c` adler32, BASE 65521, NMAX 5552) to checksum the
/// uncompressed kernelcache.
pub fn adler32(data: &[u8]) -> u32 {
    const BASE: u32 = 65521;
    const NMAX: usize = 5552;
    let mut s1: u32 = 1;
    let mut s2: u32 = 0;
    for chunk in data.chunks(NMAX) {
        for &b in chunk {
            s1 += b as u32;
            s2 += s1;
        }
        s1 %= BASE;
        s2 %= BASE;
    }
    (s2 << 16) | s1
}
