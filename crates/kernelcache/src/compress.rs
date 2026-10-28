//! compress — kernelcache container detection + decompression.
//!
//! Mirrors blacktop/ipsw `pkg/kernelcache/kernelcache.go DecompressData`:
//! * `bvx2/bvxn/bvx1/bvx-` → LZFSE (the vendored Apple C decoder through
//!   `restore::lzfse`), then thin a single-slice fat Mach-O (`lipo -thin`);
//! * `complzss…` → LZSS (the xnu `libkern/mkext.c` decoder ported in
//!   [`crate::lzss`]);
//! * `MH_MAGIC_64` → already-uncompressed kernel;
//! * anything else → an honest "unsupported (possibly encrypted)" error.
//!
//! IM4P-wrapped payloads are unwrapped first through the `img4` crate.

use img4::im4p::Im4p;

/// What was detected in a kernelcache payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Compression {
    Lzfse,
    Lzss,
    None,
}

/// Decompress a raw kernelcache payload (IM4P-unwrapped or plain).
///
/// Returns the decompressed (or passthrough) bytes.
pub fn decompress(data: &[u8]) -> Result<Vec<u8>, String> {
    // Unwrap a possible IM4P container (the IPSW kernelcache is an IM4P).
    // Raw kernelcache files pass through untouched: they never start with
    // the IM4P ASN.1 tag so the parse error is simply ignored.
    let payload: Vec<u8> = match Im4p::parse(data) {
        Ok(p) => p.data,
        Err(_) => data.to_vec(),
    };

    if restore::lzfse::is_lzfse(&payload) {
        let dec = restore::lzfse::decompress(&payload, None)?;
        return thin_fat(dec);
    }
    if crate::lzss::is_lzss(&payload) {
        let hdr = crate::lzss::parse_header(&payload)?;
        let start = hdr.stream_offset;
        let payload_end = start
            .checked_add(hdr.compressed_size as usize)
            .ok_or("lzss: compressed size overflow")?
            .min(payload.len());
        let dec = crate::lzss::decompress(&payload[start..payload_end], Some(hdr.uncompressed_size as usize));
        // Adler verification is informational.
        return Ok(dec);
    }
    // Uncompressed kernel: little-endian MH_MAGIC_64 at [0..8].
    if payload.len() >= 8 && u64::from_le_bytes(payload[0..8].try_into().unwrap()) == 0xfeedfacf {
        return Ok(payload);
    }
    Err("kernelcache: unsupported compression (possibly encrypted)".into())
}

/// Which compression a payload carries (for CLI reporting).
pub fn detect(data: &[u8]) -> Option<Compression> {
    if restore::lzfse::is_lzfse(data) {
        Some(Compression::Lzfse)
    } else if crate::lzss::is_lzss(data) {
        Some(Compression::Lzss)
    } else if data.len() >= 8 && u64::from_le_bytes(data[0..8].try_into().unwrap()) == 0xfeedfacf {
        Some(Compression::None)
    } else {
        None
    }
}

/// Thin a single-arch fat Mach-O down to its arm64(e) slice
/// (ipsw: "essentially `lipo -thin arm64e`"). Non-fat input is returned
/// as-is.
fn thin_fat(dec: Vec<u8>) -> Result<Vec<u8>, String> {
    if !macho::header::MachHeader::is_fat(&dec) {
        return Ok(dec);
    }
    let arches = macho::header::MachHeader::fat_arches(&dec)?;
    if arches.len() > 1 {
        return Err("kernelcache: fat Mach-O with more than one arch".into());
    }
    let Some((_, offset, _size)) = arches.first().copied() else {
        return Err("kernelcache: empty fat Mach-O".into());
    };
    let o = offset as usize;
    if o > dec.len() {
        return Err("kernelcache: fat slice out of bounds".into());
    }
    Ok(dec[o..].to_vec())
}
