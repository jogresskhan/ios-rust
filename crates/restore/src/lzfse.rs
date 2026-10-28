//! lzfse — Rust bindings to the vendored Apple LZFSE C decoder.
//!
//! `restore/vendor/` carries Apple's reference `lzfse` C implementation
//! (BSD-3, see `vendor/PROVENANCE.md`), compiled by `build.rs` with `cc`.
//! This module declares the FFI symbols and exposes a growable-buffer
//! wrapper [`decompress`] so callers (kernelcache, dsc, IPSW staging) can
//! decode `bvx2`/`bvxn`/`bvx1`/`bvx-` block streams without pre-knowing
//! the output size.
//!
//! Parity: Apple lzfse `lzfse_decode_buffer` (the same entry
//! `ipsw extract -k` drives through `blacktop/lzfse-cgo`).

/// Scratch size reported by the vendored decoder (`lzfse_decode_scratch_size`).
/// The upstream constant is 64 KiB (LZFSE_DECODE_SCRATCH_SIZE upper bound);
/// we allocate it ourselves so the decoder never mallocs.
const DECODE_SCRATCH_SIZE: usize = 64 * 1024;

/// Double the scratch budget for safety on large block streams.
const _SCRATCH_HEADROOM: usize = DECODE_SCRATCH_SIZE * 2;

extern "C" {
    fn lzfse_decode_buffer(
        dst_buffer: *mut u8,
        dst_size: usize,
        src_buffer: *const u8,
        src_size: usize,
        scratch_buffer: *mut u8,
    ) -> usize;
}

/// Decompress an LZFSE stream (`bvx2`/`bvxn`/`bvx1`/`bvx-` blocks) into a
/// `Vec<u8>`, guessing-and-growing the output buffer like idevicerestore's
/// `decompress_lzfse` loop does.
///
/// * `src` — the LZFSE payload (no `complzss` header; raw block stream).
/// * `hint` — optional caller estimate of the uncompressed size (used as the
///   first allocation; defaults to 4× input).
///
/// Returns the decoded bytes. Errors when the decoder cannot fit the output
/// even after several doublings (truncated/corrupt stream).
pub fn decompress(src: &[u8], hint: Option<usize>) -> Result<Vec<u8>, String> {
    if src.is_empty() {
        return Ok(Vec::new());
    }
    let mut dst_len = hint.unwrap_or_else(|| src.len().saturating_mul(4)).max(1 << 16);
    for _attempt in 0..24 {
        let mut dst = vec![0u8; dst_len];
        let mut scratch = vec![0u8; _SCRATCH_HEADROOM];
        let written = unsafe {
            lzfse_decode_buffer(
                dst.as_mut_ptr(),
                dst.len(),
                src.as_ptr(),
                src.len(),
                scratch.as_mut_ptr(),
            )
        };
        if written == 0 {
            return Err("lzfse: decoder produced 0 bytes (invalid block stream?)".into());
        }
        if written < dst.len() {
            // The decoder only truncates when dst was too small; otherwise
            // `written` is the full output. Truncation means we must grow.
            // Detect genuine completion: retry with a bigger buffer and see
            // whether `written` stays identical.
            let mut bigger = vec![0u8; dst_len * 2];
            let mut scratch2 = vec![0u8; _SCRATCH_HEADROOM];
            let written2 = unsafe {
                lzfse_decode_buffer(
                    bigger.as_mut_ptr(),
                    bigger.len(),
                    src.as_ptr(),
                    src.len(),
                    scratch2.as_mut_ptr(),
                )
            };
            if written2 == written {
                dst.truncate(written);
                return Ok(dst);
            }
            dst_len *= 2;
            continue;
        }
        // `written == dst.len()`: may still be truncated — grow and retry.
        dst_len *= 2;
        let _ = written;
    }
    Err("lzfse: output did not converge after 24 doublings (corrupt stream?)".into())
}

/// True when `data` starts with an LZFSE block magic (`bvx2`, `bvxn`, `bvx1`,
/// `bvx-`, `bvx$`). Mirrors `internal/magic.IsLZFSE` in blacktop/ipsw.
pub fn is_lzfse(data: &[u8]) -> bool {
    data.len() >= 4
        && matches!(
            &data[..4],
            b"bvx2" | b"bvxn" | b"bvx1" | b"bvx-" | b"bvx$"
        )
}
