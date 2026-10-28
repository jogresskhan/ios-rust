//! base64 — libqemuutil port (`qemu/util/base64.c` + `qemu/include/qemu/base64.h`).
//!
//! Upstream: "QEMU base64 helpers", Copyright (c) 2015 Red Hat, Inc.,
//! LGPL-2.1-or-later. `qbase64_decode` validates that the input consists
//! solely of `base64_valid_chars` (`A-Za-z0-9+/=` plus `\n`) and then
//! delegates to GLib's strict RFC-4648 decoder. The Rust port keeps the same
//! valid-character set and decodes RFC-4648 with required padding; encode
//! emits the canonical padded form (GLib `g_base64_encode` equivalent).

/// Characters accepted by QEMU `qbase64_decode` (includes `\n`).
pub const BASE64_VALID_CHARS: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n";

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const PAD: u8 = b'=';

fn decode_table(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// QEMU `qbase64_encode` (GLib `g_base64_encode`): canonical padded output.
pub fn qbase64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(n >> 6) as usize & 63] as char);
        } else {
            out.push(PAD as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[n as usize & 63] as char);
        } else {
            out.push(PAD as char);
        }
    }
    out
}

/// QEMU `qbase64_decode`: strict decode over the QEMU valid-character set.
///
/// `\n` line breaks are skipped like upstream's `strspn` character filter
/// allows them; everything else must be canonical RFC-4648 with padding.
pub fn qbase64_decode(input: &str) -> Result<Vec<u8>, String> {
    for c in input.chars() {
        if !BASE64_VALID_CHARS.contains(c) {
            return Err("Base64 data contains invalid characters".to_string());
        }
    }
    let clean: Vec<u8> = input.bytes().filter(|&c| c != b'\n').collect();
    if clean.len() % 4 != 0 {
        return Err("Base64 length is not a multiple of 4".to_string());
    }
    let mut out = Vec::with_capacity(clean.len() / 4 * 3);
    for (gi, group) in clean.chunks(4).enumerate() {
        let pad = group.iter().filter(|&&c| c == PAD).count();
        // Padding only allowed as the trailing 1 or 2 bytes of a group.
        if pad > 2 || group[..4 - pad].iter().any(|&c| c == PAD) {
            return Err(format!("Invalid base64 padding in group {gi}"));
        }
        let mut n: u32 = 0;
        for &c in &group[..4 - pad] {
            match decode_table(c) {
                Some(v) => n = (n << 6) | v as u32,
                None => return Err("Base64 data contains invalid characters".to_string()),
            }
        }
        n <<= 6 * pad as u32;
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_canonical() {
        assert_eq!(qbase64_encode(b""), "");
        assert_eq!(qbase64_encode(b"f"), "Zg==");
        assert_eq!(qbase64_encode(b"fo"), "Zm8=");
        assert_eq!(qbase64_encode(b"foo"), "Zm9v");
        assert_eq!(qbase64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(qbase64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(qbase64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn decode_strict_roundtrip() {
        assert_eq!(qbase64_decode("Zm9vYmFy").unwrap(), b"foobar");
        assert_eq!(qbase64_decode("Zm8=").unwrap(), b"fo");
        for s in ["", "Zg==", "Zm8=", "Zm9v", "Zm9vYg==", "Zm9vYmE=", "Zm9vYmFy"] {
            assert_eq!(qbase64_decode(s).unwrap(), qbase64_decode(s).unwrap());
            let decoded = qbase64_decode(s).unwrap();
            assert_eq!(qbase64_encode(&decoded), s);
        }
    }

    #[test]
    fn decode_newlines_allowed() {
        // QEMU valid_chars includes '\n' so wrapped MIME-style input works.
        assert_eq!(qbase64_decode("Zm9v\nYmFy").unwrap(), b"foobar");
        assert_eq!(
            qbase64_decode(qbase64_encode(&vec![0x5a; 100]).as_str()).unwrap(),
            vec![0x5a; 100]
        );
    }

    #[test]
    fn decode_rejects_bad_input() {
        assert!(qbase64_decode("Zm9*").is_err()); // invalid character
        assert!(qbase64_decode("Zm9v").is_ok());
        assert!(qbase64_decode("Zm9vY").is_err()); // length not multiple of 4
        assert!(qbase64_decode("=m9v").is_err()); // padding in the middle
        assert!(qbase64_decode("Z===").is_err()); // too much padding
    }
}
