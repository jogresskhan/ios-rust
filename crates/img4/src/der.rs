//! Minimal DER (ASN.1) TLV encode/parse — the subset Apple IMG4 containers
//! use (SEQUENCE 0x30, OCTET STRING 0x04, IA5String 0x16).
//!
//! Port of the DER half of sweet-core `im4p.rs` (`fn der`) with definite
//! lengths only: Apple's Image4 blobs never use indefinite (0x80) lengths,
//! so they are rejected. Long-form lengths up to 8 bytes are supported
//! (the IMG4 `IM4M` blob needs 4).

/// DER TLV item: one tag + its definite-length value.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DerItem {
    /// ASN.1 tag byte (low 8 bits; Apple containers only use low-tag-number
    /// universal tags: 0x04, 0x16, 0x30).
    pub tag: u8,
    /// Value bytes (length prefix already consumed).
    pub value: Vec<u8>,
}

/// Universal tags used by IMG4.
pub const TAG_SEQUENCE: u8 = 0x30;
/// OCTET STRING (payloads, KBAGs).
pub const TAG_OCTET_STRING: u8 = 0x04;
/// IA5String (ASCII: magic, fourcc, version strings).
pub const TAG_IA5_STRING: u8 = 0x16;

/// Parse one definite-length DER TLV at the start of `buf`.
///
/// Returns the item and the remaining (unconsumed) slice. Errors on
/// truncation, indefinite or oversized (non-minimal > 8 byte) lengths, and
/// values running past the end of the buffer.
pub fn parse_one(buf: &[u8]) -> Result<(DerItem, &[u8]), String> {
    if buf.len() < 2 {
        return Err(format!("DER: truncated header ({} bytes)", buf.len()));
    }
    let tag = buf[0];
    let mut len = buf[1] as usize;
    let mut off = 2;
    if len & 0x80 != 0 {
        let n = len & 0x7f;
        if n == 0 {
            return Err("DER: indefinite length not supported".into());
        }
        if n > 8 {
            return Err(format!("DER: long length of {n} bytes exceeds 8"));
        }
        if off + n > buf.len() {
            return Err("DER: truncated long length".into());
        }
        len = buf[off..off + n]
            .iter()
            .fold(0usize, |acc, &b| (acc << 8) | b as usize);
        off += n;
    }
    let end = off + len;
    if end > buf.len() {
        return Err(format!("DER: value of {len} bytes runs past end of buffer"));
    }
    Ok((DerItem { tag, value: buf[off..end].to_vec() }, &buf[end..]))
}

/// Encode one TLV: `tag || length || value` with the shortest definite
/// length form (short form below 0x80, else minimal long form).
pub fn encode(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len() + 5);
    out.push(tag);
    let len = value.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let be = len.to_be_bytes();
        let start = be.iter().position(|&b| b != 0).unwrap_or(be.len() - 1);
        let n = be.len() - start;
        out.push(0x80 | n as u8);
        out.extend_from_slice(&be[start..]);
    }
    out.extend_from_slice(value);
    out
}

/// Encode a SEQUENCE (tag 0x30) whose content is `items` concatenated.
pub fn sequence(items: &[Vec<u8>]) -> Vec<u8> {
    let mut content = Vec::with_capacity(items.iter().map(|i| i.len()).sum());
    for i in items {
        content.extend_from_slice(i);
    }
    encode(TAG_SEQUENCE, &content)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_form_roundtrip() {
        let enc = encode(TAG_IA5_STRING, b"IM4P");
        assert_eq!(enc, [0x16, 0x04, b'I', b'M', b'4', b'P']);
        let (item, rest) = parse_one(&enc).unwrap();
        assert_eq!(item.tag, TAG_IA5_STRING);
        assert_eq!(item.value, b"IM4P".to_vec());
        assert!(rest.is_empty());
    }

    #[test]
    fn long_form_lengths() {
        let payload = vec![0xAB; 300]; // needs 0x82 0x01 0x2C
        let enc = encode(TAG_OCTET_STRING, &payload);
        assert_eq!(&enc[..4], &[0x04, 0x82, 0x01, 0x2C][..]);
        let (item, rest) = parse_one(&enc).unwrap();
        assert_eq!(item.value.len(), 300);
        assert!(rest.is_empty());

        // 2-byte length minimal form
        let enc2 = encode(TAG_OCTET_STRING, &[0u8; 0x80]);
        assert_eq!(&enc2[..3], &[0x04, 0x81, 0x80][..]);
        let (item2, _) = parse_one(&enc2).unwrap();
        assert_eq!(item2.value.len(), 0x80);
    }

    #[test]
    fn sequence_and_multiple_items() {
        let seq = sequence(&[encode(TAG_IA5_STRING, b"IM4P"), encode(TAG_OCTET_STRING, b"xy")]);
        assert_eq!(seq[0], TAG_SEQUENCE);
        let (outer, rest) = parse_one(&seq).unwrap();
        assert!(rest.is_empty());
        let (a, rem) = parse_one(&outer.value).unwrap();
        assert_eq!(a.value, b"IM4P".to_vec());
        let (b, rem) = parse_one(rem).unwrap();
        assert_eq!(b.value, b"xy".to_vec());
        assert!(rem.is_empty());
        let _ = rest;
    }

    #[test]
    fn rejects_malformed() {
        assert!(parse_one(&[]).is_err());
        assert!(parse_one(&[0x30]).is_err());
        assert!(parse_one(&[0x30, 0x80]).is_err()); // indefinite
        assert!(parse_one(&[0x30, 0x89]).is_err()); // 9-byte long length
        assert!(parse_one(&[0x30, 0x10, 0x01]).is_err()); // value truncated
        assert!(parse_one(&[0x30, 0x82, 0x01]).is_err()); // length truncated
    }
}
