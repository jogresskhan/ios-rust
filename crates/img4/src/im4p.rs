//! IM4P payload container — the DER sequence Apple wraps every IPSW
//! component in (`DeviceTree.dtre.im4p`, `kernelcache.release.ipad6.im4p`,
//! ...).
//!
//! Structure (Apple Image4 format, mirrored by Inferno `boot.c`
//! `extract_im4p_payload` and sweet-core `im4p.rs unwrap()`):
//!
//! ```text
//! SEQUENCE {
//!   IA5String    "IM4P"        <- magic
//!   IA5String    fourcc        <- payload type, e.g. "dtre", "krnl"
//!   IA5String    version       <- description / build tag
//!   OCTET STRING data          <- payload (LZFSE-compressed in some images)
//!   [OCTET STRING KBAG ...]    <- optional, present on encrypted payloads
//! }
//! ```
//!
//! This port keeps the raw (still compressed) payload in [`Im4p::data`];
//! LZFSE decoding lives in the `restore` crate which vendors Apple's C
//! implementation.

use crate::der::{self, DerItem};

/// IM4P container magic (the first inner IA5String).
pub const IM4P_MAGIC: &[u8; 4] = b"IM4P";

/// An IM4P payload: type tag, descriptive version string and raw data.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Im4p {
    /// Payload type fourcc, e.g. `"dtre"` (device tree), `"krnl"` (kernel),
    /// `"rdsk"` (ramdisk).
    pub fourcc: String,
    /// Version / description string carried in the container.
    pub version: String,
    /// Raw payload bytes (not decompressed).
    pub data: Vec<u8>,
}

/// SHA-256 of `data` as lowercase hex — the digest IM4M tickets sign.
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(data))
}

impl Im4p {
    /// Build a new payload container.
    pub fn new(fourcc: impl Into<String>, version: impl Into<String>, data: Vec<u8>) -> Im4p {
        Im4p { fourcc: fourcc.into(), version: version.into(), data }
    }

    /// Parse an IM4P DER blob.
    ///
    /// Lenient like sweet-core `unwrap()`: the container magic must be
    /// `"IM4P"`, string tags are not re-validated, and any trailing items
    /// (KBAG, SEQUENCE) after the payload are ignored. Errors when the
    /// blob is not a DER sequence, has fewer than four items, or does not
    /// carry the `IM4P` magic.
    pub fn parse(buf: &[u8]) -> Result<Im4p, String> {
        let (outer, rest) = der::parse_one(buf).map_err(|e| format!("IM4P: {e}"))?;
        if outer.tag != der::TAG_SEQUENCE {
            return Err(format!("IM4P: expected SEQUENCE, got tag {:#04x}", outer.tag));
        }
        if !rest.is_empty() {
            return Err("IM4P: trailing bytes after top-level SEQUENCE".into());
        }

        let mut items: Vec<DerItem> = Vec::new();
        let mut inner: &[u8] = &outer.value;
        while !inner.is_empty() {
            let (item, next) = der::parse_one(inner).map_err(|e| format!("IM4P: {e}"))?;
            items.push(item);
            inner = next;
        }
        if items.len() < 4 {
            return Err(format!("IM4P: expected >= 4 DER items, got {}", items.len()));
        }
        if items[0].value != IM4P_MAGIC.as_slice() {
            return Err(format!(
                "IM4P: bad magic {:?} (want {:?})",
                items[0].value,
                std::str::from_utf8(IM4P_MAGIC).unwrap_or("?")
            ));
        }

        Ok(Im4p {
            fourcc: String::from_utf8_lossy(&items[1].value).into_owned(),
            version: String::from_utf8_lossy(&items[2].value).into_owned(),
            data: items[3].value.clone(),
        })
    }

    /// Serialise back into the DER container form (no KBAG items).
    pub fn to_bytes(&self) -> Vec<u8> {
        der::sequence(&[
            der::encode(der::TAG_IA5_STRING, IM4P_MAGIC),
            der::encode(der::TAG_IA5_STRING, self.fourcc.as_bytes()),
            der::encode(der::TAG_IA5_STRING, self.version.as_bytes()),
            der::encode(der::TAG_OCTET_STRING, &self.data),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let p = Im4p::new("dtre", "iPhone11,8 | iOS 16.7.16", vec![1, 2, 3, 4, 5]);
        let blob = p.to_bytes();
        // layout: SEQUENCE hdr (2B) || IA5 hdr (2B) || "IM4P"
        assert_eq!(&blob[4..8], IM4P_MAGIC);
        let parsed = Im4p::parse(&blob).expect("parse");
        assert_eq!(parsed, p);
        assert_eq!(parsed.fourcc, "dtre");
        assert_eq!(parsed.version, "iPhone11,8 | iOS 16.7.16");
        assert_eq!(parsed.data, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn large_payload_uses_long_form_lengths() {
        let data = vec![0x5A; 70_000]; // > 64 KiB: 3-byte DER length
        let p = Im4p::new("krnl", "test", data.clone());
        let parsed = Im4p::parse(&p.to_bytes()).expect("parse");
        assert_eq!(parsed.data.len(), 70_000);
        assert_eq!(parsed.data, data);
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(Im4p::parse(&[]).is_err());
        assert!(Im4p::parse(&[0x04]).is_err()); // not a sequence
        // sequence with wrong magic
        let bad = der::sequence(&[
            der::encode(der::TAG_IA5_STRING, b"IM4M"),
            der::encode(der::TAG_IA5_STRING, b"krnl"),
            der::encode(der::TAG_IA5_STRING, b"v"),
            der::encode(der::TAG_OCTET_STRING, &[]),
        ]);
        assert!(Im4p::parse(&bad).is_err());
        // too few items
        let short = der::sequence(&[der::encode(der::TAG_IA5_STRING, IM4P_MAGIC)]);
        assert!(Im4p::parse(&short).is_err());
    }

    #[test]
    fn trailing_kbag_items_are_ignored() {
        // Encrypted payloads carry a KBAG OCTET STRING after the data;
        // parse must ignore extras but the container stays parseable.
        let items = [
            der::encode(der::TAG_IA5_STRING, IM4P_MAGIC),
            der::encode(der::TAG_IA5_STRING, b"krnl"),
            der::encode(der::TAG_IA5_STRING, b"enc"),
            der::encode(der::TAG_OCTET_STRING, &[0u8; 32]),
            der::encode(der::TAG_OCTET_STRING, &[0xAA; 96]), // KBAG
        ];
        let blob = der::sequence(&items);
        let p = Im4p::parse(&blob).expect("parse with KBAG");
        assert_eq!(p.fourcc, "krnl");
        assert_eq!(p.data, vec![0u8; 32]);
        assert_eq!(sha256_hex(&p.data).len(), 64);
    }
}
