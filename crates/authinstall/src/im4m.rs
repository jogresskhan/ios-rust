//! IM4M structural validation — the container Apple's ticket server returns
//! as `ApImg4Ticket`.
//!
//! Structure (Apple IMG4 / img4tool shape): one outer DER SEQUENCE (0x30)
//! whose content starts with the fourcc `IM4M`, followed by a version INTEGER
//! (0x02) and member SETs (0x31: `SOS` signature blobs / `BNCN`-style cert
//! bags, `CNFD` data). Validation here is structural: TLV walk + fourcc +
//! version + length coherence. Cryptographic validation of the chain is the
//! documented gate (needs Apple's root certs — research-only path).

use img4::der;

pub const IM4M_FOURCC: &[u8; 4] = b"IM4M";

/// Validate the outer structure; returns the byte length of the IM4M.
pub fn validate(buf: &[u8]) -> Result<usize, String> {
    if buf.len() < 8 {
        return Err("im4m: too short".into());
    }
    let (outer, rest) = der::parse_one(buf).map_err(|e| format!("im4m: outer TLV: {e}"))?;
    if outer.tag != der::TAG_SEQUENCE {
        return Err(format!("im4m: expected outer 0x30, got 0x{:02x}", outer.tag));
    }
    let content = outer.value;
    if content.len() < 4 || &content[..4] != IM4M_FOURCC {
        return Err("im4m: content does not start with IM4M fourcc".into());
    }
    // version INTEGER right after the fourcc
    let (version, after) =
        der::parse_one(&content[4..]).map_err(|e| format!("im4m: version TLV: {e}"))?;
    if version.tag != 0x02 {
        return Err(format!(
            "im4m: expected version INTEGER, got 0x{:02x}",
            version.tag
        ));
    }
    if version.value.iter().all(|&b| b == 0) {
        return Err("im4m: version 0 is invalid".into());
    }
    // member sets must parse cleanly until the content is consumed
    let mut cursor = after;
    while !cursor.is_empty() {
        let (_item, next) =
            der::parse_one(cursor).map_err(|e| format!("im4m: member TLV: {e}"))?;
        cursor = next;
    }
    // length coherence: outer TLV must cover the rest of the buffer
    if !rest.is_empty() {
        return Err(format!(
            "im4m: {} trailing bytes after outer TLV",
            rest.len()
        ));
    }
    Ok(buf.len())
}

/// Return the IM4M payload slice for embedding/forwarding (e.g. into
/// restore requests that want the raw ticket).
pub fn ticket_bytes(buf: &[u8]) -> Result<&[u8], String> {
    validate(buf)?;
    Ok(buf)
}

#[cfg(test)]
pub(crate) mod test_support {
    use img4::der;

    /// Hand-built minimal IM4M: outer SEQUENCE { "IM4M", INTEGER 2, SET{"SOS"} }.
    pub fn build_fixture_im4m() -> Vec<u8> {
        let mut content: Vec<u8> = b"IM4M".to_vec();
        content.extend_from_slice(&der::encode(0x02, &[0x02]));
        let mut sos = b"SOS".to_vec();
        sos.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        content.extend_from_slice(&der::encode(0x31, &sos));
        der::encode(der::TAG_SEQUENCE, &content)
    }
}
