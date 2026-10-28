//! IM4M structural validation — the container Apple's ticket server returns
//! as `ApImg4Ticket`.
//!
//! Structure (verified against a REAL TSS response captured from
//! gs.apple.com — see `tests/real_tss.rs`): one outer DER SEQUENCE (0x30)
//! whose members are
//!   [0] OCTET STRING (0x04) = fourcc `IM4M`
//!   [1] INTEGER (0x02)      = container version (2)
//!   [2] SET (0x31)          = certificate bag (`SOS`… / CNFD-style)
//!   [3] OCTET STRING (0x04) = the Ticket body (personalized manifest)
//!   (… optional further members, e.g. IM4R restore-request echo)
//! The earlier layout assumption (fourcc bytes inline at content offset 0)
//! only ever matched our synthetic fixture — the real capture exposed it.
//! Validation is structural: TLV walk + fourcc + version + member coherence.
//! Cryptographic validation of the chain is the documented gate (needs
//! Apple's root certs — research-only path).

use img4::der;

pub const IM4M_FOURCC: &[u8; 4] = b"IM4M";

/// Parsed view of an IM4M (owned values; the ticket is ~10 KB in practice).
pub struct Im4mView {
    /// Container version INTEGER value.
    pub version: u64,
    /// The Ticket body member (the big OCTET STRING) — the personalized
    /// manifest bytes restore wants to forward.
    pub ticket: Vec<u8>,
    /// Number of certificate blobs seen in the SET member(s).
    pub certs: usize,
}

/// Parse + validate the outer structure of a real (DER) IM4M.
pub fn parse(buf: &[u8]) -> Result<Im4mView, String> {
    if buf.len() < 8 {
        return Err("im4m: too short".into());
    }
    let (outer, rest) = der::parse_one(buf).map_err(|e| format!("im4m: outer TLV: {e}"))?;
    if outer.tag != der::TAG_SEQUENCE {
        return Err(format!("im4m: expected outer 0x30, got 0x{:02x}", outer.tag));
    }
    if !rest.is_empty() {
        return Err(format!(
            "im4m: {} trailing bytes after outer TLV",
            rest.len()
        ));
    }

    // members (owned values — DerItem clones its payload)
    let mut cursor: &[u8] = &outer.value;
    let mut items: Vec<img4::der::DerItem> = Vec::new();
    while !cursor.is_empty() {
        let (item, next) = der::parse_one(cursor).map_err(|e| format!("im4m: member TLV: {e}"))?;
        items.push(item);
        cursor = next;
    }
    if items.is_empty() {
        return Err("im4m: no members".into());
    }

    // [0] fourcc OCTET STRING
    if items[0].tag != 0x04 || items[0].value.as_slice() != IM4M_FOURCC {
        return Err(format!(
            "im4m: member[0] must be OCTET STRING \"IM4M\" (got tag 0x{:02x})",
            items[0].tag
        ));
    }
    // [1] version INTEGER
    if items.len() < 2 || items[1].tag != 0x02 {
        return Err("im4m: member[1] must be the version INTEGER".into());
    }
    let mut version = 0u64;
    for &b in &items[1].value {
        version = (version << 8) | b as u64;
    }
    if version == 0 {
        return Err("im4m: version 0 is invalid".into());
    }

    // certificate SET(s) + the Ticket body OCTET STRING
    let mut certs = 0usize;
    let mut ticket: Option<Vec<u8>> = None;
    for it in items.iter().skip(2) {
        match it.tag {
            0x31 => {
                // cert bag SET — count the CERT OCTET STRINGs inside
                let mut inner: &[u8] = &it.value;
                while !inner.is_empty() {
                    let (sub, next) =
                        der::parse_one(inner).map_err(|e| format!("im4m: cert TLV: {e}"))?;
                    if sub.tag == 0x04 && sub.value.len() > 16 {
                        certs += 1;
                    }
                    inner = next;
                }
            }
            0x04 if ticket.is_none() && it.value.len() > 64 => {
                ticket = Some(it.value.clone());
            }
            _ => {}
        }
    }
    let ticket = ticket.ok_or("im4m: no Ticket body member found")?;
    Ok(Im4mView { version, ticket, certs })
}

/// Validate the outer structure; returns the number of certificates found.
pub fn validate(buf: &[u8]) -> Result<usize, String> {
    Ok(parse(buf)?.certs)
}

/// Return the IM4M ticket-body for embedding/forwarding (e.g. into
/// restore requests that want the raw ticket).
pub fn ticket_bytes(buf: &[u8]) -> Result<Vec<u8>, String> {
    Ok(parse(buf)?.ticket)
}

#[cfg(test)]
pub(crate) mod test_support {
    use img4::der;

    /// Hand-built minimal IM4M in the REAL layout: SEQUENCE {
    ///   OCTET STRING "IM4M", INTEGER 2, SET{ OCTET STRING cert… },
    ///   OCTET STRING ticket-body }
    pub fn build_fixture_im4m() -> Vec<u8> {
        let mut cert = b"ATCHCERT".to_vec();
        cert.extend_from_slice(&[0xde; 40]);
        let mut set = der::encode(0x04, &cert);
        let mut cert2 = b"ATCHCERT2".to_vec();
        cert2.extend_from_slice(&[0xca; 40]);
        set.extend_from_slice(&der::encode(0x04, &cert2));
        let mut body = b"MANB".to_vec();
        body.extend_from_slice(&[0x11u8; 120]);
        let mut out = Vec::new();
        out.extend_from_slice(&der::encode(0x04, b"IM4M"));
        out.extend_from_slice(&der::encode(0x02, &[0x02]));
        out.extend_from_slice(&der::encode(0x31, &set));
        out.extend_from_slice(&der::encode(0x04, &body));
        der::encode(der::TAG_SEQUENCE, &out)
    }
}
