//! tss — libauthinstall-class ticket plumbing (the `IMG4 signing` X-gap).
//!
//! Apple does not "sign" restore components on the host: the host builds a
//! TSS request (per-component digests + device identity) and Apple's signing
//! server returns an `ApImg4Ticket` — the IM4M personalization blob — which
//! is spliced into the restore stream exactly like `libauthinstall` does
//! (`img4_build_tss_request` / `img4_get_local_policy` / TSS client).
//!
//! This module implements the honest host half of that contract:
//! * [`build_tss_request`] — canonical (sorted-key) request dict from device
//!   identity + component digests, with `@ApImg4Ticket` set for IMG4 flows.
//! * [`parse_tss_response`] — extract and validate the `ApImg4Ticket`
//!   (IM4M container via the `img4` crate's DER parser).
//! * [`validate_im4m`] — structural IM4M check (SEQUENCE → IA5 "IM4M").
//!
//! The signing-server side stays external by design (permanent research
//! boundary, same as `permanent_gaps` in parity.json — AES-XTS device keys);
//! the request/response shape here is what the lane replays from captures.

use crate::plist_lite::{self, Plist};
use img4::der::{parse_one, TAG_IA5_STRING, TAG_SEQUENCE};
use std::collections::BTreeMap;

/// TSS request for an IMG4 (ApTicket) restore flow.
///
/// * `board_id` — ApBoardID (e.g. `8` for iPhone 11 `n104ap`).
/// * `chip_id` — ApChipID (e.g. `0x8030` for T8030/A13).
/// * `security_domain` — ApSecurityDomain (`1` for production).
/// * `ap_nonce` / `sep_nonce` — device nonces (base64 `<data>` on the wire).
/// * `unique_build_id` — BuildManifest `UniqueBuildID` digest, optional.
/// * `components` — `(tag, digest)` pairs, tag as in BuildManifest
///   (`"Ap,OS"`, `"Ap,KernelCache"`, `"Ap,SE,OS"`, …).
pub fn build_tss_request(
    board_id: u64,
    chip_id: u64,
    security_domain: u64,
    ap_nonce: &[u8],
    sep_nonce: &[u8],
    unique_build_id: Option<&[u8]>,
    components: &[(String, Vec<u8>)],
) -> Plist {
    let mut req: BTreeMap<String, Plist> = BTreeMap::new();
    // '@'-prefixed meta keys sort first (canonical TSS ordering).
    req.insert("@ApImg4Ticket".into(), Plist::Bool(true));
    req.insert("ApBoardID".into(), Plist::UInt(board_id));
    req.insert("ApChipID".into(), Plist::UInt(chip_id));
    req.insert("ApSecurityDomain".into(), Plist::UInt(security_domain));
    req.insert("ApNonce".into(), Plist::Data(ap_nonce.to_vec()));
    if !sep_nonce.is_empty() {
        req.insert("SepNonce".into(), Plist::Data(sep_nonce.to_vec()));
    }
    if let Some(ubid) = unique_build_id {
        req.insert("UniqueBuildID".into(), Plist::Data(ubid.to_vec()));
    }
    for (tag, digest) in components {
        let mut comp: BTreeMap<String, Plist> = BTreeMap::new();
        comp.insert("Digest".into(), Plist::Data(digest.clone()));
        req.insert(tag.clone(), Plist::Dict(comp));
    }
    Plist::Dict(req)
}

/// Convenience: one component entry from its fourcc-style tag and digest.
pub fn component(tag: &str, digest: &[u8]) -> (String, Vec<u8>) {
    (tag.to_string(), digest.to_vec())
}

/// Validate a structural IM4M: outer SEQUENCE whose first inner item is the
/// IA5String magic `"IM4M"`.
pub fn validate_im4m(bytes: &[u8]) -> Result<(), String> {
    let (outer, rest) = parse_one(bytes)?;
    if outer.tag != TAG_SEQUENCE {
        return Err(format!("IM4M: outer tag 0x{:02X}, expected SEQUENCE", outer.tag));
    }
    if !rest.is_empty() {
        return Err(format!("IM4M: {} trailing bytes after outer SEQUENCE", rest.len()));
    }
    let (magic, _) = parse_one(&outer.value)?;
    if magic.tag != TAG_IA5_STRING {
        return Err(format!("IM4M: magic tag 0x{:02X}, expected IA5String", magic.tag));
    }
    if magic.value != b"IM4M" {
        return Err(format!(
            "IM4M: magic {:?}, expected \"IM4M\"",
            String::from_utf8_lossy(&magic.value)
        ));
    }
    Ok(())
}

/// Extract the `ApImg4Ticket` from a TSS response dict and validate its IM4M
/// structure. Returns the raw ticket bytes (ready to splice into the restore
/// stream / `Personalized` component).
pub fn parse_tss_response(response: &Plist) -> Result<Vec<u8>, String> {
    let dict = match response {
        Plist::Dict(d) => d,
        other => return Err(format!("TSS response: expected dict, got {other:?}")),
    };
    let ticket = match dict.get("ApImg4Ticket") {
        Some(Plist::Data(b)) => b.clone(),
        Some(other) => {
            return Err(format!("ApImg4Ticket: expected <data>, got {other:?}"))
        }
        None => {
            // Apple's failure shape: {"Status": ..., "Result": "fail", ...}
            let status = dict.get("Status").cloned();
            let result = match dict.get("Result") {
                Some(Plist::Str(s)) => s.clone(),
                _ => String::new(),
            };
            return Err(format!(
                "TSS response missing ApImg4Ticket (Status={status:?}, Result={result:?})"
            ));
        }
    };
    validate_im4m(&ticket)?;
    Ok(ticket)
}

/// Parse a TSS response from raw XML bytes.
pub fn parse_tss_response_xml(xml: &str) -> Result<Vec<u8>, String> {
    let p = plist_lite::from_xml(xml)?;
    parse_tss_response(&p)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal DER IM4M: SEQUENCE { IA5 "IM4M" } (structure check only —
    /// the full certificate SET arrives from the signing server).
    fn fake_im4m() -> Vec<u8> {
        let inner = {
            let mut v = vec![TAG_IA5_STRING, 4];
            v.extend_from_slice(b"IM4M");
            v
        };
        let mut out = vec![TAG_SEQUENCE, inner.len() as u8];
        out.extend_from_slice(&inner);
        out
    }

    #[test]
    fn request_shape_is_canonical() {
        let req = build_tss_request(
            8,
            0x8030,
            1,
            &[0x00, 0x11, 0x22],
            &[0x33],
            Some(b"UBID"),
            &[
                component("Ap,OS", &[0xAA; 20]),
                component("Ap,KernelCache", &[0xBB; 20]),
            ],
        );
        match req {
            Plist::Dict(d) => {
                assert_eq!(d.get("@ApImg4Ticket"), Some(&Plist::Bool(true)));
                assert_eq!(d.get("ApBoardID"), Some(&Plist::UInt(8)));
                assert_eq!(d.get("ApChipID"), Some(&Plist::UInt(0x8030)));
                assert_eq!(d.get("ApSecurityDomain"), Some(&Plist::UInt(1)));
                assert_eq!(
                    d.get("ApNonce"),
                    Some(&Plist::Data(vec![0x00, 0x11, 0x22]))
                );
                assert_eq!(d.get("SepNonce"), Some(&Plist::Data(vec![0x33])));
                assert_eq!(d.get("UniqueBuildID"), Some(&Plist::Data(b"UBID".to_vec())));
                match d.get("Ap,OS") {
                    Some(Plist::Dict(c)) => {
                        assert_eq!(c.get("Digest"), Some(&Plist::Data(vec![0xAA; 20])));
                    }
                    other => panic!("component dict expected, got {other:?}"),
                }
                // canonical ordering: '@' key first, then lexicographic
                let keys: Vec<&String> = d.keys().collect();
                assert_eq!(keys[0], "@ApImg4Ticket");
                assert_eq!(keys[1], "Ap,KernelCache");
                assert_eq!(keys[2], "Ap,OS");
            }
            other => panic!("dict expected, got {other:?}"),
        }
    }

    #[test]
    fn response_ticket_extracts_and_validates() {
        let ticket = fake_im4m();
        let xml = format!(
            "<plist version=\"1.0\"><dict>\
<key>Status</key><integer>0</integer>\
<key>ApImg4Ticket</key><data>{}</data></dict></plist>",
            plist_lite::base64_encode(&ticket)
        );
        let got = parse_tss_response_xml(&xml).expect("ticket");
        assert_eq!(got, ticket);
    }

    #[test]
    fn response_failure_shape_is_reported() {
        let xml = "<plist version=\"1.0\"><dict>\
<key>Status</key><integer>1</integer>\
<key>Result</key><string>fail</string></dict></plist>";
        let e = parse_tss_response_xml(xml).unwrap_err();
        assert!(e.contains("missing ApImg4Ticket"), "{e}");
        assert!(e.contains("fail"), "{e}");
    }

    #[test]
    fn im4m_structure_gate() {
        assert!(validate_im4m(&fake_im4m()).is_ok());
        // truncated magic
        let bad = fake_im4m();
        assert!(validate_im4m(&bad[..bad.len() - 2]).is_err());
        // wrong magic
        let mut wrong = vec![TAG_SEQUENCE, 6, TAG_IA5_STRING, 4];
        wrong.extend_from_slice(b"IM4P");
        assert!(validate_im4m(&wrong).is_err());
    }
}
