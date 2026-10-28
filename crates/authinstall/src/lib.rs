//! authinstall — pure-Rust **libauthinstall subset** (X-row #4: IMG4
//! signing/ticketing).
//!
//! Apple's restore trust chain works like this: the host builds a **TSS
//! request** (device identity + image hashes from the BuildManifest), Apple's
//! ticket server signs it, and the returned **APTicket** (`ApImg4Ticket`) is
//! an **IM4M** — a blob *already signed by Apple*. There is no local signing
//! key; "signing" means requesting, validating and embedding the ticket.
//! This crate implements that host-side subset, replacing idevicerestore's
//! `src/tss.c` + `src/img4.c` request/validation halves (LGPL-2.1 — protocol
//! reference, not code copies):
//!
//! * [`tss::build_tss_request`] — identity fields (UniqueBuildID, ApChipID,
//!   ApBoardID, ApSecurityDomain) + ApECID + ApNonce/SepNonce + the
//!   `@ApImg4Ticket` response selector,
//! * [`tss::extract_ap_img4_ticket`] — decode the signed IM4M out of the
//!   response,
//! * [`tss::post_tss`] — minimal HTTP/1.1 POST for `/TSS/controller?action=2`
//!   over a caller-supplied stream (plain TCP for lab TSS mirrors; TLS is the
//!   caller's transport, documented ledger gate),
//! * [`im4m`] — structural validation of the IM4M container.
//!
//! Key wall (honest): we never possess Apple's signing keys — same as every
//! open-source tool. The ticket is Apple's signature.

pub mod im4m;
pub mod tss;

#[cfg(test)]
mod tests {
    use super::im4m;
    use super::tss;
    use plist::Value;

    fn identity() -> Value {
        Value::Dictionary(vec![
            ("UniqueBuildID".into(), Value::Data(vec![0xAA, 0xBB, 0xCC, 0xDD])),
            ("ApChipID".into(), Value::UInteger(0x8030)),
            ("ApBoardID".into(), Value::UInteger(0x0E)),
            ("ApSecurityDomain".into(), Value::UInteger(1)),
            ("Info".into(), Value::Dictionary(vec![])),
        ])
    }

    #[test]
    fn tss_request_carries_identity_and_nonces() {
        let req = tss::build_tss_request(
            &identity(),
            0x1234_5678_9abc,
            Some(b"apnonce-16bytes1234"),
            Some(b"sepnonce-8"),
        )
        .expect("build request");

        assert_eq!(
            req.get("UniqueBuildID").and_then(|v| v.as_data()),
            Some(&[0xAA, 0xBB, 0xCC, 0xDD][..])
        );
        assert_eq!(req.get("ApChipID").and_then(|v| v.as_uint()), Some(0x8030));
        assert_eq!(req.get("ApBoardID").and_then(|v| v.as_uint()), Some(0x0E));
        assert_eq!(req.get("ApSecurityDomain").and_then(|v| v.as_uint()), Some(1));
        assert_eq!(
            req.get("ApECID").and_then(|v| v.as_uint()),
            Some(0x1234_5678_9abc)
        );
        assert_eq!(
            req.get("ApNonce").and_then(|v| v.as_data()),
            Some(&b"apnonce-16bytes1234"[..])
        );
        assert_eq!(
            req.get("SepNonce").and_then(|v| v.as_data()),
            Some(&b"sepnonce-8"[..])
        );
        assert_eq!(req.get("@ApImg4Ticket").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(
            req.get("ApProductionMode").and_then(|v| v.as_bool()),
            Some(true)
        );
        assert!(
            req.get("Info").is_none(),
            "Info must not leak into the TSS request"
        );
    }

    #[test]
    fn tss_request_without_nonces() {
        let req = tss::build_tss_request(&identity(), 7, None, None).expect("build");
        assert!(req.get("ApNonce").is_none());
        assert!(req.get("SepNonce").is_none());
    }

    #[test]
    fn ticket_extraction_from_response() {
        let ticket_bytes: Vec<u8> = (0u8..=31).collect();
        let response = Value::Dictionary(vec![
            ("@ApImg4Ticket".into(), Value::Data(ticket_bytes.clone())),
            ("@APTicket".into(), Value::Boolean(false)),
        ]);
        let got = tss::extract_ap_img4_ticket(&response).expect("extract");
        assert_eq!(got, ticket_bytes);

        // base64-string variant (some servers ship the ticket as string data)
        let response2 = Value::Dictionary(vec![(
            "@ApImg4Ticket".into(),
            Value::String(plist::base64_encode(&ticket_bytes)),
        )]);
        assert_eq!(tss::extract_ap_img4_ticket(&response2).unwrap(), ticket_bytes);

        assert!(tss::extract_ap_img4_ticket(&Value::Dictionary(vec![])).is_err());
    }

    #[test]
    fn im4m_structural_validation() {
        let im4m = im4m::test_support::build_fixture_im4m();
        assert!(im4m::validate(&im4m).is_ok());

        // tampered fourcc → rejected
        let mut bad = im4m.clone();
        let pos = bad
            .windows(4)
            .position(|w| w == b"IM4M")
            .expect("fixture carries IM4M fourcc");
        bad[pos] = b'X';
        assert!(im4m::validate(&bad).is_err());

        // truncated length → rejected
        let mut short = im4m.clone();
        short.truncate(im4m.len() - 4);
        assert!(im4m::validate(&short).is_err());
    }

    #[test]
    fn tss_http_post_shapes_a_request() {
        // loopback echo server asserting the request shape
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 1024];
            loop {
                let n = conn.read(&mut chunk).unwrap();
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                // headers complete? then wait for exactly Content-Length bytes
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf[..pos]).to_string();
                    let len: usize = head
                        .lines()
                        .find_map(|l| {
                            let (k, v) = l.split_once(':')?;
                            if k.trim().eq_ignore_ascii_case("content-length") {
                                v.trim().parse().ok()
                            } else {
                                None
                            }
                        })
                        .unwrap_or(0);
                    if buf.len() >= pos + 4 + len {
                        break;
                    }
                }
            }
            let text = String::from_utf8_lossy(&buf).to_string();
            assert!(text.starts_with("POST /TSS/controller?action=2 HTTP/1.1"));
            assert!(text.contains("Content-Type: text/xml; charset=utf-8"));
            assert!(text.contains("<?xml"));
            conn.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
            )
            .unwrap();
        });
        let mut conn = std::net::TcpStream::connect(addr).unwrap();
        let body =
            plist::to_string(&tss::build_tss_request(&identity(), 1, None, None).unwrap());
        let resp = tss::post_tss(&mut conn, "tss.example.internal", &body).expect("post");
        assert_eq!(resp, "ok");
    }
}
