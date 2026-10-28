//! TSS request building + response parsing + minimal HTTP POST.

use plist::{self, Value};
use std::io::{self, Read, Write};

/// Build the TSS request dict for one build identity.
///
/// Copies the identity's trust fields verbatim (upstream
/// `tss_parameters_add_from_manifest`), adds device identity + nonces and the
/// `@ApImg4Ticket` response selector. `Info` (paths/variants) never crosses
/// the wire.
pub fn build_tss_request(
    identity: &Value,
    ecid: u64,
    ap_nonce: Option<&[u8]>,
    sep_nonce: Option<&[u8]>,
) -> Result<Value, String> {
    let mut request = Value::Dictionary(vec![]);

    for key in ["UniqueBuildID", "ApChipID", "ApBoardID", "ApSecurityDomain"] {
        let v = identity
            .get(key)
            .cloned()
            .ok_or_else(|| format!("tss: build identity lacks {key}"))?;
        request.set(key, v);
    }

    request.set("ApECID", Value::UInteger(ecid));
    request.set("ApProductionMode", Value::Boolean(true));
    if let Some(n) = ap_nonce {
        request.set("ApNonce", Value::Data(n.to_vec()));
    }
    if let Some(n) = sep_nonce {
        request.set("SepNonce", Value::Data(n.to_vec()));
    }
    // response selector: "give me the personalized IM4M"
    request.set("@ApImg4Ticket", Value::Boolean(true));
    Ok(request)
}

/// Pull the signed IM4M out of a TSS response (`@ApImg4Ticket` as plist data
/// or base64 string).
pub fn extract_ap_img4_ticket(response: &Value) -> Result<Vec<u8>, String> {
    match response.get("@ApImg4Ticket") {
        Some(Value::Data(d)) => Ok(d.clone()),
        Some(Value::String(s)) => plist::base64_decode(s),
        other => Err(format!(
            "tss: response lacks @ApImg4Ticket ticket (found {other:?})"
        )),
    }
}

/// Minimal HTTP/1.1 POST of a TSS request body.
///
/// The caller owns the socket: plain `TcpStream` against a lab TSS mirror,
/// or a TLS-wrapped stream against Apple's `gs.apple.com`. Reads until EOF
/// (we send `Connection: close`), returns the response body.
pub fn post_tss<S: Read + Write>(stream: &mut S, host: &str, body: &str) -> Result<String, String> {
    let head = format!(
        "POST /TSS/controller?action=2 HTTP/1.1\r\n\
         Host: {host}\r\n\
         Content-Type: text/xml; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         User-Agent: InetURL/1.0\r\n\
         Connection: close\r\n\
         \r\n",
        body.len()
    );
    stream
        .write_all(head.as_bytes())
        .and_then(|_| stream.write_all(body.as_bytes()))
        .and_then(|_| stream.flush())
        .map_err(|e| format!("tss: send failed: {e}"))?;

    let mut raw = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => raw.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(format!("tss: recv failed: {e}")),
        }
        if raw.len() > 16 << 20 {
            return Err("tss: response too large".into());
        }
    }
    let text = String::from_utf8_lossy(&raw).to_string();
    let split = text
        .find("\r\n\r\n")
        .ok_or_else(|| "tss: response without header terminator".to_string())?;
    let (head, rest) = text.split_at(split + 4);
    let status_ok = head.starts_with("HTTP/1.1 200") || head.starts_with("HTTP/1.0 200");
    if !status_ok {
        return Err(format!(
            "tss: server returned {}",
            head.lines().next().unwrap_or("?")
        ));
    }
    // Content-Length or close-delimited body
    let content_length = head
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            if k.trim().eq_ignore_ascii_case("content-length") {
                v.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(rest.len());
    Ok(rest.chars().take(content_length).collect())
}
