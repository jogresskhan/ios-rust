//! Real TSS capture test — runs against a genuine TSS response fetched from
//! Apple's live signing server (gs.apple.com) via `ipsw download tss`:
//! an XML plist with @ServerVersion + base64 ApImg4Ticket (IM4M).
//! Gated: set IOS_RUST_FIXTURES=<dir>; skipped otherwise.

use restore::plist_lite::Plist;

fn fixtures_dir() -> Option<std::path::PathBuf> {
    std::env::var_os("IOS_RUST_FIXTURES").map(std::path::PathBuf::from)
}

fn b64_decode(s: &str) -> Vec<u8> {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0u32;
    for &b in s.as_bytes() {
        if b == b'\n' || b == b'\r' || b == b' ' || b == b'\t' {
            continue;
        }
        let v = T.iter().position(|&t| t == b).unwrap_or(64) as u32;
        if v == 64 {
            break; // padding or end
        }
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    out
}

#[test]
fn real_tss_response_and_im4m() {
    let Some(dir) = fixtures_dir() else { return };
    let Some(path) = std::fs::read_dir(&dir).ok().and_then(|rd| {
        rd.flatten()
            .map(|e| e.path())
            .find(|p| p.extension().map(|e| e == "im4m").unwrap_or(false))
    }) else {
        eprintln!("skip: no .im4m fixture");
        return;
    };
    let raw = std::fs::read(&path).expect("read capture");
    let text = String::from_utf8_lossy(&raw).into_owned();
    println!("real TSS capture: {} ({} bytes)", path.display(), raw.len());

    // 1) The real response parses with our plist_lite (post-fix: hex ints,
    //    paired <true>, comments, self-closing tags).
    let parsed = restore::plist_lite::from_xml(&text)
        .expect("real TSS response parses as XML plist");
    let Plist::Dict(d) = &parsed else {
        panic!("response is a dict");
    };
    // @ServerVersion is the TSS protocol version of the REAL Apple server
    let server = match d.get("@ServerVersion") {
        Some(Plist::Str(s)) => s.clone(),
        other => panic!("@ServerVersion: {other:?}"),
    };
    println!("real @ServerVersion: {server}");
    assert!(!server.is_empty());

    // 2) ApImg4Ticket: base64 data blob → raw IM4M DER
    let Plist::Data(ticket) = d.get("ApImg4Ticket").expect("ApImg4Ticket present") else {
        panic!("ApImg4Ticket is <data>");
    };
    assert!(!ticket.is_empty());
    // The ticket is DER: SEQUENCE(0x30) whose first member is the "IM4M"
    // magic OCTET STRING.
    assert_eq!(ticket[0], 0x30, "ApImg4Ticket is DER SEQUENCE");
    assert!(ticket.windows(4).any(|w| w == b"IM4M"), "IM4M magic inside");
    println!("real ApImg4Ticket: {} bytes of IM4M DER", ticket.len());

    // 3) Structural validation of the REAL ticket (cert chain + Ticket body)
    let cert_count = authinstall::im4m::validate(ticket).expect("real IM4M validates");
    println!("real IM4M: {cert_count} cert(s) in the chain");
    assert!(cert_count >= 2, "Apple tickets carry >= 2 certs, got {cert_count}");
    let body = authinstall::im4m::ticket_bytes(ticket).expect("ticket body");
    assert!(body.len() > 100);
    println!("real IM4M structural parse: OK ({} ticket body bytes)", body.len());
}
