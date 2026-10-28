//! host — the pure-Rust **restore-host pipeline**: usbmuxhost → restored →
//! ASR, replacing the libusbmuxd + libimobiledevice + idevicerestore chain
//! for the lanes (X-rows #1–#3 closed end-to-end).
//!
//! Sequence (mirrors idevicerestore `restore.c` + the proven diag lane):
//! 1. `QueryType` → service type + `RestoreProtocolVersion`,
//! 2. `QueryValue HardwareInfo`,
//! 3. `StartRestore` with `restored::build_restore_options`,
//! 4. notification loop:
//!    * `ProgressMsg` → progress,
//!    * `CheckpointMsg` → the engine checkpoint chain (0x0104…),
//!    * `SystemImageData` → open ASR on port 12345 via the `open_asr`
//!      callback, run the validation handshake and push the image,
//!    * `StatusMsg` → record; **Status 0 = "Restore Finished"** (the exact
//!      campaign terminal-state string) → ack `ReceivedFinalStatusMsg`,
//!      stop,
//!    * `AMRError` / other failures → error out.

use asr::{AsrClient, ImageSource};
use plist::Value;
use restored::{build_restore_options, RestoredClient, RestoredEvent};
use std::io::{Read, Write};

pub const STACK_ID: &str = "usbmuxhost/restored/asr — pure Rust (X-rows closed)";

/// Everything a run produced, for reports and worklogs.
#[derive(Debug, Default, Clone)]
pub struct HostRestoreReport {
    pub protocol_version: u64,
    pub hardware_info: Option<Value>,
    /// (status code, human name) pairs in arrival order.
    pub statuses: Vec<(u64, &'static str)>,
    pub bytes_pushed: u64,
    pub finished: bool,
}

/// Off-network self-check used by `ios-rust selftest`: plist roundtrip +
/// SHA-1 vector + fletcher sum-to-zero property.
pub fn smoke() -> bool {
    // plist roundtrip
    let mut v = Value::Dictionary(vec![("Command".into(), Value::String("Initiate".into()))]);
    v.set("Checksum Chunks", Value::Boolean(true));
    let rt = plist::parse(plist::to_string(&v).as_bytes())
        .map(|p| p == v)
        .unwrap_or(false);
    // sha1("abc")
    let sha_ok = asr::sha1::sha1(b"abc")
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
        == "a9993e364706816aba3e25717850c26c9cd0d89d";
    // fletcher: stored checksum verifies
    let mut block = vec![0u8; 4096];
    for (i, b) in block.iter_mut().enumerate().skip(8) {
        *b = (i as u8).wrapping_mul(37);
    }
    let stored = apfs::compute_block_cksum(&block);
    block[0..8].copy_from_slice(&stored.to_le_bytes());
    let fletcher_ok = apfs::verify_block(&block);
    rt && sha_ok && fletcher_ok
}

/// UUIDv4-ish tag for RestoreOptions (std-only: time nanos, no rand dep).
pub fn generate_uuid() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let a = (nanos as u64) ^ 0x9E37_79B9_7F4A_7C15;
    let b = (nanos >> 64) as u64 ^ 0xBF58_476D_1CE4_E5B9;
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        (a >> 32) as u32,
        (a >> 16) as u16,
        ((a & 0xFFFF) as u16 & 0x0FFF) | 0x4000,
        ((b >> 48) as u16 & 0x3FFF) | 0x8000,
        b & 0xFFFF_FFFF_FFFF,
    )
}

/// Run the full host-side restore against a live `restored` connection.
///
/// `open_asr` is called exactly when restored signals `SystemImageData`
/// (it should usbmux-connect to port 12345 and wrap the stream in
/// [`AsrClient::new`]). `progress` receives the push fraction.
pub fn run_host_restore<S, R, F>(
    client: &mut RestoredClient<S>,
    mut open_asr: F,
    image: &mut dyn ImageSource,
    mut progress: impl FnMut(f64),
) -> Result<HostRestoreReport, String>
where
    S: Read + Write,
    R: Read + Write,
    F: FnMut() -> Result<AsrClient<R>, String>,
{
    let (type_, version) = client
        .query_type()
        .map_err(|e| format!("query_type: {e}"))?;
    if type_ != "com.apple.mobile.restored" {
        return Err(format!("unexpected restored type {type_:?}"));
    }
    let hardware_info = client.query_value("HardwareInfo").ok();
    let options = build_restore_options(&generate_uuid());
    client
        .start_restore(&options, version)
        .map_err(|e| format!("start_restore: {e}"))?;

    let mut report = HostRestoreReport {
        protocol_version: version,
        hardware_info,
        ..Default::default()
    };

    loop {
        let event = client
            .recv_event()
            .map_err(|e| format!("recv_event: {e}"))?;
        match event {
            RestoredEvent::Progress { progress: p, .. } => {
                if let Some(p) = p {
                    progress(p);
                }
            }
            RestoredEvent::Checkpoint { .. } => {
                // the engine checkpoint chain (0x0104 → …) — informational
            }
            RestoredEvent::AsyncDataRequest { data_type, .. } if data_type == "SystemImageData" => {
                let mut asr = open_asr()?;
                asr.perform_validation(image)
                    .map_err(|e| format!("asr validation: {e}"))?;
                report.bytes_pushed = asr
                    .send_payload(image, &mut progress)
                    .map_err(|e| format!("asr push: {e}"))?;
            }
            RestoredEvent::Status { code, amr_error } => {
                report
                    .statuses
                    .push((code, restored::status_name(code)));
                if let Some(err) = amr_error {
                    return Err(format!(
                        "restore failed: Status {} ({}), AMRError {}",
                        code,
                        restored::status_name(code),
                        err
                    ));
                }
                if code == 0 {
                    report.finished = true;
                    client
                        .send_final_status_ack()
                        .map_err(|e| format!("final ack: {e}"))?;
                    return Ok(report);
                }
            }
            RestoredEvent::Other(_) => {
                // PreviousRestoreLogMsg and friends are informational
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use restored::RESTORED_PORT;
    use usbmux::MuxConnection;
    use std::net::{TcpListener, TcpStream};

    fn framed_send(conn: &mut TcpStream, v: &Value) {
        let xml = plist::to_string(v);
        let mut buf = (xml.len() as u32).to_be_bytes().to_vec();
        buf.extend_from_slice(xml.as_bytes());
        conn.write_all(&buf).unwrap();
    }

    fn framed_recv(conn: &mut TcpStream) -> Value {
        let mut lb = [0u8; 4];
        conn.read_exact(&mut lb).unwrap();
        let mut buf = vec![0u8; u32::from_be_bytes(lb) as usize];
        conn.read_exact(&mut buf).unwrap();
        plist::parse(&buf).unwrap()
    }

    fn dict(pairs: Vec<(&str, Value)>) -> Value {
        Value::Dictionary(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }

    /// Device-side restored responder (port 62078).
    fn serve_restored(conn: &mut TcpStream) {
        loop {
            let req = framed_recv(conn);
            if req.get("MsgType").and_then(|m| m.as_string()) == Some("ReceivedFinalStatusMsg") {
                return;
            }
            match req.get("Request").and_then(|r| r.as_string()).unwrap_or("") {
                "QueryType" => framed_send(
                    conn,
                    &dict(vec![
                        ("Type", Value::String("com.apple.mobile.restored".into())),
                        ("RestoreProtocolVersion", Value::UInteger(14)),
                    ]),
                ),
                "QueryValue" => framed_send(
                    conn,
                    &dict(vec![(
                        "HardwareInfo",
                        dict(vec![("ProductType", Value::String("iPhone11,8".into()))]),
                    )]),
                ),
                "StartRestore" => {
                    assert!(req.get("RestoreOptions").is_some());
                    framed_send(
                        conn,
                        &dict(vec![
                            ("MsgType", Value::String("ProgressMsg".into())),
                            ("Progress", Value::Real(0.1)),
                        ]),
                    );
                    // restored is ready for the filesystem → ASR push happens
                    framed_send(
                        conn,
                        &dict(vec![("MsgType", Value::String("SystemImageData".into()))]),
                    );
                    // (the ASR push completes while this is in flight)
                    framed_send(
                        conn,
                        &dict(vec![
                            ("MsgType", Value::String("StatusMsg".into())),
                            ("Status", Value::UInteger(0)),
                        ]),
                    );
                }
                _ => return,
            }
        }
    }

    /// Device-side ASR responder (port 12345).
    fn serve_asr(conn: &mut TcpStream) {
        let send = |conn: &mut TcpStream, v: &Value| {
            conn.write_all(plist::to_string(v).as_bytes()).unwrap();
        };
        send(
            conn,
            &dict(vec![
                ("Command", Value::String("Initiate".into())),
                ("Checksum Chunks", Value::Boolean(true)),
            ]),
        );
        let read_plist = |conn: &mut TcpStream| -> Value {
            let mut buf: Vec<u8> = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                if let Ok((v, consumed)) = plist::parse_prefix(&buf) {
                    assert_eq!(buf.len() - consumed, 0, "unexpected coalesced plists");
                    return v;
                }
                let n = conn.read(&mut chunk).unwrap();
                assert!(n > 0);
                buf.extend_from_slice(&chunk[..n]);
            }
        };
        let info = read_plist(conn);
        let declared = info
            .get("Payload")
            .and_then(|p| p.get("Size"))
            .and_then(|s| s.as_uint())
            .expect("Payload.Size");
        send(
            conn,
            &dict(vec![
                ("Command", Value::String("Initiate".into())),
                ("Checksum Chunks", Value::Boolean(true)),
            ]),
        );
        let _ = read_plist(conn);
        send(conn, &dict(vec![("Command", Value::String("Payload".into()))]));
        let mut received: Vec<u8> = Vec::new();
        let expected = declared as usize + (declared as usize / 131072 + 1) * 20;
        let mut buf = [0u8; 65536];
        while received.len() < expected {
            let n = conn.read(&mut buf).unwrap();
            assert!(n > 0, "asr stream ended early");
            received.extend_from_slice(&buf[..n]);
        }
        // verify chunk structure: ≤131072 data + 20-byte sha1 tails
        let mut off = 0usize;
        let mut chunks = 0;
        while off < received.len() {
            let remaining = received.len() - off;
            let data_len = remaining.min(131072);
            let digest = asr::sha1::sha1(&received[off..off + data_len]);
            let tail = (remaining - data_len).min(20);
            assert_eq!(
                &received[off + data_len..off + data_len + tail],
                &digest[..tail],
                "sha1 tail mismatch in chunk {chunks}"
            );
            off += data_len + tail;
            chunks += 1;
        }
        assert_eq!(received.len(), expected);
    }

    /// Mock usbmuxd + device: Listen/DeviceList, then Connect branches by
    /// port — 0xF27E → restored protocol, 12345 → ASR protocol.
    fn spawn_mock_device() -> std::net::SocketAddr {
        use usbmux::{Header, HEADER_SIZE, MESSAGE_CONNECT, MESSAGE_PLIST, MESSAGE_RESULT};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let mut conn = conn.unwrap();
                std::thread::spawn(move || loop {
                    let mut hb = [0u8; HEADER_SIZE];
                    if conn.read_exact(&mut hb).is_err() {
                        return;
                    }
                    let h = Header::decode(&hb);
                    let mut payload = vec![0u8; h.length as usize - HEADER_SIZE];
                    if !payload.is_empty() && conn.read_exact(&mut payload).is_err() {
                        return;
                    }
                    match h.message {
                        MESSAGE_PLIST => {
                            let msg = match plist::parse(&payload) {
                                Ok(m) => m,
                                Err(_) => return,
                            };
                            match msg
                                .get("MessageType")
                                .and_then(|m| m.as_string())
                                .unwrap_or("")
                            {
                                "Listen" => {
                                    let reply = dict(vec![
                                        ("MessageType", Value::String("Result".into())),
                                        ("Number", Value::UInteger(0)),
                                    ]);
                                    let xml = plist::to_string(&reply);
                                    let hdr = Header::new(MESSAGE_PLIST, h.tag, xml.len());
                                    conn.write_all(&hdr.encode()).unwrap();
                                    conn.write_all(xml.as_bytes()).unwrap();
                                }
                                "DeviceList" => {
                                    let device = dict(vec![
                                        ("DeviceID", Value::UInteger(42)),
                                        (
                                            "Properties",
                                            dict(vec![
                                                ("SerialNumber", Value::String("e2e-udid".into())),
                                                ("ConnectionType", Value::String("USB".into())),
                                            ]),
                                        ),
                                    ]);
                                    let reply = dict(vec![
                                        ("MessageType", Value::String("DeviceList".into())),
                                        ("DeviceList", Value::Array(vec![device])),
                                    ]);
                                    let xml = plist::to_string(&reply);
                                    let hdr = Header::new(MESSAGE_PLIST, h.tag, xml.len());
                                    conn.write_all(&hdr.encode()).unwrap();
                                    conn.write_all(xml.as_bytes()).unwrap();
                                }
                                _ => return,
                            }
                        }
                        MESSAGE_CONNECT => {
                            let device_id =
                                u32::from_le_bytes(payload[0..4].try_into().unwrap());
                            assert_eq!(device_id, 42);
                            let port =
                                u16::from_le_bytes([payload[4], payload[5]]).swap_bytes();
                            let hdr = Header::new(MESSAGE_RESULT, h.tag, 4);
                            conn.write_all(&hdr.encode()).unwrap();
                            conn.write_all(&0u32.to_le_bytes()).unwrap();
                            match port {
                                RESTORED_PORT => serve_restored(&mut conn),
                                asr::ASR_PORT => serve_asr(&mut conn),
                                other => panic!("unexpected port {other}"),
                            }
                            return;
                        }
                        _ => return,
                    }
                });
            }
        });
        addr
    }

    #[test]
    fn end_to_end_host_restore_over_mock_device() {
        let addr = spawn_mock_device();
        let url = addr.to_string();

        // device discovery
        let mut mux_a = MuxConnection::connect_tcp(&url).unwrap();
        mux_a.listen().unwrap();
        let devs = mux_a.device_list().unwrap();
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].device_id, 42);

        // restored connection
        let mux_b = MuxConnection::connect_tcp(&url).unwrap();
        let stream = mux_b
            .connect_device(42, RESTORED_PORT)
            .expect("connect restored");
        let mut client = RestoredClient::new(stream, "ios-rust-e2e");

        let image: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        let mut src = std::io::Cursor::new(image);

        let addr_for_asr = addr.to_string();
        let report = run_host_restore(
            &mut client,
            move || {
                let mux_c = MuxConnection::connect_tcp(&addr_for_asr).unwrap();
                let s = mux_c
                    .connect_device(42, asr::ASR_PORT)
                    .map_err(|e| e.to_string())?;
                AsrClient::new(s).map_err(|e| e.to_string())
            },
            &mut src,
            |_| {},
        )
        .expect("end-to-end restore");

        assert!(report.finished);
        assert_eq!(report.protocol_version, 14);
        assert!(report.hardware_info.is_some());
        assert_eq!(report.bytes_pushed, 300_000);
        let (last_code, last_name) = report.statuses.last().expect("statuses");
        assert_eq!(*last_code, 0);
        assert_eq!(*last_name, "Restore Finished");
    }

    #[test]
    fn smoke_passes() {
        assert!(smoke());
    }
}
