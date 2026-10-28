//! restored — pure-Rust **restored protocol client** (X-row #2).
//!
//! Replaces the `restored_*` half of libimobiledevice `src/restore.c`
//! (LGPL-2.1 — protocol reference, not a code copy). Wire facts, verified
//! against upstream AND against our own Ghidra decompilation of
//! `restored_external` (ios-sweet-rust run 40609705374: port **0xF27E = 62078**
//! is hardcoded in `entry()`):
//!
//! * transport: usbmux connect to port [`RESTORED_PORT`], **no SSL**,
//! * framing: 4-byte big-endian length prefix + XML plist
//!   (`property_list_service` style) both directions,
//! * requests: `{Label, Request: "QueryType"|"QueryValue"|"StartRestore"|
//!   "Goodbye"|"Reboot", …}` with `RestoreProtocolVersion`/`RestoreOptions`,
//! * responses carry `Result: "Success"|"Failure"`; `QueryType` returns
//!   `Type` + `RestoreProtocolVersion`,
//! * notifications after `StartRestore` are `MsgType`-keyed dicts:
//!   `ProgressMsg`, `StatusMsg` (`Status` uint — **0 = "Restore Finished"**,
//!   the exact campaign terminal-state string — plus `AMRError`),
//!   `CheckpointMsg` (`CHECKPOINT_ID`/`CHECKPOINT_RESULT`), async data
//!   requests (`SystemImageData` → ASR push time), `PreviousRestoreLogMsg`.

use plist::{self, Value};
use std::io::{self, Read, Write};

/// restored listens here (0xf27e, `.port = 0xf27e` in libimobiledevice
/// restore.c and hardcoded in the ramdisk `restored_external` entry()).
pub const RESTORED_PORT: u16 = 0xf27e;

pub const RESULT_SUCCESS: &str = "Success";
pub const RESULT_FAILURE: &str = "Failure";

/// restored protocol client over a device-port stream.
pub struct RestoredClient<S: Read + Write> {
    stream: S,
    label: String,
    /// Captured `QueryType` response (upstream `client->info`).
    pub info: Option<Value>,
}

impl<S: Read + Write> RestoredClient<S> {
    pub fn new(stream: S, label: impl Into<String>) -> Self {
        RestoredClient {
            stream,
            label: label.into(),
            info: None,
        }
    }

    fn request_dict(&self, request: &str) -> Value {
        Value::Dictionary(vec![
            ("Label".into(), Value::String(self.label.clone())),
            ("Request".into(), Value::String(request.to_string())),
        ])
    }

    fn send(&mut self, v: &Value) -> io::Result<()> {
        let xml = plist::to_string(v);
        let mut buf = (xml.len() as u32).to_be_bytes().to_vec();
        buf.extend_from_slice(xml.as_bytes());
        self.stream.write_all(&buf)
    }

    fn recv(&mut self) -> io::Result<Value> {
        let mut len_buf = [0u8; 4];
        self.stream.read_exact(&mut len_buf)?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > 64 << 20 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("restored: oversized plist {len}"),
            ));
        }
        let mut buf = vec![0u8; len];
        if len > 0 {
            self.stream.read_exact(&mut buf)?;
        }
        plist::parse(&buf).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("restored plist: {e}"))
        })
    }

    fn check_result(v: &Value) -> Result<(), io::Error> {
        match v.get("Result").and_then(|r| r.as_string()) {
            Some(RESULT_SUCCESS) => Ok(()),
            Some(RESULT_FAILURE) => Err(io::Error::new(
                io::ErrorKind::Other,
                "restored: Result=Failure",
            )),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("restored: bad Result {other:?}"),
            )),
        }
    }

    /// `QueryType` → (service type, RestoreProtocolVersion). Stores `info`.
    pub fn query_type(&mut self) -> io::Result<(String, u64)> {
        let dict = self.request_dict("QueryType");
        self.send(&dict)?;
        let resp = self.recv()?;
        let type_ = resp
            .get("Type")
            .and_then(|t| t.as_string())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "restored: QueryType lacks Type")
            })?
            .to_string();
        let version = resp
            .get("RestoreProtocolVersion")
            .and_then(|v| v.as_uint())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "restored: no RestoreProtocolVersion")
            })?;
        self.info = Some(resp);
        Ok((type_, version))
    }

    /// `QueryValue` with a `QueryKey`.
    pub fn query_value(&mut self, key: &str) -> io::Result<Value> {
        let mut dict = self.request_dict("QueryValue");
        dict.set("QueryKey", Value::String(key.to_string()));
        self.send(&dict)?;
        let resp = self.recv()?;
        resp.get(key).cloned().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, format!("restored: no {key} in reply"))
        })
    }

    /// `StartRestore` — sends `RestoreOptions` + `RestoreProtocolVersion`
    /// (upstream sends without waiting for a direct reply; the device answers
    /// with async notifications).
    pub fn start_restore(&mut self, options: &Value, protocol_version: u64) -> io::Result<()> {
        let mut dict = self.request_dict("StartRestore");
        dict.set("RestoreOptions", options.clone());
        dict.set("RestoreProtocolVersion", Value::UInteger(protocol_version));
        self.send(&dict)
    }

    /// Reply to a final status message (upstream sends this after Status 0).
    pub fn send_final_status_ack(&mut self) -> io::Result<()> {
        let dict = Value::Dictionary(vec![(
            "MsgType".into(),
            Value::String("ReceivedFinalStatusMsg".into()),
        )]);
        self.send(&dict)
    }

    /// `Goodbye` (expects Result=Success).
    pub fn goodbye(&mut self) -> io::Result<()> {
        let dict = self.request_dict("Goodbye");
        self.send(&dict)?;
        let resp = self.recv()?;
        Self::check_result(&resp)
    }

    /// `Reboot` request.
    pub fn reboot(&mut self) -> io::Result<()> {
        let dict = self.request_dict("Reboot");
        self.send(&dict)?;
        self.recv()?;
        Ok(())
    }

    /// Receive the next notification and classify it.
    pub fn recv_event(&mut self) -> io::Result<RestoredEvent> {
        let msg = self.recv()?;
        Ok(RestoredEvent::from_value(msg))
    }
}

/// One notification from restored, classified.
#[derive(Debug, Clone)]
pub enum RestoredEvent {
    /// `ProgressMsg` — operation name + optional 0.0..=1.0 progress.
    Progress {
        operation: Option<String>,
        progress: Option<f64>,
    },
    /// `StatusMsg` — `Status` code (+ `AMRError` when failing).
    Status { code: u64, amr_error: Option<u64> },
    /// `CheckpointMsg` — the monitor/engine checkpoint chain.
    Checkpoint {
        id: u64,
        result: Option<i64>,
        name: Option<String>,
        complete: bool,
    },
    /// Async data request — `SystemImageData` means restored is ready for the
    /// ASR filesystem push.
    AsyncDataRequest { data_type: String, message: Value },
    /// Anything else (PreviousRestoreLogMsg, final ack replies, …).
    Other(Value),
}

impl RestoredEvent {
    pub fn from_value(msg: Value) -> RestoredEvent {
        let msg_type = msg
            .get("MsgType")
            .and_then(|m| m.as_string())
            .unwrap_or("")
            .to_string();
        match msg_type.as_str() {
            "ProgressMsg" => RestoredEvent::Progress {
                operation: msg.get("Operation").and_then(|o| o.as_string()).map(str::to_string),
                progress: match msg.get("Progress") {
                    Some(Value::Real(f)) => Some(*f),
                    Some(Value::Integer(i)) => Some(*i as f64),
                    _ => None,
                },
            },
            "StatusMsg" => RestoredEvent::Status {
                code: msg.get("Status").and_then(|s| s.as_uint()).unwrap_or(u64::MAX),
                amr_error: msg.get("AMRError").and_then(|s| s.as_uint()),
            },
            "CheckpointMsg" => RestoredEvent::Checkpoint {
                id: msg.get("CHECKPOINT_ID").and_then(|c| c.as_uint()).unwrap_or(0),
                result: msg.get("CHECKPOINT_RESULT").and_then(|c| c.as_int()),
                name: msg
                    .get("CHECKPOINT_NAME")
                    .and_then(|c| c.as_string())
                    .map(str::to_string),
                complete: msg.get("Complete").and_then(|c| c.as_bool()).unwrap_or(false),
            },
            "SystemImageData" | "BasebandData" | "RecoveryOSASRImage" | "URLAsset"
            | "StreamedImageDecryptionKey" => RestoredEvent::AsyncDataRequest {
                data_type: msg_type,
                message: msg,
            },
            _ => RestoredEvent::Other(msg),
        }
    }
}

/// Human names for the restored `Status` codes (idevicerestore's table —
/// includes the campaign's terminal string).
pub fn status_name(code: u64) -> &'static str {
    match code {
        0 => "Restore Finished",
        6 => "Disk Failure",
        14 => "Fail",
        27 => "Failed to mount filesystems.",
        50 | 51 => "Failed to load SEP Firmware.",
        53 => "Failed to recover FDR data.",
        1015 => "X-Gold Baseband Update Failed. Defective Unit?",
        0xFFFF_FFFF_FFFF_FFFF => "Verification Error",
        _ => "Unhandled status message",
    }
}

/// Build the `RestoreOptions` dict (idevicerestore `restore.c` subset for an
/// iOS 14-era restore-from-ramdisk flow).
pub fn build_restore_options(uuid: &str) -> Value {
    let padding = Value::Dictionary(vec![
        ("8".into(), Value::UInteger(80)),
        ("16".into(), Value::UInteger(160)),
        ("32".into(), Value::UInteger(320)),
        ("64".into(), Value::UInteger(640)),
        ("128".into(), Value::UInteger(1280)),
        ("256".into(), Value::UInteger(1280)),
        ("512".into(), Value::UInteger(1280)),
        ("768".into(), Value::UInteger(1280)),
        ("1024".into(), Value::UInteger(1280)),
    ]);
    Value::Dictionary(vec![
        ("BootImageType".into(), Value::String("User".into())),
        ("DFUFileType".into(), Value::String("RELEASE".into())),
        ("DataImage".into(), Value::Boolean(false)),
        ("FlashNOR".into(), Value::Boolean(true)),
        ("KernelCacheType".into(), Value::String("Release".into())),
        ("NORImageType".into(), Value::String("production".into())),
        ("SystemImageType".into(), Value::String("User".into())),
        ("CreateFilesystemPartitions".into(), Value::Boolean(true)),
        ("SystemImage".into(), Value::Boolean(true)),
        ("PersonalizedDuringPreflight".into(), Value::Boolean(true)),
        ("UpdateBaseband".into(), Value::Boolean(true)),
        ("InstallDiags".into(), Value::Boolean(false)),
        ("RootToInstall".into(), Value::Boolean(false)),
        ("UUID".into(), Value::String(uuid.to_string())),
        ("SystemPartitionPadding".into(), padding),
    ])
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};

    fn framed(conn: &mut TcpStream, v: &Value) {
        let xml = plist::to_string(v);
        let mut buf = (xml.len() as u32).to_be_bytes().to_vec();
        buf.extend_from_slice(xml.as_bytes());
        conn.write_all(&buf).unwrap();
    }

    fn read_framed(conn: &mut TcpStream) -> Value {
        let mut lb = [0u8; 4];
        conn.read_exact(&mut lb).unwrap();
        let mut buf = vec![0u8; u32::from_be_bytes(lb) as usize];
        conn.read_exact(&mut buf).unwrap();
        plist::parse(&buf).unwrap()
    }

    fn dict(pairs: Vec<(&str, Value)>) -> Value {
        Value::Dictionary(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }

    /// Mock restored: QueryType → HardwareInfo → StartRestore → events.
    fn spawn_mock_restored() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            loop {
                let req = {
                    let mut lb = [0u8; 4];
                    if conn.read_exact(&mut lb).is_err() {
                        return;
                    }
                    let mut buf = vec![0u8; u32::from_be_bytes(lb) as usize];
                    conn.read_exact(&mut buf).unwrap();
                    plist::parse(&buf).unwrap()
                };
                // the client's final-status ack carries MsgType, not Request
                if req.get("MsgType").and_then(|m| m.as_string()) == Some("ReceivedFinalStatusMsg") {
                    continue;
                }
                let req_kind = req
                    .get("Request")
                    .and_then(|r| r.as_string())
                    .unwrap_or("")
                    .to_string();
                match req_kind.as_str() {
                    "QueryType" => {
                        framed(
                            &mut conn,
                            &dict(vec![
                                ("Label", Value::String("mock".into())),
                                ("Type", Value::String("com.apple.mobile.restored".into())),
                                ("RestoreProtocolVersion", Value::UInteger(14)),
                            ]),
                        );
                    }
                    "QueryValue" => {
                        let key = req.get("QueryKey").and_then(|k| k.as_string()).unwrap_or("");
                        let value = if key == "HardwareInfo" {
                            dict(vec![("ChipID", Value::UInteger(0x8030))])
                        } else {
                            Value::UInteger(1)
                        };
                        let leaked: &'static str = Box::leak(key.to_string().into_boxed_str());
                        framed(
                            &mut conn,
                            &dict(vec![
                                ("Label", Value::String("mock".into())),
                                (leaked, value),
                            ]),
                        );
                    }
                    "StartRestore" => {
                        assert_eq!(
                            req.get("RestoreProtocolVersion").and_then(|v| v.as_uint()),
                            Some(14)
                        );
                        assert!(req.get("RestoreOptions").is_some());
                        // notifications follow asynchronously
                        framed(
                            &mut conn,
                            &dict(vec![
                                ("MsgType", Value::String("ProgressMsg".into())),
                                ("Operation", Value::String("Erasing".into())),
                                ("Progress", Value::Real(0.25)),
                            ]),
                        );
                        framed(
                            &mut conn,
                            &dict(vec![
                                ("MsgType", Value::String("CheckpointMsg".into())),
                                ("CHECKPOINT_ID", Value::UInteger(0x0104)),
                                ("CHECKPOINT_RESULT", Value::Integer(0)),
                                ("CHECKPOINT_NAME", Value::String("umask".into())),
                            ]),
                        );
                        framed(
                            &mut conn,
                            &dict(vec![
                                ("MsgType", Value::String("StatusMsg".into())),
                                ("Status", Value::UInteger(0)),
                            ]),
                        );
                        // client acks with ReceivedFinalStatusMsg, then Goodbye
                    }
                    "Goodbye" => {
                        framed(
                            &mut conn,
                            &dict(vec![("Result", Value::String("Success".into()))]),
                        );
                        return;
                    }
                    _ => return,
                }
            }
        });
        addr
    }

    #[test]
    fn full_restored_flow_against_mock() {
        let addr = spawn_mock_restored();
        let stream = TcpStream::connect(addr).unwrap();
        let mut client = RestoredClient::new(stream, "ios-rust");

        let (type_, version) = client.query_type().expect("query_type");
        assert_eq!(type_, "com.apple.mobile.restored");
        assert_eq!(version, 14);

        let hw = client.query_value("HardwareInfo").expect("query_value");
        assert_eq!(hw.get("ChipID").and_then(|c| c.as_uint()), Some(0x8030));

        let options = build_restore_options("11111111-2222-3333-4444-555555555555");
        client.start_restore(&options, version).expect("start_restore");

        let e1 = client.recv_event().expect("event 1");
        match e1 {
            RestoredEvent::Progress { operation, progress } => {
                assert_eq!(operation.as_deref(), Some("Erasing"));
                assert_eq!(progress, Some(0.25));
            }
            other => panic!("expected progress, got {other:?}"),
        }
        let e2 = client.recv_event().expect("event 2");
        match e2 {
            RestoredEvent::Checkpoint { id, name, .. } => {
                assert_eq!(id, 0x0104);
                assert_eq!(name.as_deref(), Some("umask"));
            }
            other => panic!("expected checkpoint, got {other:?}"),
        }
        let e3 = client.recv_event().expect("event 3");
        match e3 {
            RestoredEvent::Status { code, .. } => {
                assert_eq!(code, 0);
                assert_eq!(status_name(code), "Restore Finished");
            }
            other => panic!("expected status, got {other:?}"),
        }

        client.send_final_status_ack().expect("final ack");
        client.goodbye().expect("goodbye");
    }

    #[test]
    fn restore_options_key_set() {
        let opts = build_restore_options("u");
        for key in [
            "BootImageType",
            "DFUFileType",
            "KernelCacheType",
            "NORImageType",
            "SystemImageType",
            "CreateFilesystemPartitions",
            "SystemImage",
            "UUID",
            "SystemPartitionPadding",
        ] {
            assert!(opts.get(key).is_some(), "missing {key}");
        }
    }
}
