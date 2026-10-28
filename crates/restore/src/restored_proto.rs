//! restored_proto — client for the device-side `restored` restore engine
//! (the `restored protocol client` X-gap).
//!
//! Wire contract (fidelity against libimobiledevice `restored.c` +
//! idevicerestore `restore.c`, cross-checked with our own decompilation of
//! `restored_external` 18A5351d — see ios-sweet-rust RE-FINDINGS.md):
//!
//! * Framing: 4-byte big-endian payload length, then an XML plist body
//!   (restored rides directly on the usbmux tunnel opened by
//!   [`crate::usbmux::MuxClient::connect`]).
//! * Handshake: device sends the first dict carrying
//!   `ProtocolVersion` (`"14"` for iOS 14.0b5); the client replies with
//!   `Identifier` + `ProtocolVersion` of its own.
//! * `QueryValue` / `StartRestore` (`RestoreOptions` + `RestoreProtocolVersion`).
//! * Device→host stream: `Status` (`Status`/`State`/`Progress`/`Operation`),
//!   `Progress`, and `Error` dicts. `Operation` values are restored
//!   checkpoints `CHECKPOINT(op, num) == (op << 8) | num` — the codes the
//!   campaign bisected (0x0104 `handle_new_connections`,
//!   0x065B `asr_and_invert_image`, 0x067E `verify_storage_for_update`)
//!   decode through [`checkpoint_name`].

use crate::plist_lite::{self, Plist};
use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, Read, Write};

/// iOS 14.0b5 restore protocol version (`restored` "ProtocolVersion").
pub const RESTORED_PROTOCOL_VERSION: &str = "14";
/// 4-byte length prefix cap (16 MiB) — plists never approach this.
pub const MAX_FRAME: usize = 16 * 1024 * 1024;

/// Errors surfaced by the restored client.
#[derive(Debug)]
pub enum RestoredError {
    Io(io::Error),
    /// Violation of the protocol contract (bad frame, missing keys).
    Protocol(String),
    /// Device-reported `Error` dict.
    Device { error: String, code: Option<u64> },
}

impl fmt::Display for RestoredError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RestoredError::Io(e) => write!(f, "restored: io: {e}"),
            RestoredError::Protocol(m) => write!(f, "restored: protocol: {m}"),
            RestoredError::Device { error, code } => write!(
                f,
                "restored: device error {error:?} (code {:?})",
                code
            ),
        }
    }
}

impl std::error::Error for RestoredError {}

impl From<io::Error> for RestoredError {
    fn from(e: io::Error) -> Self {
        RestoredError::Io(e)
    }
}

/// Send one length-prefixed plist frame.
pub fn send_frame<W: Write>(w: &mut W, plist: &Plist) -> io::Result<()> {
    let body = plist_lite::to_xml(plist);
    if body.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("restored: frame of {} bytes exceeds cap", body.len()),
        ));
    }
    w.write_all(&(body.len() as u32).to_be_bytes())?;
    w.write_all(body.as_bytes())?;
    w.flush()
}

/// Read one length-prefixed plist frame.
pub fn read_frame<R: Read>(r: &mut R) -> io::Result<Plist> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("restored: frame length {len} exceeds cap"),
        ));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    let xml = std::str::from_utf8(&body)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("restored: utf8: {e}")))?;
    plist_lite::from_xml(xml)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("restored: {e}")))
}

fn dict_get<'a>(p: &'a Plist, key: &str) -> Option<&'a Plist> {
    match p {
        Plist::Dict(d) => d.get(key),
        _ => None,
    }
}

fn as_u64(p: Option<&Plist>) -> Option<u64> {
    match p {
        Some(Plist::UInt(n)) => Some(*n),
        _ => None,
    }
}

fn as_str(p: Option<&Plist>) -> Option<String> {
    match p {
        Some(Plist::Str(s)) => Some(s.clone()),
        _ => None,
    }
}

/// Campaign-known restored checkpoint names (op<<8|num), from the
/// `restored_external` decompilation (ios-sweet-rust RE-FINDINGS.md).
pub fn checkpoint_name(operation: u32) -> String {
    match operation {
        0x0104 => "0x0104 handle_new_connections".into(),
        0x065B => "0x065B asr_and_invert_image".into(),
        0x067E => "0x067E verify_storage_for_update".into(),
        other => format!("0x{other:04X}"),
    }
}

/// Typed view of the device→host stream.
#[derive(Debug, Clone, PartialEq)]
pub enum RestoredMessage {
    /// `{"Status": 0|1, "State": n, "Operation": checkpoint, "Progress": 0-100}`.
    Status {
        status: u64,
        state: Option<u64>,
        operation: Option<u32>,
        progress: Option<u64>,
    },
    /// `{"Progress": n, "Operation": checkpoint}` (no terminal status yet).
    Progress { operation: Option<u32>, progress: u64 },
    /// `{"Error": name, "Code": n?}` — e.g. `initial_engine_failure_no_return`.
    Error { error: String, code: Option<u64> },
    /// Anything else (forwarded verbatim).
    Other(Plist),
}

impl RestoredMessage {
    /// Classify one device→host dict.
    pub fn classify(p: &Plist) -> RestoredMessage {
        let is_error = as_str(dict_get(p, "Error"));
        if let Some(error) = is_error {
            return RestoredMessage::Error {
                error,
                code: as_u64(dict_get(p, "Code")),
            };
        }
        if let Some(status) = as_u64(dict_get(p, "Status")) {
            return RestoredMessage::Status {
                status,
                state: as_u64(dict_get(p, "State")),
                operation: as_u64(dict_get(p, "Operation")).map(|v| v as u32),
                progress: as_u64(dict_get(p, "Progress")),
            };
        }
        if let Some(progress) = as_u64(dict_get(p, "Progress")) {
            return RestoredMessage::Progress {
                operation: as_u64(dict_get(p, "Operation")).map(|v| v as u32),
                progress,
            };
        }
        RestoredMessage::Other(p.clone())
    }
}

/// Client over a tunnel to the device's `restored` service.
pub struct RestoredClient<S: Read + Write> {
    stream: S,
    pub identifier: String,
}

impl<S: Read + Write> RestoredClient<S> {
    pub fn new(stream: S, identifier: impl Into<String>) -> Self {
        RestoredClient {
            stream,
            identifier: identifier.into(),
        }
    }

    /// Perform the Hello handshake; returns the device's protocol version
    /// string (expected [`RESTORED_PROTOCOL_VERSION`]).
    pub fn handshake(&mut self) -> Result<String, RestoredError> {
        let hello = read_frame(&mut self.stream)?;
        let version = as_str(dict_get(&hello, "ProtocolVersion")).ok_or_else(|| {
            RestoredError::Protocol("hello missing ProtocolVersion".into())
        })?;
        let mut reply: BTreeMap<String, Plist> = BTreeMap::new();
        reply.insert(
            "Identifier".into(),
            Plist::Str(self.identifier.clone()),
        );
        reply.insert(
            "ProtocolVersion".into(),
            Plist::Str(RESTORED_PROTOCOL_VERSION.into()),
        );
        send_frame(&mut self.stream, &Plist::Dict(reply))?;
        Ok(version)
    }

    /// `QueryValue` round-trip; returns the `QueryResult` value.
    pub fn query_value(&mut self, key: &str) -> Result<Option<Plist>, RestoredError> {
        let mut q: BTreeMap<String, Plist> = BTreeMap::new();
        q.insert("QueryKey".into(), Plist::Str(key.into()));
        send_frame(&mut self.stream, &Plist::Dict(q))?;
        let resp = read_frame(&mut self.stream)?;
        Ok(dict_get(&resp, "QueryResult").cloned())
    }

    /// `StartRestore`: sends `RestoreOptions` (+ `RestoreProtocolVersion`).
    pub fn start_restore(
        &mut self,
        options: BTreeMap<String, Plist>,
    ) -> Result<(), RestoredError> {
        let mut m: BTreeMap<String, Plist> = BTreeMap::new();
        m.insert(
            "RestoreProtocolVersion".into(),
            Plist::UInt(RESTORED_PROTOCOL_VERSION.parse().unwrap_or(14)),
        );
        m.insert("RestoreOptions".into(), Plist::Dict(options));
        send_frame(&mut self.stream, &Plist::Dict(m))?;
        Ok(())
    }

    /// Next device→host message, classified.
    pub fn next_message(&mut self) -> Result<RestoredMessage, RestoredError> {
        let p = read_frame(&mut self.stream)?;
        Ok(RestoredMessage::classify(&p))
    }

    /// Convenience pump: collect messages until a terminal one
    /// (Status or Error) arrives, returning intermediate Progress values.
    pub fn run_to_terminal(
        &mut self,
    ) -> Result<(RestoredMessage, Vec<RestoredMessage>), RestoredError> {
        let mut seen = Vec::new();
        loop {
            let m = self.next_message()?;
            let terminal = matches!(
                &m,
                RestoredMessage::Status { .. } | RestoredMessage::Error { .. }
            );
            if terminal {
                return Ok((m, seen));
            }
            seen.push(m);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plist_lite::from_xml;
    use std::os::unix::net::UnixStream;
    use std::thread;

    fn write_frame(s: &mut impl Write, xml: &str) {
        s.write_all(&(xml.len() as u32).to_be_bytes()).unwrap();
        s.write_all(xml.as_bytes()).unwrap();
        s.flush().unwrap();
    }

    fn read_frame_xml(s: &mut impl Read) -> String {
        let mut l = [0u8; 4];
        s.read_exact(&mut l).unwrap();
        let n = u32::from_be_bytes(l) as usize;
        let mut b = vec![0u8; n];
        s.read_exact(&mut b).unwrap();
        String::from_utf8(b).unwrap()
    }

    #[test]
    fn handshake_query_startrestore_status() {
        let (a, b) = UnixStream::pair().expect("pair");
        thread::spawn(move || {
            let mut s = b;
            // device hello
            write_frame(
                &mut s,
                "<dict><key>ProtocolVersion</key><string>14</string></dict>",
            );
            // client hello reply
            let reply = read_frame_xml(&mut s);
            let d = match from_xml(&reply).unwrap() {
                Plist::Dict(d) => d,
                _ => panic!("dict expected"),
            };
            assert_eq!(d.get("ProtocolVersion"), Some(&Plist::Str("14".into())));
            assert!(d.contains_key("Identifier"));
            // QueryValue
            let q = read_frame_xml(&mut s);
            assert!(q.contains("<key>QueryKey</key>"));
            write_frame(&mut s, "<dict><key>QueryResult</key><integer>801556675</integer></dict>");
            // StartRestore
            let sr = read_frame_xml(&mut s);
            let d = match from_xml(&sr).unwrap() {
                Plist::Dict(d) => d,
                _ => panic!("dict expected"),
            };
            assert_eq!(d.get("RestoreProtocolVersion"), Some(&Plist::UInt(14)));
            assert!(matches!(d.get("RestoreOptions"), Some(Plist::Dict(_))));
            // status stream: progress then terminal 0x067E
            write_frame(
                &mut s,
                "<dict><key>Operation</key><integer>1627</integer><key>Progress</key><integer>42</integer></dict>",
            );
            write_frame(
                &mut s,
                "<dict><key>Status</key><integer>0</integer><key>State</key><integer>5</integer>\
<key>Operation</key><integer>1662</integer><key>Progress</key><integer>100</integer></dict>",
            );
        });

        let mut c = RestoredClient::new(a, "DAPTEST0001");
        let version = c.handshake().expect("handshake");
        assert_eq!(version, "14");
        let chip = c.query_value("UniqueChipID").expect("query");
        assert_eq!(chip, Some(Plist::UInt(801556675)));
        let mut opts: BTreeMap<String, Plist> = BTreeMap::new();
        opts.insert("AutoBoot".into(), Plist::Bool(false));
        opts.insert("File_System".into(), Plist::Str("Update".into()));
        c.start_restore(opts).expect("start restore");
        let (terminal, seen) = c.run_to_terminal().expect("run");
        assert_eq!(seen.len(), 1);
        match terminal {
            RestoredMessage::Status {
                status,
                state,
                operation,
                progress,
            } => {
                assert_eq!(status, 0);
                assert_eq!(state, Some(5));
                assert_eq!(operation, Some(1662)); // 0x067E
                assert_eq!(progress, Some(100));
            }
            other => panic!("expected terminal Status, got {other:?}"),
        }
    }

    #[test]
    fn error_dict_surfaces_device_error() {
        let (a, b) = UnixStream::pair().expect("pair");
        thread::spawn(move || {
            let mut s = b;
            write_frame(
                &mut s,
                "<dict><key>ProtocolVersion</key><string>14</string></dict>",
            );
            let _ = read_frame_xml(&mut s);
            write_frame(
                &mut s,
                "<dict><key>Error</key><string>initial_engine_failure_no_return</string>\
<key>Code</key><integer>260</integer></dict>",
            );
        });
        let mut c = RestoredClient::new(a, "X");
        c.handshake().unwrap();
        match c.next_message().unwrap() {
            RestoredMessage::Error { error, code } => {
                assert_eq!(error, "initial_engine_failure_no_return");
                assert_eq!(code, Some(260));
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn checkpoint_names_match_re_findings() {
        assert_eq!(checkpoint_name(0x0104), "0x0104 handle_new_connections");
        assert_eq!(checkpoint_name(0x065B), "0x065B asr_and_invert_image");
        assert_eq!(checkpoint_name(0x067E), "0x067E verify_storage_for_update");
        assert_eq!(checkpoint_name(0x0604), "0x0604");
    }

    #[test]
    fn frame_bounds_reject_huge_lengths() {
        let (mut a, _b) = UnixStream::pair().expect("pair");
        a.write_all(&[0xFF, 0xFF, 0xFF, 0xFF]).unwrap();
        assert!(read_frame(&mut a).is_err());
    }
}
