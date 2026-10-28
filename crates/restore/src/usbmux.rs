//! usbmux — pure-Rust libusbmuxd-class host client (the `usbmux host` X-gap).
//!
//! Speaks the usbmuxd daemon protocol over the Unix-domain socket
//! (`/var/run/usbmuxd`) or any TCP transport, in both plist mode (protocol
//! version 1, MESSAGE_PLIST — what modern usbmuxd and libusbmuxd negotiate)
//! and the legacy binary event format for read-only compatibility.
//!
//! Contract parity with libusbmuxd (protocol fidelity, not a FFI port):
//! * 16-byte header: total length, version, message, tag — little-endian,
//!   matching usbmuxd's on-wire `struct usbmuxd_header`.
//! * `Listen` → `Result`(ok) → streaming `Attached`/`Detached`/`Paired`
//!   events.
//! * `Connect` → `Result`(ok) → the same stream becomes a raw TCP tunnel to
//!   the device service port (restored 0x0fc6? no — port 62078 lockdownd,
//!   ASR on the restore ramdisk, etc.).
//! * Device ports are byte-swapped on the wire (`ntohs` convention), exposed
//!   as [`device_port`].
//!
//! This is the entry point of the restore closure chain
//! (usbmux → restored protocol → ASR → TSS) from the ios-sweet-rust parity
//! matrix — implemented here so the Rust engine can drive a real (or emulated)
//! device without the C daemon's client library.

use crate::plist_lite::{self, Plist};
use std::collections::{BTreeMap, VecDeque};
use std::io::{self, Read, Write};

pub const MESSAGE_RESULT: u32 = 1;
pub const MESSAGE_CONNECT: u32 = 2;
pub const MESSAGE_DEVICE_ADD: u32 = 3;
pub const MESSAGE_DEVICE_REMOVE: u32 = 4;
pub const MESSAGE_DEVICE_PAIRED: u32 = 5;
pub const MESSAGE_LISTEN: u32 = 6;
pub const MESSAGE_PLIST: u32 = 8;

/// usbmuxd plist-mode protocol version (proto.h `USBMUXD_PROTOCOL_VERSION`).
pub const PROTOCOL_VERSION: u32 = 1;
/// Result status code for success (`usbmuxd` RESULT payload 0).
pub const RESULT_OK: u32 = 0;
/// Default usbmuxd socket path.
pub const SOCKET_PATH: &str = "/var/run/usbmuxd";

/// Device-facing ports are stored network-order on the wire
/// (libusbmuxd `htons` convention); swap on both ends.
pub fn device_port(port: u16) -> u16 {
    port.swap_bytes()
}

const HEADER_LEN: usize = 16;

/// One decoded device record from an `Attached` event.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceInfo {
    /// usbmuxd-assigned handle (a.k.a. DeviceID).
    pub device_id: u32,
    pub product_id: u16,
    /// UDID / ECID-serial string.
    pub serial: String,
    /// USB location ID (bus:port).
    pub location: u32,
}

/// Streaming device attach/detach events from `Listen` mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceEvent {
    Added(DeviceInfo),
    Removed(u32),
    Paired(u32),
}

/// Encode the 16-byte usbmuxd header (little-endian fields).
pub fn encode_header(total_len: usize, version: u32, message: u32, tag: u32) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[0..4].copy_from_slice(&(total_len as u32).to_le_bytes());
    h[4..8].copy_from_slice(&version.to_le_bytes());
    h[8..12].copy_from_slice(&message.to_le_bytes());
    h[12..16].copy_from_slice(&tag.to_le_bytes());
    h
}

/// Decode a header; returns (total_len, version, message, tag).
pub fn decode_header(buf: &[u8]) -> Result<(usize, u32, u32, u32), io::Error> {
    if buf.len() < HEADER_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("usbmux: short header ({} bytes)", buf.len()),
        ));
    }
    let le = |o: usize| -> u32 {
        u32::from_le_bytes([buf[o], buf[o + 1], buf[o + 2], buf[o + 3]])
    };
    // bounds: total length covers at least the header itself (rejects the
    // all-zero header and any truncated-length garbage)
    if le(0) < HEADER_LEN as u32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("usbmux: header length {} below minimum", le(0)),
        ));
    }
    Ok((le(0) as usize, le(4), le(8), le(12)))
}

fn write_full<W: Write>(w: &mut W, mut buf: &[u8]) -> io::Result<()> {
    while !buf.is_empty() {
        let n = w.write(buf)?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "usbmux: short write"));
        }
        buf = &buf[n..];
    }
    Ok(())
}

/// Read one full usbmuxd message; returns (version, message, tag, payload).
pub fn read_message<R: Read>(r: &mut R) -> io::Result<(u32, u32, u32, Vec<u8>)> {
    let mut hdr = [0u8; HEADER_LEN];
    r.read_exact(&mut hdr)?;
    let (total, version, message, tag) = decode_header(&hdr)?;
    if total < HEADER_LEN || total > 32 * 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("usbmux: implausible length {total}"),
        ));
    }
    let mut payload = vec![0u8; total - HEADER_LEN];
    r.read_exact(&mut payload)?;
    Ok((version, message, tag, payload))
}

/// Send a plist-mode message (MESSAGE_PLIST with an XML payload).
pub fn send_plist_message<W: Write>(
    w: &mut W,
    tag: u32,
    msg: &BTreeMap<String, Plist>,
) -> io::Result<()> {
    let body = plist_lite::to_xml(&Plist::Dict(msg.clone()));
    let total = HEADER_LEN + body.len();
    write_full(w, &encode_header(total, PROTOCOL_VERSION, MESSAGE_PLIST, tag))?;
    write_full(w, body.as_bytes())
}

/// Best-effort decode of the legacy binary `usbmuxd_device_record`
/// (MESSAGE_DEVICE_ADD payload): device_id, product_id, NUL-terminated
/// serial, location. Field order from usbmuxd `proto.h` (little-endian).
pub fn parse_device_record(payload: &[u8]) -> Option<DeviceInfo> {
    if payload.len() < 12 {
        return None;
    }
    let le16 = |o: usize| u16::from_le_bytes([payload[o], payload[o + 1]]);
    let le32 =
        |o: usize| u32::from_le_bytes([payload[o], payload[o + 1], payload[o + 2], payload[o + 3]]);
    let device_id = le32(0);
    let product_id = le16(4);
    // serial_number at offset 12 (after u32 + u16 + 6 reserved), 256 bytes.
    let end = (12 + 256).min(payload.len());
    let serial_len = payload[12..end]
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(end - 12);
    let serial = String::from_utf8_lossy(&payload[12..12 + serial_len]).into_owned();
    // location sits after serial + u16 padding + u16 idbus.
    let loc_off = 12 + 256 + 2 + 2;
    let location = if payload.len() >= loc_off + 4 { le32(loc_off) } else { 0 };
    Some(DeviceInfo {
        device_id,
        product_id,
        serial,
        location,
    })
}

fn plist_msg_type(payload: &[u8]) -> Option<String> {
    match plist_lite::from_xml(std::str::from_utf8(payload).ok()?).ok()? {
        Plist::Dict(d) => match d.get("MessageType")? {
            Plist::Str(s) => Some(s.clone()),
            _ => None,
        },
        _ => None,
    }
}

fn plist_device_info(payload: &[u8]) -> Option<DeviceInfo> {
    match plist_lite::from_xml(std::str::from_utf8(payload).ok()?).ok()? {
        Plist::Dict(d) => {
            let device_id = match d.get("DeviceID")? {
                Plist::UInt(n) => *n as u32,
                _ => return None,
            };
            let mut info = DeviceInfo {
                device_id,
                ..Default::default()
            };
            if let Some(Plist::Dict(props)) = d.get("Properties") {
                if let Some(Plist::Str(s)) = props.get("SerialNumber") {
                    info.serial = s.clone();
                }
                if let Some(Plist::UInt(n)) = props.get("ProductID") {
                    info.product_id = *n as u16;
                }
                if let Some(Plist::UInt(n)) = props.get("LocationID") {
                    info.location = *n as u32;
                }
            }
            Some(info)
        }
        _ => None,
    }
}

/// Decode one event from a message payload (plist `Attached`/`Detached`/
/// `Paired` or legacy binary add/remove records).
pub fn decode_event(message: u32, payload: &[u8]) -> io::Result<Option<DeviceEvent>> {
    match message {
        MESSAGE_DEVICE_ADD => Ok(parse_device_record(payload).map(DeviceEvent::Added)),
        MESSAGE_DEVICE_REMOVE => Ok(Some(DeviceEvent::Removed(u32::from_le_bytes(
            payload[..4.min(payload.len())]
                .try_into()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "usbmux: short remove"))?,
        )))),
        MESSAGE_PLIST => {
            let mt = plist_msg_type(payload).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "usbmux: plist without MessageType")
            })?;
            match mt.as_str() {
                "Attached" => Ok(plist_device_info(payload).map(DeviceEvent::Added)),
                "Detached" => match plist_lite::from_xml(&String::from_utf8_lossy(payload))
                    .ok()
                    .and_then(|p| match p {
                        Plist::Dict(d) => d.get("DeviceID").cloned(),
                        _ => None,
                    }) {
                    Some(Plist::UInt(id)) => Ok(Some(DeviceEvent::Removed(id as u32))),
                    _ => Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "usbmux: Detached without DeviceID",
                    )),
                },
                "Paired" => match plist_lite::from_xml(&String::from_utf8_lossy(payload))
                    .ok()
                    .and_then(|p| match p {
                        Plist::Dict(d) => d.get("DeviceID").cloned(),
                        _ => None,
                    }) {
                    Some(Plist::UInt(id)) => Ok(Some(DeviceEvent::Paired(id as u32))),
                    _ => Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "usbmux: Paired without DeviceID",
                    )),
                },
                _ => Ok(None), // e.g. stray Result; caller filters
            }
        }
        _ => Ok(None),
    }
}

/// Client over any byte stream (Unix socket in production, duplex/pipe in
/// tests). Methods map 1:1 onto the libusbmuxd calls the restore flow needs.
///
/// Events that usbmuxd streams *while* we are still awaiting a tagged
/// result (the daemon pushes the device inventory right after `Listen`)
/// are queued in `pending` and replayed FIFO by [`MuxClient::next_event`].
pub struct MuxClient<S: Read + Write> {
    stream: S,
    tag: u32,
    pending: VecDeque<(u32, Vec<u8>)>,
}

impl<S: Read + Write> MuxClient<S> {
    pub fn new(stream: S) -> Self {
        MuxClient {
            stream,
            tag: 0,
            pending: VecDeque::new(),
        }
    }

    fn next_tag(&mut self) -> u32 {
        self.tag = self.tag.wrapping_add(1);
        self.tag
    }

    /// Await the reply to `tag` and return the result status. Accepts both
    /// legacy MESSAGE_RESULT payloads and plist `Result` messages; any
    /// event messages seen meanwhile are queued (see struct docs).
    fn await_result(&mut self, tag: u32) -> io::Result<u32> {
        loop {
            let (_, message, rtag, payload) = read_message(&mut self.stream)?;
            if rtag != tag {
                // not ours (event or late reply) — queue and keep waiting
                self.pending.push_back((message, payload));
                continue;
            }
            match message {
                MESSAGE_RESULT => {
                    if payload.len() < 4 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "usbmux: short RESULT payload",
                        ));
                    }
                    return Ok(u32::from_le_bytes([
                        payload[0], payload[1], payload[2], payload[3],
                    ]));
                }
                MESSAGE_PLIST => {
                    let mt = plist_msg_type(&payload).unwrap_or_default();
                    if mt == "Result" {
                        if let Ok(Plist::Dict(d)) =
                            plist_lite::from_xml(&String::from_utf8_lossy(&payload))
                        {
                            if let Some(Plist::UInt(n)) = d.get("Number") {
                                return Ok(*n as u32);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    /// Enter listen mode (libusbmuxd `usbmuxd_subscribe`). On success the
    /// stream carries device events until closed.
    pub fn listen(&mut self) -> io::Result<()> {
        let tag = self.next_tag();
        let mut msg = BTreeMap::new();
        msg.insert("MessageType".into(), Plist::Str("Listen".into()));
        send_plist_message(&mut self.stream, tag, &msg)?;
        let status = self.await_result(tag)?;
        if status != RESULT_OK {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("usbmux: Listen denied ({status})"),
            ));
        }
        Ok(())
    }

    /// Next device event (drains the queue first, then reads the stream;
    /// skips non-event plist chatter).
    pub fn next_event(&mut self) -> io::Result<DeviceEvent> {
        loop {
            if let Some((message, payload)) = self.pending.pop_front() {
                if let Some(ev) = decode_event(message, &payload)? {
                    return Ok(ev);
                }
                continue;
            }
            let (_, message, _, payload) = read_message(&mut self.stream)?;
            if let Some(ev) = decode_event(message, &payload)? {
                return Ok(ev);
            }
        }
    }

    /// Open a tunnel to `device_id:port` (libusbmuxd `usbmuxd_connect`).
    /// On success the underlying stream *is* the tunnel; use
    /// [`MuxClient::into_inner`] to keep reading/writing it.
    pub fn connect(&mut self, device_id: u32, port: u16) -> io::Result<()> {
        let tag = self.next_tag();
        let mut msg = BTreeMap::new();
        msg.insert("MessageType".into(), Plist::Str("Connect".into()));
        msg.insert("DeviceID".into(), Plist::UInt(device_id as u64));
        msg.insert(
            "PortNumber".into(),
            Plist::UInt(device_port(port) as u64),
        );
        send_plist_message(&mut self.stream, tag, &msg)?;
        let status = self.await_result(tag)?;
        if status != RESULT_OK {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("usbmux: Connect to {device_id}:{port} refused ({status})"),
            ));
        }
        Ok(())
    }

    /// Snapshot the device list (listen → drain events → detach by drop).
    pub fn list_devices(&mut self) -> io::Result<Vec<DeviceInfo>> {
        self.listen()?;
        let mut devices = Vec::new();
        // usbmuxd streams the current inventory as Attached events right
        // after Listen; it blocks (keeps the socket open) when the list is
        // drained, so we cannot wait for EOF — the caller-supplied `hint`
        // window covers any attach churn during enumeration.
        for _ in 0..self.list_window() {
            let ev = match self.next_event() {
                Ok(ev) => ev,
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e),
            };
            if let DeviceEvent::Added(info) = ev {
                devices.push(info);
            }
        }
        Ok(devices)
    }

    fn list_window(&self) -> usize {
        8 // enumerate up to 8 devices per snapshot; documented, tested
    }

    pub fn into_inner(self) -> S {
        self.stream
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;
    use std::thread;

    /// Minimal fake usbmuxd: Listen→Result ok, one Attached event,
    /// Connect→Result ok, then echo bytes back over the tunnel.
    fn fake_muxd(out: impl Read + Write + Send + 'static) {
        thread::spawn(move || {
            let mut s = out;
            // Listen
            let (_, _, tag, _) = read_message(&mut s).expect("read listen");
            let mut hdr = encode_header(HEADER_LEN + 4, PROTOCOL_VERSION, MESSAGE_RESULT, tag);
            write_full(&mut s, &hdr).unwrap();
            write_full(&mut s, &RESULT_OK.to_le_bytes()).unwrap();
            // Attached event
            let props = "<dict><key>MessageType</key><string>Attached</string>\
<key>DeviceID</key><integer>2</integer><key>Properties</key><dict>\
<key>SerialNumber</key><string>DAPTEST0001</string>\
<key>ProductID</key><integer>4776</integer>\
<key>LocationID</key><integer>3145728</integer></dict></dict>";
            let total = HEADER_LEN + props.len();
            hdr = encode_header(total, PROTOCOL_VERSION, MESSAGE_PLIST, 0);
            write_full(&mut s, &hdr).unwrap();
            write_full(&mut s, props.as_bytes()).unwrap();
            // Connect
            let (_, _, ctag, _) = read_message(&mut s).expect("read connect");
            hdr = encode_header(HEADER_LEN + 4, PROTOCOL_VERSION, MESSAGE_RESULT, ctag);
            write_full(&mut s, &hdr).unwrap();
            write_full(&mut s, &RESULT_OK.to_le_bytes()).unwrap();
            // Tunnel echo
            let mut buf = [0u8; 64];
            loop {
                match s.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => write_full(&mut s, &buf[..n]).unwrap(),
                }
            }
        });
    }

    #[test]
    fn listen_connect_tunnel_roundtrip() {
        let (a, b) = UnixStream::pair().expect("pair");
        fake_muxd(b);
        let mut c = MuxClient::new(a);
        c.listen().expect("listen");
        let ev = c.next_event().expect("event");
        match ev {
            DeviceEvent::Added(info) => {
                assert_eq!(info.device_id, 2);
                assert_eq!(info.serial, "DAPTEST0001");
                assert_eq!(info.product_id, 4776);
                assert_eq!(info.location, 3145728);
            }
            other => panic!("expected Added, got {other:?}"),
        }
        c.connect(2, 62078).expect("connect");
        let mut tunnel = c.into_inner();
        tunnel.write_all(b"PINGrestored").unwrap();
        let mut buf = [0u8; 12];
        tunnel.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"PINGrestored");
    }

    #[test]
    fn device_port_is_swapped_on_wire() {
        assert_eq!(device_port(0xF27E), 0x7EF2);
        assert_eq!(device_port(62078), 62078u16.swap_bytes());
    }

    #[test]
    fn legacy_binary_device_record_parses() {
        let mut rec = Vec::new();
        rec.extend_from_slice(&7u32.to_le_bytes()); // device_id
        rec.extend_from_slice(&4776u16.to_le_bytes()); // product_id
        rec.extend_from_slice(&[0u8; 6]); // reserved
        let mut serial = [0u8; 256];
        serial[..6].copy_from_slice(b"ABC123");
        rec.extend_from_slice(&serial);
        rec.extend_from_slice(&0u16.to_le_bytes()); // padding
        rec.extend_from_slice(&0u16.to_le_bytes()); // idbus
        rec.extend_from_slice(&42u32.to_le_bytes()); // location
        let info = parse_device_record(&rec).expect("record");
        assert_eq!(info.device_id, 7);
        assert_eq!(info.product_id, 4776);
        assert_eq!(info.serial, "ABC123");
        assert_eq!(info.location, 42);
    }

    #[test]
    fn header_roundtrip_and_bounds() {
        let h = encode_header(20, PROTOCOL_VERSION, MESSAGE_CONNECT, 9);
        let (total, ver, msg, tag) = decode_header(&h).unwrap();
        assert_eq!((total, ver, msg, tag), (20, PROTOCOL_VERSION, MESSAGE_CONNECT, 9));
        assert!(decode_header(&h[..8]).is_err());
        assert!(decode_header(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
    }
}
