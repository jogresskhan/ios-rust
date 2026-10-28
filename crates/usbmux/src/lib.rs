//! usbmux — the **usbmuxhost** library: a pure-Rust usbmuxd client.
//!
//! Closes the #1 X-row from the ios-sweet-rust parity map ("usbmux client")
//! in Rust, replacing `libusbmuxd`. Wire format per upstream
//! `include/usbmuxd-proto.h` + `src/libusbmuxd.c` (LGPL-2.1 — protocol
//! reference, not code copies):
//!
//! ```text
//! struct usbmuxd_header { u32 length; u32 version; u32 message; u32 tag; }  // LE, length includes header
//! MESSAGE_RESULT=1 CONNECT=2 LISTEN=3 DEVICE_ADD=4 DEVICE_REMOVE=5 DEVICE_PAIRED=6 PLIST=8
//! struct usbmuxd_connect_request { header; u32 device_id; u16 port(BE); u16 reserved; }
//! ```
//!
//! Plist messages (type 8) carry an XML plist with a `MessageType` string
//! ("Listen", "DeviceList", "Connect", "Attached", "Detached", "Paired",
//! "ReadPairRecord"). `PortNumber` in plist Connect is the port in **network
//! byte order** (`htons`) exactly like `libusbmuxd.c`.
//!
//! Transport: `/var/run/usbmuxd` unix socket, or TCP `127.0.0.1:27015`
//! (`USBMUXD_SOCKET_ADDRESS` honoured: `unix:/path` or `tcp:host:port`).
//! After a successful CONNECT the same socket becomes a raw TCP pipe to the
//! selected device port ([`MuxStream`]).

use plist::{self, Value};
use std::io::{self, Read, Write};
use std::net::TcpStream;

/// Protocol version carried in every header (`USBMUXD_PROTOCOL_VERSION`).
pub const PROTOCOL_VERSION: u32 = 0;
/// Classic TCP fallback port (`USBMUXD_SOCKET_PORT`).
pub const TCP_FALLBACK_PORT: u16 = 27015;
/// Default unix socket path (`USBMUXD_SOCKET_FILE`).
pub const DEFAULT_SOCKET_PATH: &str = "/var/run/usbmuxd";

pub const MESSAGE_RESULT: u32 = 1;
pub const MESSAGE_CONNECT: u32 = 2;
pub const MESSAGE_LISTEN: u32 = 3;
pub const MESSAGE_DEVICE_ADD: u32 = 4;
pub const MESSAGE_DEVICE_REMOVE: u32 = 5;
pub const MESSAGE_DEVICE_PAIRED: u32 = 6;
pub const MESSAGE_PLIST: u32 = 8;

/// usbmuxd result codes (`enum usbmuxd_result`).
pub mod result {
    pub const OK: u32 = 0;
    pub const BADCOMMAND: u32 = 1;
    pub const BADDEV: u32 = 2;
    pub const CONNREFUSED: u32 = 3;
    pub const BADVERSION: u32 = 6;
}

/// One connected iOS device as reported by usbmuxd.
#[derive(Debug, Clone, PartialEq)]
pub struct Device {
    pub device_id: u32,
    pub udid: String,
    pub connection_type: String,
    pub product_id: u16,
    pub location_id: u32,
}

/// Wire header (`usbmuxd_header`), little-endian on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub length: u32,
    pub version: u32,
    pub message: u32,
    pub tag: u32,
}

pub const HEADER_SIZE: usize = 16;

impl Header {
    pub fn new(message: u32, tag: u32, payload_len: usize) -> Header {
        Header {
            length: (HEADER_SIZE + payload_len) as u32,
            version: PROTOCOL_VERSION,
            message,
            tag,
        }
    }

    pub fn encode(&self) -> [u8; HEADER_SIZE] {
        let mut b = [0u8; HEADER_SIZE];
        b[0..4].copy_from_slice(&self.length.to_le_bytes());
        b[4..8].copy_from_slice(&self.version.to_le_bytes());
        b[8..12].copy_from_slice(&self.message.to_le_bytes());
        b[12..16].copy_from_slice(&self.tag.to_le_bytes());
        b
    }

    pub fn decode(buf: &[u8; HEADER_SIZE]) -> Header {
        Header {
            length: u32::from_le_bytes(buf[0..4].try_into().unwrap()),
            version: u32::from_le_bytes(buf[4..8].try_into().unwrap()),
            message: u32::from_le_bytes(buf[8..12].try_into().unwrap()),
            tag: u32::from_le_bytes(buf[12..16].try_into().unwrap()),
        }
    }
}

/// Encode the payload of a binary `MESSAGE_CONNECT` body.
pub fn connect_request_body(device_id: u32, port: u16) -> [u8; 8] {
    let mut b = [0u8; 8];
    b[0..4].copy_from_slice(&device_id.to_le_bytes());
    b[4..6].copy_from_slice(&port.swap_bytes().to_le_bytes()); // network byte order, like htons
    b[6..8].copy_from_slice(&0u16.to_le_bytes());
    b
}

/// Decode `htons`-encoded ports used in both binary and plist connects.
pub fn decode_htons_port(v: u64) -> u16 {
    (v as u16).swap_bytes()
}

/// A live usbmuxd connection (control channel until CONNECT turns it into a
/// device stream).
pub struct MuxConnection {
    stream: Box<dyn ReadWrite>,
    next_tag: u32,
}

pub trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

impl MuxConnection {
    /// Connect using the upstream resolution order:
    /// `USBMUXD_SOCKET_ADDRESS` → unix socket → TCP fallback.
    pub fn connect_default() -> io::Result<MuxConnection> {
        if let Ok(addr) = std::env::var("USBMUXD_SOCKET_ADDRESS") {
            if let Some(path) = addr.strip_prefix("unix:") {
                return MuxConnection::connect_unix(path);
            }
            if let Some(spec) = addr.strip_prefix("tcp:") {
                return TcpStream::connect(spec).map(MuxConnection::from_tcp);
            }
            // bare path form
            return MuxConnection::connect_unix(&addr);
        }
        if let Ok(c) = MuxConnection::connect_unix(DEFAULT_SOCKET_PATH) {
            return Ok(c);
        }
        TcpStream::connect(("127.0.0.1", TCP_FALLBACK_PORT)).map(MuxConnection::from_tcp)
    }

    #[cfg(unix)]
    pub fn connect_unix(path: &str) -> io::Result<MuxConnection> {
        use std::os::unix::net::UnixStream;
        UnixStream::connect(path).map(|s| MuxConnection {
            stream: Box::new(s),
            next_tag: 1,
        })
    }

    #[cfg(not(unix))]
    pub fn connect_unix(_path: &str) -> io::Result<MuxConnection> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "unix sockets unavailable",
        ))
    }

    pub fn connect_tcp(addr: &str) -> io::Result<MuxConnection> {
        TcpStream::connect(addr).map(MuxConnection::from_tcp)
    }

    pub fn from_tcp(stream: TcpStream) -> MuxConnection {
        MuxConnection {
            stream: Box::new(stream),
            next_tag: 1,
        }
    }

    /// Adopt an already-connected stream (tests, exotic transports).
    pub fn from_stream(stream: Box<dyn ReadWrite>) -> MuxConnection {
        MuxConnection {
            stream,
            next_tag: 1,
        }
    }

    fn next_tag(&mut self) -> u32 {
        let t = self.next_tag;
        self.next_tag = self.next_tag.wrapping_add(1);
        t
    }

    pub fn send_packet(&mut self, message: u32, tag: u32, payload: &[u8]) -> io::Result<()> {
        let header = Header::new(message, tag, payload.len());
        self.stream.write_all(&header.encode())?;
        self.stream.write_all(payload)
    }

    /// Receive one packet; returns header + payload bytes.
    pub fn recv_packet(&mut self) -> io::Result<(Header, Vec<u8>)> {
        let mut hb = [0u8; HEADER_SIZE];
        self.stream.read_exact(&mut hb)?;
        let header = Header::decode(&hb);
        if header.length < HEADER_SIZE as u32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("usbmuxd: bad length {}", header.length),
            ));
        }
        let mut payload = vec![0u8; (header.length - HEADER_SIZE as u32) as usize];
        if !payload.is_empty() {
            self.stream.read_exact(&mut payload)?;
        }
        Ok((header, payload))
    }

    pub fn send_plist_packet(&mut self, tag: u32, message: &Value) -> io::Result<()> {
        let xml = plist::to_string(message);
        self.send_packet(MESSAGE_PLIST, tag, xml.as_bytes())
    }

    fn recv_plist(&mut self) -> io::Result<(Header, Value)> {
        let (header, payload) = self.recv_packet()?;
        if header.message != MESSAGE_PLIST {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("usbmuxd: expected plist packet, got type {}", header.message),
            ));
        }
        let value = plist::parse(&payload).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("usbmuxd plist: {e}"))
        })?;
        Ok((header, value))
    }

    /// Expect `{MessageType: "Result", Number: n}`; error unless `n == OK`.
    fn expect_ok(&mut self, what: &str) -> io::Result<()> {
        let (_, v) = self.recv_plist()?;
        let mtype = v
            .get("MessageType")
            .and_then(|m| m.as_string())
            .unwrap_or("");
        if mtype != "Result" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("usbmuxd {what}: expected Result, got {mtype:?}"),
            ));
        }
        let number = v.get("Number").and_then(|n| n.as_uint()).unwrap_or(u64::MAX);
        if number != result::OK as u64 {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("usbmuxd {what}: result {number}"),
            ));
        }
        Ok(())
    }

    fn device_from_value(v: &Value) -> Option<Device> {
        let device_id = v.get("DeviceID").and_then(|d| d.as_uint())? as u32;
        let props = v
            .get("Properties")
            .cloned()
            .unwrap_or(Value::Dictionary(vec![]));
        let udid = props
            .get("SerialNumber")
            .and_then(|s| s.as_string())
            .unwrap_or("")
            .to_string();
        let connection_type = props
            .get("ConnectionType")
            .and_then(|s| s.as_string())
            .unwrap_or("USB")
            .to_string();
        let product_id = props.get("ProductID").and_then(|p| p.as_uint()).unwrap_or(0) as u16;
        let location_id = props.get("LocationID").and_then(|p| p.as_uint()).unwrap_or(0) as u32;
        Some(Device {
            device_id,
            udid,
            connection_type,
            product_id,
            location_id,
        })
    }

    /// `Listen` then snapshot the current device set (DeviceList reply).
    pub fn listen(&mut self) -> io::Result<()> {
        let tag = self.next_tag();
        self.send_plist_packet(
            tag,
            &Value::Dictionary(vec![("MessageType".into(), Value::String("Listen".into()))]),
        )?;
        self.expect_ok("listen")
    }

    /// `DeviceList` request → parsed device table.
    pub fn device_list(&mut self) -> io::Result<Vec<Device>> {
        let tag = self.next_tag();
        self.send_plist_packet(
            tag,
            &Value::Dictionary(vec![(
                "MessageType".into(),
                Value::String("DeviceList".into()),
            )]),
        )?;
        let (_, v) = self.recv_plist()?;
        let mtype = v
            .get("MessageType")
            .and_then(|m| m.as_string())
            .unwrap_or("");
        if mtype != "DeviceList" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("usbmuxd: expected DeviceList reply, got {mtype:?}"),
            ));
        }
        let mut out = Vec::new();
        if let Some(list) = v.get("DeviceList").and_then(|l| l.as_array()) {
            for d in list {
                if let Some(dev) = Self::device_from_value(d) {
                    out.push(dev);
                }
            }
        }
        Ok(out)
    }

    /// Wait for the next device event (`Attached`/`Detached`/`Paired` — with
    /// legacy `DeviceAdd`/`DeviceRemove`/`DevicePaired` accepted too).
    pub fn next_event(&mut self) -> io::Result<MuxEvent> {
        loop {
            let (_, v) = self.recv_plist()?;
            let mtype = v
                .get("MessageType")
                .and_then(|m| m.as_string())
                .unwrap_or("");
            match mtype {
                "Attached" | "DeviceAdd" => {
                    if let Some(d) = Self::device_from_value(&v) {
                        return Ok(MuxEvent::DeviceAdd(d));
                    }
                }
                "Detached" | "DeviceRemove" => {
                    if let Some(id) = v.get("DeviceID").and_then(|d| d.as_uint()) {
                        return Ok(MuxEvent::DeviceRemove(id as u32));
                    }
                }
                "Paired" | "DevicePaired" => {
                    if let Some(id) = v.get("DeviceID").and_then(|d| d.as_uint()) {
                        return Ok(MuxEvent::Paired(id as u32));
                    }
                }
                "Result" => continue, // stray acks are skipped
                other => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("usbmuxd: unexpected event {other:?}"),
                    ))
                }
            }
        }
    }

    /// Connect to a device TCP port (binary `MESSAGE_CONNECT`, port in
    /// network byte order). On success the connection becomes a raw stream.
    pub fn connect_device(mut self, device_id: u32, port: u16) -> io::Result<MuxStream> {
        let tag = self.next_tag();
        let body = connect_request_body(device_id, port);
        self.send_packet(MESSAGE_CONNECT, tag, &body)?;
        // Reply is a MESSAGE_RESULT (binary) on classic usbmuxd.
        let (header, payload) = self.recv_packet()?;
        let ok = match header.message {
            MESSAGE_RESULT => {
                payload.len() >= 4
                    && u32::from_le_bytes(payload[0..4].try_into().unwrap()) == result::OK
            }
            MESSAGE_PLIST => plist::parse(&payload)
                .ok()
                .and_then(|v| v.get("Number").and_then(|n| n.as_uint()))
                .map(|n| n == result::OK as u64)
                .unwrap_or(false),
            _ => false,
        };
        if !ok {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("usbmuxd: connect to device port {port} refused"),
            ));
        }
        Ok(MuxStream {
            stream: self.stream,
            eof: false,
        })
    }

    /// Plist-protocol connect variant (`{MessageType: "Connect", …}`) used by
    /// newer clients; falls through to a raw stream on `Result: OK`.
    pub fn connect_device_plist(
        mut self,
        device_id: u32,
        port: u16,
        conn_type: &str,
    ) -> io::Result<MuxStream> {
        let tag = self.next_tag();
        let msg = Value::Dictionary(vec![
            ("MessageType".into(), Value::String("Connect".into())),
            ("DeviceID".into(), Value::UInteger(device_id as u64)),
            (
                "PortNumber".into(),
                Value::UInteger((port.swap_bytes() as u32) as u64),
            ),
            ("ConnType".into(), Value::String(conn_type.to_string())),
        ]);
        self.send_plist_packet(tag, &msg)?;
        self.expect_ok("connect")?;
        Ok(MuxStream {
            stream: self.stream,
            eof: false,
        })
    }
}

/// Device events delivered on a listening mux connection.
#[derive(Debug, Clone, PartialEq)]
pub enum MuxEvent {
    DeviceAdd(Device),
    DeviceRemove(u32),
    Paired(u32),
}

/// Raw byte stream to one device port (post-CONNECT).
pub struct MuxStream {
    stream: Box<dyn ReadWrite>,
    eof: bool,
}

impl MuxStream {
    /// Take ownership back (e.g. to hand the stream to a protocol client).
    pub fn into_inner(self) -> Box<dyn ReadWrite> {
        self.stream
    }
}

impl Read for MuxStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.eof {
            return Ok(0);
        }
        let n = self.stream.read(buf)?;
        if n == 0 {
            self.eof = true;
        }
        Ok(n)
    }
}

impl Write for MuxStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn plist_dict(pairs: Vec<(&str, Value)>) -> Value {
        Value::Dictionary(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }

    /// In-process mock usbmuxd (TCP): Listen→OK, DeviceList→one device,
    /// Connect (binary or plist)→OK then the socket becomes an echo device.
    fn spawn_mock_muxd() -> (std::net::SocketAddr, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let echo_hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let hits = echo_hits.clone();
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let mut conn = conn.unwrap();
                let hits = hits.clone();
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
                    if h.message == MESSAGE_CONNECT {
                        // binary connect: u32 device_id + BE port + reserved
                        let device_id = u32::from_le_bytes(payload[0..4].try_into().unwrap());
                        assert_eq!(device_id, 42);
                        let port = u16::from_le_bytes([payload[4], payload[5]]).swap_bytes();
                        assert_eq!(port, 12345, "binary connect port must be network order");
                        let hdr = Header::new(MESSAGE_RESULT, h.tag, 4);
                        conn.write_all(&hdr.encode()).unwrap();
                        conn.write_all(&result::OK.to_le_bytes()).unwrap();
                        hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        // become the device: echo raw bytes back
                        let mut buf = [0u8; 4096];
                        loop {
                            match conn.read(&mut buf) {
                                Ok(0) | Err(_) => return,
                                Ok(n) => {
                                    if conn.write_all(&buf[..n]).is_err() {
                                        return;
                                    }
                                }
                            }
                        }
                    }
                    if h.message != MESSAGE_PLIST {
                        return;
                    }
                    let msg = match plist::parse(&payload) {
                        Ok(m) => m,
                        Err(_) => return,
                    };
                    let mtype = msg
                        .get("MessageType")
                        .and_then(|m| m.as_string())
                        .unwrap_or("");
                    match mtype {
                        "Listen" => {
                            let reply = plist_dict(vec![
                                ("MessageType", Value::String("Result".into())),
                                ("Number", Value::UInteger(result::OK as u64)),
                            ]);
                            let xml = plist::to_string(&reply);
                            let hdr = Header::new(MESSAGE_PLIST, h.tag, xml.len());
                            conn.write_all(&hdr.encode()).unwrap();
                            conn.write_all(xml.as_bytes()).unwrap();
                        }
                        "DeviceList" => {
                            let device = plist_dict(vec![
                                ("DeviceID", Value::UInteger(42)),
                                (
                                    "Properties",
                                    plist_dict(vec![
                                        ("SerialNumber", Value::String("000081010011a222e3334455".into())),
                                        ("ConnectionType", Value::String("USB".into())),
                                        ("ProductID", Value::UInteger(4776)),
                                        ("LocationID", Value::UInteger(0x14100000)),
                                    ]),
                                ),
                            ]);
                            let reply = plist_dict(vec![
                                ("MessageType", Value::String("DeviceList".into())),
                                ("DeviceList", Value::Array(vec![device])),
                            ]);
                            let xml = plist::to_string(&reply);
                            let hdr = Header::new(MESSAGE_PLIST, h.tag, xml.len());
                            conn.write_all(&hdr.encode()).unwrap();
                            conn.write_all(xml.as_bytes()).unwrap();
                        }
                        "Connect" => {
                            // plist-protocol connect: PortNumber is htons'ed
                            let port_raw = msg.get("PortNumber").and_then(|p| p.as_uint()).unwrap_or(0);
                            assert_eq!(
                                decode_htons_port(port_raw),
                                12345,
                                "plist connect port must be network order"
                            );
                            let reply = plist_dict(vec![
                                ("MessageType", Value::String("Result".into())),
                                ("Number", Value::UInteger(result::OK as u64)),
                            ]);
                            let xml = plist::to_string(&reply);
                            let hdr = Header::new(MESSAGE_PLIST, h.tag, xml.len());
                            conn.write_all(&hdr.encode()).unwrap();
                            conn.write_all(xml.as_bytes()).unwrap();
                            hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            let mut buf = [0u8; 4096];
                            loop {
                                match conn.read(&mut buf) {
                                    Ok(0) | Err(_) => return,
                                    Ok(n) => {
                                        if conn.write_all(&buf[..n]).is_err() {
                                            return;
                                        }
                                    }
                                }
                            }
                        }
                        _ => return,
                    }
                });
            }
        });
        (addr, echo_hits)
    }

    #[test]
    fn header_roundtrip() {
        let h = Header::new(MESSAGE_CONNECT, 7, 8);
        let b = h.encode();
        assert_eq!(Header::decode(&b), h);
        assert_eq!(h.length, 24);
    }

    #[test]
    fn connect_body_port_is_network_order() {
        let body = connect_request_body(1, 0xf27e);
        // htons(0xF27E) = 0x7EF2, stored little-endian → bytes F2 7E
        assert_eq!(body[4], 0xf2);
        assert_eq!(body[5], 0x7e);
        assert_eq!(u16::from_le_bytes([body[4], body[5]]).swap_bytes(), 0xf27e);
        assert_eq!(decode_htons_port(0x7ef2), 0xf27e);
    }

    #[test]
    fn full_mux_flow_against_mock_muxd() {
        let (addr, echo_hits) = spawn_mock_muxd();
        let mut mux = MuxConnection::connect_tcp(&addr.to_string()).unwrap();

        mux.listen().expect("listen");
        let devices = mux.device_list().expect("device list");
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].device_id, 42);
        assert_eq!(devices[0].udid, "000081010011a222e3334455");
        assert_eq!(devices[0].connection_type, "USB");

        // binary connect → raw stream echo
        let mut stream = mux.connect_device(42, 12345).expect("connect");
        stream.write_all(b"hello restore").unwrap();
        let mut buf = [0u8; 13];
        stream.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"hello restore");
        assert_eq!(echo_hits.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn plist_connect_flow_against_mock_muxd() {
        let (addr, _hits) = spawn_mock_muxd();
        let mux = MuxConnection::connect_tcp(&addr.to_string()).unwrap();
        let mut stream = mux.connect_device_plist(42, 12345, "").expect("plist connect");
        stream.write_all(b"abc").unwrap();
        let mut buf = [0u8; 3];
        stream.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"abc");
    }
}
