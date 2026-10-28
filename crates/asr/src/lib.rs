//! asr — pure-Rust **ASR client** (Apple Software Restore pusher).
//!
//! Closes the #3 X-row from the ios-sweet-rust parity map ("ASR client"),
//! replacing idevicerestore's `src/asr.c` (LGPL-2.1 — protocol reference,
//! not a code copy). Wire facts (verified against upstream):
//!
//! * transport: usbmux to device port [`ASR_PORT`] (12345),
//! * control channel: **raw XML plists, no framing prefix** — one plist per
//!   read burst (`asr_receive` does a single `idevice_connection_receive`
//!   then `plist_from_xml`); over plain TCP bursts can coalesce, so the
//!   client buffers and consumes one message at a time ([`plist::parse_prefix`]),
//! * handshake: device sends `{"Command":"Initiate", "Checksum Chunks":B}`;
//!   host answers with the packet-info dict (`asr_send_validation_packet_info`),
//! * loop: `Initiate` (again — may toggle checksum chunks) → re-send info;
//!   `OOBData` (`OOB Offset`/`OOB Length`) → serve bytes from the image;
//!   `Payload` → stream time,
//! * payload: 131072-byte chunks; when checksum chunks are on, a 20-byte
//!   SHA-1 over the chunk is appended (`sha1(data,size,data+size)`),
//! * completion is signalled by restored `StatusMsg` (not ASR).
//!
//! The device listens on TCP/12345 **via usbmux** — pair this crate with
//! the `usbmux` crate's `connect_device`.

pub mod sha1;

use plist::{self, Value};
use std::io::{self, Read, Write};

/// ASR device port (`ASR_DEFAULT_PORT` in asr.h).
pub const ASR_PORT: u16 = 12345;
pub const ASR_VERSION: u64 = 1;
pub const ASR_STREAM_ID: u64 = 1;
pub const ASR_FEC_SLICE_STRIDE: u64 = 40;
pub const ASR_PACKETS_PER_FEC: u64 = 25;
pub const ASR_PAYLOAD_PACKET_SIZE: u64 = 1450;
pub const ASR_PAYLOAD_CHUNK_SIZE: usize = 131072;
pub const ASR_CHECKSUM_CHUNK_SIZE: u64 = 131072;

/// The image being pushed: random-access reader over the rootfs/ramdisk.
pub trait ImageSource {
    fn size(&self) -> u64;
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<usize>;
}

impl ImageSource for std::io::Cursor<Vec<u8>> {
    fn size(&self) -> u64 {
        self.get_ref().len() as u64
    }
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        self.set_position(offset);
        self.read(buf)
    }
}

impl ImageSource for std::fs::File {
    fn size(&self) -> u64 {
        self.metadata().map(|m| m.len()).unwrap_or(0)
    }
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        use std::os::unix::fs::FileExt;
        FileExt::read_at(self, buf, offset)
    }
}

/// ASR protocol client over a device-port stream.
pub struct AsrClient<S: Read + Write> {
    stream: S,
    /// Unconsumed bytes from coalesced TCP bursts (see `read_xml_plist`).
    rbuf: Vec<u8>,
    pub checksum_chunks: bool,
    pub bytes_sent: u64,
}

impl<S: Read + Write> AsrClient<S> {
    /// Adopt a connected stream (usbmux `connect_device(ASR_PORT)`).
    pub fn new(stream: S) -> io::Result<AsrClient<S>> {
        let mut client = AsrClient {
            stream,
            rbuf: Vec::new(),
            checksum_chunks: false,
            bytes_sent: 0,
        };
        // First plist from the device: {"Command": "Initiate", "Checksum Chunks": B}
        let mut rbuf = std::mem::take(&mut client.rbuf);
        let first = read_xml_plist(&mut client.stream, &mut rbuf)?;
        client.rbuf = rbuf;
        if let Some(cmd) = first.get("Command").and_then(|c| c.as_string()) {
            if cmd != "Initiate" {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("asr: unexpected first command {cmd:?}"),
                ));
            }
        }
        client.checksum_chunks = first
            .get("Checksum Chunks")
            .and_then(|c| c.as_bool())
            .unwrap_or(false);
        Ok(client)
    }

    fn send_plist(&mut self, v: &Value) -> io::Result<()> {
        let xml = plist::to_string(v);
        self.stream.write_all(xml.as_bytes())
    }

    fn recv_plist(&mut self) -> io::Result<Value> {
        let mut rbuf = std::mem::take(&mut self.rbuf);
        let v = read_xml_plist(&mut self.stream, &mut rbuf)?;
        self.rbuf = rbuf;
        Ok(v)
    }

    /// `asr_send_validation_packet_info` — byte-for-byte key set.
    pub fn send_validation_packet_info(&mut self, image_size: u64) -> io::Result<()> {
        let payload_info = Value::Dictionary(vec![
            ("Port".into(), Value::UInteger(1)),
            ("Size".into(), Value::UInteger(image_size)),
        ]);
        let mut packet_info = Value::Dictionary(vec![]);
        if self.checksum_chunks {
            packet_info.set("Checksum Chunk Size", Value::UInteger(ASR_CHECKSUM_CHUNK_SIZE));
        }
        packet_info.set("FEC Slice Stride", Value::UInteger(ASR_FEC_SLICE_STRIDE));
        packet_info.set("Packet Payload Size", Value::UInteger(ASR_PAYLOAD_PACKET_SIZE));
        packet_info.set("Packets Per FEC", Value::UInteger(ASR_PACKETS_PER_FEC));
        packet_info.set("Payload", payload_info);
        packet_info.set("Stream ID", Value::UInteger(ASR_STREAM_ID));
        packet_info.set("Version", Value::UInteger(ASR_VERSION));
        self.send_plist(&packet_info)
    }

    /// Drive the validation loop until the device says `Payload`.
    pub fn perform_validation(&mut self, image: &mut dyn ImageSource) -> io::Result<()> {
        self.send_validation_packet_info(image.size())?;
        loop {
            let packet = self.recv_plist()?;
            let command = packet
                .get("Command")
                .and_then(|c| c.as_string())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "asr: missing Command in validation packet",
                    )
                })?
                .to_string();
            match command.as_str() {
                "Initiate" => {
                    // May switch checksum chunks on for a second initiate.
                    if let Some(b) = packet.get("Checksum Chunks").and_then(|c| c.as_bool()) {
                        self.checksum_chunks = b;
                    }
                    self.send_validation_packet_info(image.size())?;
                }
                "OOBData" => {
                    let offset = packet
                        .get("OOB Offset")
                        .and_then(|v| v.as_uint())
                        .ok_or_else(|| {
                            io::Error::new(io::ErrorKind::InvalidData, "asr: OOB missing offset")
                        })?;
                    let length = packet
                        .get("OOB Length")
                        .and_then(|v| v.as_uint())
                        .ok_or_else(|| {
                            io::Error::new(io::ErrorKind::InvalidData, "asr: OOB missing length")
                        })?;
                    let mut buf = vec![0u8; length as usize];
                    let mut done = 0usize;
                    while done < buf.len() {
                        let n = image.read_at(offset + done as u64, &mut buf[done..])?;
                        if n == 0 {
                            return Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                format!("asr: OOB read short at offset {offset}"),
                            ));
                        }
                        done += n;
                    }
                    self.stream.write_all(&buf)?;
                }
                "Payload" => return Ok(()),
                other => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("asr: unknown command {other:?}"),
                    ))
                }
            }
        }
    }

    /// `asr_send_payload` — stream the image in 128 KiB chunks with optional
    /// per-chunk SHA-1 tails; `progress` gets 0.0..=1.0 at each percent step.
    pub fn send_payload(
        &mut self,
        image: &mut dyn ImageSource,
        mut progress: impl FnMut(f64),
    ) -> io::Result<u64> {
        let total = image.size();
        let mut offset = 0u64;
        let mut last_pct = -1i32;
        while offset < total {
            let want = ((total - offset) as usize).min(ASR_PAYLOAD_CHUNK_SIZE);
            let mut chunk = vec![0u8; want];
            let mut done = 0usize;
            while done < want {
                let n = image.read_at(offset + done as u64, &mut chunk[done..])?;
                if n == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "asr: image ended early",
                    ));
                }
                done += n;
            }
            if self.checksum_chunks {
                let digest = sha1::sha1(&chunk);
                chunk.extend_from_slice(&digest);
            }
            self.stream.write_all(&chunk)?;
            self.bytes_sent += want as u64;
            offset += want as u64;
            let pct = ((offset as f64 / total as f64) * 100.0) as i32;
            if pct > last_pct {
                progress(offset as f64 / total as f64);
                last_pct = pct;
            }
        }
        Ok(self.bytes_sent)
    }
}

/// Read one raw XML plist from an ASR-style stream, buffering any coalesced
/// remainder in `rbuf` for the next call.
fn read_xml_plist<S: Read>(stream: &mut S, rbuf: &mut Vec<u8>) -> io::Result<Value> {
    let mut chunk = [0u8; 4096];
    loop {
        // parse the first message; keep any coalesced remainder buffered
        if let Ok((v, consumed)) = plist::parse_prefix(rbuf) {
            rbuf.drain(..consumed);
            return Ok(v);
        }
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "asr: short plist read",
            ));
        }
        rbuf.extend_from_slice(&chunk[..n]);
        if rbuf.len() > 1 << 20 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "asr: oversized plist",
            ));
        }
    }
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};

    fn read_plist_from(conn: &mut TcpStream) -> Value {
        let mut buf: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            if let Ok((v, consumed)) = plist::parse_prefix(&buf) {
                let leftover = buf.len() - consumed;
                assert_eq!(leftover, 0, "mock did not expect coalesced plists");
                return v;
            }
            let n = conn.read(&mut chunk).unwrap();
            assert!(n > 0, "client closed early");
            buf.extend_from_slice(&chunk[..n]);
        }
    }

    /// Mock ASR daemon: drives the upstream device-side state machine.
    fn spawn_mock_asr() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            // 1. device → Initiate (checksum chunks ON)
            conn.write_all(
                plist::to_string(&Value::Dictionary(vec![
                    ("Command".into(), Value::String("Initiate".into())),
                    ("Checksum Chunks".into(), Value::Boolean(true)),
                ]))
                .as_bytes(),
            )
            .unwrap();
            // 2. expect packet info
            let info = read_plist_from(&mut conn);
            assert_eq!(
                info.get("Version").and_then(|v| v.as_uint()),
                Some(ASR_VERSION)
            );
            assert_eq!(info.get("Stream ID").and_then(|v| v.as_uint()), Some(1));
            assert_eq!(
                info.get("Checksum Chunk Size").and_then(|v| v.as_uint()),
                Some(ASR_CHECKSUM_CHUNK_SIZE)
            );
            let declared = info
                .get("Payload")
                .and_then(|p| p.get("Size"))
                .and_then(|s| s.as_uint())
                .expect("Payload.Size");
            // 3. second Initiate (toggles nothing) → info again
            conn.write_all(
                plist::to_string(&Value::Dictionary(vec![
                    ("Command".into(), Value::String("Initiate".into())),
                    ("Checksum Chunks".into(), Value::Boolean(true)),
                ]))
                .as_bytes(),
            )
            .unwrap();
            let _ = read_plist_from(&mut conn);
            // 4. OOBData request for bytes 5..9
            conn.write_all(
                plist::to_string(&Value::Dictionary(vec![
                    ("Command".into(), Value::String("OOBData".into())),
                    ("OOB Offset".into(), Value::UInteger(5)),
                    ("OOB Length".into(), Value::UInteger(4)),
                ]))
                .as_bytes(),
            )
            .unwrap();
            let mut oob = [0u8; 4];
            conn.read_exact(&mut oob).unwrap();
            assert_eq!(&oob, b"WORL");
            // 5. Payload command → client streams
            conn.write_all(
                plist::to_string(&Value::Dictionary(vec![(
                    "Command".into(),
                    Value::String("Payload".into()),
                )]))
                .as_bytes(),
            )
            .unwrap();
            let mut received: Vec<u8> = Vec::new();
            let expected = declared as usize + (declared as usize / ASR_PAYLOAD_CHUNK_SIZE + 1) * 20;
            let mut buf = [0u8; 65536];
            while received.len() < expected {
                let n = conn.read(&mut buf).unwrap();
                assert!(n > 0, "client stream ended early");
                received.extend_from_slice(&buf[..n]);
            }
            // verify: chunks of <=131072 each followed by a valid SHA-1 tail
            let mut offset = 0usize;
            let mut chunk_count = 0;
            while offset < received.len() {
                let remaining = received.len() - offset;
                let data_len = remaining.min(ASR_PAYLOAD_CHUNK_SIZE);
                let digest = sha1::sha1(&received[offset..offset + data_len]);
                let tail = (remaining - data_len).min(20);
                assert_eq!(
                    &received[offset + data_len..offset + data_len + tail],
                    &digest[..tail],
                    "sha1 tail mismatch at chunk {chunk_count}"
                );
                offset += data_len + tail;
                chunk_count += 1;
            }
            assert_eq!(chunk_count, 3, "300005 bytes → 3 chunks");
        });
        addr
    }

    #[test]
    fn sha1_known_vectors() {
        let hex_string = |d: &[u8]| d.iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(
            hex_string(&sha1::sha1(b"")),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
        assert_eq!(
            hex_string(&sha1::sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hex_string(&sha1::sha1(b"The quick brown fox jumps over the lazy dog")),
            "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
        );
    }

    #[test]
    fn full_asr_push_against_mock_asr() {
        let addr = spawn_mock_asr();
        let stream = TcpStream::connect(addr).unwrap();
        let mut client = AsrClient::new(stream).expect("asr open");
        assert!(client.checksum_chunks, "device asked for checksum chunks");

        let image: Vec<u8> = b"HELLO"
            .iter()
            .chain(b"WORLD".iter().cycle().take(300000))
            .cloned()
            .collect();
        let mut src = std::io::Cursor::new(image);

        client.perform_validation(&mut src).expect("validation");
        let mut progress_steps = 0;
        let sent = client
            .send_payload(&mut src, |_| progress_steps += 1)
            .expect("payload");
        assert_eq!(sent, 300005);
        assert!(progress_steps >= 2, "progress must fire during push");
    }
}
