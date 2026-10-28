//! asr — host side of the Apple Software Restore (ASR) transfer protocol
//! (the `ASR client` X-gap).
//!
//! Wire contract ported 1:1 from idevicerestore `asr.c` (the same code whose
//! 7.38 GB rootfs push the C-engine lane proved end-to-end at ~4.7 MB/s):
//!
//! 1. The device-side `asr` daemon (restore ramdisk) connects back to the
//!    host and sends `{"Command":"Initiate"[, "Checksum Chunks": bool]}`.
//! 2. The host answers with the validation packet-info dict
//!    ([`AsrConn::send_validation_packet_info`] — Version 1, Stream ID 1,
//!    FEC slice stride 40, packets per FEC 25, payload packet size 1450,
//!    checksum chunk size 131072 when the device opted in).
//! 3. Loop over device commands: a second `Initiate` (re-answer with packet
//!    info), `OOBData` (host seeks into the image and streams the exact
//!    requested window), `Payload` (validation done, stream the image).
//! 4. Payload bytes flow raw (no framing) in 128 KiB chunks.
//!
//! Plists here are NOT length-prefixed on the wire — the XML envelope is the
//! framing; [`read_asr_plist`] scans for the closing `</plist>` tag, which is
//! tolerant of TCP segmentation where the C code relied on lucky single
//! reads.

use crate::plist_lite::{self, Plist};
use std::collections::BTreeMap;
use std::io::{self, Read, Seek, SeekFrom, Write};

pub const ASR_VERSION: u64 = 1;
pub const ASR_STREAM_ID: u64 = 1;
pub const ASR_FEC_SLICE_STRIDE: u64 = 40;
pub const ASR_PACKETS_PER_FEC: u64 = 25;
pub const ASR_PAYLOAD_PACKET_SIZE: u64 = 1450;
pub const ASR_PAYLOAD_CHUNK_SIZE: usize = 131072;
pub const ASR_CHECKSUM_CHUNK_SIZE: u64 = 131072;

fn read_asr_plist_inner(read: &mut dyn FnMut(&mut [u8]) -> io::Result<usize>) -> io::Result<Plist> {
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    loop {
        // Try to close out a complete plist each round: the XML envelope is
        // the framing, and libplist's output ends with `</plist>\n` — so
        // trailing whitespace after the closing tag must be tolerated.
        let end = buf
            .iter()
            .rposition(|b| !b.is_ascii_whitespace())
            .map(|i| i + 1)
            .unwrap_or(0);
        if buf[..end].ends_with(b"</plist>") {
            let xml = std::str::from_utf8(&buf[..end]).map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidData, format!("asr: utf8: {e}"))
            })?;
            return plist_lite::from_xml(xml)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("asr: {e}")));
        }
        let n = read(&mut chunk)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("asr: connection closed mid-plist ({} bytes)", buf.len()),
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > 4 * 1024 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "asr: plist exceeds 4 MiB",
            ));
        }
    }
}

/// Receive one ASR plist (framed by its own XML envelope).
pub fn read_asr_plist<R: Read>(r: &mut R) -> io::Result<Plist> {
    read_asr_plist_inner(&mut |buf| r.read(buf))
}

/// Send one ASR plist (raw XML, no length prefix).
pub fn send_asr_plist<W: Write>(w: &mut W, plist: &Plist) -> io::Result<()> {
    let xml = plist_lite::to_xml(plist);
    w.write_all(xml.as_bytes())?;
    w.flush()
}

fn command_of(p: &Plist) -> Option<String> {
    match p {
        Plist::Dict(d) => match d.get("Command")? {
            Plist::Str(s) => Some(s.clone()),
            _ => None,
        },
        _ => None,
    }
}

fn checksum_chunks_of(p: &Plist) -> Option<bool> {
    match p {
        Plist::Dict(d) => match d.get("Checksum Chunks")? {
            Plist::Bool(b) => Some(*b),
            _ => None,
        },
        _ => None,
    }
}

/// Host-side ASR connection (device connected back to our listener socket).
pub struct AsrConn<S: Read + Write> {
    stream: S,
    /// Whether the device asked for per-chunk checksums (`Checksum Chunks`).
    pub checksum_chunks: bool,
}

/// The validation packet-info dict (asr.c `asr_send_validation_packet_info`).
pub fn validation_packet_info(ipsw_size: u64) -> Plist {
    let mut payload: BTreeMap<String, Plist> = BTreeMap::new();
    payload.insert("Port".into(), Plist::UInt(1));
    payload.insert("Size".into(), Plist::UInt(ipsw_size));
    let mut info: BTreeMap<String, Plist> = BTreeMap::new();
    info.insert("Checksum Chunk Size".into(), Plist::UInt(ASR_CHECKSUM_CHUNK_SIZE));
    info.insert("FEC Slice Stride".into(), Plist::UInt(ASR_FEC_SLICE_STRIDE));
    info.insert("Packet Payload Size".into(), Plist::UInt(ASR_PAYLOAD_PACKET_SIZE));
    info.insert("Packets Per FEC".into(), Plist::UInt(ASR_PACKETS_PER_FEC));
    info.insert("Payload".into(), Plist::Dict(payload));
    info.insert("Stream ID".into(), Plist::UInt(ASR_STREAM_ID));
    info.insert("Version".into(), Plist::UInt(ASR_VERSION));
    Plist::Dict(info)
}

impl<S: Read + Write> AsrConn<S> {
    /// Wrap an accepted stream and consume the device's `Initiate`.
    pub fn open(stream: S) -> io::Result<Self> {
        let mut conn = AsrConn {
            stream,
            checksum_chunks: false,
        };
        let p = read_asr_plist(&mut conn.stream)?;
        match command_of(&p) {
            Some(c) if c == "Initiate" => {}
            Some(other) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("asr: expected Initiate, got {other:?}"),
                ))
            }
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "asr: Initiate without Command",
                ))
            }
        }
        if let Some(b) = checksum_chunks_of(&p) {
            conn.checksum_chunks = b;
        }
        Ok(conn)
    }

    /// The validation packet-info dict — see [`validation_packet_info`].
    pub fn packet_info(ipsw_size: u64) -> Plist {
        validation_packet_info(ipsw_size)
    }

    pub fn send_validation_packet_info(&mut self, ipsw_size: u64) -> io::Result<()> {
        send_asr_plist(&mut self.stream, &validation_packet_info(ipsw_size))
    }

    /// Drive the validation loop until the device says `Payload`.
    /// `file` is the (streamable) disk image; `progress` receives
    /// (bytes_sent, total) for OOB windows. Returns the image length.
    pub fn perform_validation<F: Read + Seek>(
        &mut self,
        file: &mut F,
        file_len: u64,
        mut progress: impl FnMut(u64, u64),
    ) -> io::Result<u64> {
        self.send_validation_packet_info(file_len)?;
        let mut attempts = 0u32;
        loop {
            let packet = match read_asr_plist(&mut self.stream) {
                Ok(p) => p,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    attempts += 1;
                    if attempts >= 10 {
                        return Err(e);
                    }
                    continue;
                }
                Err(e) => return Err(e),
            };
            attempts = 0;
            let command = command_of(&packet).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "asr: packet without Command")
            })?;
            match command.as_str() {
                // iBridgeOS 9.0+ may re-Initiate to flip checksum mode.
                "Initiate" => {
                    if let Some(b) = checksum_chunks_of(&packet) {
                        self.checksum_chunks = b;
                    }
                    self.send_validation_packet_info(file_len)?;
                }
                "OOBData" => {
                    self.handle_oob_data_request(&packet, file, &mut progress)?;
                }
                "Payload" => return Ok(file_len),
                other => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("asr: unknown command {other:?}"),
                    ))
                }
            }
        }
    }

    /// asr.c `asr_handle_oob_data_request`: stream the exact requested
    /// window of the image.
    pub fn handle_oob_data_request<F: Read + Seek>(
        &mut self,
        packet: &Plist,
        file: &mut F,
        mut progress: impl FnMut(u64, u64),
    ) -> io::Result<()> {
        let (offset, length) = match packet {
            Plist::Dict(d) => {
                let offset = match d.get("OOB Offset") {
                    Some(Plist::UInt(n)) => *n,
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "asr: OOB request missing/invalid 'OOB Offset'",
                        ))
                    }
                };
                let length = match d.get("OOB Length") {
                    Some(Plist::UInt(n)) => *n,
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "asr: OOB request missing/invalid 'OOB Length'",
                        ))
                    }
                };
                (offset, length)
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "asr: OOB packet not a dict",
                ))
            }
        };
        file.seek(SeekFrom::Start(offset))?;
        let mut remaining = length;
        let mut chunk = vec![0u8; ASR_PAYLOAD_CHUNK_SIZE];
        while remaining > 0 {
            let want = chunk.len().min(remaining as usize);
            let n = file.read(&mut chunk[..want])?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("asr: image EOF inside OOB window (offset {offset}, len {length})"),
                ));
            }
            self.stream.write_all(&chunk[..n])?;
            remaining -= n as u64;
            progress(length - remaining, length);
        }
        Ok(())
    }

    /// Stream the full image payload (the 7.38 GB rootfs push in the lane).
    /// Returns bytes sent; `progress` receives (sent, total).
    pub fn stream_payload<R: Read>(
        &mut self,
        file: &mut R,
        total: u64,
        mut progress: impl FnMut(u64, u64),
    ) -> io::Result<u64> {
        let mut sent: u64 = 0;
        let mut chunk = vec![0u8; ASR_PAYLOAD_CHUNK_SIZE];
        loop {
            let n = file.read(&mut chunk)?;
            if n == 0 {
                break;
            }
            self.stream.write_all(&chunk[..n])?;
            sent += n as u64;
            progress(sent, total);
        }
        self.stream.flush()?;
        Ok(sent)
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

    fn read_xml(s: &mut impl Read) -> String {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let n = s.read(&mut chunk).unwrap();
            buf.extend_from_slice(&chunk[..n]);
            let end = buf
                .iter()
                .rposition(|b| !b.is_ascii_whitespace())
                .map(|i| i + 1)
                .unwrap_or(0);
            if buf[..end].ends_with(b"</plist>") {
                break;
            }
        }
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn full_validation_and_payload_stream() {
        let image: Vec<u8> = (0..8192u32).map(|i| (i % 251) as u8).collect();
        let image_len = image.len() as u64;
        let (a, b) = UnixStream::pair().expect("pair");
        let img_for_thread = image.clone();
        thread::spawn(move || {
            let mut s = b;
            // 1) device Initiate (checksums on)
            send_asr_plist(
                &mut s,
                &Plist::Dict({
                    let mut d: BTreeMap<String, Plist> = BTreeMap::new();
                    d.insert("Command".into(), Plist::Str("Initiate".into()));
                    d.insert("Checksum Chunks".into(), Plist::Bool(true));
                    d
                }),
            )
            .unwrap();
            // 2) host packet info
            let info = read_xml(&mut s);
            let parsed = plist_lite::from_xml(&info).unwrap();
            match &parsed {
                Plist::Dict(d) => {
                    assert_eq!(d.get("Version"), Some(&Plist::UInt(1)));
                    assert_eq!(d.get("Stream ID"), Some(&Plist::UInt(1)));
                    assert_eq!(
                        d.get("FEC Slice Stride"),
                        Some(&Plist::UInt(40))
                    );
                    assert_eq!(
                        d.get("Packet Payload Size"),
                        Some(&Plist::UInt(1450))
                    );
                    assert_eq!(
                        d.get("Checksum Chunk Size"),
                        Some(&Plist::UInt(131072))
                    );
                    match d.get("Payload") {
                        Some(Plist::Dict(p)) => {
                            assert_eq!(p.get("Size"), Some(&Plist::UInt(image_len)));
                        }
                        _ => panic!("Payload dict expected"),
                    }
                }
                _ => panic!("dict expected"),
            }
            // 3) second Initiate (keep checksums)
            send_asr_plist(
                &mut s,
                &Plist::Dict({
                    let mut d: BTreeMap<String, Plist> = BTreeMap::new();
                    d.insert("Command".into(), Plist::Str("Initiate".into()));
                    d
                }),
            )
            .unwrap();
            let _ = read_xml(&mut s);
            // 4) OOB request: bytes 4096..4196
            send_asr_plist(
                &mut s,
                &Plist::Dict({
                    let mut d: BTreeMap<String, Plist> = BTreeMap::new();
                    d.insert("Command".into(), Plist::Str("OOBData".into()));
                    d.insert("OOB Offset".into(), Plist::UInt(4096));
                    d.insert("OOB Length".into(), Plist::UInt(100));
                    d
                }),
            )
            .unwrap();
            let mut oob = vec![0u8; 100];
            s.read_exact(&mut oob).unwrap();
            assert_eq!(&oob[..], &img_for_thread[4096..4196]);
            // 5) Payload → host streams the image
            send_asr_plist(
                &mut s,
                &Plist::Dict({
                    let mut d: BTreeMap<String, Plist> = BTreeMap::new();
                    d.insert("Command".into(), Plist::Str("Payload".into()));
                    d
                }),
            )
            .unwrap();
            let mut received = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                match s.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => received.extend_from_slice(&chunk[..n]),
                }
            }
            assert_eq!(received, img_for_thread);
        });

        let mut cur = std::io::Cursor::new(image);
        let mut conn = AsrConn::open(a).expect("open");
        assert!(conn.checksum_chunks, "checksum opt-in must be seen");
        let mut oob_ticks = 0u64;
        let len = conn
            .perform_validation(&mut cur, image_len, |_, _| oob_ticks += 1)
            .expect("validation");
        assert_eq!(len, image_len);
        assert!(oob_ticks > 0);
        cur.set_position(0);
        let mut last = (0u64, 0u64);
        let sent = conn
            .stream_payload(&mut cur, image_len, |s, t| last = (s, t))
            .expect("stream");
        assert_eq!(sent, image_len);
        assert_eq!(last, (image_len, image_len));
    }

    #[test]
    fn open_rejects_non_initiate() {
        let (mut a, mut b) = UnixStream::pair().expect("pair");
        b.write_all(b"garbage without plist tail").unwrap();
        a.write_all(b"garbage without plist tail").unwrap();
        // ensure read loop hits EOF instead of hanging
        drop(b);
        assert!(AsrConn::open(a).is_err());
    }

    #[test]
    fn read_asr_plist_tolerates_trailing_newline() {
        let mut data = std::io::Cursor::new(
            b"<dict><key>Command</key><string>Payload</string></dict>\n".to_vec(),
        );
        let p = read_asr_plist(&mut data).expect("parse");
        assert_eq!(command_of(&p).as_deref(), Some("Payload"));
    }

    #[test]
    fn packet_info_shape_matches_asr_c() {
        let info = validation_packet_info(7_380_000_000);
        match info {
            Plist::Dict(d) => {
                assert_eq!(d.get("Version"), Some(&Plist::UInt(ASR_VERSION)));
                assert_eq!(d.get("Packets Per FEC"), Some(&Plist::UInt(25)));
                assert_eq!(
                    d.get("Checksum Chunk Size"),
                    Some(&Plist::UInt(131072))
                );
            }
            _ => panic!("dict expected"),
        }
    }
}
