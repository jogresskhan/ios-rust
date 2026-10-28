//! sections — a minimal `LC_SEGMENT_64`/section walker for thin 64-bit
//! Mach-O images (the kernelcache and its fileset entries).
//!
//! The `macho` crate parses segments without segment/section names; the
//! kernelcache work needs named sections (`__TEXT.__const`,
//! `__PRELINK_INFO.__info`), so this module walks load commands directly.
//!
//! Parity: xnu `EXTERNAL_HEADERS/mach-o/loader.h` `segment_command_64`
//! / `section_64` layouts (same source the `macho` crate's fileset.rs uses).

use macho::header::{MachHeader, MH_FILESET};

/// `sizeof(struct segment_command_64)`.
const SEGMENT_CMD_64_SIZE: usize = 72;
/// `sizeof(struct section_64)`.
const SECTION_CMD_64_SIZE: usize = 80;

fn u32le(buf: &[u8], off: usize) -> Option<u32> {
    if off + 4 <= buf.len() {
        Some(u32::from_le_bytes(buf[off..off + 4].try_into().unwrap()))
    } else {
        None
    }
}

fn u64le(buf: &[u8], off: usize) -> Option<u64> {
    if off + 8 <= buf.len() {
        Some(u64::from_le_bytes(buf[off..off + 8].try_into().unwrap()))
    } else {
        None
    }
}

/// Read a fixed 16-byte Mach-O name field (segname/sectname) as a String.
fn name16(buf: &[u8], off: usize) -> String {
    if off + 16 > buf.len() {
        return String::new();
    }
    let end = buf[off..off + 16]
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(16);
    String::from_utf8_lossy(&buf[off..off + end]).into_owned()
}

/// One named section found in the image.
#[derive(Debug, Clone)]
pub struct Section {
    pub segment: String,
    pub name: String,
    pub addr: u64,
    /// Absolute file offset of the section bytes.
    pub offset: u64,
    pub size: u64,
}

/// Walk every `LC_SEGMENT_64`'s sections of a thin 64-bit Mach-O image.
pub fn sections(img: &[u8]) -> Vec<Section> {
    let mut out = Vec::new();
    let Ok(hdr) = MachHeader::parse(img) else {
        return out;
    };
    let mut off = 32usize;
    for _ in 0..hdr.ncmds {
        let Some(cmd) = u32le(img, off) else { break };
        let Some(cmdsize) = u32le(img, off + 4) else { break };
        if cmdsize < 8 || off + cmdsize as usize > img.len() {
            break;
        }
        if cmd == 0x19 && cmdsize as usize >= SEGMENT_CMD_64_SIZE {
            // LC_SEGMENT_64: segname at +8, nsects at +64.
            let seg = name16(img, off + 8);
            let nsects = u32le(img, off + 64).unwrap_or(0) as usize;
            for s in 0..nsects {
                let so = off + 72 + s * SECTION_CMD_64_SIZE;
                if so + SECTION_CMD_64_SIZE > off + cmdsize as usize || so + 80 > img.len() {
                    break;
                }
                out.push(Section {
                    segment: seg.clone(),
                    name: name16(img, so),
                    addr: u64le(img, so + 32).unwrap_or(0),
                    // section_64 layout: size (u64) at +40, file offset
                    // (u32) at +48 — found by real-fixture testing on the
                    // T8030 iOS 13.7 kernelcache (the two were swapped).
                    size: u64le(img, so + 40).unwrap_or(0),
                    offset: u32le(img, so + 48).unwrap_or(0) as u64,
                });
            }
        }
        off += cmdsize as usize;
    }
    out
}

/// Find one section by segment/section name.
pub fn find_section(img: &[u8], segment: &str, name: &str) -> Option<Section> {
    sections(img).into_iter().find(|s| s.segment == segment && s.name == name)
}

/// Section bytes when the offset/size lie inside `img`.
pub fn section_bytes<'a>(img: &'a [u8], segment: &str, name: &str) -> Option<&'a [u8]> {
    let s = find_section(img, segment, name)?;
    let o = s.offset as usize;
    let e = o.checked_add(s.size as usize)?;
    if e <= img.len() {
        Some(&img[o..e])
    } else {
        None
    }
}

/// List the fileset entries of an MH_FILESET kernel collection as
/// (entry_id, Mach-O bytes) pairs — the per-KEXT images (uses the `macho`
/// crate's fileset parser).
pub fn fileset_entry_images(img: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    if let Ok(fs) = macho::fileset::load_fileset(img) {
        for e in &fs.entries {
            let o = e.fileoff as usize;
            // Entry size: until the next entry's header or end of file.
            let mut end = img.len();
            for other in &fs.entries {
                if other.fileoff > e.fileoff {
                    end = end.min(other.fileoff as usize);
                }
            }
            if o < end {
                out.push((e.entry_id.clone(), img[o..end].to_vec()));
            }
        }
    }
    out
}

/// True when the image is an MH_FILESET kernel collection.
pub fn is_fileset(img: &[u8]) -> bool {
    MachHeader::parse(img).map(|h| h.filetype == MH_FILESET).unwrap_or(false)
}
