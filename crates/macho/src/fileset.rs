//! MH_FILESET kernelcache (kernel collection) loader.
//!
//! Port of the fileset half of Inferno `hw/arm/apple-silicon/boot.c`:
//! `apple_boot_load_macho` walks the top-level load commands, copies each
//! `LC_SEGMENT_64`'s file-backed bytes and grabs the `LC_UNIXTHREAD` entry
//! PC (`cmd + 0x110`, arm64 layout); `apple_boot_get_fileset` collects
//! `LC_FILESET_ENTRY` commands (`com.apple.kernel`, `com.apple.pmap`,
//! `com.apple.driver...`). Command layouts mirror xnu
//! `EXTERNAL_HEADERS/mach-o/loader.h` and sweet-core `macho.rs`.

use crate::header::{MachHeader, MH_FILESET};

/// `LC_SEGMENT_64`.
pub const LC_SEGMENT_64: u32 = 0x19;
/// `LC_UNIXTHREAD`.
pub const LC_UNIXTHREAD: u32 = 0x5;
/// `LC_REQ_DYLD` — "may only be understood by dyld" flag.
pub const LC_REQ_DYLD: u32 = 0x8000_0000;
/// `LC_FILESET_ENTRY` (current xnu / Inferno `boot.h`: `0x35 | LC_REQ_DYLD`).
pub const LC_FILESET_ENTRY: u32 = 0x35 | LC_REQ_DYLD;
/// Older `loader.h` drafts spelled `LC_FILESET_ENTRY` as `0x61 | LC_REQ_DYLD`;
/// accepted for robustness alongside [`LC_FILESET_ENTRY`].
pub const LC_FILESET_ENTRY_ALT: u32 = 0x61 | LC_REQ_DYLD;

/// `sizeof(struct segment_command_64)`.
const SEGMENT_CMD_64_SIZE: usize = 72;
/// `sizeof(struct fileset_entry_command)`.
const FILESET_CMD_SIZE: usize = 32;
/// Offset of the arm64 entry PC inside an `LC_UNIXTHREAD` command
/// (Inferno: `cmd + 0x110` — flavor+count then 32 registers).
const UNIXTHREAD_PC_OFF: usize = 0x110;

/// One `LC_FILESET_ENTRY` of the kernel collection.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FilesetEntry {
    /// `entry_id` string, e.g. `"com.apple.kernel"`.
    pub entry_id: String,
    /// Link address of the entry's Mach-O.
    pub vmaddr: u64,
    /// File offset of the entry's Mach-O header within the kernelcache.
    pub fileoff: u64,
}

/// File-backed view of one `LC_SEGMENT_64` of the top-level image.
///
/// `data` holds `filesize` bytes copied from the image (Inferno copies
/// `filesize` into a zero-filled `vmsize` buffer; consumers zero-extend
/// here by treating `data` as file-backed and `vmsize` as the mapping size).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Segment {
    pub vmaddr: u64,
    pub vmsize: u64,
    pub fileoff: u64,
    pub data: Vec<u8>,
}

/// Parsed MH_FILESET kernelcache.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Fileset {
    /// Top-level `LC_SEGMENT_64` segments in load-command order.
    pub segments: Vec<Segment>,
    /// `LC_FILESET_ENTRY` records in load-command order.
    pub entries: Vec<FilesetEntry>,
    /// `LC_UNIXTHREAD` entry PC of the top-level image (0 when absent).
    pub entry_point: u64,
}

fn u32le(buf: &[u8], off: usize) -> Result<u32, String> {
    if off + 4 > buf.len() {
        return Err(format!("fileset: u32 read out of bounds at {off:#x}"));
    }
    Ok(u32::from_le_bytes(buf[off..off + 4].try_into().unwrap()))
}

fn u64le(buf: &[u8], off: usize) -> Result<u64, String> {
    if off + 8 > buf.len() {
        return Err(format!("fileset: u64 read out of bounds at {off:#x}"));
    }
    Ok(u64::from_le_bytes(buf[off..off + 8].try_into().unwrap()))
}

/// NUL-terminated string inside `[start, end)` (command-local string).
fn cstr_in(buf: &[u8], start: usize, end: usize) -> Result<String, String> {
    if start >= buf.len() || start >= end {
        return Err("fileset: string offset out of bounds".into());
    }
    let end = end.min(buf.len());
    let s: String = buf[start..end]
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as char)
        .collect();
    Ok(s)
}

/// Parse an MH_FILESET kernelcache: top-level segments, fileset entries and
/// the entry point.
pub fn load_fileset(img: &[u8]) -> Result<Fileset, String> {
    let header = MachHeader::parse(img)?;
    if header.filetype != MH_FILESET {
        return Err(format!(
            "fileset: filetype {} is not MH_FILESET",
            header.filetype
        ));
    }

    let mut out = Fileset::default();
    let mut off = 32usize;
    for i in 0..header.ncmds {
        if off + 8 > img.len() {
            return Err(format!("fileset: truncated load command {i} at {off:#x}"));
        }
        let cmd = u32le(img, off)?;
        let cmdsize = u32le(img, off + 4)? as usize;
        if cmdsize < 8 || off + cmdsize > img.len() {
            return Err(format!("fileset: bad load command size {cmdsize} at {off:#x}"));
        }
        match cmd {
            LC_SEGMENT_64 => {
                if cmdsize < SEGMENT_CMD_64_SIZE {
                    return Err(format!("fileset: short LC_SEGMENT_64 at {off:#x}"));
                }
                let vmaddr = u64le(img, off + 24)?;
                let vmsize = u64le(img, off + 32)?;
                let fileoff = u64le(img, off + 40)?;
                let filesize = u64le(img, off + 48)? as usize;
                let end = fileoff as usize + filesize;
                if end > img.len() {
                    return Err(format!(
                        "fileset: segment data {fileoff:#x}+{filesize:#x} out of bounds"
                    ));
                }
                out.segments.push(Segment {
                    vmaddr,
                    vmsize,
                    fileoff,
                    data: img[fileoff as usize..end].to_vec(),
                });
            }
            LC_FILESET_ENTRY | LC_FILESET_ENTRY_ALT => {
                if cmdsize < FILESET_CMD_SIZE {
                    return Err(format!("fileset: short LC_FILESET_ENTRY at {off:#x}"));
                }
                let id_off = off + u32le(img, off + 24)? as usize;
                let entry_id = cstr_in(img, id_off, off + cmdsize)?;
                out.entries.push(FilesetEntry {
                    entry_id,
                    vmaddr: u64le(img, off + 8)?,
                    fileoff: u64le(img, off + 16)?,
                });
            }
            LC_UNIXTHREAD => {
                // flavor(4) + count(4) + 32 registers before the PC
                // (ARM_THREAD_STATE64); Inferno hardcodes cmd + 0x110.
                if cmdsize < UNIXTHREAD_PC_OFF + 8 {
                    return Err(format!(
                        "fileset: short LC_UNIXTHREAD ({cmdsize} bytes) at {off:#x}"
                    ));
                }
                out.entry_point = u64le(img, off + UNIXTHREAD_PC_OFF)?;
            }
            _ => {}
        }
        off += cmdsize;
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::{MH_CPUTYPE_ARM64, MH_MAGIC_64};

    /// Build a minimal-but-valid MH_FILESET blob with one segment, one
    /// fileset entry and a UNIXTHREAD entry point.
    fn sample_fileset() -> Vec<u8> {
        let mut img = vec![0u8; 0x2000];

        let put32 = |buf: &mut Vec<u8>, off: usize, v: u32| {
            buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
        };
        let put64 = |buf: &mut Vec<u8>, off: usize, v: u64| {
            buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
        };

        // header
        put32(&mut img, 0, MH_MAGIC_64);
        put32(&mut img, 4, MH_CPUTYPE_ARM64);
        put32(&mut img, 8, 0);
        put32(&mut img, 12, MH_FILESET);
        put32(&mut img, 16, 3); // ncmds
        put32(&mut img, 20, 72 + 48 + 288); // sizeofcmds

        // LC_SEGMENT_64 __TEXT: vmaddr 0x100000 vmsize 0x4000 fileoff 0 filesize 0x1000
        let seg = 32usize;
        put32(&mut img, seg, LC_SEGMENT_64);
        put32(&mut img, seg + 4, 72);
        img[seg + 8..seg + 8 + 6].copy_from_slice(b"__TEXT");
        put64(&mut img, seg + 24, 0x10_0000);
        put64(&mut img, seg + 32, 0x4000);
        put64(&mut img, seg + 40, 0);
        put64(&mut img, seg + 48, 0x1000);

        // LC_FILESET_ENTRY "com.apple.kernel": vmaddr 0x100000 fileoff 0
        let fe = seg + 72;
        put32(&mut img, fe, LC_FILESET_ENTRY);
        put32(&mut img, fe + 4, 48);
        put64(&mut img, fe + 8, 0x10_0000);
        put64(&mut img, fe + 16, 0);
        put32(&mut img, fe + 24, 32); // entry_id offset within the command
        img[fe + 32..fe + 32 + b"com.apple.kernel\0".len()]
            .copy_from_slice(b"com.apple.kernel\0");

        // LC_UNIXTHREAD with pc at cmd+0x110
        let ut = fe + 48;
        put32(&mut img, ut, LC_UNIXTHREAD);
        put32(&mut img, ut + 4, 288);
        put32(&mut img, ut + 8, 6); // ARM_THREAD_STATE64
        put32(&mut img, ut + 12, 68); // count
        put64(&mut img, ut + UNIXTHREAD_PC_OFF, 0x10_0400);

        // payload marker inside the segment data (past the load commands)
        img[0x200] = 0xC3;
        img
    }

    #[test]
    fn load_segments_entries_entry_point() {
        let img = sample_fileset();
        let fs = load_fileset(&img).expect("load_fileset");

        assert_eq!(fs.segments.len(), 1);
        let s = &fs.segments[0];
        assert_eq!((s.vmaddr, s.vmsize, s.fileoff), (0x10_0000, 0x4000, 0));
        assert_eq!(s.data.len(), 0x1000);
        assert_eq!(s.data[0x200], 0xC3); // data copied from the image

        assert_eq!(fs.entries.len(), 1);
        assert_eq!(fs.entries[0].entry_id, "com.apple.kernel");
        assert_eq!(fs.entries[0].vmaddr, 0x10_0000);
        assert_eq!(fs.entries[0].fileoff, 0);

        assert_eq!(fs.entry_point, 0x10_0400);
    }

    #[test]
    fn rejects_non_fileset_and_corrupt() {
        let mut img = sample_fileset();
        assert!(load_fileset(&img).is_ok());

        // wrong filetype
        img[12..16].copy_from_slice(&2u32.to_le_bytes()); // MH_EXECUTE
        assert!(load_fileset(&img).is_err());
        img[12..16].copy_from_slice(&MH_FILESET.to_le_bytes());

        // bad magic
        img[0..4].copy_from_slice(&0xdead_f00du32.to_le_bytes());
        assert!(load_fileset(&img).is_err());
        img[0..4].copy_from_slice(&MH_MAGIC_64.to_le_bytes());

        // lying cmdsize
        img[32 + 4..32 + 8].copy_from_slice(&0xdeadu32.to_le_bytes());
        assert!(load_fileset(&img).is_err());
    }

    #[test]
    fn segment_data_bounds_checked() {
        let mut img = sample_fileset();
        // claim 0x100000 bytes of file-backed data in a 0x2000 image
        img[32 + 48..32 + 56].copy_from_slice(&0x10_0000u64.to_le_bytes());
        assert!(load_fileset(&img).is_err());
    }

    #[test]
    fn entry_id_string_offset_is_command_relative() {
        let img = sample_fileset();
        // The entry_id offset (32) is relative to the command start — the
        // parser must resolve it to fe+32, not blob+32.
        let fe = 32 + 72;
        let id_off = fe + u32::from_le_bytes(img[fe + 24..fe + 28].try_into().unwrap()) as usize;
        assert_eq!(id_off, fe + 32);
        let fs = load_fileset(&img).unwrap();
        assert_eq!(fs.entries[0].entry_id, "com.apple.kernel");
    }
}
