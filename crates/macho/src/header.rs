//! Mach-O 64-bit header parse + FAT (universal binary) slice discovery.
//!
//! Port of the header half of Inferno `hw/arm/apple-silicon/boot.c`
//! (`MachoHeader64`, `apple_boot_get_macho_buffer` uses
//! `MACH_MAGIC_64 = 0xfeedfacf`) and sweet-core `macho.rs fat_slice_arm64`.
//! Fat headers are **big-endian** (`FAT_MAGIC = 0xcafebabe` stored as-is);
//! thin 64-bit Mach-O headers are **little-endian**.

/// 64-bit Mach-O magic (`MACH_MAGIC_64` / `MH_MAGIC_64`).
pub const MH_MAGIC_64: u32 = 0xfeed_facf;
/// Byte-swapped magic (big-endian readers) — accepted by `parse` too.
pub const MH_CIGAM_64: u32 = 0xcffa_edfe;
/// ARM64 cputype (`CPU_TYPE_ARM64`, `arm64e` adds `0x0100_0000` bit).
pub const MH_CPUTYPE_ARM64: u32 = 0x0100_000c;
/// `MH_FILESET` — kernel collections (kernelcache).
pub const MH_FILESET: u32 = 12;
/// `FAT_MAGIC` as stored in the file (big-endian bytes `CA FE BA BE`).
pub const FAT_MAGIC: u32 = 0xcafe_babe;

/// Size of a 64-bit Mach-O header (magic..reserved).
const MACH_HEADER64_SIZE: usize = 32;
/// Size of one `fat_arch` entry.
const FAT_ARCH_SIZE: usize = 20;

/// Parsed 64-bit Mach-O header (Inferno `MachoHeader64`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MachHeader {
    /// Magic (`MH_MAGIC_64` for LE thin binaries).
    pub magic: u32,
    /// CPU type (`MH_CPUTYPE_ARM64` on every T8030 slice).
    pub cputype: u32,
    /// CPU subtype (mask + capability bits).
    pub cpusubtype: u32,
    /// File type (`MH_EXECUTE`, `MH_FILESET`, `MH_KEXT_BUNDLE`, ...).
    pub filetype: u32,
    /// Number of load commands following the header.
    pub ncmds: u32,
    /// Total byte size of the load command area.
    pub sizeofcmds: u32,
}

fn u32le(buf: &[u8], off: usize) -> Result<u32, String> {
    if off + 4 > buf.len() {
        return Err(format!("Mach-O: u32 read out of bounds at {off:#x}"));
    }
    Ok(u32::from_le_bytes(buf[off..off + 4].try_into().unwrap()))
}

fn u32be(buf: &[u8], off: usize) -> Result<u32, String> {
    if off + 4 > buf.len() {
        return Err(format!("Mach-O: u32 read out of bounds at {off:#x}"));
    }
    Ok(u32::from_be_bytes(buf[off..off + 4].try_into().unwrap()))
}

impl MachHeader {
    /// Parse a thin 64-bit Mach-O header (first 32 bytes, little-endian).
    /// `MH_CIGAM_64` input is byte-swapped into `MH_MAGIC_64`.
    pub fn parse(buf: &[u8]) -> Result<MachHeader, String> {
        if buf.len() < MACH_HEADER64_SIZE {
            return Err(format!(
                "Mach-O: header truncated ({} < 32 bytes)",
                buf.len()
            ));
        }
        let mut magic = u32le(buf, 0)?;
        if magic == MH_CIGAM_64 {
            magic = magic.swap_bytes();
        }
        if magic != MH_MAGIC_64 {
            return Err(format!("Mach-O: bad magic {magic:#010x} (want MH_MAGIC_64)"));
        }
        Ok(MachHeader {
            magic,
            cputype: u32le(buf, 4)?,
            cpusubtype: u32le(buf, 8)?,
            filetype: u32le(buf, 12)?,
            ncmds: u32le(buf, 16)?,
            sizeofcmds: u32le(buf, 20)?,
        })
    }

    /// True when the buffer starts with the FAT magic (`CA FE BA BE`).
    pub fn is_fat(buf: &[u8]) -> bool {
        buf.len() >= 8 && u32::from_be_bytes(buf[..4].try_into().unwrap()) == FAT_MAGIC
    }

    /// `fat_arch` entries as `(cputype, offset, size)` triples.
    ///
    /// Fat headers and arch entries are big-endian (sweet-core
    /// `fat_slice_arm64` reads them through `u32le(..).swap_bytes()`, which
    /// is the same thing).
    pub fn fat_arches(buf: &[u8]) -> Result<Vec<(u32, u64, u64)>, String> {
        if !Self::is_fat(buf) {
            return Err("Mach-O: not a FAT universal binary".into());
        }
        let narch = u32be(buf, 4)? as usize;
        let mut out = Vec::with_capacity(narch);
        for i in 0..narch {
            let e = 8 + i * FAT_ARCH_SIZE;
            if e + FAT_ARCH_SIZE > buf.len() {
                return Err(format!("Mach-O: FAT arch entry {i} out of bounds"));
            }
            let cputype = u32be(buf, e)?;
            let offset = u32be(buf, e + 8)? as u64;
            let size = u32be(buf, e + 12)? as u64;
            if offset + size > buf.len() as u64 {
                return Err(format!(
                    "Mach-O: FAT slice {i} ({offset:#x}+{size:#x}) out of bounds"
                ));
            }
            out.push((cputype, offset, size));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_thin_header() {
        let mut buf = vec![0u8; 32];
        buf[0..4].copy_from_slice(&MH_MAGIC_64.to_le_bytes());
        buf[4..8].copy_from_slice(&MH_CPUTYPE_ARM64.to_le_bytes());
        buf[8..12].copy_from_slice(&0u32.to_le_bytes());
        buf[12..16].copy_from_slice(&MH_FILESET.to_le_bytes());
        buf[16..20].copy_from_slice(&3u32.to_le_bytes());
        buf[20..24].copy_from_slice(&0x1234u32.to_le_bytes());

        let h = MachHeader::parse(&buf).unwrap();
        assert_eq!(h.magic, MH_MAGIC_64);
        assert_eq!(h.cputype, MH_CPUTYPE_ARM64);
        assert_eq!(h.filetype, MH_FILESET);
        assert_eq!(h.ncmds, 3);
        assert_eq!(h.sizeofcmds, 0x1234);
        assert!(!MachHeader::is_fat(&buf));
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(MachHeader::parse(&[]).is_err());
        assert!(MachHeader::parse(&[0u8; 31]).is_err());
        let mut buf = vec![0u8; 32];
        buf[0..4].copy_from_slice(&0xdead_f00d_u32.to_le_bytes());
        assert!(MachHeader::parse(&buf).is_err());
    }

    #[test]
    fn fat_arches_big_endian() {
        // FAT magic is stored big-endian in the file.
        let mut buf = Vec::new();
        buf.extend_from_slice(&FAT_MAGIC.to_be_bytes());
        buf.extend_from_slice(&2u32.to_be_bytes()); // narch
        // entry 0: arm64 slice at 0x1000, size 0x20000
        buf.extend_from_slice(&MH_CPUTYPE_ARM64.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes()); // cpusubtype
        buf.extend_from_slice(&0x1000u32.to_be_bytes()); // offset
        buf.extend_from_slice(&0x2_0000u32.to_be_bytes()); // size
        buf.extend_from_slice(&12u32.to_be_bytes()); // align
        // entry 1: arm64e slice at 0x21000, size 0x10000
        buf.extend_from_slice(&0x0200_000cu32.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&0x2_1000u32.to_be_bytes());
        buf.extend_from_slice(&0x1_0000u32.to_be_bytes());
        buf.extend_from_slice(&12u32.to_be_bytes());
        // pad to cover the slices
        buf.resize(0x2_1000 + 0x1_0000, 0);

        assert!(MachHeader::is_fat(&buf));
        let arches = MachHeader::fat_arches(&buf).unwrap();
        assert_eq!(arches.len(), 2);
        assert_eq!(arches[0], (MH_CPUTYPE_ARM64, 0x1000, 0x2_0000));
        assert_eq!(arches[1], (0x0200_000c, 0x2_1000, 0x1_0000));
    }

    #[test]
    fn fat_bounds_checks() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&FAT_MAGIC.to_be_bytes());
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(&[0u8; 16]); // truncated entry (missing align)
        assert!(MachHeader::fat_arches(&buf).is_err());
        // slice claimed past EOF
        let mut buf2 = buf.clone();
        buf2.truncate(28);
        assert!(MachHeader::fat_arches(&buf2).is_err());
        assert!(!MachHeader::is_fat(&buf2[..4])); // too short to be FAT
    }
}
