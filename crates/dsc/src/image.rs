//! image — cache image listings (`dyld_cache_image_info` /
//! `dyld_cache_image_text_info`).
//!
//! Parity: ipsw `pkg/dyld/types.go:332 CacheImageInfo` (32 bytes) and
//! `types.go:898 CacheImageTextInfo` (32 bytes).

use crate::header::CacheHeader;

/// `dyld_cache_image_info` — one per cached dylib/bundle.
#[derive(Debug, Clone)]
pub struct CacheImageInfo {
    /// Unslid VM address of the image's mach_header.
    pub address: u64,
    pub mod_time: u64,
    pub inode: u64,
    /// File offset of the NUL-terminated install path.
    pub path_file_offset: u32,
}

/// One listed image with its resolved path.
#[derive(Debug, Clone)]
pub struct CacheImage {
    pub index: usize,
    pub address: u64,
    pub mod_time: u64,
    pub inode: u64,
    pub path: String,
}

/// `dyld_cache_image_text_info` — __TEXT summary per image (dyld4+).
#[derive(Debug, Clone)]
pub struct CacheImageTextInfo {
    pub uuid: [u8; 16],
    /// Unslid start of __TEXT.
    pub load_address: u64,
    pub text_segment_size: u32,
    pub path: String,
}

fn cstr_at(buf: &[u8], off: usize) -> String {
    if off >= buf.len() {
        return String::new();
    }
    let end = buf[off..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| off + p)
        .unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[off..end]).into_owned()
}

/// Parse the image list. Old (pre-dyld4) caches carry
/// `ImagesOffsetOld/ImagesCountOld`; dyld4 caches moved the list to
/// `ImagesOffset/ImagesCount` (ipsw file.go:515).
pub fn parse_images(buf: &[u8], hdr: &CacheHeader) -> Vec<CacheImage> {
    let (offset, count) = if hdr.images_offset_old > 0 {
        (hdr.images_offset_old, hdr.images_count_old)
    } else {
        (hdr.images_offset, hdr.images_count)
    };
    let mut out = Vec::new();
    for i in 0..count as usize {
        let o = offset as usize + i * 32;
        if o + 32 > buf.len() {
            break;
        }
        let p = &buf[o..o + 32];
        let path_file_offset = u32::from_le_bytes(p[24..28].try_into().unwrap());
        out.push(CacheImage {
            index: i,
            address: u64::from_le_bytes(p[0..8].try_into().unwrap()),
            mod_time: u64::from_le_bytes(p[8..16].try_into().unwrap()),
            inode: u64::from_le_bytes(p[16..24].try_into().unwrap()),
            path: cstr_at(buf, path_file_offset as usize),
        });
    }
    out
}

/// Parse the `dyld_cache_image_text_info` array (dyld4 caches).
pub fn parse_images_text(buf: &[u8], hdr: &CacheHeader) -> Vec<CacheImageTextInfo> {
    let mut out = Vec::new();
    for i in 0..hdr.images_text_count as usize {
        let o = hdr.images_text_offset as usize + i * 32;
        if o + 32 > buf.len() {
            break;
        }
        let p = &buf[o..o + 32];
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&p[0..16]);
        let path_offset = u32::from_le_bytes(p[28..32].try_into().unwrap());
        out.push(CacheImageTextInfo {
            uuid,
            load_address: u64::from_le_bytes(p[16..24].try_into().unwrap()),
            text_segment_size: u32::from_le_bytes(p[24..28].try_into().unwrap()),
            path: cstr_at(buf, path_offset as usize),
        });
    }
    out
}

/// Find the image whose __TEXT range contains `vmaddr`
/// (binary-search equivalent of ipsw `GetImageContainingTextAddr`).
pub fn image_containing<'a>(
    text: &'a [CacheImageTextInfo],
    vmaddr: u64,
) -> Option<&'a CacheImageTextInfo> {
    text.iter()
        .find(|t| vmaddr >= t.load_address && vmaddr < t.load_address + t.text_segment_size as u64)
}
