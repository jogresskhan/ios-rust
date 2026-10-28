//! subcache — split-cache member tables (`dyld_subcache_entry` v1/v2) and
//! the on-disk file naming rules.
//!
//! Parity: ipsw `pkg/dyld/types.go:1223 SubcacheEntry`, naming rules
//! `pkg/dyld/file.go:236-274`.

use crate::header::CacheHeader;

/// One subcache table entry (parsed form).
#[derive(Debug, Clone)]
pub struct SubcacheEntry {
    pub uuid: [u8; 16],
    /// VM offset of this member's content within the shared region.
    pub cache_vm_offset: u64,
    /// Filename suffix (v2 entries): `".1"`, `".2"`, `".development"` etc.
    pub suffix: String,
}

/// Parse the subcache entry array. v1 entries are 24 bytes
/// (uuid + vm_offset); v2 (`MappingOffset >= 0x200`) are 56 bytes with a
/// trailing 32-byte NUL-padded filename suffix.
pub fn parse_subcaches(buf: &[u8], hdr: &CacheHeader) -> Result<Vec<SubcacheEntry>, String> {
    let mut out = Vec::new();
    let entry_size = if hdr.has_subcache_entry_v2() { 56 } else { 24 };
    for i in 0..hdr.sub_cache_array_count as usize {
        let o = hdr.sub_cache_array_offset as usize + i * entry_size;
        if o + entry_size > buf.len() {
            return Err(format!("dsc: subcache entry {i} out of bounds"));
        }
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&buf[o..o + 16]);
        let vm_offset = u64::from_le_bytes(buf[o + 16..o + 24].try_into().unwrap());
        let suffix = if entry_size == 56 {
            let raw = &buf[o + 24..o + 56];
            let end = raw.iter().position(|&b| b == 0).unwrap_or(32);
            String::from_utf8_lossy(&raw[..end]).into_owned()
        } else {
            String::new()
        };
        out.push(SubcacheEntry {
            uuid,
            cache_vm_offset: vm_offset,
            suffix,
        });
    }
    Ok(out)
}

/// Filesystem path of a subcache member, following the ipsw rules:
/// * a trailing `.development` is stripped from the main path only when
///   the header is v2-new enough AND the cache is a universal (split) cache;
/// * the member suffix comes from the entry's `FileSuffix` when non-empty,
///   else `.{index}` (1-based).
pub fn member_path(main_path: &str, hdr: &CacheHeader, entry: &SubcacheEntry, index: usize) -> String {
    let base = if hdr.has_subcache_entry_v2() && hdr.cache_type() == Some(crate::header::CacheType::Universal) {
        match main_path.strip_suffix(".development") {
            Some(b) => b.to_string(),
            None => main_path.to_string(),
        }
    } else {
        main_path.to_string()
    };
    if entry.suffix.is_empty() {
        format!("{base}.{}", index + 1)
    } else {
        format!("{base}{}", entry.suffix)
    }
}

/// Path of the `.symbols` file (unmapped local symbols), when
/// `SymbolFileUUID` is set. Naming per ipsw file.go:236-274.
pub fn symbols_path(main_path: &str, hdr: &CacheHeader) -> Option<String> {
    if hdr.symbol_file_uuid == [0u8; 16] {
        return None;
    }
    let base = if hdr.has_subcache_entry_v2() {
        match main_path.strip_suffix(".development") {
            Some(b) => b.to_string(),
            None => main_path.to_string(),
        }
    } else {
        main_path.to_string()
    };
    Some(format!("{base}.symbols"))
}
