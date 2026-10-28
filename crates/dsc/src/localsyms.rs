//! localsyms — the local-symbols blob (`dyld_cache_local_symbols_info`).
//!
//! On pre-dyld4 caches the blob lives inside the main file at
//! `LocalSymbolsOffset`; on dyld4 caches it moved to the separate
//! `.symbols` file (unmapped member, `SymbolFileUUID`).
//!
//! Parity: ipsw `pkg/dyld/types.go:795-818 CacheLocalSymbolsInfo` /
//! `CacheLocalSymbolsEntry64` / `CacheLocalSymbol` (nlist_64).

/// The 24-byte `dyld_cache_local_symbols_info` header.
#[derive(Debug, Clone, Copy)]
pub struct LocalSymbolsInfo {
    pub nlist_offset: u32,
    pub nlist_count: u32,
    pub strings_offset: u32,
    pub strings_size: u32,
    pub entries_offset: u32,
    pub entries_count: u32,
}

/// One per-dylib symbol range (16-byte `dyld_cache_local_symbols_entry_64`).
#[derive(Debug, Clone, Copy)]
pub struct LocalSymbolsEntry64 {
    /// Offset in the cache file of the dylib's start.
    pub dylib_offset: u64,
    pub nlist_start_index: u32,
    pub nlist_count: u32,
}

/// One local symbol (`nlist_64` + resolved name).
#[derive(Debug, Clone)]
pub struct LocalSymbol {
    /// Index into the dylib list via the owning entry's dylib_offset.
    pub dylib_offset: u64,
    pub name: String,
    pub n_strx: u32,
    pub n_type: u8,
    pub n_sect: u8,
    pub n_desc: u16,
    pub n_value: u64,
}

/// Parse the header (little-endian, six u32 fields).
pub fn parse_info(blob: &[u8]) -> Result<LocalSymbolsInfo, String> {
    if blob.len() < 24 {
        return Err(format!(
            "dsc: local-symbols blob too small ({} bytes)",
            blob.len()
        ));
    }
    let rd32 = |o: usize| u32::from_le_bytes(blob[o..o + 4].try_into().unwrap());
    Ok(LocalSymbolsInfo {
        nlist_offset: rd32(0),
        nlist_count: rd32(4),
        strings_offset: rd32(8),
        strings_size: rd32(12),
        entries_offset: rd32(16),
        entries_count: rd32(20),
    })
}

/// Walk every entry's symbol range and resolve names from the string pool.
///
/// `blob` is the full local-symbols region (starting at the info header).
pub fn parse_symbols(blob: &[u8]) -> Result<Vec<LocalSymbol>, String> {
    let info = parse_info(blob)?;
    let mut out = Vec::new();
    for e in 0..info.entries_count as usize {
        let eo = info.entries_offset as usize + e * 16;
        if eo + 16 > blob.len() {
            break;
        }
        let dylib_offset = u64::from_le_bytes(blob[eo..eo + 8].try_into().unwrap());
        let start = u32::from_le_bytes(blob[eo + 8..eo + 12].try_into().unwrap());
        let count = u32::from_le_bytes(blob[eo + 12..eo + 16].try_into().unwrap());
        for s in 0..count as usize {
            let no = info.nlist_offset as usize + (start as usize + s) * 16;
            if no + 16 > blob.len() {
                break;
            }
            let n_strx = u32::from_le_bytes(blob[no..no + 4].try_into().unwrap());
            let n_type = blob[no + 4];
            let n_sect = blob[no + 5];
            let n_desc = u16::from_le_bytes(blob[no + 6..no + 8].try_into().unwrap());
            let n_value = u64::from_le_bytes(blob[no + 8..no + 16].try_into().unwrap());
            let so = info.strings_offset as usize + n_strx as usize;
            let name = if so < blob.len() {
                let end = blob[so..]
                    .iter()
                    .position(|&b| b == 0)
                    .map(|p| so + p)
                    .unwrap_or(blob.len());
                String::from_utf8_lossy(&blob[so..end]).into_owned()
            } else {
                String::new()
            };
            out.push(LocalSymbol {
                dylib_offset,
                name,
                n_strx,
                n_type,
                n_sect,
                n_desc,
                n_value,
            });
        }
    }
    Ok(out)
}
