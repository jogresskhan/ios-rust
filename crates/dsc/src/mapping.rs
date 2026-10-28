//! mapping — cache mappings (segments) with flag→name derivation.
//!
//! Parity: ipsw `pkg/dyld/types.go CacheMappingInfo` /
//! `CacheMappingAndSlideInfo`, name derivation `pkg/dyld/file.go:440-497`.

/// `dyld_cache_mapping_info` (32 bytes, LE): plain mapping on pre-dyld4
/// caches.
#[derive(Debug, Clone, Copy)]
pub struct CacheMappingInfo {
    pub address: u64,
    pub size: u64,
    pub file_offset: u64,
    pub max_prot: VmProtection,
    pub init_prot: VmProtection,
}

/// `dyld_cache_mapping_and_slide_info` (56 bytes, LE): iOS 14+ mappings
/// carrying their own slide-info pointer + flags.
#[derive(Debug, Clone, Copy)]
pub struct CacheMappingAndSlideInfo {
    pub address: u64,
    pub size: u64,
    pub file_offset: u64,
    pub slide_info_offset: u64,
    pub slide_info_size: u64,
    pub flags: u64,
    pub max_prot: VmProtection,
    pub init_prot: VmProtection,
}

/// VM protection bits (`VmProtection` int32 in Go; 1=R, 2=W, 4=X).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmProtection(pub i32);

impl VmProtection {
    pub fn read(self) -> bool {
        self.0 & 1 != 0
    }
    pub fn write(self) -> bool {
        self.0 & 2 != 0
    }
    pub fn execute(self) -> bool {
        self.0 & 4 != 0
    }
    pub fn as_str(self) -> &'static str {
        match (self.read(), self.write(), self.execute()) {
            (true, true, true) => "rwx",
            (true, true, false) => "rw-",
            (true, false, true) => "r-x",
            (true, false, false) => "r--",
            (false, true, true) => "-wx",
            (false, true, false) => "-w-",
            (false, false, true) => "--x",
            _ => "---",
        }
    }
}

/// Mapping flag bits (ipsw `CacheMappingFlag`).
pub const FLAG_AUTH_DATA: u64 = 1 << 0;
pub const FLAG_DIRTY_DATA: u64 = 1 << 1;
pub const FLAG_CONST_DATA: u64 = 1 << 2;
pub const FLAG_TEXT_STUBS: u64 = 1 << 3;
pub const FLAG_DYNAMIC_CONFIG_DATA: u64 = 1 << 4;
pub const FLAG_READ_ONLY_DATA: u64 = 1 << 5;
pub const FLAG_CONST_TPRO_DATA: u64 = 1 << 6;

/// A mapping joined with its derived Mach-O-style segment name.
#[derive(Debug, Clone)]
pub struct CacheMapping {
    pub address: u64,
    pub size: u64,
    pub file_offset: u64,
    pub slide_info_offset: u64,
    pub slide_info_size: u64,
    pub flags: u64,
    pub max_prot: VmProtection,
    pub init_prot: VmProtection,
    /// Derived segment name (`__TEXT`, `__DATA_CONST`, `__AUTH`, …).
    pub name: String,
    /// True when parsed from the iOS14+ `mapping_with_slide` array.
    pub has_slide_info: bool,
}

impl CacheMapping {
    pub fn from_plain(m: CacheMappingInfo) -> CacheMapping {
        let name = if m.init_prot.execute() {
            "__TEXT"
        } else if m.init_prot.write() {
            "__DATA"
        } else if m.init_prot.read() {
            "__LINKEDIT"
        } else {
            "__UNKNOWN"
        };
        CacheMapping {
            address: m.address,
            size: m.size,
            file_offset: m.file_offset,
            slide_info_offset: 0,
            slide_info_size: 0,
            flags: 0,
            max_prot: m.max_prot,
            init_prot: m.init_prot,
            name: name.to_string(),
            has_slide_info: false,
        }
    }

    pub fn from_slide(m: CacheMappingAndSlideInfo) -> CacheMapping {
        // Segment-name derivation mirrors ipsw file.go:464-497 exactly:
        // X → __TEXT/__TEXT_STUBS; W → __AUTH/__TPRO/__DATA (+ suffix);
        // R → __LINKEDIT. Suffixes ride only on the write branch.
        let name = if m.max_prot.execute() {
            if m.flags & FLAG_TEXT_STUBS != 0 {
                "__TEXT_STUBS".to_string()
            } else {
                "__TEXT".to_string()
            }
        } else if m.max_prot.write() {
            let base = if m.flags & FLAG_AUTH_DATA != 0 {
                "__AUTH"
            } else if m.flags & FLAG_CONST_TPRO_DATA != 0 {
                "__TPRO"
            } else {
                "__DATA"
            };
            let suffix = if m.flags & FLAG_DIRTY_DATA != 0 {
                "_DIRTY"
            } else if m.flags & FLAG_CONST_DATA != 0 {
                "_CONST"
            } else if m.flags & FLAG_DYNAMIC_CONFIG_DATA != 0 {
                "_CONFIG"
            } else {
                ""
            };
            format!("{base}{suffix}")
        } else {
            "__LINKEDIT".to_string()
        };
        CacheMapping {
            address: m.address,
            size: m.size,
            file_offset: m.file_offset,
            slide_info_offset: m.slide_info_offset,
            slide_info_size: m.slide_info_size,
            flags: m.flags,
            max_prot: m.max_prot,
            init_prot: m.init_prot,
            name,
            has_slide_info: m.slide_info_size > 0,
        }
    }
}

/// Parse a `dyld_cache_mapping_info` array.
pub fn parse_mappings(buf: &[u8], offset: u32, count: u32) -> Result<Vec<CacheMapping>, String> {
    let mut out = Vec::new();
    for i in 0..count as usize {
        let o = offset as usize + i * 32;
        if o + 32 > buf.len() {
            return Err(format!("dsc: mapping {i} out of bounds"));
        }
        let p = &buf[o..o + 32];
        out.push(CacheMapping::from_plain(CacheMappingInfo {
            address: u64::from_le_bytes(p[0..8].try_into().unwrap()),
            size: u64::from_le_bytes(p[8..16].try_into().unwrap()),
            file_offset: u64::from_le_bytes(p[16..24].try_into().unwrap()),
            max_prot: VmProtection(i32::from_le_bytes(p[24..28].try_into().unwrap())),
            init_prot: VmProtection(i32::from_le_bytes(p[28..32].try_into().unwrap())),
        }));
    }
    Ok(out)
}

/// Parse a `dyld_cache_mapping_and_slide_info` array (56-byte entries).
pub fn parse_mappings_with_slide(
    buf: &[u8],
    offset: u32,
    count: u32,
) -> Result<Vec<CacheMapping>, String> {
    let mut out = Vec::new();
    for i in 0..count as usize {
        let o = offset as usize + i * 56;
        if o + 56 > buf.len() {
            return Err(format!("dsc: mapping_with_slide {i} out of bounds"));
        }
        let p = &buf[o..o + 56];
        out.push(CacheMapping::from_slide(CacheMappingAndSlideInfo {
            address: u64::from_le_bytes(p[0..8].try_into().unwrap()),
            size: u64::from_le_bytes(p[8..16].try_into().unwrap()),
            file_offset: u64::from_le_bytes(p[16..24].try_into().unwrap()),
            slide_info_offset: u64::from_le_bytes(p[24..32].try_into().unwrap()),
            slide_info_size: u64::from_le_bytes(p[32..40].try_into().unwrap()),
            flags: u64::from_le_bytes(p[40..48].try_into().unwrap()),
            max_prot: VmProtection(i32::from_le_bytes(p[48..52].try_into().unwrap())),
            init_prot: VmProtection(i32::from_le_bytes(p[52..56].try_into().unwrap())),
        }));
    }
    Ok(out)
}
