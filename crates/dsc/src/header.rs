//! header — the `dyld_cache_header` and its version gates.
//!
//! All offsets are little-endian C-natural-alignment values verified against
//! blacktop/ipsw `pkg/dyld/types.go` (itself matching Apple's
//! `dyld_cache_format.h`). The header grew over the years; the field
//! `MappingOffset` doubles as a "header size" gate in modern caches.
//!
//! Parity: ipsw `pkg/dyld/types.go:128 CacheHeader` (Apple dyld_cache_format.h
//! `dyld_cache_header`).

/// Known-good cache magic strings, NUL-trimmed (ipsw `pkg/dyld/file.go:30`).
pub const MAGICS: &[&str] = &[
    "dyld_v1    i386",
    "dyld_v1  x86_64",
    "dyld_v1 x86_64h",
    "dyld_v1   armv5",
    "dyld_v1   armv6",
    "dyld_v1   armv7",
    "dyld_v1  armv7s",
    "dyld_v1   arm64",
    "dyld_v1arm64_32",
    "dyld_v1  arm64e",
    "dyld_v1arm64ex1",
];

/// Magic of the dyld4 dynamic-data blob (`dyld_data    v0`).
pub const DYNAMIC_DATA_MAGIC: &str = "dyld_data    v0";

/// Cache kind (header field `CacheType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheType {
    Development,
    Production,
    Universal,
}

impl CacheType {
    pub fn from_u64(v: u64) -> Option<CacheType> {
        match v {
            0 => Some(CacheType::Development),
            1 => Some(CacheType::Production),
            2 => Some(CacheType::Universal),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            CacheType::Development => "development",
            CacheType::Production => "production",
            CacheType::Universal => "universal",
        }
    }
}

/// `formatVersion` bitfield (low byte = version, high bits are flags).
#[derive(Debug, Clone, Copy, Default)]
pub struct FormatVersion(pub u32);

impl FormatVersion {
    pub fn version(self) -> u8 {
        (self.0 & 0xff) as u8
    }
    pub fn dylibs_expected_on_disk(self) -> bool {
        self.0 & 0x100 != 0
    }
    pub fn is_simulator(self) -> bool {
        self.0 & 0x200 != 0
    }
    pub fn locally_built(self) -> bool {
        self.0 & 0x400 != 0
    }
    pub fn built_from_chained_fixups(self) -> bool {
        self.0 & 0x800 != 0
    }
    pub fn new_format_tlvs(self) -> bool {
        self.0 & 0x1000 != 0
    }
}

/// Packed OS version (`X.Y.Z` in 6/6/8 bits? — Apple packs `x<<16|y<<8|z`).
pub fn unpack_version(v: u32) -> (u32, u32, u32) {
    ((v >> 16) & 0xffff, (v >> 8) & 0xff, v & 0xff)
}

/// The parsed `dyld_cache_header` — every field at its exact byte offset.
#[derive(Debug, Clone)]
pub struct CacheHeader {
    pub magic_raw: [u8; 16],
    /// 0x10 — file offset of mappings; doubles as header-size version gate.
    pub mapping_offset: u32,
    pub mapping_count: u32,          // 0x14
    pub images_offset_old: u32,      // 0x18
    pub images_count_old: u32,       // 0x1C
    pub dyld_base_address: u64,      // 0x20
    pub code_signature_offset: u64,  // 0x28
    pub code_signature_size: u64,    // 0x30
    pub slide_info_offset_unused: u64, // 0x38 (pre-iOS14 kernel slide info)
    pub slide_info_size_unused: u64,   // 0x40
    pub local_symbols_offset: u64,   // 0x48
    pub local_symbols_size: u64,     // 0x50
    pub uuid: [u8; 16],              // 0x58
    pub cache_type: u64,             // 0x68
    pub branch_pools_offset: u32,    // 0x70
    pub branch_pools_count: u32,     // 0x74
    pub accelerate_info_addr_unused_or_dyld_addr: u64,       // 0x78
    pub accelerate_info_size_unused_or_dyld_start_func: u64, // 0x80
    pub images_text_offset: u64, // 0x88
    pub images_text_count: u64,  // 0x90
    pub patch_info_addr: u64,    // 0x98
    pub patch_info_size: u64,    // 0xA0
    pub other_image_group_addr_unused: u64, // 0xA8
    pub other_image_group_size_unused: u64, // 0xB0
    pub prog_closures_addr: u64, // 0xB8
    pub prog_closures_size: u64, // 0xC0
    pub prog_closures_trie_addr: u64, // 0xC8
    pub prog_closures_trie_size: u64, // 0xD0
    pub platform: u64,           // 0xD8
    pub format_version: u32,     // 0xE0 (+4 pad)
    pub shared_region_start: u64, // 0xE8
    pub shared_region_size: u64, // 0xF0
    pub max_slide: u64,          // 0xF8
    pub dylibs_image_array_addr: u64, // 0x100
    pub dylibs_image_array_size: u64, // 0x108
    pub dylibs_trie_addr: u64,   // 0x110
    pub dylibs_trie_size: u64,   // 0x118
    pub other_image_array_addr: u64, // 0x120
    pub other_image_array_size: u64, // 0x128
    pub other_trie_addr: u64,    // 0x130
    pub other_trie_size: u64,    // 0x138
    pub mapping_with_slide_offset: u32, // 0x140
    pub mapping_with_slide_count: u32,  // 0x144
    pub dylibs_pbl_state_array_addr_unused: u64, // 0x148
    pub dylibs_pbl_set_addr: u64,   // 0x150
    pub programs_pbl_set_pool_addr: u64, // 0x158
    pub programs_pbl_set_pool_size: u64, // 0x160
    pub program_trie_addr: u64,     // 0x168
    pub program_trie_size: u32,     // 0x170
    pub os_version: u32,            // 0x174
    pub alt_platform: u64,          // 0x178
    pub alt_os_version: u32,        // 0x180 (+4 pad)
    pub swift_opts_offset: u64,     // 0x188
    pub swift_opts_size: u64,       // 0x190
    pub sub_cache_array_offset: u32, // 0x198
    pub sub_cache_array_count: u32,  // 0x19C
    pub symbol_file_uuid: [u8; 16],  // 0x1A0
    pub rosetta_read_only_addr: u64, // 0x1B0
    pub rosetta_read_only_size: u64, // 0x1B8
    pub rosetta_read_write_addr: u64, // 0x1C0
    pub rosetta_read_write_size: u64, // 0x1C8
    pub images_offset: u32,          // 0x1D0
    pub images_count: u32,           // 0x1D4
    pub cache_sub_type: u32,         // 0x1D8
    pub objc_opts_offset: u64,       // 0x1E0
    pub objc_opts_size: u64,         // 0x1E8
    pub cache_atlas_offset: u64,     // 0x1F0
    pub cache_atlas_size: u64,       // 0x1F8
    pub dynamic_data_offset: u64,    // 0x200
    pub dynamic_data_max_size: u64,  // 0x208
    pub tpro_mappings_offset: u32,   // 0x210
    pub tpro_mappings_count: u32,    // 0x214
    pub function_variant_info_addr: u64, // 0x218
    pub function_variant_info_size: u64, // 0x220
    pub prewarming_data_offset: u64, // 0x228
    pub prewarming_data_size: u64,   // 0x230
    pub cache_cpu_type: u32,         // 0x238 (27.x beta1+)
    pub cache_cpu_subtype: u32,      // 0x23C
    pub cache_cpu_reserved: u64,     // 0x240 (end 0x248)
}

impl CacheHeader {
    /// Magic as a trimmed UTF-8 string (`"dyld_v1   arm64"` …).
    pub fn magic(&self) -> String {
        let end = self
            .magic_raw
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.magic_raw.len());
        String::from_utf8_lossy(&self.magic_raw[..end]).into_owned()
    }

    pub fn cache_type(&self) -> Option<CacheType> {
        CacheType::from_u64(self.cache_type)
    }

    /// dyld4 detection (iOS 15+/macOS 12+ split caches): old image list empty.
    pub fn is_dyld4(&self) -> bool {
        self.images_offset_old == 0 && self.images_count_old == 0
    }

    /// Header is new enough to carry `CacheCPUType/Subtype`
    /// (`MappingOffset >= 0x248`; ipsw `HasCacheCPUFields`).
    pub fn has_cache_cpu_fields(&self) -> bool {
        self.mapping_offset >= 0x248
    }

    /// Subcache entries carry 32-byte filename suffixes
    /// (`MappingOffset >= 0x200`).
    pub fn has_subcache_entry_v2(&self) -> bool {
        self.mapping_offset >= 0x200
    }

    /// TPRO mappings present (`MappingOffset >= 0x208` per ipsw).
    pub fn has_tpro_mappings(&self) -> bool {
        self.mapping_offset >= 0x208
    }

    /// PrebuiltLoader support (`MappingOffset >= 0x150 && >= 0x170`,
    /// `DylibsPblSetAddr != 0`).
    pub fn has_prebuilt_loaders(&self) -> bool {
        self.mapping_offset >= 0x170 && self.dylibs_pbl_set_addr != 0
    }

    /// Arm64-family magic (covers `arm64`, `arm64e`, `arm64_32`, `arm64ex1`).
    pub fn is_arm64(&self) -> bool {
        self.magic().contains("arm64")
    }

    /// True when the magic implies 64-bit pointers (`arm64`/`arm64e`/… but
    /// NOT `arm64_32`).
    pub fn is_64bit(&self) -> bool {
        self.magic().contains("64") && !self.magic().contains("arm64_32")
    }

    /// Parse the fixed 0x248-byte header region from the start of a cache
    /// file image. Fields beyond the on-disk header size (older caches) are
    /// zero-filled — that is exactly how Apple's format evolved.
    pub fn parse(buf: &[u8]) -> Result<CacheHeader, String> {
        if buf.len() < 0x118 {
            return Err(format!(
                "dsc: buffer too small for a dyld cache header: {} bytes",
                buf.len()
            ));
        }
        let rd16 = |off: usize| -> [u8; 16] {
            let mut out = [0u8; 16];
            if off + 16 <= buf.len() {
                out.copy_from_slice(&buf[off..off + 16]);
            }
            out
        };
        let rd32 = |off: usize| -> u32 {
            if off + 4 <= buf.len() {
                u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
            } else {
                0
            }
        };
        let rd64 = |off: usize| -> u64 {
            if off + 8 <= buf.len() {
                let mut b = [0u8; 8];
                b.copy_from_slice(&buf[off..off + 8]);
                u64::from_le_bytes(b)
            } else {
                0
            }
        };
        let magic_raw = rd16(0x00);
        let magic_s = {
            let end = magic_raw.iter().position(|&b| b == 0).unwrap_or(16);
            String::from_utf8_lossy(&magic_raw[..end]).into_owned()
        };
        if !MAGICS.iter().any(|m| magic_s.starts_with(m.trim_end())) {
            return Err(format!("dsc: not a dyld shared cache (magic {magic_s:?})"));
        }
        Ok(CacheHeader {
            magic_raw,
            mapping_offset: rd32(0x10),
            mapping_count: rd32(0x14),
            images_offset_old: rd32(0x18),
            images_count_old: rd32(0x1C),
            dyld_base_address: rd64(0x20),
            code_signature_offset: rd64(0x28),
            code_signature_size: rd64(0x30),
            slide_info_offset_unused: rd64(0x38),
            slide_info_size_unused: rd64(0x40),
            local_symbols_offset: rd64(0x48),
            local_symbols_size: rd64(0x50),
            uuid: rd16(0x58),
            cache_type: rd64(0x68),
            branch_pools_offset: rd32(0x70),
            branch_pools_count: rd32(0x74),
            accelerate_info_addr_unused_or_dyld_addr: rd64(0x78),
            accelerate_info_size_unused_or_dyld_start_func: rd64(0x80),
            images_text_offset: rd64(0x88),
            images_text_count: rd64(0x90),
            patch_info_addr: rd64(0x98),
            patch_info_size: rd64(0xA0),
            other_image_group_addr_unused: rd64(0xA8),
            other_image_group_size_unused: rd64(0xB0),
            prog_closures_addr: rd64(0xB8),
            prog_closures_size: rd64(0xC0),
            prog_closures_trie_addr: rd64(0xC8),
            prog_closures_trie_size: rd64(0xD0),
            platform: rd64(0xD8),
            format_version: rd32(0xE0),
            shared_region_start: rd64(0xE8),
            shared_region_size: rd64(0xF0),
            max_slide: rd64(0xF8),
            dylibs_image_array_addr: rd64(0x100),
            dylibs_image_array_size: rd64(0x108),
            dylibs_trie_addr: rd64(0x110),
            dylibs_trie_size: rd64(0x118),
            other_image_array_addr: rd64(0x120),
            other_image_array_size: rd64(0x128),
            other_trie_addr: rd64(0x130),
            other_trie_size: rd64(0x138),
            mapping_with_slide_offset: rd32(0x140),
            mapping_with_slide_count: rd32(0x144),
            dylibs_pbl_state_array_addr_unused: rd64(0x148),
            dylibs_pbl_set_addr: rd64(0x150),
            programs_pbl_set_pool_addr: rd64(0x158),
            programs_pbl_set_pool_size: rd64(0x160),
            program_trie_addr: rd64(0x168),
            program_trie_size: rd32(0x170),
            os_version: rd32(0x174),
            alt_platform: rd64(0x178),
            alt_os_version: rd32(0x180),
            swift_opts_offset: rd64(0x188),
            swift_opts_size: rd64(0x190),
            sub_cache_array_offset: rd32(0x198),
            sub_cache_array_count: rd32(0x19C),
            symbol_file_uuid: rd16(0x1A0),
            rosetta_read_only_addr: rd64(0x1B0),
            rosetta_read_only_size: rd64(0x1B8),
            rosetta_read_write_addr: rd64(0x1C0),
            rosetta_read_write_size: rd64(0x1C8),
            images_offset: rd32(0x1D0),
            images_count: rd32(0x1D4),
            cache_sub_type: rd32(0x1D8),
            objc_opts_offset: rd64(0x1E0),
            objc_opts_size: rd64(0x1E8),
            cache_atlas_offset: rd64(0x1F0),
            cache_atlas_size: rd64(0x1F8),
            dynamic_data_offset: rd64(0x200),
            dynamic_data_max_size: rd64(0x208),
            tpro_mappings_offset: rd32(0x210),
            tpro_mappings_count: rd32(0x214),
            function_variant_info_addr: rd64(0x218),
            function_variant_info_size: rd64(0x220),
            prewarming_data_offset: rd64(0x228),
            prewarming_data_size: rd64(0x230),
            cache_cpu_type: rd32(0x238),
            cache_cpu_subtype: rd32(0x23C),
            cache_cpu_reserved: rd64(0x240),
        })
    }
}
