//! prebuilt — dyld4 `PrebuiltLoaderSet` ("sp4d") / `PrebuiltLoader` ("l4yd")
//! parsing, straight from the on-disk byte layout.
//!
//! Parity: ipsw `pkg/dyld/prebuilt_types.go` (structs + bit accessors) and
//! `pkg/dyld/prebuilt.go` (`readPrebuiltLoaderSetHeader`, `parsePrebuiltLoaderSet`,
//! `parsePrebuiltLoader`, `SupportsProgramTrie`, `SupportsDylibPrebuiltLoader`).
//!
//! Layout notes (Go `encoding/binary` is *packed* — no interior padding — so
//! every offset below is the packed field order; I verified each against the
//! C-natural layout and they coincide everywhere here because the only u64
//! fields land on already-8-aligned offsets. Tail padding differs:
//!
//! | Go struct                  | source                 | bytes (packed) | C `sizeof` |
//! |----------------------------|------------------------|----------------|------------|
//! | `Loader`                   | prebuilt_types.go:53   | 8              | 8          |
//! | `prebuiltLoaderSetHeader`  | prebuilt_types.go:725  | 76             | 80 (+4 tail pad) |
//! | `prebuiltLoaderHeader`     | prebuilt_types.go:405  | 416            | 416 (`Sections` lands 8-aligned at 0x48) |
//! | `SectionLocations`         | prebuilt_types.go:397  | 344            | 344        |
//! | `fileValidation`           | prebuilt_types.go:332  | 54             | 56 (+2 tail pad) |
//! | `ObjCBinaryInfo`           | prebuilt_types.go:491  | 76             | 80 (+4 tail pad) |
//! | `ExportsTrieLoaderInFile`  | prebuilt_types.go:347  | 12             | 16 standalone (+4 tail pad) |
//! | `Region`                   | prebuilt_types.go:257  | 16             | 16         |
//! | `CachePatch`               | prebuilt_types.go:237  | 16             | 16         |
//! | `DylibPatch`               | prebuilt_types.go:251  | 16             | 16         |
//!
//! A `PrebuiltLoader` on disk is `Loader` (8B) + (UUID 16B + CpuSubtype 4B +
//! Unused 4B iff the `hasUUIDLoadCommand` info bit is set) +
//! `prebuiltLoaderHeader` (416B), then variable data pointed at by header
//! offsets that are *relative to the loader start* (offset 0 = `Loader.Magic`).
//!
//! Skipped (future work): the set-level ObjC hash tables
//! (`ObjCSelectorOpt`/`ObjCClassOpt` — 1056-byte `objCStringTable` header +
//! tab/checkbytes/offsets) and the Swift conformance multimaps. The per-loader
//! `ObjCBinaryInfo` **is** parsed.

use std::fmt;

use crate::mapping::VmProtection;

/// "l4yd" — `Loader.Magic` (prebuilt_types.go:16).
pub const LOADER_MAGIC: u32 = 0x6c34_7964;
/// "sp4d" — `prebuiltLoaderSetHeader.Magic` (prebuilt_types.go:17).
pub const PREBUILT_LOADER_SET_MAGIC: u32 = 0x7370_3464;
/// `IndexOfTwin` sentinel (prebuilt_types.go:18).
pub const NO_UNZIPPERED_TWIN: u16 = 0xFFFF;

/// Extract `bits` starting at `start` from `value`
/// (go-macho `types.ExtractBits`: `(v >> start) & ((1 << bits) - 1)`).
#[inline]
pub fn extract_bits(value: u64, start: u32, bits: u32) -> u64 {
    debug_assert!(bits >= 1 && start + bits <= 64);
    (value >> start) & ((1u64 << bits) - 1)
}

// ---------------------------------------------------------------------------
// little-endian primitive readers (byte-slice style of header.rs/image.rs)
// ---------------------------------------------------------------------------

pub(crate) fn rd_u16(buf: &[u8], off: usize) -> Result<u16, String> {
    if off + 2 > buf.len() {
        return Err(format!("dsc: prebuilt read past end of buffer at {off:#x}"));
    }
    Ok(u16::from_le_bytes([buf[off], buf[off + 1]]))
}

pub(crate) fn rd_u32(buf: &[u8], off: usize) -> Result<u32, String> {
    if off + 4 > buf.len() {
        return Err(format!("dsc: prebuilt read past end of buffer at {off:#x}"));
    }
    Ok(u32::from_le_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
    ]))
}

pub(crate) fn rd_u64(buf: &[u8], off: usize) -> Result<u64, String> {
    if off + 8 > buf.len() {
        return Err(format!("dsc: prebuilt read past end of buffer at {off:#x}"));
    }
    let mut b = [0u8; 8];
    b.copy_from_slice(&buf[off..off + 8]);
    Ok(u64::from_le_bytes(b))
}

/// NUL-terminated C string. Errors when unterminated — matches the Go
/// `bufio.ReadString('\x00')` + EOF handling in `parsePrebuiltLoader`.
pub(crate) fn rd_cstr(buf: &[u8], off: usize) -> Result<String, String> {
    if off >= buf.len() {
        return Err(format!("dsc: prebuilt string offset {off:#x} out of range"));
    }
    match buf[off..].iter().position(|&b| b == 0) {
        Some(end) => Ok(String::from_utf8_lossy(&buf[off..off + end]).into_owned()),
        None => Err(format!("dsc: prebuilt unterminated string at {off:#x}")),
    }
}

// ---------------------------------------------------------------------------
// LoaderRef / LoaderInfo / Loader  (prebuilt_types.go:24..119)
// ---------------------------------------------------------------------------

/// `type LoaderRef uint16` — 15-bit index + app bit.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LoaderRef(pub u16);

impl LoaderRef {
    /// `Index` — bits 0..15, index into the PrebuiltLoaderSet.
    pub fn index(self) -> u16 {
        extract_bits(self.0 as u64, 0, 15) as u16
    }
    /// `IsApp` — bit 15: app vs dyld-cache PrebuiltLoaderSet.
    pub fn is_app(self) -> bool {
        extract_bits(self.0 as u64, 15, 1) != 0
    }
    /// `IsMissingWeakImage` — index 0x7fff without the app bit.
    pub fn is_missing_weak_image(self) -> bool {
        self.index() == 0x7fff && !self.is_app()
    }
}

impl fmt::Display for LoaderRef {
    /// Mirrors Go `LoaderRef.String()`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "index: {}", self.index())?;
        if self.is_app() {
            write!(f, ", type: app")?;
        }
        if self.is_missing_weak_image() {
            write!(f, " (missing weak image)")?;
        }
        Ok(())
    }
}

/// `Loader.Info` — the 16 flag bits documented at prebuilt_types.go:56-70.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LoaderInfo(pub u16);

impl LoaderInfo {
    /// bit 0 — PrebuiltLoader vs JustInTimeLoader.
    pub fn is_prebuilt(self) -> bool {
        extract_bits(self.0 as u64, 0, 1) != 0
    }
    /// bit 1.
    pub fn dylib_in_dyld_cache(self) -> bool {
        extract_bits(self.0 as u64, 1, 1) != 0
    }
    /// bit 2.
    pub fn has_objc(self) -> bool {
        extract_bits(self.0 as u64, 2, 1) != 0
    }
    /// bit 3.
    pub fn may_have_plus_load(self) -> bool {
        extract_bits(self.0 as u64, 3, 1) != 0
    }
    /// bit 4 — `__DATA_CONST`; don't use directly, prefer
    /// `has_constant_segments_to_protect` (upstream note).
    pub fn has_read_only_data(self) -> bool {
        extract_bits(self.0 as u64, 4, 1) != 0
    }
    /// bit 5 — part of launch or has non-unloadable data (objc, tlv).
    pub fn never_unload(self) -> bool {
        extract_bits(self.0 as u64, 5, 1) != 0
    }
    /// bit 6 — RTLD_NODELETE.
    pub fn leave_mapped(self) -> bool {
        extract_bits(self.0 as u64, 6, 1) != 0
    }
    /// bit 7 — has `__DATA_CONST,__objc_selrefs`.
    pub fn has_read_only_objc(self) -> bool {
        extract_bits(self.0 as u64, 7, 1) != 0
    }
    /// bit 8.
    pub fn pre2022_binary(self) -> bool {
        extract_bits(self.0 as u64, 8, 1) != 0
    }
    /// bit 9 — mapped by exclave core.
    pub fn is_premapped(self) -> bool {
        extract_bits(self.0 as u64, 9, 1) != 0
    }
    /// bit 10 — the loader carries a UUID; gates the on-disk UUID/CpuSubtype/
    /// Unused prefix (prebuilt.go:566).
    pub fn has_uuid_load_command(self) -> bool {
        extract_bits(self.0 as u64, 10, 1) != 0
    }
    /// bit 11.
    pub fn has_weak_defs(self) -> bool {
        extract_bits(self.0 as u64, 11, 1) != 0
    }
    /// bit 12.
    pub fn has_tlvs(self) -> bool {
        extract_bits(self.0 as u64, 12, 1) != 0
    }
    /// bit 13.
    pub fn below_lib_system(self) -> bool {
        extract_bits(self.0 as u64, 13, 1) != 0
    }
    /// bits 14..16 — Go `Padding()`.
    pub fn padding(self) -> u8 {
        extract_bits(self.0 as u64, 14, 2) as u8
    }

    /// Flag half of Go `Loader.String()` (the `prebuilt|objc|tlvs` list).
    pub fn flags_str(self) -> String {
        let mut out: Vec<&str> = Vec::new();
        if self.is_prebuilt() {
            out.push("prebuilt");
        } else {
            out.push("jit");
        }
        if self.dylib_in_dyld_cache() {
            out.push("in-cache-dylib");
        }
        if self.has_objc() {
            out.push("objc");
        }
        if self.may_have_plus_load() {
            out.push("+load");
        }
        if self.has_read_only_data() {
            out.push("ro-data");
        }
        if self.never_unload() {
            out.push("never-unload");
        }
        if self.leave_mapped() {
            out.push("leave-mapped");
        }
        if self.has_read_only_objc() {
            out.push("ro-objc");
        }
        if self.pre2022_binary() {
            out.push("pre-2022");
        }
        if self.is_premapped() {
            out.push("premapped");
        }
        if self.has_uuid_load_command() {
            out.push("uuid-load-cmd");
        }
        if self.has_weak_defs() {
            out.push("weak-defs");
        }
        if self.has_tlvs() {
            out.push("tlvs");
        }
        if self.below_lib_system() {
            out.push("below-libsystem");
        }
        out.join("|")
    }
}

/// `type Loader struct` (prebuilt_types.go:53) — 8 bytes on disk:
/// Magic u32 @0, Info u16 @4, Ref u16 @6.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Loader {
    pub magic: u32,
    pub info: LoaderInfo,
    pub r#ref: LoaderRef,
}

pub const LOADER_SIZE: usize = 8;
pub const LOADER_OFF_MAGIC: usize = 0x00;
pub const LOADER_OFF_INFO: usize = 0x04;
pub const LOADER_OFF_REF: usize = 0x06;

impl Loader {
    pub fn parse(buf: &[u8], off: usize) -> Result<Loader, String> {
        Ok(Loader {
            magic: rd_u32(buf, off + LOADER_OFF_MAGIC)?,
            info: LoaderInfo(rd_u16(buf, off + LOADER_OFF_INFO)?),
            r#ref: LoaderRef(rd_u16(buf, off + LOADER_OFF_REF)?),
        })
    }
}

impl fmt::Display for Loader {
    /// Mirrors Go `Loader.String()`: `"<flags>, ref: <ref>"`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}, ref: {}", self.info.flags_str(), self.r#ref)
    }
}

// ---------------------------------------------------------------------------
// DependentKind (prebuilt_types.go:170)
// ---------------------------------------------------------------------------

/// `type DependentKind uint8`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DependentKind {
    Normal,
    WeakLink,
    Reexport,
    Upward,
    Delayed,
}

pub const KIND_NORMAL: u8 = 0;
pub const KIND_WEAK_LINK: u8 = 1;
pub const KIND_REEXPORT: u8 = 2;
pub const KIND_UPWARD: u8 = 4;
pub const KIND_DELAYED: u8 = 8;

impl DependentKind {
    pub fn from_u8(v: u8) -> Option<DependentKind> {
        match v {
            KIND_NORMAL => Some(DependentKind::Normal),
            KIND_WEAK_LINK => Some(DependentKind::WeakLink),
            KIND_REEXPORT => Some(DependentKind::Reexport),
            KIND_UPWARD => Some(DependentKind::Upward),
            KIND_DELAYED => Some(DependentKind::Delayed),
            _ => None,
        }
    }
    /// Go `DependentKind.String()`.
    pub fn as_str(self) -> &'static str {
        match self {
            DependentKind::Normal => "regular",
            DependentKind::WeakLink => "weak-link",
            DependentKind::Reexport => "re-export",
            DependentKind::Upward => "upward",
            DependentKind::Delayed => "delay-init",
        }
    }
}

// ---------------------------------------------------------------------------
// BindTargetRef / CachePatch / DylibPatch (prebuilt_types.go:197..254)
// ---------------------------------------------------------------------------

/// `type BindTargetRef uint64` — loader-ref | high8 | signed low39, or an
/// absolute value when bit 63 is set.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BindTargetRef(pub u64);

/// `deserializeAbsoluteValue` — sign-extend bit 62 into bit 63
/// (prebuilt_types.go:352).
pub fn deserialize_absolute_value(value: u64) -> u64 {
    if value & 0x4000_0000_0000_0000 != 0 {
        value | 0x8000_0000_0000_0000
    } else {
        value
    }
}

impl BindTargetRef {
    /// bits 0..16.
    pub fn loader_ref(self) -> LoaderRef {
        LoaderRef(extract_bits(self.0, 0, 16) as u16)
    }
    /// bits 16..24 (private `high8` in Go).
    pub fn high8(self) -> u64 {
        extract_bits(self.0, 16, 8)
    }
    /// bits 24..63 (private `low39`, signed in use).
    pub fn low39(self) -> u64 {
        extract_bits(self.0, 24, 39)
    }
    /// `AbsoluteValue` — the 63-bit payload sign-extended.
    pub fn absolute_value(self) -> u64 {
        deserialize_absolute_value(extract_bits(self.0, 0, 63))
    }
    /// `Kind` — bit 63.
    pub fn kind(self) -> u8 {
        extract_bits(self.0, 63, 1) as u8
    }
    /// `IsAbsolute` — kind == 1.
    pub fn is_absolute(self) -> bool {
        self.kind() == 1
    }
    /// `Offset` — absolute value, or `high8 << 56 | sign-extended low39`.
    pub fn offset(self) -> u64 {
        if self.is_absolute() {
            return self.absolute_value();
        }
        let mut signed_offset = self.low39();
        if signed_offset & 0x0000_0040_0000_0000 != 0 {
            signed_offset |= 0x00FF_FF80_0000_0000;
        }
        (self.high8() << 56) | signed_offset
    }
}

/// `type CachePatch struct` (prebuilt_types.go:237) — 16 bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CachePatch {
    pub dylib_index: u32,
    pub dylib_vm_offset: u32,
    pub patch_to: BindTargetRef,
}

pub const CACHE_PATCH_SIZE: usize = 16;
pub const CACHE_PATCH_OFF_DYLIB_INDEX: usize = 0x00;
pub const CACHE_PATCH_OFF_DYLIB_VM_OFFSET: usize = 0x04;
pub const CACHE_PATCH_OFF_PATCH_TO: usize = 0x08;

impl CachePatch {
    pub fn parse(buf: &[u8], off: usize) -> Result<CachePatch, String> {
        Ok(CachePatch {
            dylib_index: rd_u32(buf, off + CACHE_PATCH_OFF_DYLIB_INDEX)?,
            dylib_vm_offset: rd_u32(buf, off + CACHE_PATCH_OFF_DYLIB_VM_OFFSET)?,
            patch_to: BindTargetRef(rd_u64(buf, off + CACHE_PATCH_OFF_PATCH_TO)?),
        })
    }
}

/// `dpkind` values (prebuilt_types.go:242).
pub const DP_END_OF_PATCH_TABLE: i64 = -1;
pub const DP_MISSING_WEAK_IMPORT: i64 = 0;
pub const DP_OBJC_CLASS: i64 = 1;
pub const DP_SINGLETON: i64 = 2;

/// `type DylibPatch struct` (prebuilt_types.go:251) — int64 + dpkind(int64),
/// 16 bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DylibPatch {
    pub override_offset_of_impl: i64,
    pub kind: i64,
}

pub const DYLIB_PATCH_SIZE: usize = 16;

impl DylibPatch {
    pub fn parse(buf: &[u8], off: usize) -> Result<DylibPatch, String> {
        Ok(DylibPatch {
            override_offset_of_impl: rd_u64(buf, off)? as i64,
            kind: rd_u64(buf, off + 8)? as i64,
        })
    }
}

// ---------------------------------------------------------------------------
// Region (prebuilt_types.go:256)
// ---------------------------------------------------------------------------

/// `type Region struct` — 16 bytes: Info u64 (vmOffset:59 | perms:3 |
/// isZeroFill:1 | readOnlyData:1), FileOffset u32, FileSize u32.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Region {
    pub info: u64,
    pub file_offset: u32,
    pub file_size: u32,
}

pub const REGION_SIZE: usize = 16;

impl Region {
    pub fn parse(buf: &[u8], off: usize) -> Result<Region, String> {
        Ok(Region {
            info: rd_u64(buf, off)?,
            file_offset: rd_u32(buf, off + 8)?,
            file_size: rd_u32(buf, off + 12)?,
        })
    }

    /// bits 0..59.
    pub fn vm_offset(self) -> u64 {
        extract_bits(self.info, 0, 59)
    }
    /// bits 59..62 as `VmProtection`.
    pub fn perms(self) -> VmProtection {
        VmProtection(extract_bits(self.info, 59, 3) as i32)
    }
    /// bit 62.
    pub fn is_zero_fill(self) -> bool {
        extract_bits(self.info, 62, 1) != 0
    }
    /// bit 63.
    pub fn read_only_data(self) -> bool {
        extract_bits(self.info, 63, 1) != 0
    }
}

// ---------------------------------------------------------------------------
// fileValidation / CodeSignatureInFile / ExportsTrieLoaderInFile
// (prebuilt_types.go:331..350)
// ---------------------------------------------------------------------------

/// `type fileValidation struct` — 54 packed bytes (C sizeof 56: 2-byte tail
/// pad after the two bools).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FileValidation {
    pub slice_offset: u64,  // 0x00
    pub device_id: u64,     // 0x08
    pub inode: u64,         // 0x10
    pub mtime: u64,         // 0x18
    pub cd_hash: [u8; 20],  // 0x20 — validates the file has not changed
    pub check_inode_mtime: bool, // 0x34
    pub check_cd_hash: bool,     // 0x35
}

pub const FILE_VALIDATION_SIZE: usize = 54;

impl FileValidation {
    pub fn parse(buf: &[u8], off: usize) -> Result<FileValidation, String> {
        if off + FILE_VALIDATION_SIZE > buf.len() {
            return Err(format!(
                "dsc: prebuilt fileValidation at {off:#x} truncated"
            ));
        }
        let mut cd_hash = [0u8; 20];
        cd_hash.copy_from_slice(&buf[off + 0x20..off + 0x34]);
        Ok(FileValidation {
            slice_offset: rd_u64(buf, off)?,
            device_id: rd_u64(buf, off + 8)?,
            inode: rd_u64(buf, off + 0x10)?,
            mtime: rd_u64(buf, off + 0x18)?,
            cd_hash,
            check_inode_mtime: buf[off + 0x34] != 0,
            check_cd_hash: buf[off + 0x35] != 0,
        })
    }
}

/// `type CodeSignatureInFile struct` — 8 bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CodeSignatureInFile {
    pub file_offset: u32,
    pub size: u32,
}

pub const CODE_SIGNATURE_IN_FILE_SIZE: usize = 8;

/// `type ExportsTrieLoaderInFile struct` — 12 packed bytes (C sizeof 16).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExportsTrieLoaderInFile {
    pub offset: u64,
    pub size: u32,
}

pub const EXPORTS_TRIE_LOADER_SIZE: usize = 12;

// ---------------------------------------------------------------------------
// dyld_section_location kinds (prebuilt_types.go:365, names from
// prebuilt_string.go stringer, `dyld_section_location_` prefix trimmed)
// ---------------------------------------------------------------------------

/// `type dyld_section_location_kind uint32`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DyldSectionLocationKind {
    TextSwift5Protos = 0,
    TextSwift5Proto = 1,
    TextSwift5Types = 2,
    TextSwift5Replace = 3,
    TextSwift5Replace2 = 4,
    TextSwift5AcFuncs = 5,
    ObjcImageInfo = 6,
    DataSelRefs = 7,
    DataMsgRefs = 8,
    DataClassRefs = 9,
    DataSuperRefs = 10,
    DataProtocolRefs = 11,
    DataClassList = 12,
    DataNonLazyClassList = 13,
    DataStubList = 14,
    DataCategoryList = 15,
    DataCategoryList2 = 16,
    DataNonLazyCategoryList = 17,
    DataProtocolList = 18,
    DataObjcForkOk = 19,
    DataRawIsa = 20,
}

pub const DYLD_SECTION_LOCATION_COUNT: usize = 21;

impl DyldSectionLocationKind {
    pub fn from_u32(v: u32) -> Option<DyldSectionLocationKind> {
        match v {
            0 => Some(DyldSectionLocationKind::TextSwift5Protos),
            1 => Some(DyldSectionLocationKind::TextSwift5Proto),
            2 => Some(DyldSectionLocationKind::TextSwift5Types),
            3 => Some(DyldSectionLocationKind::TextSwift5Replace),
            4 => Some(DyldSectionLocationKind::TextSwift5Replace2),
            5 => Some(DyldSectionLocationKind::TextSwift5AcFuncs),
            6 => Some(DyldSectionLocationKind::ObjcImageInfo),
            7 => Some(DyldSectionLocationKind::DataSelRefs),
            8 => Some(DyldSectionLocationKind::DataMsgRefs),
            9 => Some(DyldSectionLocationKind::DataClassRefs),
            10 => Some(DyldSectionLocationKind::DataSuperRefs),
            11 => Some(DyldSectionLocationKind::DataProtocolRefs),
            12 => Some(DyldSectionLocationKind::DataClassList),
            13 => Some(DyldSectionLocationKind::DataNonLazyClassList),
            14 => Some(DyldSectionLocationKind::DataStubList),
            15 => Some(DyldSectionLocationKind::DataCategoryList),
            16 => Some(DyldSectionLocationKind::DataCategoryList2),
            17 => Some(DyldSectionLocationKind::DataNonLazyCategoryList),
            18 => Some(DyldSectionLocationKind::DataProtocolList),
            19 => Some(DyldSectionLocationKind::DataObjcForkOk),
            20 => Some(DyldSectionLocationKind::DataRawIsa),
            _ => None,
        }
    }

    /// stringer name (`stringer -trimprefix=dyld_section_location_`).
    pub fn as_str(self) -> &'static str {
        match self {
            DyldSectionLocationKind::TextSwift5Protos => "text_swift5_protos",
            DyldSectionLocationKind::TextSwift5Proto => "text_swift5_proto",
            DyldSectionLocationKind::TextSwift5Types => "text_swift5_types",
            DyldSectionLocationKind::TextSwift5Replace => "text_swift5_replace",
            DyldSectionLocationKind::TextSwift5Replace2 => "text_swift5_replace2",
            DyldSectionLocationKind::TextSwift5AcFuncs => "text_swift5_ac_funcs",
            DyldSectionLocationKind::ObjcImageInfo => "objc_image_info",
            DyldSectionLocationKind::DataSelRefs => "data_sel_refs",
            DyldSectionLocationKind::DataMsgRefs => "data_msg_refs",
            DyldSectionLocationKind::DataClassRefs => "data_class_refs",
            DyldSectionLocationKind::DataSuperRefs => "data_super_refs",
            DyldSectionLocationKind::DataProtocolRefs => "data_protocol_refs",
            DyldSectionLocationKind::DataClassList => "data_class_list",
            DyldSectionLocationKind::DataNonLazyClassList => "data_non_lazy_class_list",
            DyldSectionLocationKind::DataStubList => "data_stub_list",
            DyldSectionLocationKind::DataCategoryList => "data_category_list",
            DyldSectionLocationKind::DataCategoryList2 => "data_category_list2",
            DyldSectionLocationKind::DataNonLazyCategoryList => "data_non_lazy_category_list",
            DyldSectionLocationKind::DataProtocolList => "data_protocol_list",
            DyldSectionLocationKind::DataObjcForkOk => "data_objc_fork_ok",
            DyldSectionLocationKind::DataRawIsa => "data_raw_isa",
        }
    }
}

impl fmt::Display for DyldSectionLocationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One non-zero section location, materialized from `SectionLocations`
/// (the value the Go print flow emits per entry).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DyldSectionLocation {
    pub kind: DyldSectionLocationKind,
    pub offset: u64,
    pub size: u64,
}

/// `type SectionLocations struct` (prebuilt_types.go:397) — Version u32 @0,
/// Flags u32 @4, Offsets [21]u64 @8, Sizes [21]u64 @0xB0. 344 bytes.
#[derive(Debug, Clone)]
pub struct SectionLocations {
    pub version: u32,
    pub flags: u32,
    pub offsets: [u64; DYLD_SECTION_LOCATION_COUNT],
    pub sizes: [u64; DYLD_SECTION_LOCATION_COUNT],
}

pub const SECTION_LOCATIONS_SIZE: usize = 4 + 4 + 2 * DYLD_SECTION_LOCATION_COUNT * 8; // 344

impl Default for SectionLocations {
    fn default() -> Self {
        SectionLocations {
            version: 0,
            flags: 0,
            offsets: [0; DYLD_SECTION_LOCATION_COUNT],
            sizes: [0; DYLD_SECTION_LOCATION_COUNT],
        }
    }
}

impl SectionLocations {
    pub fn parse(buf: &[u8], off: usize) -> Result<SectionLocations, String> {
        if off + SECTION_LOCATIONS_SIZE > buf.len() {
            return Err(format!(
                "dsc: prebuilt SectionLocations at {off:#x} truncated"
            ));
        }
        let mut offsets = [0u64; DYLD_SECTION_LOCATION_COUNT];
        let mut sizes = [0u64; DYLD_SECTION_LOCATION_COUNT];
        for i in 0..DYLD_SECTION_LOCATION_COUNT {
            offsets[i] = rd_u64(buf, off + 8 + i * 8)?;
            sizes[i] = rd_u64(buf, off + 8 + DYLD_SECTION_LOCATION_COUNT * 8 + i * 8)?;
        }
        Ok(SectionLocations {
            version: rd_u32(buf, off)?,
            flags: rd_u32(buf, off + 4)?,
            offsets,
            sizes,
        })
    }

    /// Non-zero locations in kind order — mirrors the `String()` print loop
    /// (`for idx, off := range pl.Header.Sections.Offsets { if off == 0 { continue } …}`).
    pub fn locations(&self) -> impl Iterator<Item = DyldSectionLocation> + '_ {
        self.offsets.iter().enumerate().filter_map(|(i, &off)| {
            if off == 0 {
                return None;
            }
            Some(DyldSectionLocation {
                kind: DyldSectionLocationKind::from_u32(i as u32)?,
                offset: off,
                size: self.sizes[i],
            })
        })
    }
}

// ---------------------------------------------------------------------------
// prebuiltLoaderHeader (prebuilt_types.go:405) — 416 packed bytes
// ---------------------------------------------------------------------------

pub const PREBUILT_LOADER_HEADER_SIZE: usize = 0x1A0; // 416

pub const PBLH_PATH_OFFSET: usize = 0x00;
pub const PBLH_DEP_REFS_ARRAY_OFFSET: usize = 0x02;
pub const PBLH_DEP_KINDS_ARRAY_OFFSET: usize = 0x04;
pub const PBLH_FIXUPS_LOAD_COMMAND_OFFSET: usize = 0x06;
pub const PBLH_ALT_PATH_OFFSET: usize = 0x08;
pub const PBLH_FILE_VALIDATION_OFFSET: usize = 0x0A;
pub const PBLH_INFO: usize = 0x0C;
pub const PBLH_REGIONS_OFFSET: usize = 0x0E;
pub const PBLH_DEP_COUNT: usize = 0x10;
pub const PBLH_BIND_TARGET_REFS_OFFSET: usize = 0x12;
pub const PBLH_BIND_TARGET_REFS_COUNT: usize = 0x14;
pub const PBLH_OBJC_BINARY_INFO_OFFSET: usize = 0x18;
pub const PBLH_INDEX_OF_TWIN: usize = 0x1C;
pub const PBLH_PAD: usize = 0x1E; // Go `_ uint16`
pub const PBLH_EXPORTS_TRIE_OFFSET: usize = 0x20; // ExportsTrieLoader.Offset u64
pub const PBLH_EXPORTS_TRIE_SIZE: usize = 0x28; // ExportsTrieLoader.Size u32
pub const PBLH_VM_SIZE: usize = 0x2C;
pub const PBLH_CODE_SIGNATURE_FILE_OFFSET: usize = 0x30;
pub const PBLH_CODE_SIGNATURE_SIZE: usize = 0x34;
pub const PBLH_PATCH_TABLE_OFFSET: usize = 0x38;
pub const PBLH_OVERRIDE_BIND_TARGET_REFS_OFFSET: usize = 0x3C;
pub const PBLH_OVERRIDE_BIND_TARGET_REFS_COUNT: usize = 0x40;
pub const PBLH_PAD2: usize = 0x44; // Go `_ uint32 // padding`
pub const PBLH_SECTIONS: usize = 0x48; // SectionLocations (8-aligned — no pad needed)

/// `prebuiltLoaderHeader.Info` bitfields (prebuilt_types.go:414-419):
/// hasInitializers:1, isOverridable:1, supportsCatalyst:1,
/// isCatalystOverride:1, regionsCount:12.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PrebuiltLoaderHeaderInfo(pub u16);

impl PrebuiltLoaderHeaderInfo {
    pub fn has_initializers(self) -> bool {
        extract_bits(self.0 as u64, 0, 1) != 0
    }
    pub fn is_overridable(self) -> bool {
        extract_bits(self.0 as u64, 1, 1) != 0
    }
    pub fn supports_catalyst(self) -> bool {
        extract_bits(self.0 as u64, 2, 1) != 0
    }
    pub fn is_catalyst_override(self) -> bool {
        extract_bits(self.0 as u64, 3, 1) != 0
    }
    pub fn regions_count(self) -> u16 {
        extract_bits(self.0 as u64, 4, 12) as u16
    }
}

/// `type prebuiltLoaderHeader struct` — the fixed 416-byte part of a
/// PrebuiltLoader. All variable data hangs off `*Offset` fields that are
/// relative to the loader start (prebuilt.go `parsePrebuiltLoader`).
#[derive(Debug, Clone, Default)]
pub struct PrebuiltLoaderHeader {
    pub path_offset: u16,
    pub dependent_loader_refs_array_offset: u16,
    pub dependent_kind_array_offset: u16,
    pub fixups_load_command_offset: u16,
    pub alt_path_offset: u16,
    pub file_validation_offset: u16,
    pub info: PrebuiltLoaderHeaderInfo,
    pub regions_offset: u16,
    pub dep_count: u16,
    pub bind_target_refs_offset: u16,
    pub bind_target_refs_count: u32,
    pub objc_binary_info_offset: u32,
    pub index_of_twin: u16,
    pub exports_trie: ExportsTrieLoaderInFile,
    pub vm_size: u32,
    pub code_signature: CodeSignatureInFile,
    pub patch_table_offset: u32,
    pub override_bind_target_refs_offset: u32,
    pub override_bind_target_refs_count: u32,
    pub sections: SectionLocations,
}

impl PrebuiltLoaderHeader {
    pub fn parse(buf: &[u8], off: usize) -> Result<PrebuiltLoaderHeader, String> {
        if off + PREBUILT_LOADER_HEADER_SIZE > buf.len() {
            return Err(format!(
                "dsc: prebuilt loader header at {off:#x} truncated (need {} bytes)",
                PREBUILT_LOADER_HEADER_SIZE
            ));
        }
        Ok(PrebuiltLoaderHeader {
            path_offset: rd_u16(buf, off + PBLH_PATH_OFFSET)?,
            dependent_loader_refs_array_offset: rd_u16(buf, off + PBLH_DEP_REFS_ARRAY_OFFSET)?,
            dependent_kind_array_offset: rd_u16(buf, off + PBLH_DEP_KINDS_ARRAY_OFFSET)?,
            fixups_load_command_offset: rd_u16(buf, off + PBLH_FIXUPS_LOAD_COMMAND_OFFSET)?,
            alt_path_offset: rd_u16(buf, off + PBLH_ALT_PATH_OFFSET)?,
            file_validation_offset: rd_u16(buf, off + PBLH_FILE_VALIDATION_OFFSET)?,
            info: PrebuiltLoaderHeaderInfo(rd_u16(buf, off + PBLH_INFO)?),
            regions_offset: rd_u16(buf, off + PBLH_REGIONS_OFFSET)?,
            dep_count: rd_u16(buf, off + PBLH_DEP_COUNT)?,
            bind_target_refs_offset: rd_u16(buf, off + PBLH_BIND_TARGET_REFS_OFFSET)?,
            bind_target_refs_count: rd_u32(buf, off + PBLH_BIND_TARGET_REFS_COUNT)?,
            objc_binary_info_offset: rd_u32(buf, off + PBLH_OBJC_BINARY_INFO_OFFSET)?,
            index_of_twin: rd_u16(buf, off + PBLH_INDEX_OF_TWIN)?,
            exports_trie: ExportsTrieLoaderInFile {
                offset: rd_u64(buf, off + PBLH_EXPORTS_TRIE_OFFSET)?,
                size: rd_u32(buf, off + PBLH_EXPORTS_TRIE_SIZE)?,
            },
            vm_size: rd_u32(buf, off + PBLH_VM_SIZE)?,
            code_signature: CodeSignatureInFile {
                file_offset: rd_u32(buf, off + PBLH_CODE_SIGNATURE_FILE_OFFSET)?,
                size: rd_u32(buf, off + PBLH_CODE_SIGNATURE_SIZE)?,
            },
            patch_table_offset: rd_u32(buf, off + PBLH_PATCH_TABLE_OFFSET)?,
            override_bind_target_refs_offset: rd_u32(
                buf,
                off + PBLH_OVERRIDE_BIND_TARGET_REFS_OFFSET,
            )?,
            override_bind_target_refs_count: rd_u32(
                buf,
                off + PBLH_OVERRIDE_BIND_TARGET_REFS_COUNT,
            )?,
            sections: SectionLocations::parse(buf, off + PBLH_SECTIONS)?,
        })
    }
}

// ---------------------------------------------------------------------------
// ObjCBinaryInfo (prebuilt_types.go:491) — 76 packed bytes (C sizeof 80)
// ---------------------------------------------------------------------------

pub const OBJC_BINARY_INFO_SIZE: usize = 76;

/// `type ObjCBinaryInfo struct` — layout of the objc sections of a binary.
/// The 8 bools sit in one byte each at 0x38..0x40 (Go `_ bool //padding` is
/// the 8th).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ObjCBinaryInfo {
    pub image_info_runtime_offset: u64,        // 0x00
    pub sel_refs_runtime_offset: u64,          // 0x08
    pub class_list_runtime_offset: u64,        // 0x10
    pub category_list_runtime_offset: u64,     // 0x18
    pub protocol_list_runtime_offset: u64,     // 0x20
    pub sel_refs_count: u32,                   // 0x28
    pub class_list_count: u32,                 // 0x2C
    pub category_count: u32,                   // 0x30
    pub protocol_list_count: u32,              // 0x34
    pub has_class_stable_swift_fixups: bool,   // 0x38
    pub has_class_method_lists_to_set_uniqued: bool,   // 0x39
    pub has_category_method_lists_to_set_uniqued: bool, // 0x3A
    pub has_protocol_method_lists_to_set_uniqued: bool, // 0x3B
    pub has_class_method_lists_to_unique: bool,    // 0x3C
    pub has_category_method_lists_to_unique: bool, // 0x3D
    pub has_protocol_method_lists_to_unique: bool, // 0x3E
    pub padding: bool,                          // 0x3F — Go `_ bool`
    pub protocol_fixups_offset: u32,            // 0x40
    pub selector_references_fixups_offset: u32, // 0x44
    pub selector_references_fixups_count: u32,  // 0x48
}

impl ObjCBinaryInfo {
    pub fn parse(buf: &[u8], off: usize) -> Result<ObjCBinaryInfo, String> {
        if off + OBJC_BINARY_INFO_SIZE > buf.len() {
            return Err(format!(
                "dsc: prebuilt ObjCBinaryInfo at {off:#x} truncated"
            ));
        }
        Ok(ObjCBinaryInfo {
            image_info_runtime_offset: rd_u64(buf, off)?,
            sel_refs_runtime_offset: rd_u64(buf, off + 0x08)?,
            class_list_runtime_offset: rd_u64(buf, off + 0x10)?,
            category_list_runtime_offset: rd_u64(buf, off + 0x18)?,
            protocol_list_runtime_offset: rd_u64(buf, off + 0x20)?,
            sel_refs_count: rd_u32(buf, off + 0x28)?,
            class_list_count: rd_u32(buf, off + 0x2C)?,
            category_count: rd_u32(buf, off + 0x30)?,
            protocol_list_count: rd_u32(buf, off + 0x34)?,
            has_class_stable_swift_fixups: buf[off + 0x38] != 0,
            has_class_method_lists_to_set_uniqued: buf[off + 0x39] != 0,
            has_category_method_lists_to_set_uniqued: buf[off + 0x3A] != 0,
            has_protocol_method_lists_to_set_uniqued: buf[off + 0x3B] != 0,
            has_class_method_lists_to_unique: buf[off + 0x3C] != 0,
            has_category_method_lists_to_unique: buf[off + 0x3D] != 0,
            has_protocol_method_lists_to_unique: buf[off + 0x3E] != 0,
            padding: buf[off + 0x3F] != 0,
            protocol_fixups_offset: rd_u32(buf, off + 0x40)?,
            selector_references_fixups_offset: rd_u32(buf, off + 0x44)?,
            selector_references_fixups_count: rd_u32(buf, off + 0x48)?,
        })
    }
}

// ---------------------------------------------------------------------------
// PrebuiltLoader (prebuilt_types.go:575, parsed in prebuilt.go:559)
// ---------------------------------------------------------------------------

/// One dependent of a loader. Go resolves `Name` through the cache image
/// list (`f.Images[dep.Index()].Name`); here `name` stays empty and callers
/// resolve `dep` against their own image list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Dependent {
    pub name: String,
    pub kind: u8,
    pub dep: LoaderRef,
}

impl Dependent {
    pub fn kind_enum(&self) -> Option<DependentKind> {
        DependentKind::from_u8(self.kind)
    }
}

/// `type PrebuiltLoader struct` — the parsed view of one on-disk loader.
/// Disk layout: `Loader` @0, then (iff `info.has_uuid_load_command()`)
/// UUID @8, CpuSubtype @24, Unused @28, then `prebuiltLoaderHeader` @32
/// (@8 without the UUID prefix). All header offsets are relative to the
/// loader start.
#[derive(Debug, Clone, Default)]
pub struct PrebuiltLoader {
    pub loader: Loader,
    /// Present iff `loader.info.has_uuid_load_command()`; zeroed otherwise.
    pub uuid: [u8; 16],
    pub cpu_subtype: u32,
    pub unused: u32,
    pub header: PrebuiltLoaderHeader,
    pub path: String,
    pub alt_path: String,
    /// `IndexOfTwin` when it is not `NO_UNZIPPERED_TWIN` (resolve against the
    /// cache image list like Go's `pbl.Twin`).
    pub twin_index: Option<u16>,
    pub dependents: Vec<Dependent>,
    pub file_validation: Option<FileValidation>,
    pub regions: Vec<Region>,
    pub bind_targets: Vec<BindTargetRef>,
    pub dylib_patches: Vec<DylibPatch>,
    pub override_bind_targets: Vec<BindTargetRef>,
    pub objc_fixup_info: Option<ObjCBinaryInfo>,
    pub objc_canonical_protocol_fixups: Vec<bool>,
    pub objc_selector_fixups: Vec<BindTargetRef>,
}

impl PrebuiltLoader {
    /// Parse one loader whose bytes start at `loader_start` (offset 0 of the
    /// loader; every header offset is relative to this). Mirrors ipsw
    /// `parsePrebuiltLoader` (prebuilt.go:559).
    pub fn parse(buf: &[u8], loader_start: usize) -> Result<PrebuiltLoader, String> {
        let loader = Loader::parse(buf, loader_start)?;
        if loader.magic != LOADER_MAGIC {
            return Err(format!(
                "dsc: invalid magic for prebuilt loader: expected {:x} got {:x}",
                LOADER_MAGIC, loader.magic
            ));
        }

        let mut pos = loader_start + LOADER_SIZE;
        let mut uuid = [0u8; 16];
        let mut cpu_subtype = 0u32;
        let mut unused = 0u32;
        if loader.info.has_uuid_load_command() {
            if pos + 16 + 4 + 4 > buf.len() {
                return Err("dsc: prebuilt loader uuid/cpu-subtype truncated".into());
            }
            uuid.copy_from_slice(&buf[pos..pos + 16]);
            cpu_subtype = rd_u32(buf, pos + 16)?;
            unused = rd_u32(buf, pos + 20)?;
            pos += 24;
        }
        let header = PrebuiltLoaderHeader::parse(buf, pos)?;
        let base = loader_start; // all header offsets are loader-relative

        // Path / alt path (NUL-terminated strings).
        let path = if header.path_offset > 0 {
            rd_cstr(buf, base + header.path_offset as usize)?
        } else {
            String::new()
        };
        let alt_path = if header.alt_path_offset > 0 {
            rd_cstr(buf, base + header.alt_path_offset as usize)?
        } else {
            String::new()
        };

        // fileValidation.
        let file_validation = if header.file_validation_offset > 0 {
            Some(FileValidation::parse(
                buf,
                base + header.file_validation_offset as usize,
            )?)
        } else {
            None
        };

        // Regions.
        let mut regions = Vec::new();
        if header.info.regions_count() > 0 {
            for i in 0..header.info.regions_count() as usize {
                regions.push(Region::parse(
                    buf,
                    base + header.regions_offset as usize + i * REGION_SIZE,
                )?);
            }
        }

        // Dependents (+ optional kinds array; zero kinds => KindNormal, the
        // Go `kindsArray := make([]DependentKind, DepCount)` default).
        let mut dependents = Vec::new();
        if header.dependent_loader_refs_array_offset > 0 {
            let refs_base = base + header.dependent_loader_refs_array_offset as usize;
            let kinds_base = if header.dependent_kind_array_offset > 0 {
                base + header.dependent_kind_array_offset as usize
            } else {
                refs_base // Go seeks here but only reads when the kind offset is set
            };
            for i in 0..header.dep_count as usize {
                let dep = LoaderRef(rd_u16(buf, refs_base + i * 2)?);
                let kind = if header.dependent_kind_array_offset > 0 {
                    buf.get(kinds_base + i)
                        .copied()
                        .ok_or_else(|| format!("dsc: prebuilt dependent kinds at {kinds_base:#x} truncated"))?
                } else {
                    KIND_NORMAL
                };
                dependents.push(Dependent {
                    name: String::new(),
                    kind,
                    dep,
                });
            }
        }

        // Bind targets / override bind targets (arrays of u64).
        let mut bind_targets = Vec::new();
        if header.bind_target_refs_count > 0 {
            for i in 0..header.bind_target_refs_count as usize {
                bind_targets.push(BindTargetRef(rd_u64(
                    buf,
                    base + header.bind_target_refs_offset as usize + i * 8,
                )?));
            }
        }
        let mut override_bind_targets = Vec::new();
        if header.override_bind_target_refs_count > 0 {
            for i in 0..header.override_bind_target_refs_count as usize {
                override_bind_targets.push(BindTargetRef(rd_u64(
                    buf,
                    base + header.override_bind_target_refs_offset as usize + i * 8,
                )?));
            }
        }

        // ObjC binary info + fixup arrays hanging off it.
        let mut objc_fixup_info = None;
        let mut objc_canonical_protocol_fixups = Vec::new();
        let mut objc_selector_fixups = Vec::new();
        if header.objc_binary_info_offset > 0 {
            let objc_base = base + header.objc_binary_info_offset as usize;
            let ofi = ObjCBinaryInfo::parse(buf, objc_base)?;
            // NOTE: upstream counts canonical-protocol fixups with
            // ProtocolListCount (prebuilt.go:699) — reproduced as-is.
            let fixups_base = objc_base + ofi.protocol_fixups_offset as usize;
            for i in 0..ofi.protocol_list_count as usize {
                let b = buf
                    .get(fixups_base + i)
                    .ok_or_else(|| format!("dsc: prebuilt objc canonical protocol fixups at {fixups_base:#x} truncated"))?;
                objc_canonical_protocol_fixups.push(*b != 0);
            }
            let sel_base = objc_base + ofi.selector_references_fixups_offset as usize;
            for i in 0..ofi.selector_references_fixups_count as usize {
                objc_selector_fixups.push(BindTargetRef(rd_u64(buf, sel_base + i * 8)?));
            }
            objc_fixup_info = Some(ofi);
        }

        // Unzippered twin (resolve the index against the image list later).
        let twin_index = if header.index_of_twin != NO_UNZIPPERED_TWIN {
            Some(header.index_of_twin)
        } else {
            None
        };

        // Dylib patch table: 16-byte entries until kind == endOfPatchTable.
        let mut dylib_patches = Vec::new();
        if header.patch_table_offset > 0 {
            let mut pos = base + header.patch_table_offset as usize;
            loop {
                let patch = DylibPatch::parse(buf, pos)?;
                dylib_patches.push(patch);
                pos += DYLIB_PATCH_SIZE;
                if patch.kind == DP_END_OF_PATCH_TABLE {
                    break;
                }
            }
        }

        Ok(PrebuiltLoader {
            loader,
            uuid,
            cpu_subtype,
            unused,
            header,
            path,
            alt_path,
            twin_index,
            dependents,
            file_validation,
            regions,
            bind_targets,
            dylib_patches,
            override_bind_targets,
            objc_fixup_info,
            objc_canonical_protocol_fixups,
            objc_selector_fixups,
        })
    }

    /// `GetFileOffset` (prebuilt_types.go:595) — translate a runtime VM
    /// offset into a file offset via the loader's regions.
    pub fn get_file_offset(&self, vmoffset: u64) -> u64 {
        for region in &self.regions {
            if vmoffset >= region.vm_offset() && vmoffset < region.vm_offset() + region.file_size as u64 {
                return region.file_offset as u64 + (vmoffset - region.vm_offset());
            }
        }
        0
    }
}

// ---------------------------------------------------------------------------
// prebuiltLoaderSetHeader / PrebuiltLoaderSet
// (prebuilt_types.go:725, parsed in prebuilt.go:201/255)
// ---------------------------------------------------------------------------

pub const PREBUILT_LOADER_SET_HEADER_SIZE: usize = 76; // Go binary.Size; C sizeof 80 (+4 tail pad)

pub const PBLSH_MAGIC: usize = 0x00;
pub const PBLSH_VERSION_HASH: usize = 0x04;
pub const PBLSH_LENGTH: usize = 0x08;
pub const PBLSH_LOADERS_ARRAY_COUNT: usize = 0x0C;
pub const PBLSH_LOADERS_ARRAY_OFFSET: usize = 0x10;
pub const PBLSH_CACHE_PATCH_COUNT: usize = 0x14;
pub const PBLSH_CACHE_PATCH_OFFSET: usize = 0x18;
pub const PBLSH_DYLD_CACHE_UUID_OFFSET: usize = 0x1C;
pub const PBLSH_MUST_BE_MISSING_PATHS_COUNT: usize = 0x20;
pub const PBLSH_MUST_BE_MISSING_PATHS_OFFSET: usize = 0x24;
pub const PBLSH_OBJC_SELECTOR_HASH_TABLE_OFFSET: usize = 0x28;
pub const PBLSH_OBJC_CLASS_HASH_TABLE_OFFSET: usize = 0x2C;
pub const PBLSH_OBJC_PROTOCOL_HASH_TABLE_OFFSET: usize = 0x30;
pub const PBLSH_OBJC_FLAGS: usize = 0x34;
pub const PBLSH_OBJC_PROTOCOL_CLASS_CACHE_OFFSET: usize = 0x38;
pub const PBLSH_SWIFT_TYPE_CONFORMANCE_TABLE_OFFSET: usize = 0x40;
pub const PBLSH_SWIFT_METADATA_CONFORMANCE_TABLE_OFFSET: usize = 0x44;
pub const PBLSH_SWIFT_FOREIGN_TYPE_CONFORMANCE_TABLE_OFFSET: usize = 0x48;

/// `type prebuiltLoaderSetHeader struct` — the fixed 76-byte head of a
/// loader set (the C struct pads to 80; `objcProtocolClassCacheOffset` at
/// 0x38 is already 8-aligned so there is no interior padding).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PrebuiltLoaderSetHeader {
    pub magic: u32,
    pub version_hash: u32, // PREBUILTLOADER_VERSION
    pub length: u32,
    pub loaders_array_count: u32,
    pub loaders_array_offset: u32,
    pub cache_patch_count: u32,
    pub cache_patch_offset: u32,
    pub dyld_cache_uuid_offset: u32,
    pub must_be_missing_paths_count: u32,
    pub must_be_missing_paths_offset: u32,
    pub objc_selector_hash_table_offset: u32,
    pub objc_class_hash_table_offset: u32,
    pub objc_protocol_hash_table_offset: u32,
    pub objc_flags: u32,
    pub objc_protocol_class_cache_offset: u64,
    pub swift_type_conformance_table_offset: u32,
    pub swift_metadata_conformance_table_offset: u32,
    pub swift_foreign_type_conformance_table_offset: u32,
}

impl PrebuiltLoaderSetHeader {
    pub fn parse(buf: &[u8], base: usize) -> Result<PrebuiltLoaderSetHeader, String> {
        if base + PREBUILT_LOADER_SET_HEADER_SIZE > buf.len() {
            return Err(format!(
                "dsc: buffer too small for a PrebuiltLoaderSet header: {} bytes",
                buf.len().saturating_sub(base)
            ));
        }
        Ok(PrebuiltLoaderSetHeader {
            magic: rd_u32(buf, base + PBLSH_MAGIC)?,
            version_hash: rd_u32(buf, base + PBLSH_VERSION_HASH)?,
            length: rd_u32(buf, base + PBLSH_LENGTH)?,
            loaders_array_count: rd_u32(buf, base + PBLSH_LOADERS_ARRAY_COUNT)?,
            loaders_array_offset: rd_u32(buf, base + PBLSH_LOADERS_ARRAY_OFFSET)?,
            cache_patch_count: rd_u32(buf, base + PBLSH_CACHE_PATCH_COUNT)?,
            cache_patch_offset: rd_u32(buf, base + PBLSH_CACHE_PATCH_OFFSET)?,
            dyld_cache_uuid_offset: rd_u32(buf, base + PBLSH_DYLD_CACHE_UUID_OFFSET)?,
            must_be_missing_paths_count: rd_u32(buf, base + PBLSH_MUST_BE_MISSING_PATHS_COUNT)?,
            must_be_missing_paths_offset: rd_u32(buf, base + PBLSH_MUST_BE_MISSING_PATHS_OFFSET)?,
            objc_selector_hash_table_offset: rd_u32(
                buf,
                base + PBLSH_OBJC_SELECTOR_HASH_TABLE_OFFSET,
            )?,
            objc_class_hash_table_offset: rd_u32(buf, base + PBLSH_OBJC_CLASS_HASH_TABLE_OFFSET)?,
            objc_protocol_hash_table_offset: rd_u32(
                buf,
                base + PBLSH_OBJC_PROTOCOL_HASH_TABLE_OFFSET,
            )?,
            objc_flags: rd_u32(buf, base + PBLSH_OBJC_FLAGS)?,
            objc_protocol_class_cache_offset: rd_u64(
                buf,
                base + PBLSH_OBJC_PROTOCOL_CLASS_CACHE_OFFSET,
            )?,
            swift_type_conformance_table_offset: rd_u32(
                buf,
                base + PBLSH_SWIFT_TYPE_CONFORMANCE_TABLE_OFFSET,
            )?,
            swift_metadata_conformance_table_offset: rd_u32(
                buf,
                base + PBLSH_SWIFT_METADATA_CONFORMANCE_TABLE_OFFSET,
            )?,
            swift_foreign_type_conformance_table_offset: rd_u32(
                buf,
                base + PBLSH_SWIFT_FOREIGN_TYPE_CONFORMANCE_TABLE_OFFSET,
            )?,
        })
    }

    /// `HasOptimizedObjC` (prebuilt_types.go:762).
    pub fn has_optimized_objc(&self) -> bool {
        self.objc_selector_hash_table_offset != 0
            || self.objc_class_hash_table_offset != 0
            || self.objc_protocol_hash_table_offset != 0
    }

    /// `HasOptimizedSwift` (prebuilt_types.go:765).
    pub fn has_optimized_swift(&self) -> bool {
        self.swift_foreign_type_conformance_table_offset != 0
            || self.swift_metadata_conformance_table_offset != 0
            || self.swift_type_conformance_table_offset != 0
    }
}

/// `type PrebuiltLoaderSet struct` — a parsed loader set. `Loaders` hold the
/// full `PrebuiltLoader` views (the Go `[]PrebuiltLoader`); the raw 4-byte
/// offsets from `LoadersArrayOffset` are kept in `loader_offsets` for
/// cross-referencing.
///
/// Parsed: header, loader array + every loader's variable data, cache
/// patches, dyld-cache UUID, must-be-missing paths. Skipped (future work):
/// the ObjC selector/class/protocol hash tables and the three Swift
/// conformance multimaps.
#[derive(Debug, Clone, Default)]
pub struct PrebuiltLoaderSet {
    pub header: PrebuiltLoaderSetHeader,
    pub loader_offsets: Vec<u32>,
    pub loaders: Vec<PrebuiltLoader>,
    pub patches: Vec<CachePatch>,
    /// Read from `dyld_cache_uuid_offset` when set. (Upstream reads this
    /// into a local and drops it — prebuilt.go:299-305 — so its
    /// `DyldCacheUUID` field is never populated; we keep the value.)
    pub dyld_cache_uuid: [u8; 16],
    pub must_be_missing_paths: Vec<String>,
}

/// `validate_magic` for a set header (`PrebuiltLoaderSetMagic`).
pub fn validate_magic(magic: u32) -> Result<(), String> {
    if magic != PREBUILT_LOADER_SET_MAGIC {
        return Err(format!(
            "dsc: invalid magic for PrebuiltLoaderSet: expected {:x} got {:x}",
            PREBUILT_LOADER_SET_MAGIC, magic
        ));
    }
    Ok(())
}

impl PrebuiltLoaderSet {
    /// Parse a loader set from the start of `buf`.
    pub fn parse(buf: &[u8]) -> Result<PrebuiltLoaderSet, String> {
        Self::parse_at(buf, 0)
    }

    /// Parse a loader set that begins at `base` within `buf` (all offsets in
    /// the set — loader offsets, patch offset, path offsets — are relative to
    /// `base`, exactly like the Go section reader rooted at the set).
    pub fn parse_at(buf: &[u8], base: usize) -> Result<PrebuiltLoaderSet, String> {
        let header = PrebuiltLoaderSetHeader::parse(buf, base)?;
        validate_magic(header.magic)?;

        // readPrebuiltLoaderSetHeader extent checks (prebuilt.go:209-223).
        if (header.length as usize) < PREBUILT_LOADER_SET_HEADER_SIZE
            || base + header.length as usize > buf.len()
        {
            return Err(format!(
                "dsc: invalid prebuilt loader set size {:#x}",
                header.length
            ));
        }
        let array_bytes = header.loaders_array_count as u64 * 4;
        if header.loaders_array_offset > header.length
            || array_bytes > (header.length - header.loaders_array_offset) as u64
        {
            return Err(format!(
                "dsc: prebuilt loader array offset {:#x} count {} exceeds set size {:#x}",
                header.loaders_array_offset, header.loaders_array_count, header.length
            ));
        }

        // The u32 loader-offset array…
        let mut loader_offsets = Vec::with_capacity(header.loaders_array_count as usize);
        for i in 0..header.loaders_array_count as usize {
            loader_offsets.push(rd_u32(buf, base + header.loaders_array_offset as usize + i * 4)?);
        }
        // …and the loaders it points at.
        let mut loaders = Vec::with_capacity(loader_offsets.len());
        for &lo in &loader_offsets {
            if lo as usize >= header.length as usize {
                return Err(format!(
                    "dsc: prebuilt loader offset {lo:#x} exceeds set size {:#x}",
                    header.length
                ));
            }
            loaders.push(PrebuiltLoader::parse(buf, base + lo as usize)?);
        }

        // Cache patches (16 bytes each). NOTE: upstream has a FIXME that
        // these values look bogus for /usr/bin/abmlite — we just parse them.
        let mut patches = Vec::new();
        if header.cache_patch_count > 0 {
            for i in 0..header.cache_patch_count as usize {
                patches.push(CachePatch::parse(
                    buf,
                    base + header.cache_patch_offset as usize + i * CACHE_PATCH_SIZE,
                )?);
            }
        }

        // Dyld cache UUID (see field doc for the upstream quirk).
        let mut dyld_cache_uuid = [0u8; 16];
        if header.dyld_cache_uuid_offset > 0 {
            let off = base + header.dyld_cache_uuid_offset as usize;
            if off + 16 > buf.len() {
                return Err("dsc: prebuilt loader set dyld cache uuid truncated".into());
            }
            dyld_cache_uuid.copy_from_slice(&buf[off..off + 16]);
        }

        // Must-be-missing paths: NUL-terminated strings, one per count.
        let mut must_be_missing_paths = Vec::new();
        if header.must_be_missing_paths_count > 0 {
            let mut pos = base + header.must_be_missing_paths_offset as usize;
            for _ in 0..header.must_be_missing_paths_count {
                let s = rd_cstr(buf, pos)?;
                pos += s.len() + 1;
                must_be_missing_paths.push(s);
            }
        }

        // Data-integrity guard from prebuilt.go:321 — objc tables require at
        // least one loader.
        if loaders.is_empty()
            && (header.objc_selector_hash_table_offset > 0
                || header.objc_class_hash_table_offset > 0
                || header.objc_protocol_hash_table_offset > 0)
        {
            return Err(format!(
                "dsc: prebuilt objc table requires at least one loader \
                 (LoadersArrayCount={}, ObjcSelectorHashTableOffset={:#x}, \
                 ObjcClassHashTableOffset={:#x}, ObjcProtocolHashTableOffset={:#x})",
                header.loaders_array_count,
                header.objc_selector_hash_table_offset,
                header.objc_class_hash_table_offset,
                header.objc_protocol_hash_table_offset
            ));
        }

        // Skipped: ObjCSelectorOpt/ObjCClassOpt tables (gated in Go on
        // `!Loaders[0].HasUUIDLoadCommand()`) and the Swift conformance
        // multimaps — see module docs.

        Ok(PrebuiltLoaderSet {
            header,
            loader_offsets,
            loaders,
            patches,
            dyld_cache_uuid,
            must_be_missing_paths,
        })
    }
}

// ---------------------------------------------------------------------------
// program trie (prebuilt.go:16/26/101 — SupportsProgramTrie,
// ForEachLaunchLoaderSet, GetLaunchLoaderSet)
// ---------------------------------------------------------------------------

/// Cache-header gate for the program trie (`SupportsProgramTrie`): the
/// header must be new enough to carry `ProgramTrieSize` (field at 0x170) and
/// `ProgramTrieAddr` must be non-zero.
pub fn supports_program_trie(mapping_offset: u32, program_trie_addr: u64) -> bool {
    mapping_offset >= 0x170 && program_trie_addr != 0
}

/// Cache-header gate for the dylib PrebuiltLoaderSet
/// (`SupportsDylibPrebuiltLoader`): header carries `ProgramTrieSize` (0x170)
/// and `DylibsPblSetAddr` (0x150), and `DylibsPblSetAddr` is non-zero.
pub fn supports_dylib_prebuilt_loader(mapping_offset: u32, dylibs_pbl_set_addr: u64) -> bool {
    mapping_offset >= 0x170 && mapping_offset >= 0x150 && dylibs_pbl_set_addr != 0
}

/// One terminal trie entry: an exec path and its uleb128 value — the offset
/// into the programs-pbl-set pool (`ProgramsPblSetPoolAddr + value`), i.e.
/// what `ForEachLaunchLoaderSet` reads at `node.Offset`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrieEntry {
    pub path: String,
    pub value: u64,
    /// Byte offset of the uleb128 value inside the trie blob (Go `node.Offset`).
    pub value_offset: usize,
}

/// ULEB128 reader (go-macho `trie.ReadUleb128`).
pub fn read_uleb128(buf: &[u8], pos: &mut usize) -> Result<u64, String> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    loop {
        let byte = *buf
            .get(*pos)
            .ok_or_else(|| format!("dsc: uleb128 truncated at {:#x}", *pos))?;
        *pos += 1;
        result |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 63 {
            return Err("dsc: uleb128 too large".into());
        }
    }
    Ok(result)
}

fn read_cstr_bytes(buf: &[u8], pos: &mut usize) -> Result<Vec<u8>, String> {
    let start = *pos;
    loop {
        match buf.get(*pos) {
            Some(&0) => {
                let s = buf[start..*pos].to_vec();
                *pos += 1;
                return Ok(s);
            }
            Some(_) => *pos += 1,
            None => return Err(format!("dsc: trie edge string unterminated at {start:#x}")),
        }
    }
}

/// Trie node as emitted by dyld's cache-trie builder (the format shared by
/// the program/dylibs/other/prog-closures tries; reconstructed from dyld's
/// trie walker and ipsw's use of `trie.ParseTrie`/`trie.WalkTrie` —
/// round-trip verified by the tests here):
///
/// ```text
/// node:
///   edge cstring (NUL terminated)
///   terminal byte T        (0 = non-terminal; else size in bytes of the
///                           terminal data that follows)
///   [T bytes terminal data — for cache tries: one uleb128 value]
///   uleb128 childCount
///   childCount × { uleb128 childOffset; child edge cstring (NUL terminated) }
/// ```
fn trie_node_at(
    buf: &[u8],
    offset: usize,
    cumulative: &str,
    out: &mut Vec<TrieEntry>,
    visited: &mut std::collections::HashSet<usize>,
) -> Result<(), String> {
    if offset >= buf.len() {
        return Err(format!("dsc: trie node offset {offset:#x} out of range"));
    }
    if !visited.insert(offset) {
        return Ok(()); // dyld/llvm track seen nodes to survive corrupt tries
    }
    let mut pos = offset;
    let edge = read_cstr_bytes(buf, &mut pos)?;
    let path = format!(
        "{cumulative}{}",
        String::from_utf8_lossy(&edge)
    );
    let terminal_size = buf[pos];
    pos += 1;
    if terminal_size != 0 {
        let value_offset = pos;
        let value = read_uleb128(buf, &mut pos)?;
        out.push(TrieEntry {
            path: path.clone(),
            value,
            value_offset,
        });
        pos = value_offset + terminal_size as usize; // stride by the declared size
    }
    let child_count = read_uleb128(buf, &mut pos)?;
    for _ in 0..child_count {
        let child_offset = read_uleb128(buf, &mut pos)? as usize;
        // The parent-listed edge is read to advance the stream but NOT
        // appended to the path: every node repeats its own edge cstring at
        // its start, and that self-edge is what trie_node_at appends
        // (`path = cumulative + own_edge`). Appending both duplicates each
        // path segment (/usr/bin//usr/bin/foo…).
        let _child_edge = read_cstr_bytes(buf, &mut pos)?;
        trie_node_at(buf, child_offset, &path, out, visited)?;
    }
    Ok(())
}

/// Parse every terminal entry of a cache trie
/// (`trie.ParseTrie` + the per-node uleb read in `ForEachLaunchLoaderSet`).
pub fn parse_program_trie(trie: &[u8]) -> Result<Vec<TrieEntry>, String> {
    let mut out = Vec::new();
    let mut visited = std::collections::HashSet::new();
    trie_node_at(trie, 0, "", &mut out, &mut visited)?;
    Ok(out)
}

/// Walk the trie for `path` and return its pool-offset value
/// (`trie.WalkTrie` + `trie.ReadUleb128` from `GetLaunchLoaderSet`).
pub fn walk_program_trie(trie: &[u8], path: &str) -> Result<u64, String> {
    let mut offset = 0usize;
    let mut cumulative = String::new();
    loop {
        if offset >= trie.len() {
            return Err(format!("dsc: trie node offset {offset:#x} out of range"));
        }
        let mut pos = offset;
        let edge = String::from_utf8_lossy(&read_cstr_bytes(trie, &mut pos)?).into_owned();
        cumulative.push_str(&edge);
        let terminal_size = trie[pos];
        pos += 1;
        if terminal_size != 0 {
            let value_offset = pos;
            let value = read_uleb128(trie, &mut pos)?;
            if cumulative == path {
                return Ok(value);
            }
            pos = value_offset + terminal_size as usize;
        }
        let child_count = read_uleb128(trie, &mut pos)?;
        let mut next = None;
        for _ in 0..child_count {
            let child_offset = read_uleb128(trie, &mut pos)? as usize;
            let child_edge =
                String::from_utf8_lossy(&read_cstr_bytes(trie, &mut pos)?).into_owned();
            if path.as_bytes()[cumulative.len().min(path.len())..]
                .starts_with(child_edge.as_bytes())
            {
                next = Some((child_offset, child_edge));
            }
        }
        match next {
            // NOTE: do NOT push the parent-listed edge here — the child
            // node repeats its own edge cstring, which the loop head appends
            // (`cumulative.push_str(&edge)`); pushing both doubles segments.
            Some((child_offset, _)) => {
                offset = child_offset;
            }
            None => {
                return Err(format!(
                    "could not find executable {path} in the ProgramTrie"
                ))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// layout sanity asserts (Go has no unsafe.Sizeof asserts in these files; pin
// our documented constants so a refactor cannot silently move a field)
// ---------------------------------------------------------------------------

const _: () = assert!(LOADER_SIZE == 8);
const _: () = assert!(PREBUILT_LOADER_SET_HEADER_SIZE == 76);
const _: () = assert!(PREBUILT_LOADER_HEADER_SIZE == 416);
const _: () = assert!(SECTION_LOCATIONS_SIZE == 344);
const _: () = assert!(FILE_VALIDATION_SIZE == 54);
const _: () = assert!(OBJC_BINARY_INFO_SIZE == 76);
const _: () = assert!(CACHE_PATCH_SIZE == 16);
const _: () = assert!(DYLIB_PATCH_SIZE == 16);
const _: () = assert!(REGION_SIZE == 16);
const _: () = assert!(DYLD_SECTION_LOCATION_COUNT == 21);
const _: () = assert!(PBLH_SECTIONS + SECTION_LOCATIONS_SIZE == PREBUILT_LOADER_HEADER_SIZE);

#[cfg(test)]
mod tests {
    use super::*;

    fn w16(v: &mut [u8], off: usize, val: u16) {
        v[off..off + 2].copy_from_slice(&val.to_le_bytes());
    }
    fn w32(v: &mut [u8], off: usize, val: u32) {
        v[off..off + 4].copy_from_slice(&val.to_le_bytes());
    }
    fn w64(v: &mut [u8], off: usize, val: u64) {
        v[off..off + 8].copy_from_slice(&val.to_le_bytes());
    }
    fn wb(v: &mut [u8], off: usize, bytes: &[u8]) {
        v[off..off + bytes.len()].copy_from_slice(bytes);
    }
    fn wcstr(v: &mut [u8], off: usize, s: &str) -> usize {
        wb(v, off, s.as_bytes());
        v[off + s.len()] = 0;
        off + s.len() + 1
    }

    #[test]
    fn loader_ref_bits() {
        let r = LoaderRef(0x8123);
        assert_eq!(r.index(), 0x0123);
        assert!(r.is_app());
        assert!(!r.is_missing_weak_image());

        let missing = LoaderRef(0x7FFF);
        assert_eq!(missing.index(), 0x7FFF);
        assert!(!missing.is_app());
        assert!(missing.is_missing_weak_image());

        let app_max = LoaderRef(0xFFFF);
        assert!(app_max.is_app());
        assert!(!app_max.is_missing_weak_image()); // app bit set

        assert_eq!(format!("{missing}"), "index: 32767 (missing weak image)");
        assert_eq!(format!("{app_max}"), "index: 32767, type: app");
    }

    #[test]
    fn loader_info_all_bits() {
        // every documented bit + the 2 padding bits
        let info = LoaderInfo(0xFFFF);
        assert!(info.is_prebuilt());
        assert!(info.dylib_in_dyld_cache());
        assert!(info.has_objc());
        assert!(info.may_have_plus_load());
        assert!(info.has_read_only_data());
        assert!(info.never_unload());
        assert!(info.leave_mapped());
        assert!(info.has_read_only_objc());
        assert!(info.pre2022_binary());
        assert!(info.is_premapped());
        assert!(info.has_uuid_load_command());
        assert!(info.has_weak_defs());
        assert!(info.has_tlvs());
        assert!(info.below_lib_system());
        assert_eq!(info.padding(), 0b11);
        assert_eq!(info.padding(), 3);

        assert!(!LoaderInfo(0).is_prebuilt());
        assert_eq!(LoaderInfo(0).flags_str(), "jit");
        // flags_str mirrors the Go String() list order
        let f = LoaderInfo((1 << 0) | (1 << 2) | (1 << 12));
        assert_eq!(f.flags_str(), "prebuilt|objc|tlvs");
    }

    #[test]
    fn loader_parse_and_display() {
        // 12 bytes = exactly the 8-byte Loader prefix at 0 plus 4 slack,
        // so `parse(buf, 8)` (needing bytes 8..16) is genuinely past-end.
        let mut buf = vec![0u8; 12];
        w32(&mut buf, 0, LOADER_MAGIC);
        w16(&mut buf, 4, (1 << 0) | (1 << 1) | (1 << 10));
        w16(&mut buf, 6, 0x0005);
        let l = Loader::parse(&buf, 0).unwrap();
        assert_eq!(l.magic, LOADER_MAGIC);
        assert!(l.info.is_prebuilt());
        assert!(l.info.dylib_in_dyld_cache());
        assert!(l.info.has_uuid_load_command());
        assert_eq!(l.r#ref.index(), 5);
        assert_eq!(format!("{l}"), "prebuilt|in-cache-dylib|uuid-load-cmd, ref: index: 5");

        assert!(Loader::parse(&buf, 8).is_err()); // past end
    }

    #[test]
    fn bind_target_ref_kinds() {
        // absolute: bit63 set, bit62 propagates through deserialize
        let abs = BindTargetRef(0xC000_0000_0000_0000);
        assert!(abs.is_absolute());
        assert_eq!(abs.kind(), 1);
        assert_eq!(abs.absolute_value(), 0xC000_0000_0000_0000);
        assert_eq!(abs.offset(), 0xC000_0000_0000_0000);

        let abs_pos = BindTargetRef(0x0000_0000_0000_1234);
        assert!(!abs_pos.is_absolute()); // kind bit clear
        assert_eq!(abs_pos.absolute_value(), 0x1234);

        // image-relative: high8 (bits16..24) + sign-extended low39 (bits24..63)
        let raw = (0x1234u64 << 24) | (0x56u64 << 16) | 0x0002;
        let rel = BindTargetRef(raw);
        assert!(!rel.is_absolute());
        assert_eq!(rel.kind(), 0);
        assert_eq!(rel.loader_ref().index(), 2);
        assert!(!rel.loader_ref().is_app());
        assert_eq!(rel.high8(), 0x56);
        assert_eq!(rel.low39(), 0x1234);
        assert_eq!(rel.offset(), 0x5600_0000_0000_1234);

        // negative offset: bit 38 of the 39-bit field set => sign extension
        let neg = BindTargetRef((0x40_0000_0000u64 << 24) | (0x7Fu64 << 16) | 0x0001);
        assert_eq!(neg.low39(), 0x40_0000_0000); // 0x40_0000_0000 == 1 << 38
        // exact expectation computed per Go:
        let mut signed = 0x40_0000_0000u64;
        if signed & 0x0000_0040_0000_0000 != 0 {
            signed |= 0x00FF_FF80_0000_0000;
        }
        assert_eq!(neg.offset(), (0x7Fu64 << 56) | signed);
        assert_eq!(neg.offset(), 0x7FFF_FFC0_0000_0000);

        assert_eq!(deserialize_absolute_value(0x4000_0000_0000_0000), 0xC000_0000_0000_0000);
        assert_eq!(deserialize_absolute_value(1), 1);
    }

    #[test]
    fn region_bits() {
        let mut buf = vec![0u8; 32];
        let info = 0x1000u64 | (5u64 << 59) | (1u64 << 63);
        w64(&mut buf, 0, info);
        w32(&mut buf, 8, 0x1_0000);
        w32(&mut buf, 12, 0x4_0000);
        let r = Region::parse(&buf, 0).unwrap();
        assert_eq!(r.vm_offset(), 0x1000);
        assert_eq!(r.perms().as_str(), "r-x");
        assert!(!r.is_zero_fill());
        assert!(r.read_only_data());
        assert_eq!(r.file_offset, 0x1_0000);
        assert_eq!(r.file_size, 0x4_0000);

        let zf = Region {
            info: 1u64 << 62,
            file_offset: 0,
            file_size: 0,
        };
        assert!(zf.is_zero_fill());
    }

    #[test]
    fn file_validation_layout() {
        let mut buf = vec![0u8; 64];
        w64(&mut buf, 0x00, 0x1000); // slice offset
        w64(&mut buf, 0x08, 0x2000); // device id
        w64(&mut buf, 0x10, 0x3000); // inode
        w64(&mut buf, 0x18, 0x4000); // mtime
        for i in 0..20 {
            buf[0x20 + i] = i as u8;
        }
        buf[0x34] = 1; // check inode/mtime
        buf[0x35] = 1; // check cdhash
        let fv = FileValidation::parse(&buf, 0).unwrap();
        assert_eq!(fv.slice_offset, 0x1000);
        assert_eq!(fv.device_id, 0x2000);
        assert_eq!(fv.inode, 0x3000);
        assert_eq!(fv.mtime, 0x4000);
        assert_eq!(fv.cd_hash[19], 19);
        assert!(fv.check_inode_mtime);
        assert!(fv.check_cd_hash);
        assert_eq!(FILE_VALIDATION_SIZE, 54);
    }

    #[test]
    fn dyld_section_location_kinds_and_names() {
        assert_eq!(DYLD_SECTION_LOCATION_COUNT, 21);
        assert_eq!(
            DyldSectionLocationKind::from_u32(0).unwrap().as_str(),
            "text_swift5_protos"
        );
        assert_eq!(
            DyldSectionLocationKind::from_u32(5).unwrap().as_str(),
            "text_swift5_ac_funcs"
        );
        assert_eq!(
            DyldSectionLocationKind::from_u32(6).unwrap().as_str(),
            "objc_image_info"
        );
        assert_eq!(
            DyldSectionLocationKind::from_u32(7).unwrap().as_str(),
            "data_sel_refs"
        );
        assert_eq!(
            DyldSectionLocationKind::from_u32(20).unwrap().as_str(),
            "data_raw_isa"
        );
        assert!(DyldSectionLocationKind::from_u32(21).is_none()); // == count

        let mut sl = SectionLocations::default();
        sl.version = 1;
        sl.offsets[0] = 0x100;
        sl.sizes[0] = 0x10;
        sl.offsets[6] = 0x200;
        sl.sizes[6] = 0x40;
        let locs: Vec<DyldSectionLocation> = sl.locations().collect();
        assert_eq!(locs.len(), 2);
        assert_eq!(locs[0].kind, DyldSectionLocationKind::TextSwift5Protos);
        assert_eq!(locs[0].offset, 0x100);
        assert_eq!(locs[0].size, 0x10);
        assert_eq!(locs[1].kind, DyldSectionLocationKind::ObjcImageInfo);
    }

    #[test]
    fn section_locations_roundtrip() {
        let mut buf = vec![0u8; 0x200];
        w32(&mut buf, 0, 1); // version
        w32(&mut buf, 4, 0); // flags
        w64(&mut buf, 8 + 7 * 8, 0xAAAA); // offsets[7] (data_sel_refs)
        w64(&mut buf, 8 + 21 * 8 + 7 * 8, 0x30); // sizes[7]
        let sl = SectionLocations::parse(&buf, 0).unwrap();
        assert_eq!(sl.version, 1);
        assert_eq!(sl.offsets[7], 0xAAAA);
        assert_eq!(sl.sizes[7], 0x30);
        assert_eq!(SECTION_LOCATIONS_SIZE, 344);
    }

    #[test]
    fn prebuilt_loader_header_layout() {
        // 416-byte header at 0x40 inside a scratch buffer; every field gets a
        // unique value so wrong offsets cannot alias.
        let hdr_off = 0x40;
        let mut buf = vec![0u8; hdr_off + PREBUILT_LOADER_HEADER_SIZE + 8];
        w16(&mut buf, hdr_off + PBLH_PATH_OFFSET, 0x1111);
        w16(&mut buf, hdr_off + PBLH_DEP_REFS_ARRAY_OFFSET, 0x2222);
        w16(&mut buf, hdr_off + PBLH_DEP_KINDS_ARRAY_OFFSET, 0x3333);
        w16(&mut buf, hdr_off + PBLH_FIXUPS_LOAD_COMMAND_OFFSET, 0x4444);
        w16(&mut buf, hdr_off + PBLH_ALT_PATH_OFFSET, 0x5555);
        w16(&mut buf, hdr_off + PBLH_FILE_VALIDATION_OFFSET, 0x6666);
        w16(&mut buf, hdr_off + PBLH_INFO, 0x0022); // isOverridable(bit1) + regionsCount=2 (bits4..16), no initializers
        w16(&mut buf, hdr_off + PBLH_REGIONS_OFFSET, 0x7777);
        w16(&mut buf, hdr_off + PBLH_DEP_COUNT, 4);
        w16(&mut buf, hdr_off + PBLH_BIND_TARGET_REFS_OFFSET, 0x8888);
        w32(&mut buf, hdr_off + PBLH_BIND_TARGET_REFS_COUNT, 9);
        w32(&mut buf, hdr_off + PBLH_OBJC_BINARY_INFO_OFFSET, 0xAAAA_AAAA);
        w16(&mut buf, hdr_off + PBLH_INDEX_OF_TWIN, 0x0007);
        w64(&mut buf, hdr_off + PBLH_EXPORTS_TRIE_OFFSET, 0x1000);
        w32(&mut buf, hdr_off + PBLH_EXPORTS_TRIE_SIZE, 0x200);
        w32(&mut buf, hdr_off + PBLH_VM_SIZE, 0x4_0000);
        w32(&mut buf, hdr_off + PBLH_CODE_SIGNATURE_FILE_OFFSET, 0x3_0000);
        w32(&mut buf, hdr_off + PBLH_CODE_SIGNATURE_SIZE, 0x1000);
        w32(&mut buf, hdr_off + PBLH_PATCH_TABLE_OFFSET, 0xBBBB_BBBB);
        w32(&mut buf, hdr_off + PBLH_OVERRIDE_BIND_TARGET_REFS_OFFSET, 0xCCCC_CCCC);
        w32(&mut buf, hdr_off + PBLH_OVERRIDE_BIND_TARGET_REFS_COUNT, 2);
        w32(&mut buf, hdr_off + PBLH_SECTIONS, 1); // sections.version
        w64(&mut buf, hdr_off + PBLH_SECTIONS + 8, 0x100); // sections.offsets[0]

        let h = PrebuiltLoaderHeader::parse(&buf, hdr_off).unwrap();
        assert_eq!(h.path_offset, 0x1111);
        assert_eq!(h.dependent_loader_refs_array_offset, 0x2222);
        assert_eq!(h.dependent_kind_array_offset, 0x3333);
        assert_eq!(h.fixups_load_command_offset, 0x4444);
        assert_eq!(h.alt_path_offset, 0x5555);
        assert_eq!(h.file_validation_offset, 0x6666);
        assert!(!h.info.has_initializers());
        assert!(h.info.is_overridable());
        assert!(!h.info.supports_catalyst());
        assert!(!h.info.is_catalyst_override());
        assert_eq!(h.info.regions_count(), 2);
        assert_eq!(h.regions_offset, 0x7777);
        assert_eq!(h.dep_count, 4);
        assert_eq!(h.bind_target_refs_offset, 0x8888);
        assert_eq!(h.bind_target_refs_count, 9);
        assert_eq!(h.objc_binary_info_offset, 0xAAAA_AAAA);
        assert_eq!(h.index_of_twin, 7);
        assert_eq!(h.exports_trie.offset, 0x1000);
        assert_eq!(h.exports_trie.size, 0x200);
        assert_eq!(h.vm_size, 0x4_0000);
        assert_eq!(h.code_signature.file_offset, 0x3_0000);
        assert_eq!(h.code_signature.size, 0x1000);
        assert_eq!(h.patch_table_offset, 0xBBBB_BBBB);
        assert_eq!(h.override_bind_target_refs_offset, 0xCCCC_CCCC);
        assert_eq!(h.override_bind_target_refs_count, 2);
        assert_eq!(h.sections.version, 1);
        assert_eq!(h.sections.offsets[0], 0x100);

        // padding fields exist at 0x1E / 0x44 and do not disturb neighbors
        w16(&mut buf, hdr_off + PBLH_PAD, 0xDEAD);
        w32(&mut buf, hdr_off + PBLH_PAD2, 0xBEEF);
        let h2 = PrebuiltLoaderHeader::parse(&buf, hdr_off).unwrap();
        assert_eq!(h2.index_of_twin, 7); // untouched by the pad write
        assert_eq!(h2.override_bind_target_refs_offset, 0xCCCC_CCCC);

        assert_eq!(PBLH_SECTIONS + SECTION_LOCATIONS_SIZE, PREBUILT_LOADER_HEADER_SIZE);
    }

    #[test]
    fn objc_binary_info_layout() {
        let mut buf = vec![0u8; 96];
        w64(&mut buf, 0x00, 0x4000);
        w64(&mut buf, 0x08, 0x4080);
        w64(&mut buf, 0x10, 0x4100);
        w64(&mut buf, 0x18, 0x4180);
        w64(&mut buf, 0x20, 0x4200);
        w32(&mut buf, 0x28, 3);
        w32(&mut buf, 0x2C, 2);
        w32(&mut buf, 0x30, 1);
        w32(&mut buf, 0x34, 4);
        for i in 0..8 {
            buf[0x38 + i] = ((i + 1) % 2) as u8; // 1,0,1,0… — matches the true/false assert pattern
        }
        w32(&mut buf, 0x40, 0x90);
        w32(&mut buf, 0x44, 0x94);
        w32(&mut buf, 0x48, 5);
        let o = ObjCBinaryInfo::parse(&buf, 0).unwrap();
        assert_eq!(o.image_info_runtime_offset, 0x4000);
        assert_eq!(o.sel_refs_runtime_offset, 0x4080);
        assert_eq!(o.class_list_runtime_offset, 0x4100);
        assert_eq!(o.category_list_runtime_offset, 0x4180);
        assert_eq!(o.protocol_list_runtime_offset, 0x4200);
        assert_eq!(o.sel_refs_count, 3);
        assert_eq!(o.class_list_count, 2);
        assert_eq!(o.category_count, 1);
        assert_eq!(o.protocol_list_count, 4);
        assert!(o.has_class_stable_swift_fixups);
        assert!(!o.has_class_method_lists_to_set_uniqued);
        assert!(o.has_category_method_lists_to_set_uniqued);
        assert!(!o.has_protocol_method_lists_to_set_uniqued);
        assert!(o.has_class_method_lists_to_unique);
        assert!(!o.has_category_method_lists_to_unique);
        assert!(o.has_protocol_method_lists_to_unique);
        assert!(!o.padding);
        assert_eq!(o.protocol_fixups_offset, 0x90);
        assert_eq!(o.selector_references_fixups_offset, 0x94);
        assert_eq!(o.selector_references_fixups_count, 5);
        assert_eq!(OBJC_BINARY_INFO_SIZE, 76);
    }

    #[test]
    fn cache_patch_and_dylib_patch() {
        let mut buf = vec![0u8; 48];
        w32(&mut buf, 0, 7);
        w32(&mut buf, 4, 0x2000);
        w64(&mut buf, 8, 0xC000_0000_0000_0000);
        let p = CachePatch::parse(&buf, 0).unwrap();
        assert_eq!(p.dylib_index, 7);
        assert_eq!(p.dylib_vm_offset, 0x2000);
        assert!(p.patch_to.is_absolute());
        assert_eq!(p.patch_to.absolute_value(), 0xC000_0000_0000_0000);

        w64(&mut buf, 16, 0xFFFF_FFFF_FFFF_FFFC); // i64 -4
        w64(&mut buf, 24, 0xFFFF_FFFF_FFFF_FFFF); // i64 -1 = endOfPatchTable
        let dp = DylibPatch::parse(&buf, 16).unwrap();
        assert_eq!(dp.override_offset_of_impl, -4);
        assert_eq!(dp.kind, DP_END_OF_PATCH_TABLE);

        // a positive kind reads back verbatim
        let mut buf2 = vec![0u8; 16];
        w64(&mut buf2, 0, 0x1234);
        w64(&mut buf2, 8, DP_MISSING_WEAK_IMPORT as u64);
        let dp2 = DylibPatch::parse(&buf2, 0).unwrap();
        assert_eq!(dp2.override_offset_of_impl, 0x1234);
        assert_eq!(dp2.kind, DP_MISSING_WEAK_IMPORT);
    }

    #[test]
    fn dependent_kind_names() {
        assert_eq!(DependentKind::Normal.as_str(), "regular");
        assert_eq!(DependentKind::WeakLink.as_str(), "weak-link");
        assert_eq!(DependentKind::Reexport.as_str(), "re-export");
        assert_eq!(DependentKind::Upward.as_str(), "upward");
        assert_eq!(DependentKind::Delayed.as_str(), "delay-init");
        assert!(DependentKind::from_u8(3).is_none());
        assert!(DependentKind::from_u8(KIND_UPWARD).is_some());
    }

    #[test]
    fn prebuilt_loader_set_parse() {
        // Fully synthetic PrebuiltLoaderSet with 3 loaders exercising every
        // parsed sub-structure. Offsets are chosen to leave room; all header
        // offsets inside loaders are loader-relative, as on disk.
        const LEN: usize = 0x810;
        let mut buf = vec![0u8; LEN];

        // ---- set header (76 bytes) ----
        w32(&mut buf, PBLSH_MAGIC, PREBUILT_LOADER_SET_MAGIC);
        w32(&mut buf, PBLSH_VERSION_HASH, 0x2023_0101);
        w32(&mut buf, PBLSH_LENGTH, LEN as u32);
        w32(&mut buf, PBLSH_LOADERS_ARRAY_COUNT, 3);
        w32(&mut buf, PBLSH_LOADERS_ARRAY_OFFSET, 0x4C);
        w32(&mut buf, PBLSH_CACHE_PATCH_COUNT, 1);
        w32(&mut buf, PBLSH_CACHE_PATCH_OFFSET, 0x7B0);
        w32(&mut buf, PBLSH_DYLD_CACHE_UUID_OFFSET, 0x7C0);
        w32(&mut buf, PBLSH_MUST_BE_MISSING_PATHS_COUNT, 2);
        w32(&mut buf, PBLSH_MUST_BE_MISSING_PATHS_OFFSET, 0x7D0);
        // objc/swift table offsets stay 0

        // ---- loader offset array @0x4C ----
        w32(&mut buf, 0x4C + 0, 0x80);
        w32(&mut buf, 0x4C + 4, 0x300);
        w32(&mut buf, 0x4C + 8, 0x600);

        // ================= loader 0 @0x80 (uuid prefix) =================
        const L0: usize = 0x80;
        w32(&mut buf, L0, LOADER_MAGIC);
        w16(&mut buf, L0 + 4, (1 << 0) | (1 << 1) | (1 << 10) | (1 << 11)); // prebuilt|in-cache|uuid|weak-defs
        w16(&mut buf, L0 + 6, 0x0000);
        for i in 0..16 {
            buf[L0 + 8 + i] = 0x11;
        }
        w32(&mut buf, L0 + 24, 0x0000_000C); // cpu subtype (arm64)
        w32(&mut buf, L0 + 28, 0); // unused
        let h0 = L0 + 32; // header @0xA0

        w16(&mut buf, h0 + PBLH_PATH_OFFSET, 0x1C0); // L0+0x240
        w16(&mut buf, h0 + PBLH_DEP_REFS_ARRAY_OFFSET, 0x1D0); // L0+0x250
        w16(&mut buf, h0 + PBLH_DEP_KINDS_ARRAY_OFFSET, 0x1D8); // L0+0x258
        w16(&mut buf, h0 + PBLH_FIXUPS_LOAD_COMMAND_OFFSET, 0x1234);
        w16(&mut buf, h0 + PBLH_ALT_PATH_OFFSET, 0);
        w16(&mut buf, h0 + PBLH_FILE_VALIDATION_OFFSET, 0x200); // loader-relative → fv struct at L0+0x200
        w16(&mut buf, h0 + PBLH_INFO, (1 << 0) | (1 << 1) | (1 << 4)); // initializers|overridable|regions=1
        w16(&mut buf, h0 + PBLH_REGIONS_OFFSET, 0x1E0); // L0+0x260
        w16(&mut buf, h0 + PBLH_DEP_COUNT, 2);
        w16(&mut buf, h0 + PBLH_BIND_TARGET_REFS_OFFSET, 0x1F0); // L0+0x270
        w32(&mut buf, h0 + PBLH_BIND_TARGET_REFS_COUNT, 1);
        w32(&mut buf, h0 + PBLH_OBJC_BINARY_INFO_OFFSET, 0);
        w16(&mut buf, h0 + PBLH_INDEX_OF_TWIN, NO_UNZIPPERED_TWIN);
        w64(&mut buf, h0 + PBLH_EXPORTS_TRIE_OFFSET, 0x1000);
        w32(&mut buf, h0 + PBLH_EXPORTS_TRIE_SIZE, 0x200);
        w32(&mut buf, h0 + PBLH_VM_SIZE, 0x4_0000);
        w32(&mut buf, h0 + PBLH_CODE_SIGNATURE_FILE_OFFSET, 0x3_0000);
        w32(&mut buf, h0 + PBLH_CODE_SIGNATURE_SIZE, 0x1000);
        w32(&mut buf, h0 + PBLH_PATCH_TABLE_OFFSET, 0);
        w32(&mut buf, h0 + PBLH_SECTIONS, 1); // version
        w64(&mut buf, h0 + PBLH_SECTIONS + 8, 0x100); // offsets[0]
        w64(&mut buf, h0 + PBLH_SECTIONS + 8 + 7 * 8, 0x200); // offsets[7] sel_refs
        w64(&mut buf, h0 + PBLH_SECTIONS + 8 + 21 * 8 + 7 * 8, 0x40); // sizes[7]

        // loader-relative variable data
        wcstr(&mut buf, L0 + 0x1C0, "/usr/bin/foo");
        w16(&mut buf, L0 + 0x1D0, 0x0002);
        w16(&mut buf, L0 + 0x1D2, 0x8005);
        buf[L0 + 0x1D8] = KIND_NORMAL;
        buf[L0 + 0x1D9] = KIND_DELAYED;
        let region_info = 0x1000u64 | (5u64 << 59) | (1u64 << 63);
        w64(&mut buf, L0 + 0x1E0, region_info);
        w32(&mut buf, L0 + 0x1E8, 0);
        w32(&mut buf, L0 + 0x1EC, 0x4_0000);
        let bt = (0x1234u64 << 24) | (0x56u64 << 16) | 0x0002;
        w64(&mut buf, L0 + 0x1F0, bt);
        // file validation @L0+0x200 (must fit before loader 1 @0x300 — the
        // 54-byte struct at 0x280 would overlap the next loader)
        w64(&mut buf, L0 + 0x200, 0x1000);
        w64(&mut buf, L0 + 0x208, 0x2000);
        w64(&mut buf, L0 + 0x210, 0x3000);
        w64(&mut buf, L0 + 0x218, 0x4000);
        for i in 0..20 {
            buf[L0 + 0x220 + i] = 0xA0 + i as u8;
        }
        buf[L0 + 0x234] = 1;
        buf[L0 + 0x235] = 1;

        // ================= loader 1 @0x300 (no uuid; objc + patches + twin) ====
        const L1: usize = 0x300;
        w32(&mut buf, L1, LOADER_MAGIC);
        w16(&mut buf, L1 + 4, 1 << 0); // prebuilt only
        w16(&mut buf, L1 + 6, 0x0003);
        let h1 = L1 + 8; // header @0x308 (no uuid prefix)

        w16(&mut buf, h1 + PBLH_PATH_OFFSET, 0x1C0); // L1+0x4C0
        w16(&mut buf, h1 + PBLH_DEP_REFS_ARRAY_OFFSET, 0);
        w16(&mut buf, h1 + PBLH_DEP_KINDS_ARRAY_OFFSET, 0);
        w16(&mut buf, h1 + PBLH_ALT_PATH_OFFSET, 0x1E0); // L1+0x4E0
        w16(&mut buf, h1 + PBLH_INFO, 0); // zero regions
        w16(&mut buf, h1 + PBLH_BIND_TARGET_REFS_OFFSET, 0x200); // L1+0x500
        w32(&mut buf, h1 + PBLH_BIND_TARGET_REFS_COUNT, 2);
        w32(&mut buf, h1 + PBLH_OBJC_BINARY_INFO_OFFSET, 0x240); // L1+0x540
        w16(&mut buf, h1 + PBLH_INDEX_OF_TWIN, 5);
        w32(&mut buf, h1 + PBLH_VM_SIZE, 0x8000);
        w32(&mut buf, h1 + PBLH_PATCH_TABLE_OFFSET, 0x2B0); // L1+0x5B0
        w32(&mut buf, h1 + PBLH_OVERRIDE_BIND_TARGET_REFS_OFFSET, 0x290); // L1+0x590
        w32(&mut buf, h1 + PBLH_OVERRIDE_BIND_TARGET_REFS_COUNT, 1);
        w32(&mut buf, h1 + PBLH_SECTIONS + 8 + 7 * 8, 0x300); // offsets[7]

        wcstr(&mut buf, L1 + 0x1C0, "/usr/lib/libbar.dylib");
        wcstr(&mut buf, L1 + 0x1E0, "/System/iOS/libbar.dylib");
        w64(&mut buf, L1 + 0x200, 0xC000_0000_0000_0000); // absolute
        w64(&mut buf, L1 + 0x208, bt);
        w64(&mut buf, L1 + 0x290, 0x1234); // override target (past ObjCBinaryInfo end 0x28C)
        // ObjCBinaryInfo @L1+0x540
        let oi = L1 + 0x240;
        w64(&mut buf, oi + 0x00, 0x4000);
        w64(&mut buf, oi + 0x08, 0x4080);
        w64(&mut buf, oi + 0x10, 0x4100);
        w64(&mut buf, oi + 0x18, 0);
        w64(&mut buf, oi + 0x20, 0x4200);
        w32(&mut buf, oi + 0x28, 3); // sel refs
        w32(&mut buf, oi + 0x2C, 2); // classes
        w32(&mut buf, oi + 0x30, 0); // categories
        w32(&mut buf, oi + 0x34, 1); // protocols
        buf[oi + 0x38] = 1; // class stable swift fixups
        w32(&mut buf, oi + 0x40, 0x90); // protocol fixups offset (rel to oi)
        w32(&mut buf, oi + 0x44, 0x94); // selector fixups offset (rel to oi)
        w32(&mut buf, oi + 0x48, 1); // selector fixups count
        buf[oi + 0x90] = 1; // canonical protocol fixup (true)
        w64(&mut buf, oi + 0x94, 0xC000_0000_0000_0000); // selector fixup target
        // patch table @L1+0x5B0: one real entry + end marker
        w64(&mut buf, L1 + 0x2B0, 0x100); // override offset of impl
        w64(&mut buf, L1 + 0x2B8, DP_OBJC_CLASS as u64);
        w64(&mut buf, L1 + 0x2C0, 0);
        w64(&mut buf, L1 + 0x2C8, DP_END_OF_PATCH_TABLE as u64);

        // ================= loader 2 @0x600 (minimal) =================
        const L2: usize = 0x600;
        w32(&mut buf, L2, LOADER_MAGIC);
        w16(&mut buf, L2 + 4, 0);
        w16(&mut buf, L2 + 6, 0x8000); // app bit
        w16(&mut buf, L2 + 8 + PBLH_INDEX_OF_TWIN, NO_UNZIPPERED_TWIN);
        // header otherwise all-zero => no path, no deps, no regions…

        // ---- tail: cache patch, dyld uuid, missing paths ----
        w32(&mut buf, 0x7B0, 7);
        w32(&mut buf, 0x7B4, 0x2000);
        w64(&mut buf, 0x7B8, 0xC000_0000_0000_0000);
        for i in 0..16 {
            buf[0x7C0 + i] = 0x5A;
        }
        wcstr(&mut buf, 0x7D0, "/no/such/lib");
        wcstr(&mut buf, 0x7DD, "/gone"); // sequential cstrs: first ends at 0x7DD

        // ---- parse ----
        let pset = PrebuiltLoaderSet::parse(&buf).unwrap();

        // header
        assert_eq!(pset.header.magic, PREBUILT_LOADER_SET_MAGIC);
        assert_eq!(pset.header.version_hash, 0x2023_0101);
        assert_eq!(pset.header.length as usize, LEN);
        assert_eq!(pset.header.loaders_array_count, 3);
        assert_eq!(pset.header.loaders_array_offset, 0x4C);
        assert!(!pset.header.has_optimized_objc());
        assert!(!pset.header.has_optimized_swift());

        assert_eq!(pset.loader_offsets, vec![0x80, 0x300, 0x600]);
        assert_eq!(pset.loaders.len(), 3);

        // loader 0
        let l0 = &pset.loaders[0];
        assert_eq!(l0.loader.magic, LOADER_MAGIC);
        assert!(l0.loader.info.is_prebuilt());
        assert!(l0.loader.info.dylib_in_dyld_cache());
        assert!(l0.loader.info.has_uuid_load_command());
        assert!(l0.loader.info.has_weak_defs());
        assert!(l0.loader.info.flags_str().contains("uuid-load-cmd"));
        assert!(l0.uuid.iter().all(|&b| b == 0x11));
        assert_eq!(l0.cpu_subtype, 0x0000_000C);
        assert_eq!(l0.unused, 0);
        assert_eq!(l0.path, "/usr/bin/foo");
        assert_eq!(l0.alt_path, "");
        assert_eq!(l0.twin_index, None);
        assert!(l0.header.info.has_initializers());
        assert!(l0.header.info.is_overridable());
        assert_eq!(l0.header.info.regions_count(), 1); // bits 4..16 of header Info
        assert_eq!(l0.header.vm_size, 0x4_0000);
        assert_eq!(l0.header.exports_trie.offset, 0x1000);
        assert_eq!(l0.header.exports_trie.size, 0x200);
        assert_eq!(l0.header.code_signature.file_offset, 0x3_0000);
        assert_eq!(l0.header.code_signature.size, 0x1000);
        assert_eq!(l0.header.sections.version, 1);
        assert_eq!(l0.header.sections.offsets[0], 0x100);
        assert_eq!(l0.header.sections.offsets[7], 0x200);
        assert_eq!(l0.header.sections.sizes[7], 0x40);
        let sel_loc: Vec<DyldSectionLocation> = l0.header.sections.locations().collect();
        assert_eq!(sel_loc.len(), 2);
        assert_eq!(sel_loc[1].kind, DyldSectionLocationKind::DataSelRefs);
        assert_eq!(sel_loc[1].size, 0x40);

        // loader 0 variable data
        assert_eq!(l0.regions.len(), 1);
        assert_eq!(l0.regions[0].vm_offset(), 0x1000);
        assert_eq!(l0.regions[0].perms().as_str(), "r-x");
        assert!(l0.regions[0].read_only_data());
        assert!(!l0.regions[0].is_zero_fill());
        assert_eq!(l0.get_file_offset(0x1010), 0x10); // region translation
        assert_eq!(l0.get_file_offset(0x9999_9999), 0);
        assert_eq!(l0.dependents.len(), 2);
        assert_eq!(l0.dependents[0].dep.index(), 2);
        assert!(!l0.dependents[0].dep.is_app());
        assert_eq!(l0.dependents[0].kind, KIND_NORMAL);
        assert_eq!(l0.dependents[0].kind_enum(), Some(DependentKind::Normal));
        assert_eq!(l0.dependents[1].dep.index(), 5);
        assert!(l0.dependents[1].dep.is_app());
        assert_eq!(l0.dependents[1].kind, KIND_DELAYED);
        assert_eq!(l0.dependents[1].kind_enum(), Some(DependentKind::Delayed));
        assert_eq!(l0.bind_targets.len(), 1);
        assert_eq!(l0.bind_targets[0].offset(), 0x5600_0000_0000_1234);
        assert!(l0.file_validation.is_some());
        let fv = l0.file_validation.unwrap();
        assert!(fv.check_cd_hash);
        assert!(fv.check_inode_mtime);
        assert_eq!(fv.inode, 0x3000);
        assert!(l0.dylib_patches.is_empty());
        assert!(l0.objc_fixup_info.is_none());

        // loader 1
        let l1 = &pset.loaders[1];
        assert!(!l1.loader.info.has_uuid_load_command());
        assert!(l1.uuid.iter().all(|&b| b == 0));
        assert_eq!(l1.cpu_subtype, 0);
        assert_eq!(l1.header.vm_size, 0x8000);
        assert_eq!(l1.path, "/usr/lib/libbar.dylib");
        assert_eq!(l1.alt_path, "/System/iOS/libbar.dylib");
        assert_eq!(l1.twin_index, Some(5));
        assert!(l1.regions.is_empty()); // regions_count == 0
        assert!(l1.dependents.is_empty());
        assert_eq!(l1.bind_targets.len(), 2);
        assert!(l1.bind_targets[0].is_absolute());
        assert_eq!(l1.bind_targets[0].offset(), 0xC000_0000_0000_0000);
        assert_eq!(l1.override_bind_targets.len(), 1);
        assert_eq!(l1.override_bind_targets[0].0, 0x1234);
        let ofi = l1.objc_fixup_info.unwrap();
        assert_eq!(ofi.sel_refs_count, 3);
        assert_eq!(ofi.class_list_count, 2);
        assert_eq!(ofi.protocol_list_count, 1);
        assert!(ofi.has_class_stable_swift_fixups);
        assert_eq!(l1.objc_canonical_protocol_fixups, vec![true]);
        assert_eq!(l1.objc_selector_fixups.len(), 1);
        assert!(l1.objc_selector_fixups[0].is_absolute());
        assert_eq!(l1.dylib_patches.len(), 2);
        assert_eq!(l1.dylib_patches[0].kind, DP_OBJC_CLASS);
        assert_eq!(l1.dylib_patches[0].override_offset_of_impl, 0x100);
        assert_eq!(l1.dylib_patches[1].kind, DP_END_OF_PATCH_TABLE);

        // loader 2
        let l2 = &pset.loaders[2];
        assert_eq!(l2.loader.r#ref.0, 0x8000);
        assert!(l2.loader.r#ref.is_app());
        assert_eq!(l2.loader.r#ref.index(), 0);
        assert_eq!(l2.path, "");
        assert!(l2.regions.is_empty() && l2.bind_targets.is_empty());
        assert_eq!(l2.twin_index, None); // 0xFFFF sentinel => no twin
        assert!(l2.header.info.regions_count() == 0);

        // tail data
        assert_eq!(pset.patches.len(), 1);
        assert_eq!(pset.patches[0].dylib_index, 7);
        assert_eq!(pset.patches[0].dylib_vm_offset, 0x2000);
        assert!(pset.patches[0].patch_to.is_absolute());
        assert!(pset.dyld_cache_uuid.iter().all(|&b| b == 0x5A));
        assert_eq!(pset.must_be_missing_paths, vec!["/no/such/lib", "/gone"]);
    }

    #[test]
    fn prebuilt_loader_set_rejects() {
        // bad magic
        let mut buf = vec![0u8; 128];
        w32(&mut buf, PBLSH_MAGIC, 0x1234_5678);
        let err = PrebuiltLoaderSet::parse(&buf).unwrap_err();
        assert!(err.contains("invalid magic for PrebuiltLoaderSet"), "{err}");
        validate_magic(PREBUILT_LOADER_SET_MAGIC).unwrap();
        assert!(validate_magic(0).is_err());

        // length below minimum
        let mut buf2 = vec![0u8; 128];
        w32(&mut buf2, PBLSH_MAGIC, PREBUILT_LOADER_SET_MAGIC);
        w32(&mut buf2, PBLSH_LENGTH, 8);
        assert!(PrebuiltLoaderSet::parse(&buf2).unwrap_err().contains("size"));

        // length beyond buffer
        let mut buf3 = vec![0u8; 128];
        w32(&mut buf3, PBLSH_MAGIC, PREBUILT_LOADER_SET_MAGIC);
        w32(&mut buf3, PBLSH_LENGTH, 0x1000);
        assert!(PrebuiltLoaderSet::parse(&buf3).unwrap_err().contains("size"));

        // loader array out of set bounds
        let mut buf4 = vec![0u8; 128];
        w32(&mut buf4, PBLSH_MAGIC, PREBUILT_LOADER_SET_MAGIC);
        w32(&mut buf4, PBLSH_LENGTH, 128);
        w32(&mut buf4, PBLSH_LOADERS_ARRAY_COUNT, 100);
        w32(&mut buf4, PBLSH_LOADERS_ARRAY_OFFSET, 76);
        assert!(PrebuiltLoaderSet::parse(&buf4)
            .unwrap_err()
            .contains("exceeds set size"));

        // objc tables require a loader
        let mut buf5 = vec![0u8; 128];
        w32(&mut buf5, PBLSH_MAGIC, PREBUILT_LOADER_SET_MAGIC);
        w32(&mut buf5, PBLSH_LENGTH, 128);
        w32(&mut buf5, PBLSH_OBJC_SELECTOR_HASH_TABLE_OFFSET, 0x80);
        assert!(PrebuiltLoaderSet::parse(&buf5)
            .unwrap_err()
            .contains("requires at least one loader"));
    }

    #[test]
    fn program_trie_gates() {
        assert!(!supports_program_trie(0x150, 0x1234)); // header too old
        assert!(!supports_program_trie(0x170, 0));
        assert!(supports_program_trie(0x170, 0x1234));
        assert!(!supports_dylib_prebuilt_loader(0x140, 0x1234));
        assert!(!supports_dylib_prebuilt_loader(0x170, 0));
        assert!(supports_dylib_prebuilt_loader(0x170, 0x1234));
    }

    #[test]
    fn uleb128_roundtrip() {
        let mut buf = vec![0xAC, 0x02]; // 300
        let mut pos = 0;
        assert_eq!(read_uleb128(&buf, &mut pos).unwrap(), 300);
        assert_eq!(pos, 2);
        buf = vec![0x80];
        assert!(read_uleb128(&buf, &mut pos).is_err()); // truncated continuation
    }

    #[test]
    fn program_trie_parse_and_walk() {
        // Trie (format documented on `trie_node_at`), laid out by hand so the
        // offsets are visible:
        //   root "" -> "/usr/bin/" and "/bin/"
        //   "/usr/bin/" -> "foo" (uleb 0x1234), "bar" (uleb 0x78)
        //   "/bin/" -> "ls" (uleb 0x99)
        let mut t: Vec<u8> = Vec::new();

        // root node @0: edge "", non-terminal, 2 children
        t.extend_from_slice(b"\0\x00\x02");
        let p_usr = t.len();
        t.push(0);
        t.extend_from_slice(b"/usr/bin/\0");
        let p_bin = t.len();
        t.push(0);
        t.extend_from_slice(b"/bin/\0");
        assert_eq!(t.len(), 0x15); // root is 21 bytes

        // node "/usr/bin/" @0x15: edge repeated in-node, non-terminal, 2 children
        t[p_usr] = t.len() as u8;
        t.extend_from_slice(b"/usr/bin/\0\x00\x02");
        let p_foo = t.len();
        t.push(0);
        t.extend_from_slice(b"foo\0");
        let p_bar = t.len();
        t.push(0);
        t.extend_from_slice(b"bar\0");

        // node "foo": terminal, uleb128(0x1234) = [0xB4, 0x24]
        t[p_foo] = t.len() as u8;
        t.extend_from_slice(b"foo\0\x02\xB4\x24\x00");
        // node "bar": terminal, 1-byte uleb 0x78
        t[p_bar] = t.len() as u8;
        t.extend_from_slice(b"bar\0\x01\x78\x00");

        // node "/bin/": non-terminal, 1 child
        t[p_bin] = t.len() as u8;
        t.extend_from_slice(b"/bin/\0\x00\x01");
        let p_ls = t.len();
        t.push(0);
        t.extend_from_slice(b"ls\0");

        // node "ls": terminal
        t[p_ls] = t.len() as u8;
        t.extend_from_slice(b"ls\0\x02\x99\x01\x00");

        let entries = parse_program_trie(&t).unwrap();
        assert_eq!(entries.len(), 3);
        let foo = entries
            .iter()
            .find(|e| e.path == "/usr/bin/foo")
            .expect("foo entry");
        assert_eq!(foo.value, 0x1234);
        // value_offset points at the 0xB4 uleb byte right after the terminal size
        assert_eq!(t[foo.value_offset], 0xB4);
        let mut by_path: std::collections::HashMap<String, u64> = entries
            .iter()
            .map(|e| (e.path.clone(), e.value))
            .collect();
        assert_eq!(by_path.remove("/usr/bin/bar"), Some(0x78));
        assert_eq!(by_path.remove("/bin/ls"), Some(0x99));
        assert_eq!(by_path.remove("/usr/bin/foo"), Some(0x1234));
        assert!(by_path.is_empty());

        assert_eq!(walk_program_trie(&t, "/usr/bin/foo").unwrap(), 0x1234);
        assert_eq!(walk_program_trie(&t, "/usr/bin/bar").unwrap(), 0x78);
        assert_eq!(walk_program_trie(&t, "/bin/ls").unwrap(), 0x99);
        assert!(walk_program_trie(&t, "/usr/bin/baz")
            .unwrap_err()
            .contains("could not find executable"));
    }
}
