//! closure — dyld launch/dlopen closure records: the typed-byte stream used
//! by the pre-dyld4 program closures (`ProgClosuresAddr`), the dylibs/other
//! image arrays, and the launch-closure payloads.
//!
//! Parity: ipsw `pkg/dyld/closure.go` (kinds, bit accessors,
//! `parseClosureContainers` → `parseLaunchClosure` → `parseClosureImageArray`
//! → `parseClosureImage`) and `closure_string.go` (stringer names).
//!
//! Everything here is a record walker over `typedBytes` headers:
//! `u32 = type:8 | payload_length:24`, followed by `payload_length` bytes.
//! Upstream *panics* on `Image`/`DlopenClosure` containers and on
//! `InterposeTuples`/`ExistingFiles` launch records; we return errors
//! instead (documented per-arm). `SelectorTable`, `ClassTable` and
//! `DuplicateClassesTable` payloads are skipped exactly like upstream
//! (`r.Seek(payloadLength, io.SeekCurrent)`).
//!
//! Honest notes: the dyld_section_location kind→name table is ported in
//! `crate::prebuilt` (upstream it is generated into `prebuilt_string.go`,
//! not `closure_string.go`). ObjC selector/class hash tables inside
//! closures, and function-varint encodings, remain future work.

use std::fmt;

use crate::prebuilt::{extract_bits, rd_u16, rd_u32, rd_u64};

/// `sizeof(typedBytes)` (closure.go:575 `sizeOfTypeBytes`).
pub const SIZE_OF_TYPED_BYTES: u32 = 4;

// image-number ranges (closure.go:73-80)
pub const FIRST_DYLD_CACHE_IMAGE_NUM: u32 = 0x0000_0001;
pub const LAST_DYLD_CACHE_IMAGE_NUM: u32 = 0x0000_0FFF;
pub const FIRST_OTHER_OS_IMAGE_NUM: u32 = 0x0000_1001;
pub const LAST_OTHER_OS_IMAGE_NUM: u32 = 0x0000_1FFF;
pub const FIRST_LAUNCH_CLOSURE_IMAGE_NUM: u32 = 0x0000_2000;
pub const MISSING_WEAK_LINKED_IMAGE: u32 = 0x0FFF_FFFF;

/// `diskSegmentType` "read-only data" special case (closure.go:301).
pub const READ_ONLY_DATA_PERMISSIONS: u32 = 2;

// ---------------------------------------------------------------------------
// closureType (closure.go:20-71, names from closure_string.go)
// ---------------------------------------------------------------------------

/// `type closureType uint32`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ClosureType {
    // containers which have an overall length and TypedBytes inside their content
    LaunchClosure = 1,
    ImageArray = 2,
    Image = 3,
    DlopenClosure = 4,
    // attributes for Images
    ImageFlags = 7,
    PathWithHash = 8,
    FileInodeAndTime = 9,
    CdHash = 10,
    Uuid = 11,
    MappingInfo = 12,
    DiskSegment = 13,
    CacheSegment = 14,
    Dependents = 15,
    InitOffsets = 16,
    DofOffsets = 17,
    CodeSignLoc = 18,
    FarPlayLoc = 19,
    RebaseFixups = 20,
    BindFixups = 21,
    CachePatchInfo = 22, // deprecated
    TextFixups = 23,
    ImageOverride = 24,
    InitBefores = 25,
    InitsSection = 26,
    ChainedFixupsTargets = 27,
    TermOffsets = 28,
    ChainedStartsOffset = 29,
    ObjcFixups = 30,
    // attributes for Closures (launch or dlopen)
    ClosureFlags = 32,
    DyldCacheUUID = 33,
    MissingFiles = 34,
    EnvVar = 35,
    TopImage = 36,
    LibDyldEntry = 37,
    LibSystemNum = 38,
    MainEntry = 40,
    StartEntry = 41,
    CacheOverrides = 42,
    InterposeTuples = 43,
    ExistingFiles = 44,
    SelectorTable = 45,
    ClassTable = 46,
    Warning = 47,
    DuplicateClassesTable = 48,
    ProgVars = 49,
}

impl ClosureType {
    pub fn from_u32(v: u32) -> Option<ClosureType> {
        use ClosureType::*;
        Some(match v {
            1 => LaunchClosure,
            2 => ImageArray,
            3 => Image,
            4 => DlopenClosure,
            7 => ImageFlags,
            8 => PathWithHash,
            9 => FileInodeAndTime,
            10 => CdHash,
            11 => Uuid,
            12 => MappingInfo,
            13 => DiskSegment,
            14 => CacheSegment,
            15 => Dependents,
            16 => InitOffsets,
            17 => DofOffsets,
            18 => CodeSignLoc,
            19 => FarPlayLoc,
            20 => RebaseFixups,
            21 => BindFixups,
            22 => CachePatchInfo,
            23 => TextFixups,
            24 => ImageOverride,
            25 => InitBefores,
            26 => InitsSection,
            27 => ChainedFixupsTargets,
            28 => TermOffsets,
            29 => ChainedStartsOffset,
            30 => ObjcFixups,
            32 => ClosureFlags,
            33 => DyldCacheUUID,
            34 => MissingFiles,
            35 => EnvVar,
            36 => TopImage,
            37 => LibDyldEntry,
            38 => LibSystemNum,
            40 => MainEntry,
            41 => StartEntry,
            42 => CacheOverrides,
            43 => InterposeTuples,
            44 => ExistingFiles,
            45 => SelectorTable,
            46 => ClassTable,
            47 => Warning,
            48 => DuplicateClassesTable,
            49 => ProgVars,
            _ => return None,
        })
    }

    /// stringer name (`stringer -type=closureType`).
    pub fn as_str(self) -> &'static str {
        use ClosureType::*;
        match self {
            LaunchClosure => "launchClosure",
            ImageArray => "imageArray",
            Image => "image",
            DlopenClosure => "dlopenClosure",
            ImageFlags => "imageFlags",
            PathWithHash => "pathWithHash",
            FileInodeAndTime => "fileInodeAndTime",
            CdHash => "cdHash",
            Uuid => "uuid",
            MappingInfo => "mappingInfo",
            DiskSegment => "diskSegment",
            CacheSegment => "cacheSegment",
            Dependents => "dependents",
            InitOffsets => "initOffsets",
            DofOffsets => "dofOffsets",
            CodeSignLoc => "codeSignLoc",
            FarPlayLoc => "farPlayLoc",
            RebaseFixups => "rebaseFixups",
            BindFixups => "bindFixups",
            CachePatchInfo => "cachePatchInfo",
            TextFixups => "textFixups",
            ImageOverride => "imageOverride",
            InitBefores => "initBefores",
            InitsSection => "initsSection",
            ChainedFixupsTargets => "chainedFixupsTargets",
            TermOffsets => "termOffsets",
            ChainedStartsOffset => "chainedStartsOffset",
            ObjcFixups => "objcFixups",
            ClosureFlags => "closureFlags",
            DyldCacheUUID => "dyldCacheUUID",
            MissingFiles => "missingFiles",
            EnvVar => "envVar",
            TopImage => "topImage",
            LibDyldEntry => "libDyldEntry",
            LibSystemNum => "libSystemNum",
            MainEntry => "mainEntry",
            StartEntry => "startEntry",
            CacheOverrides => "cacheOverrides",
            InterposeTuples => "interposeTuples",
            ExistingFiles => "existingFiles",
            SelectorTable => "selectorTable",
            ClassTable => "classTable",
            Warning => "warning",
            DuplicateClassesTable => "duplicateClassesTable",
            ProgVars => "progVars",
        }
    }
}

impl fmt::Display for ClosureType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Stringer fallback for raw kind bytes (`closureType(5)`).
pub fn closure_type_name(raw: u32) -> String {
    match ClosureType::from_u32(raw) {
        Some(k) => k.as_str().to_string(),
        None => format!("closureType({raw})"),
    }
}

// ---------------------------------------------------------------------------
// typedBytes / countAndHasRoots / lcFlags / cFlags (closure.go:563-785)
// ---------------------------------------------------------------------------

/// `type typedBytes uint32` — `type:8 | payload_length:24`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TypedBytes(pub u32);

impl TypedBytes {
    pub fn kind_raw(self) -> u32 {
        extract_bits(self.0 as u64, 0, 8) as u32
    }
    pub fn kind(self) -> Option<ClosureType> {
        ClosureType::from_u32(self.kind_raw())
    }
    pub fn payload_length(self) -> u32 {
        extract_bits(self.0 as u64, 8, 24) as u32
    }
}

impl fmt::Display for TypedBytes {
    /// Mirrors Go `typedBytes.String()`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "type: {}, length: {:#x}, raw: {:#x}",
            closure_type_name(self.kind_raw()),
            self.payload_length(),
            self.0
        )
    }
}

/// `type countAndHasRoots uint32` — count:31 | hasRoots:1.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CountAndHasRoots(pub u32);

impl CountAndHasRoots {
    pub fn count(self) -> u32 {
        extract_bits(self.0 as u64, 0, 31) as u32
    }
    pub fn has_roots(self) -> bool {
        extract_bits(self.0 as u64, 31, 1) != 0
    }
}

/// `type lcFlags uint32` (closure.go:589).
///
/// NOTE: upstream ipsw reads **every** boolean accessor from bits 0..16 —
/// evidently a transcription slip of dyld's `Closure::Flags` bitfield — and
/// this port mirrors that verbatim (bug included) so behavior matches the
/// reference implementation. `InitImageCount` (bits 0..16) is the only
/// meaningfully decoded field.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LcFlags(pub u32);

impl LcFlags {
    pub fn used_at_paths(self) -> bool {
        extract_bits(self.0 as u64, 0, 16) != 0
    }
    pub fn used_fallback_paths(self) -> bool {
        extract_bits(self.0 as u64, 0, 16) != 0
    }
    pub fn init_image_count(self) -> u32 {
        extract_bits(self.0 as u64, 0, 16) as u32
    }
    pub fn has_inserted_libraries(self) -> bool {
        extract_bits(self.0 as u64, 0, 16) != 0
    }
    pub fn has_prog_vars(self) -> bool {
        extract_bits(self.0 as u64, 0, 16) != 0
    }
    pub fn used_interposing(self) -> bool {
        extract_bits(self.0 as u64, 0, 16) != 0
    }
    pub fn padding(self) -> u32 {
        extract_bits(self.0 as u64, 0, 16) as u32
    }
}

impl fmt::Display for LcFlags {
    /// Mirrors Go `lcFlags.String()`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut flags: Vec<&str> = Vec::new();
        if self.used_at_paths() {
            flags.push("@paths");
        }
        if !self.used_fallback_paths() {
            flags.push("fallback_paths");
        }
        if self.has_inserted_libraries() {
            flags.push("inserted_libs");
        }
        if self.has_prog_vars() {
            flags.push("prog_vars");
        }
        if self.used_interposing() {
            flags.push("interposing");
        }
        write!(
            f,
            "initial_image_count: {}, flags: [{}]",
            self.init_image_count(),
            flags.join("|")
        )
    }
}

/// `type cFlags uint64` — the per-image flags (closure.go:635).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CFlags(pub u64);

impl CFlags {
    pub fn image_num(self) -> u16 {
        extract_bits(self.0, 0, 16) as u16
    }
    pub fn max_load_count(self) -> u16 {
        extract_bits(self.0, 16, 12) as u16
    }
    /// bit 28 — an error occurred creating the info for this image.
    pub fn is_invalid(self) -> bool {
        extract_bits(self.0, 28, 1) != 0
    }
    /// bit 29 — 16K pages vs 4K.
    pub fn has_16kb_pages(self) -> bool {
        extract_bits(self.0, 29, 1) != 0
    }
    /// bit 30.
    pub fn is_64(self) -> bool {
        extract_bits(self.0, 30, 1) != 0
    }
    /// bit 31.
    pub fn has_objc(self) -> bool {
        extract_bits(self.0, 31, 1) != 0
    }
    /// bit 32.
    pub fn may_have_plus_loads(self) -> bool {
        extract_bits(self.0, 32, 1) != 0
    }
    /// bit 33 — image is DSMOS or FarPlay encrypted.
    pub fn is_encrypted(self) -> bool {
        extract_bits(self.0, 33, 1) != 0
    }
    /// bit 34.
    pub fn has_weak_defs(self) -> bool {
        extract_bits(self.0, 34, 1) != 0
    }
    /// bit 35.
    pub fn never_unload(self) -> bool {
        extract_bits(self.0, 35, 1) != 0
    }
    /// bit 36 — dylibs use file-system relative paths.
    pub fn cwd_same_as_this(self) -> bool {
        extract_bits(self.0, 36, 1) != 0
    }
    /// bit 37 — part of OS, can be loaded into an LV process.
    pub fn is_platform_binary(self) -> bool {
        extract_bits(self.0, 37, 1) != 0
    }
    /// bit 38.
    pub fn is_bundle(self) -> bool {
        extract_bits(self.0, 38, 1) != 0
    }
    /// bit 39.
    pub fn is_dylib(self) -> bool {
        extract_bits(self.0, 39, 1) != 0
    }
    /// bit 40.
    pub fn is_executable(self) -> bool {
        extract_bits(self.0, 40, 1) != 0
    }
    /// bit 41 — only applicable to cached dylibs.
    pub fn overridable_dylib(self) -> bool {
        extract_bits(self.0, 41, 1) != 0
    }
    /// bit 42.
    pub fn in_dyld_cache(self) -> bool {
        extract_bits(self.0, 42, 1) != 0
    }
    /// bit 43.
    pub fn has_terminators(self) -> bool {
        extract_bits(self.0, 43, 1) != 0
    }
    /// bit 44.
    pub fn has_read_only_data(self) -> bool {
        extract_bits(self.0, 44, 1) != 0
    }
    /// bit 45.
    pub fn has_chained_fixups(self) -> bool {
        extract_bits(self.0, 45, 1) != 0
    }
    /// bit 46.
    pub fn has_precomputed_objc(self) -> bool {
        extract_bits(self.0, 46, 1) != 0
    }
    /// bit 47.
    pub fn fixups_not_encoded(self) -> bool {
        extract_bits(self.0, 47, 1) != 0
    }
    /// bit 48.
    pub fn rebases_not_encoded(self) -> bool {
        extract_bits(self.0, 48, 1) != 0
    }
    /// bit 49.
    pub fn has_override_image_num(self) -> bool {
        extract_bits(self.0, 49, 1) != 0
    }
}

// ---------------------------------------------------------------------------
// segment / pattern / target packings (closure.go:286-433)
// ---------------------------------------------------------------------------

/// `type cacheSegmentType uint64` — cacheOffset:32 | size:28 | perms:4.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CacheSegmentType(pub u64);

impl CacheSegmentType {
    pub fn cache_offset(self) -> u32 {
        extract_bits(self.0, 0, 32) as u32
    }
    pub fn size(self) -> u32 {
        extract_bits(self.0, 32, 28) as u32
    }
    pub fn permissions(self) -> u32 {
        extract_bits(self.0, 60, 4) as u32
    }
}

/// `type diskSegmentType uint64` — filePages:30 | vmPages:30 | perms:3 |
/// paddingNotSeg:1.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DiskSegmentType(pub u64);

impl DiskSegmentType {
    pub fn file_page_count(self) -> u32 {
        extract_bits(self.0, 0, 30) as u32
    }
    pub fn vm_page_count(self) -> u32 {
        extract_bits(self.0, 30, 30) as u32
    }
    pub fn permissions(self) -> u32 {
        extract_bits(self.0, 60, 3) as u32
    }
    /// Upstream quirk kept: permission value 2 prints as `-w-` (read-only
    /// data segments are described with write-bit encodings).
    pub fn perm_string(self) -> String {
        let perms = perms_str(self.permissions());
        if self.permissions() == READ_ONLY_DATA_PERMISSIONS {
            "-w-".to_string()
        } else {
            perms
        }
    }
    /// bit 63 — this "segment" is padding, not a real segment.
    pub fn padding_not_seg(self) -> bool {
        extract_bits(self.0, 63, 1) != 0
    }
}

/// 3-bit VM-protection → `rwx` string (go-macho `VmProtection.String()`).
fn perms_str(perms: u32) -> String {
    let r = perms & 1 != 0;
    let w = perms & 2 != 0;
    let x = perms & 4 != 0;
    let mut s = String::new();
    s.push(if r { 'r' } else { '-' });
    s.push(if w { 'w' } else { '-' });
    s.push(if x { 'x' } else { '-' });
    s
}

/// `type rebasePatternType uint32` — repeat:20 | contig:8 | skip:4.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RebasePatternType(pub u32);

impl RebasePatternType {
    pub fn repeat_count(self) -> u32 {
        extract_bits(self.0 as u64, 0, 20) as u32
    }
    pub fn contig_count(self) -> u32 {
        extract_bits(self.0 as u64, 20, 8) as u32
    }
    pub fn skip_count(self) -> u32 {
        extract_bits(self.0 as u64, 28, 4) as u32
    }
}

/// `type targetKind uint8`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetKind {
    Rebase = 0,
    SharedCache = 1,
    Image = 2,
    Absolute = 3,
}

/// `type resolvedSymbolTarget uint64` — kind:2 then kind-specific payload.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResolvedSymbolTarget(pub u64);

impl ResolvedSymbolTarget {
    pub fn kind(self) -> TargetKind {
        match extract_bits(self.0, 0, 2) {
            0 => TargetKind::Rebase,
            1 => TargetKind::SharedCache,
            2 => TargetKind::Image,
            _ => TargetKind::Absolute,
        }
    }
    /// bits 2..24 (shared-cache kind).
    pub fn shared_cache_offset(self) -> u64 {
        extract_bits(self.0, 2, 22)
    }
    /// bits 2..24 (image kind).
    pub fn image_num(self) -> u64 {
        extract_bits(self.0, 2, 22)
    }
    /// bits 24..64 (image kind).
    pub fn image_offset(self) -> u64 {
        extract_bits(self.0, 24, 40)
    }
    /// `AbsoluteValue` — the 62-bit payload as i64. Upstream does *not*
    /// sign-extend here despite the comment; mirrored verbatim.
    pub fn absolute_value(self) -> i64 {
        extract_bits(self.0, 2, 62) as i64
    }
    pub fn raw(self) -> u64 {
        self.0
    }
}

impl fmt::Display for ResolvedSymbolTarget {
    /// Mirrors Go `resolvedSymbolTarget.String()`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind() {
            TargetKind::Rebase => write!(f, "kind: rebase, raw: {:#x}", self.raw()),
            TargetKind::SharedCache => write!(f, "kind: shared_cache, offset: {:#x}", self.shared_cache_offset()),
            TargetKind::Image => write!(
                f,
                "kind: image, index: {}, offset: {:#x}",
                self.image_num(),
                self.image_offset()
            ),
            TargetKind::Absolute => write!(f, "kind: absolute, value: {:#x}", self.absolute_value()),
        }
    }
}

/// `type bindPatternType uint64` — startVMOffset:40 | skip:8 | repeat:16.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BindPatternType(pub u64);

impl BindPatternType {
    pub fn start_vm_offset(self) -> u64 {
        extract_bits(self.0, 0, 40)
    }
    pub fn skip_count(self) -> u64 {
        extract_bits(self.0, 40, 8)
    }
    pub fn repeat_count(self) -> u64 {
        extract_bits(self.0, 48, 16)
    }
}

/// `type BindPattern struct` — Target + Detail, 16 bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BindPattern {
    pub target: ResolvedSymbolTarget,
    pub detail: BindPatternType,
}

pub const BIND_PATTERN_SIZE: usize = 16;

impl BindPattern {
    pub fn parse(buf: &[u8], off: usize) -> Result<BindPattern, String> {
        Ok(BindPattern {
            target: ResolvedSymbolTarget(rd_u64(buf, off)?),
            detail: BindPatternType(rd_u64(buf, off + 8)?),
        })
    }
}

/// `type TextFixupPattern struct` — 16 bytes (u64 target, u32, u16, u16).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TextFixupPattern {
    pub target: ResolvedSymbolTarget, // 0x00
    pub start_vm_offset: u32,         // 0x08
    pub repeat_count: u16,            // 0x0C
    pub skip_count: u16,              // 0x0E
}

pub const TEXT_FIXUP_PATTERN_SIZE: usize = 16;

impl TextFixupPattern {
    pub fn parse(buf: &[u8], off: usize) -> Result<TextFixupPattern, String> {
        Ok(TextFixupPattern {
            target: ResolvedSymbolTarget(rd_u64(buf, off)?),
            start_vm_offset: rd_u32(buf, off + 8)?,
            repeat_count: rd_u16(buf, off + 12)?,
            skip_count: rd_u16(buf, off + 14)?,
        })
    }
}

// ---------------------------------------------------------------------------
// linkedImage / small attribute structs (closure.go:527-811)
// ---------------------------------------------------------------------------

/// `type linkKind uint32`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkKind {
    Regular = 0,
    Weak = 1,
    Upward = 2,
    ReExport = 3,
}

impl LinkKind {
    pub fn from_u32(v: u32) -> Option<LinkKind> {
        match v {
            0 => Some(LinkKind::Regular),
            1 => Some(LinkKind::Weak),
            2 => Some(LinkKind::Upward),
            3 => Some(LinkKind::ReExport),
            _ => None,
        }
    }
    /// stringer name.
    pub fn as_str(self) -> &'static str {
        match self {
            LinkKind::Regular => "regular",
            LinkKind::Weak => "weak",
            LinkKind::Upward => "upward",
            LinkKind::ReExport => "reExport",
        }
    }
}

/// `type linkedImage uint32` — imgNum:30 | link:2.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LinkedImage(pub u32);

impl LinkedImage {
    pub fn img_num(self) -> u32 {
        extract_bits(self.0 as u64, 0, 30) as u32
    }
    pub fn link(self) -> LinkKind {
        match extract_bits(self.0 as u64, 30, 2) {
            0 => LinkKind::Regular,
            1 => LinkKind::Weak,
            2 => LinkKind::Upward,
            _ => LinkKind::ReExport,
        }
    }
}

/// `mappingInfoType` — TotalVmPages + SliceOffsetIn4K, 8 bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MappingInfo {
    pub total_vm_pages: u32,
    pub slice_offset_in_4k: u32,
}

pub const MAPPING_INFO_SIZE: usize = 8;

impl MappingInfo {
    pub fn parse(buf: &[u8], off: usize) -> Result<MappingInfo, String> {
        Ok(MappingInfo {
            total_vm_pages: rd_u32(buf, off)?,
            slice_offset_in_4k: rd_u32(buf, off + 4)?,
        })
    }
}

/// `initializerSectionRangeType` — 8 bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InitializerSectionRange {
    pub section_offset: u32,
    pub section_size: u32,
}

pub const INITIALIZER_SECTION_RANGE_SIZE: usize = 8;

impl InitializerSectionRange {
    pub fn parse(buf: &[u8], off: usize) -> Result<InitializerSectionRange, String> {
        Ok(InitializerSectionRange {
            section_offset: rd_u32(buf, off)?,
            section_size: rd_u32(buf, off + 4)?,
        })
    }
}

/// `codeSignatureLocationType` — 8 bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CodeSignatureLocation {
    pub file_offset: u32,
    pub file_size: u32,
}

pub const CODE_SIGNATURE_LOCATION_SIZE: usize = 8;

impl CodeSignatureLocation {
    pub fn parse(buf: &[u8], off: usize) -> Result<CodeSignatureLocation, String> {
        Ok(CodeSignatureLocation {
            file_offset: rd_u32(buf, off)?,
            file_size: rd_u32(buf, off + 4)?,
        })
    }
}

/// `farPlayLocType` — 8 bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FarPlayLoc {
    pub range_start: u32,
    pub range_length: u32,
}

pub const FAR_PLAY_LOC_SIZE: usize = 8;

impl FarPlayLoc {
    pub fn parse(buf: &[u8], off: usize) -> Result<FarPlayLoc, String> {
        Ok(FarPlayLoc {
            range_start: rd_u32(buf, off)?,
            range_length: rd_u32(buf, off + 4)?,
        })
    }
}

/// `fileInfoType` — 16 bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FileInfo {
    pub inode: u64,
    pub mod_time: u64,
}

pub const FILE_INFO_SIZE: usize = 16;

impl FileInfo {
    pub fn parse(buf: &[u8], off: usize) -> Result<FileInfo, String> {
        Ok(FileInfo {
            inode: rd_u64(buf, off)?,
            mod_time: rd_u64(buf, off + 8)?,
        })
    }
}

/// `type PatchEntry struct` — 16 bytes (u32 + u32 + u64; the u64 lands on
/// offset 8 both packed and C-aligned).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PatchEntry {
    pub overridden_dylib_in_cache: u32, // 0x00
    pub export_cache_offset: u32,       // 0x04
    pub replacement: ResolvedSymbolTarget, // 0x08
}

pub const PATCH_ENTRY_SIZE: usize = 16;

impl PatchEntry {
    pub fn parse(buf: &[u8], off: usize) -> Result<PatchEntry, String> {
        Ok(PatchEntry {
            overridden_dylib_in_cache: rd_u32(buf, off)?,
            export_cache_offset: rd_u32(buf, off + 4)?,
            replacement: ResolvedSymbolTarget(rd_u64(buf, off + 8)?),
        })
    }
}

/// `type warningType struct` — Go field `Type` renamed `kind` (Rust keyword).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Warning {
    pub kind: u32,
    pub message: Vec<u8>,
}

// ---------------------------------------------------------------------------
// ObjC fixups (closure.go:435-525)
// ---------------------------------------------------------------------------

/// `objcFixupsType` — fixed 24-byte header of an `objcFixups` record.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ObjcFixupsHeader {
    pub protocol_class_target: ResolvedSymbolTarget, // 0x00
    pub image_info_vm_offset: u64,                   // 0x08
    pub protocol_fixup_count: u32,                   // 0x10
    pub sel_ref_fixup_count: u32,                    // 0x14
}

pub const OBJC_FIXUPS_HEADER_SIZE: usize = 24;

impl ObjcFixupsHeader {
    pub fn parse(buf: &[u8], off: usize) -> Result<ObjcFixupsHeader, String> {
        Ok(ObjcFixupsHeader {
            protocol_class_target: ResolvedSymbolTarget(rd_u64(buf, off)?),
            image_info_vm_offset: rd_u64(buf, off + 8)?,
            protocol_fixup_count: rd_u32(buf, off + 0x10)?,
            sel_ref_fixup_count: rd_u32(buf, off + 0x14)?,
        })
    }
}

/// `type ObjcFixups struct` — the parsed objcFixups record.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ObjcFixups {
    pub header: ObjcFixupsHeader,
    pub protocol_isa_fixups: Vec<ProtocolISAFixup>,
    pub sel_ref_fixups: Vec<SelectorReferenceFixup>,
    pub stable_swift_fixup_count: u32,
    pub method_list_fixup_count: u32,
    pub class_stable_swift_fixups: Vec<ClassStableSwiftFixup>,
    pub method_list_fixups: Vec<MethodListFixup>,
}

/// `protocolISAFixup` / `classStableSwiftFixup` / `methodListFixup` share the
/// same u64 packing: startVMOffset:40 | skip:8 | repeat:16.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProtocolISAFixup(pub u64);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClassStableSwiftFixup(pub u64);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MethodListFixup(pub u64);

/// The shared `start/skip/repeat` accessor shape.
pub trait FixupPattern {
    fn raw(&self) -> u64;
    fn start_vm_offset(&self) -> u64 {
        extract_bits(self.raw(), 0, 40)
    }
    fn skip_count(&self) -> u64 {
        extract_bits(self.raw(), 40, 8)
    }
    fn repeat_count(&self) -> u64 {
        extract_bits(self.raw(), 48, 16)
    }
}

macro_rules! impl_fixup_pattern {
    ($($t:ty),*) => {$(
        impl FixupPattern for $t {
            fn raw(&self) -> u64 { self.0 }
        }
    )*};
}

impl_fixup_pattern!(ProtocolISAFixup, ClassStableSwiftFixup, MethodListFixup);

/// `type SelectorReferenceFixup uint32` — the raw value doubles as a
/// `chainEntry`: index:24 | next:7 | inSharedCache:1.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SelectorReferenceFixup(pub u32);

impl SelectorReferenceFixup {
    pub fn chain_entry(self) -> ChainEntry {
        ChainEntry(self.0)
    }
}

/// `type chainEntry uint32`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ChainEntry(pub u32);

impl ChainEntry {
    pub fn index(self) -> u32 {
        extract_bits(self.0 as u64, 0, 24) as u32
    }
    pub fn next(self) -> u32 {
        extract_bits(self.0 as u64, 24, 7) as u32
    }
    pub fn in_shared_cache(self) -> bool {
        extract_bits(self.0 as u64, 31, 1) != 0
    }
}

// ---------------------------------------------------------------------------
// image array + closures (closure.go:82-124, 548-561)
// ---------------------------------------------------------------------------

/// `imageArrayType` — the fixed 12-byte head of an image-array blob.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ImageArrayHeader {
    pub t: TypedBytes,        // 0x00
    pub first_image_num: u32, // 0x04
    pub count_and_has_roots: CountAndHasRoots, // 0x08
}

pub const IMAGE_ARRAY_HEADER_SIZE: usize = 12;

impl ImageArrayHeader {
    pub fn parse(buf: &[u8], off: usize) -> Result<ImageArrayHeader, String> {
        Ok(ImageArrayHeader {
            t: TypedBytes(rd_u32(buf, off)?),
            first_image_num: rd_u32(buf, off + 4)?,
            count_and_has_roots: CountAndHasRoots(rd_u32(buf, off + 8)?),
        })
    }
}

/// `type CImage struct` — one closure image (parsed view).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CImage {
    pub id: u32,
    pub name: String,
    pub hash: u32,
    pub uuid: [u8; 16],
    pub flags: CFlags,
    pub dependents: Vec<LinkedImage>,
    pub cache_segments: Vec<CacheSegmentType>,
    pub disk_segments: Vec<DiskSegmentType>,
    pub init_order: Vec<u32>, // initBefores
    pub dof_offsets: Vec<u32>,
    pub initializer_offsets: Vec<u32>,
    pub terminator_offsets: Vec<u32>,
    pub initializer_sections: Vec<InitializerSectionRange>,
    pub mapping_info: MappingInfo,
    pub code_signature_location: CodeSignatureLocation,
    pub cd_hash: Vec<u8>,
    pub rebases: Vec<RebasePatternType>,
    pub binds: Vec<BindPattern>,
    pub text_fixups: Vec<TextFixupPattern>,
    pub chained_fixups_targets: Vec<ResolvedSymbolTarget>,
    pub chained_starts_offset: u64,
    pub objc_fixups: ObjcFixups,
    pub far_play_location: FarPlayLoc,
    pub file_info: FileInfo,
    pub image_override: u32,
}

impl CImage {
    /// `GetID` — the image number stored in the flags.
    pub fn get_id(&self) -> u32 {
        self.flags.image_num() as u32
    }
    /// `PageSize` — 0x4000 with 16K pages, else 0x1000.
    pub fn page_size(&self) -> u32 {
        if self.flags.has_16kb_pages() {
            0x4000
        } else {
            0x1000
        }
    }
}

/// `type LaunchClosure struct` — parsed view of a launch-closure payload.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct LaunchClosure {
    pub flags: LcFlags,
    pub images: Vec<CImage>,
    pub dyld_uuid: [u8; 16],
    pub lib_system_num: u32,
    pub lib_dyld_entry: ResolvedSymbolTarget,
    pub top_image: u32,
    pub main_entry: ResolvedSymbolTarget,
    pub start_entry: ResolvedSymbolTarget,
    pub prog_vars: u32,
    pub warnings: Vec<Warning>,
    pub dyld_cache_fixups: Vec<PatchEntry>,
    pub missing_files: Vec<String>,
    pub env_vars: Vec<String>,
}

// ---------------------------------------------------------------------------
// generic record walker (`parse_closure_contents`)
// ---------------------------------------------------------------------------

/// One typed-byte record: `kind` + raw payload. `kind` is `None` for kind
/// bytes this port does not name (mirrors stringer's `closureType(N)`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosureRecord {
    pub kind: Option<ClosureType>,
    pub kind_raw: u32,
    /// Bytes following the 4-byte header (`payload_length` of them).
    pub payload: Vec<u8>,
    /// Offset of the typedBytes header within the parsed region.
    pub header_offset: usize,
}

impl ClosureRecord {
    pub fn kind_name(&self) -> String {
        closure_type_name(self.kind_raw)
    }
}

/// Walk `len` bytes at `off` as a flat typed-byte record stream
/// (`binary.Read(typedBytes)` + payload, faithfully to the Go walkers; the
/// higher-level parsers add the kind-specific semantics).
pub fn parse_closure_contents(
    bytes: &[u8],
    off: usize,
    len: usize,
) -> Result<Vec<ClosureRecord>, String> {
    let end = off
        .checked_add(len)
        .ok_or_else(|| "dsc: closure region overflows".to_string())?;
    if end > bytes.len() {
        return Err(format!(
            "dsc: closure contents [{off:#x}, {end:#x}) exceed buffer of {} bytes",
            bytes.len()
        ));
    }
    let mut records = Vec::new();
    let mut pos = off;
    while pos < end {
        if pos + SIZE_OF_TYPED_BYTES as usize > end {
            return Err(format!(
                "dsc: truncated typedBytes header at {pos:#x}"
            ));
        }
        let raw = u32::from_le_bytes([
            bytes[pos],
            bytes[pos + 1],
            bytes[pos + 2],
            bytes[pos + 3],
        ]);
        let tb = TypedBytes(raw);
        let payload_len = tb.payload_length() as usize;
        let payload_start = pos + SIZE_OF_TYPED_BYTES as usize;
        if payload_start + payload_len > end {
            return Err(format!(
                "dsc: {} payload at {payload_start:#x} truncated (want {payload_len})",
                closure_type_name(tb.kind_raw())
            ));
        }
        records.push(ClosureRecord {
            kind: tb.kind(),
            kind_raw: tb.kind_raw(),
            payload: bytes[payload_start..payload_start + payload_len].to_vec(),
            header_offset: pos - off,
        });
        pos = payload_start + payload_len;
    }
    Ok(records)
}

// ---------------------------------------------------------------------------
// internal reading helpers
// ---------------------------------------------------------------------------

fn rd_typed_bytes(buf: &[u8], pos: &mut usize) -> Result<TypedBytes, String> {
    if *pos + SIZE_OF_TYPED_BYTES as usize > buf.len() {
        return Err(format!("dsc: truncated typedBytes header at {pos:#x}"));
    }
    let raw = u32::from_le_bytes([
        buf[*pos],
        buf[*pos + 1],
        buf[*pos + 2],
        buf[*pos + 3],
    ]);
    *pos += SIZE_OF_TYPED_BYTES as usize;
    Ok(TypedBytes(raw))
}

fn rd_payload<'a>(buf: &'a [u8], pos: &mut usize, len: usize) -> Result<&'a [u8], String> {
    if *pos + len > buf.len() {
        return Err(format!(
            "dsc: payload at {pos:#x} truncated (want {len}, have {})",
            buf.len() - *pos
        ));
    }
    let s = &buf[*pos..*pos + len];
    *pos += len;
    Ok(s)
}

fn rd_u32_array(buf: &[u8], pos: &mut usize, count: usize) -> Result<Vec<u32>, String> {
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        if *pos + 4 > buf.len() {
            return Err(format!("dsc: u32 array at {pos:#x} truncated"));
        }
        out.push(rd_u32(buf, *pos)?);
        *pos += 4;
    }
    Ok(out)
}

fn rd_u64_array(buf: &[u8], pos: &mut usize, count: usize) -> Result<Vec<u64>, String> {
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        if *pos + 8 > buf.len() {
            return Err(format!("dsc: u64 array at {pos:#x} truncated"));
        }
        out.push(rd_u64(buf, *pos)?);
        *pos += 8;
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// container / closure / image parsers (closure.go:1171-1575)
// ---------------------------------------------------------------------------

/// One closure container: either a full launch closure or an image array.
#[derive(Debug, Clone, PartialEq)]
pub enum ClosureContainer {
    LaunchClosure(LaunchClosure),
    ImageArray(Vec<CImage>),
}

/// `parseClosureContainers` — walk a stream of container records
/// (`imageArray` / `launchClosure` blobs, as found at `ProgClosuresAddr`,
/// `DylibsImageArrayAddr`, `OtherImageArrayAddr`).
pub fn parse_closure_containers(buf: &[u8]) -> Result<Vec<ClosureContainer>, String> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    loop {
        if pos >= buf.len() {
            break; // io.EOF — clean end of the container stream
        }
        let container = rd_typed_bytes(buf, &mut pos)?;
        match container.kind() {
            Some(ClosureType::LaunchClosure) => {
                let dat = rd_payload(buf, &mut pos, container.payload_length() as usize)?;
                out.push(ClosureContainer::LaunchClosure(parse_launch_closure(dat)?));
            }
            Some(ClosureType::ImageArray) => {
                // Upstream rewinds over the header and re-reads it as part of
                // the image-array blob.
                pos -= SIZE_OF_TYPED_BYTES as usize;
                let dat = rd_payload(
                    buf,
                    &mut pos,
                    container.payload_length() as usize + SIZE_OF_TYPED_BYTES as usize,
                )?;
                out.push(ClosureContainer::ImageArray(parse_closure_image_array(dat)?));
            }
            Some(ClosureType::Image) => {
                return Err("dsc: closure container image not implemented (upstream panics)".into());
            }
            Some(ClosureType::DlopenClosure) => {
                return Err(
                    "dsc: closure container dlopenClosure not implemented (upstream panics)".into(),
                );
            }
            other => {
                return Err(format!(
                    "dsc: got unexpected container type {}",
                    other
                        .map(|k| k.as_str().to_string())
                        .unwrap_or_else(|| format!("closureType({})", container.kind_raw()))
                ));
            }
        }
    }
    Ok(out)
}

/// `parseLaunchClosure` — walk the typed-byte attributes of one closure.
pub fn parse_launch_closure(buf: &[u8]) -> Result<LaunchClosure, String> {
    let mut lc = LaunchClosure::default();
    let mut pos = 0usize;
    loop {
        if pos >= buf.len() {
            break; // io.EOF
        }
        let tbytes = rd_typed_bytes(buf, &mut pos)?;
        match tbytes.kind() {
            Some(ClosureType::ImageArray) => {
                pos -= SIZE_OF_TYPED_BYTES as usize;
                let dat = rd_payload(
                    buf,
                    &mut pos,
                    tbytes.payload_length() as usize + SIZE_OF_TYPED_BYTES as usize,
                )?;
                lc.images.extend(parse_closure_image_array(dat)?);
            }
            Some(ClosureType::ClosureFlags) => {
                lc.flags = LcFlags(rd_u32(buf, pos_and_end(&mut pos, 4)?)?);
            }
            Some(ClosureType::DyldCacheUUID) => {
                let dat = rd_payload(buf, &mut pos, 16)?;
                lc.dyld_uuid.copy_from_slice(dat);
            }
            Some(ClosureType::MissingFiles) => {
                let dat = rd_payload(buf, &mut pos, tbytes.payload_length() as usize)?;
                for part in dat.split(|&b| b == 0) {
                    if !part.is_empty() {
                        lc.missing_files
                            .push(String::from_utf8_lossy(part).into_owned());
                    }
                }
            }
            Some(ClosureType::EnvVar) => {
                let dat = rd_payload(buf, &mut pos, tbytes.payload_length() as usize)?;
                lc.env_vars.push(String::from_utf8_lossy(dat).into_owned());
            }
            Some(ClosureType::TopImage) => {
                lc.top_image = rd_u32(buf, pos_and_end(&mut pos, 4)?)?;
            }
            Some(ClosureType::LibDyldEntry) => {
                lc.lib_dyld_entry = ResolvedSymbolTarget(rd_u64(buf, pos_and_end(&mut pos, 8)?)?);
            }
            Some(ClosureType::LibSystemNum) => {
                lc.lib_system_num = rd_u32(buf, pos_and_end(&mut pos, 4)?)?;
            }
            Some(ClosureType::MainEntry) => {
                lc.main_entry = ResolvedSymbolTarget(rd_u64(buf, pos_and_end(&mut pos, 8)?)?);
            }
            Some(ClosureType::StartEntry) => {
                lc.start_entry = ResolvedSymbolTarget(rd_u64(buf, pos_and_end(&mut pos, 8)?)?);
            }
            Some(ClosureType::CacheOverrides) => {
                let count = tbytes.payload_length() as usize / PATCH_ENTRY_SIZE;
                for i in 0..count {
                    lc.dyld_cache_fixups
                        .push(PatchEntry::parse(buf, pos + i * PATCH_ENTRY_SIZE)?);
                }
                pos += count * PATCH_ENTRY_SIZE;
            }
            Some(ClosureType::InterposeTuples) => {
                return Err(
                    "dsc: launch closure type interposeTuples not implemented (upstream panics)"
                        .into(),
                );
            }
            Some(ClosureType::ExistingFiles) => {
                return Err(
                    "dsc: launch closure type existingFiles not implemented (upstream panics)"
                        .into(),
                );
            }
            // selectorTable / classTable / duplicateClassesTable: skipped
            // exactly like upstream (`r.Seek(payloadLength, io.SeekCurrent)`).
            Some(ClosureType::SelectorTable)
            | Some(ClosureType::ClassTable)
            | Some(ClosureType::DuplicateClassesTable) => {
                rd_payload(buf, &mut pos, tbytes.payload_length() as usize)?;
            }
            Some(ClosureType::Warning) => {
                let mut warn = Warning::default();
                warn.kind = rd_u32(buf, pos_and_end(&mut pos, 4)?)?;
                let msg_len = tbytes.payload_length() as usize - 4;
                warn.message = rd_payload(buf, &mut pos, msg_len)?.to_vec();
                lc.warnings.push(warn);
            }
            Some(ClosureType::ProgVars) => {
                lc.prog_vars = rd_u32(buf, pos_and_end(&mut pos, 4)?)?;
            }
            other => {
                return Err(format!(
                    "dsc: found unsupported launch closure type {}",
                    other
                        .map(|k| k.as_str().to_string())
                        .unwrap_or_else(|| format!("closureType({})", tbytes.kind_raw()))
                ));
            }
        }
    }
    Ok(lc)
}

/// Advance `pos` by `n` and return the original position (read-from helper).
fn pos_and_end(pos: &mut usize, n: usize) -> Result<usize, String> {
    let at = *pos;
    *pos += n;
    Ok(at)
}

/// `parseClosureImageArray` — an image-array blob: 12-byte header, u32
/// offsets per image, then `count` image containers.
pub fn parse_closure_image_array(buf: &[u8]) -> Result<Vec<CImage>, String> {
    let mut iarray = ImageArrayHeader::parse(buf, 0)?;
    let count = iarray.count_and_has_roots.count() as usize;
    let mut pos = IMAGE_ARRAY_HEADER_SIZE;
    let _offsets = rd_u32_array(buf, &mut pos, count)?;

    let mut cimages = Vec::new();
    for _ in 0..count {
        let itype = rd_typed_bytes(buf, &mut pos)?;
        if itype.kind() != Some(ClosureType::Image) {
            return Err(format!(
                "dsc: got unexpected type {}; expected image",
                closure_type_name(itype.kind_raw())
            ));
        }
        let dat = rd_payload(buf, &mut pos, itype.payload_length() as usize)?;
        let ci = parse_closure_image(dat)?;
        if ci.id != 0 {
            // TODO(upstream): why do these zeroed out images exist?
            cimages.push(ci);
        }
    }
    iarray.t = TypedBytes(iarray.t.0); // keep header for symmetry
    Ok(cimages)
}

/// `parseClosureImage` — walk the typed-byte attributes of one image.
pub fn parse_closure_image(buf: &[u8]) -> Result<CImage, String> {
    let mut ci = CImage::default();
    let mut pos = 0usize;
    loop {
        if pos >= buf.len() {
            break; // io.EOF
        }
        let tbytes = rd_typed_bytes(buf, &mut pos)?;
        match tbytes.kind() {
            Some(ClosureType::ImageFlags) => {
                ci.flags = CFlags(rd_u64(buf, pos_and_end(&mut pos, 8)?)?);
                ci.id = ci.get_id();
            }
            Some(ClosureType::PathWithHash) => {
                ci.hash = rd_u32(buf, pos_and_end(&mut pos, 4)?)?;
                let path_len = tbytes.payload_length() as usize - 4;
                let dat = rd_payload(buf, &mut pos, path_len)?;
                ci.name = String::from_utf8_lossy(dat)
                    .trim_matches('\0')
                    .to_string();
            }
            Some(ClosureType::FileInodeAndTime) => {
                ci.file_info = FileInfo::parse(buf, pos_and_end(&mut pos, FILE_INFO_SIZE)?)?;
            }
            Some(ClosureType::CdHash) => {
                if tbytes.payload_length() != 20 {
                    return Err(format!(
                        "dsc: found unexpected cdhash of length {}; expected 20",
                        tbytes.payload_length()
                    ));
                }
                ci.cd_hash = rd_payload(buf, &mut pos, 20)?.to_vec();
            }
            Some(ClosureType::Uuid) => {
                let dat = rd_payload(buf, &mut pos, 16)?;
                ci.uuid.copy_from_slice(dat);
            }
            Some(ClosureType::MappingInfo) => {
                ci.mapping_info =
                    MappingInfo::parse(buf, pos_and_end(&mut pos, MAPPING_INFO_SIZE)?)?;
            }
            Some(ClosureType::DiskSegment) => {
                let count = tbytes.payload_length() as usize / 8;
                let raws = rd_u64_array(buf, &mut pos, count)?;
                ci.disk_segments = raws.into_iter().map(DiskSegmentType).collect();
            }
            Some(ClosureType::CacheSegment) => {
                let count = tbytes.payload_length() as usize / 8;
                let raws = rd_u64_array(buf, &mut pos, count)?;
                ci.cache_segments = raws.into_iter().map(CacheSegmentType).collect();
            }
            Some(ClosureType::Dependents) => {
                let count = tbytes.payload_length() as usize / 4;
                let raws = rd_u32_array(buf, &mut pos, count)?;
                ci.dependents = raws.into_iter().map(LinkedImage).collect();
            }
            Some(ClosureType::InitOffsets) => {
                // upstream appends per record (initOffsets may repeat)
                let count = tbytes.payload_length() as usize / 4;
                ci.initializer_offsets
                    .extend(rd_u32_array(buf, &mut pos, count)?);
            }
            Some(ClosureType::DofOffsets) => {
                let count = tbytes.payload_length() as usize / 4;
                ci.dof_offsets.extend(rd_u32_array(buf, &mut pos, count)?);
            }
            Some(ClosureType::CodeSignLoc) => {
                ci.code_signature_location =
                    CodeSignatureLocation::parse(buf, pos_and_end(&mut pos, CODE_SIGNATURE_LOCATION_SIZE)?)?;
            }
            Some(ClosureType::FarPlayLoc) => {
                ci.far_play_location =
                    FarPlayLoc::parse(buf, pos_and_end(&mut pos, FAR_PLAY_LOC_SIZE)?)?;
            }
            Some(ClosureType::RebaseFixups) => {
                let count = tbytes.payload_length() as usize / 4;
                let raws = rd_u32_array(buf, &mut pos, count)?;
                ci.rebases = raws.into_iter().map(RebasePatternType).collect();
            }
            Some(ClosureType::BindFixups) => {
                let count = tbytes.payload_length() as usize / BIND_PATTERN_SIZE;
                for i in 0..count {
                    ci.binds
                        .push(BindPattern::parse(buf, pos + i * BIND_PATTERN_SIZE)?);
                }
                pos += count * BIND_PATTERN_SIZE;
            }
            Some(ClosureType::CachePatchInfo) => {
                return Err(format!(
                    "dsc: found deprecated type {}",
                    tbytes
                ));
            }
            Some(ClosureType::TextFixups) => {
                let count = tbytes.payload_length() as usize / TEXT_FIXUP_PATTERN_SIZE;
                for i in 0..count {
                    ci.text_fixups
                        .push(TextFixupPattern::parse(buf, pos + i * TEXT_FIXUP_PATTERN_SIZE)?);
                }
                pos += count * TEXT_FIXUP_PATTERN_SIZE;
            }
            Some(ClosureType::ImageOverride) => {
                ci.image_override = rd_u32(buf, pos_and_end(&mut pos, 4)?)?;
            }
            Some(ClosureType::InitBefores) => {
                let count = tbytes.payload_length() as usize / 4;
                ci.init_order = rd_u32_array(buf, &mut pos, count)?;
            }
            Some(ClosureType::InitsSection) => {
                let count = tbytes.payload_length() as usize / INITIALIZER_SECTION_RANGE_SIZE;
                for i in 0..count {
                    ci.initializer_sections.push(InitializerSectionRange::parse(
                        buf,
                        pos + i * INITIALIZER_SECTION_RANGE_SIZE,
                    )?);
                }
                pos += count * INITIALIZER_SECTION_RANGE_SIZE;
            }
            Some(ClosureType::ChainedFixupsTargets) => {
                let count = tbytes.payload_length() as usize / 8;
                let raws = rd_u64_array(buf, &mut pos, count)?;
                ci.chained_fixups_targets = raws.into_iter().map(ResolvedSymbolTarget).collect();
            }
            Some(ClosureType::TermOffsets) => {
                let count = tbytes.payload_length() as usize / 4;
                ci.terminator_offsets
                    .extend(rd_u32_array(buf, &mut pos, count)?);
            }
            Some(ClosureType::ChainedStartsOffset) => {
                ci.chained_starts_offset = rd_u64(buf, pos_and_end(&mut pos, 8)?)?;
            }
            Some(ClosureType::ObjcFixups) => {
                ci.objc_fixups = parse_objc_fixups(buf, &mut pos, tbytes.payload_length() as usize)?;
            }
            other => {
                return Err(format!(
                    "dsc: found unsupported type {}",
                    other
                        .map(|k| k.as_str().to_string())
                        .unwrap_or_else(|| format!("closureType({})", tbytes.kind_raw()))
                ));
            }
        }
    }
    Ok(ci)
}

/// The `objcFixups` record body (closure.go:1529-1568): fixed header,
/// protocol-ISA fixups, sel-ref fixups, then (when payload remains) the
/// stable-swift/method-list section.
fn parse_objc_fixups(buf: &[u8], pos: &mut usize, payload_len: usize) -> Result<ObjcFixups, String> {
    let mut fx = ObjcFixups::default();
    let mut consumed = 0usize;
    fx.header = ObjcFixupsHeader::parse(buf, *pos)?;
    *pos += OBJC_FIXUPS_HEADER_SIZE;
    consumed += OBJC_FIXUPS_HEADER_SIZE;

    if fx.header.protocol_fixup_count > 0 {
        // NOTE: rd_u64_array already advances `pos`; only `consumed` is
        // tracked manually here (a double-advance here desynchronises the
        // enclosing image record walk).
        let raws = rd_u64_array(buf, pos, fx.header.protocol_fixup_count as usize)?;
        fx.protocol_isa_fixups = raws.into_iter().map(ProtocolISAFixup).collect();
        consumed += fx.header.protocol_fixup_count as usize * 8;
    }
    if fx.header.sel_ref_fixup_count > 0 {
        let raws = rd_u32_array(buf, pos, fx.header.sel_ref_fixup_count as usize)?;
        fx.sel_ref_fixups = raws.into_iter().map(SelectorReferenceFixup).collect();
        consumed += fx.header.sel_ref_fixup_count as usize * 4;
    }
    if payload_len > consumed {
        fx.stable_swift_fixup_count = rd_u32(buf, pos_and_end(pos, 4)?)?;
        fx.method_list_fixup_count = rd_u32(buf, pos_and_end(pos, 4)?)?;
        if fx.stable_swift_fixup_count > 0 {
            let raws = rd_u64_array(buf, pos, fx.stable_swift_fixup_count as usize)?;
            fx.class_stable_swift_fixups = raws.into_iter().map(ClassStableSwiftFixup).collect();
        }
        if fx.method_list_fixup_count > 0 {
            let raws = rd_u64_array(buf, pos, fx.method_list_fixup_count as usize)?;
            fx.method_list_fixups = raws.into_iter().map(MethodListFixup).collect();
        }
    }
    Ok(fx)
}

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

    /// Append a typedBytes record: `type:8 | len:24` header + payload.
    fn put_record(v: &mut Vec<u8>, kind: u32, payload: &[u8]) {
        let raw = ((payload.len() as u32) << 8) | kind;
        v.extend_from_slice(&raw.to_le_bytes());
        v.extend_from_slice(payload);
    }

    #[test]
    fn closure_type_names_match_stringer() {
        // boundaries from closure_string.go
        for (raw, name) in [
            (1u32, "launchClosure"),
            (2, "imageArray"),
            (3, "image"),
            (4, "dlopenClosure"),
            (7, "imageFlags"),
            (8, "pathWithHash"),
            (9, "fileInodeAndTime"),
            (10, "cdHash"),
            (11, "uuid"),
            (12, "mappingInfo"),
            (13, "diskSegment"),
            (14, "cacheSegment"),
            (15, "dependents"),
            (16, "initOffsets"),
            (17, "dofOffsets"),
            (18, "codeSignLoc"),
            (19, "farPlayLoc"),
            (20, "rebaseFixups"),
            (21, "bindFixups"),
            (22, "cachePatchInfo"),
            (23, "textFixups"),
            (24, "imageOverride"),
            (25, "initBefores"),
            (26, "initsSection"),
            (27, "chainedFixupsTargets"),
            (28, "termOffsets"),
            (29, "chainedStartsOffset"),
            (30, "objcFixups"),
            (32, "closureFlags"),
            (33, "dyldCacheUUID"),
            (34, "missingFiles"),
            (35, "envVar"),
            (36, "topImage"),
            (37, "libDyldEntry"),
            (38, "libSystemNum"),
            (40, "mainEntry"),
            (41, "startEntry"),
            (42, "cacheOverrides"),
            (43, "interposeTuples"),
            (44, "existingFiles"),
            (45, "selectorTable"),
            (46, "classTable"),
            (47, "warning"),
            (48, "duplicateClassesTable"),
            (49, "progVars"),
        ] {
            let k = ClosureType::from_u32(raw).unwrap_or_else(|| panic!("kind {raw}"));
            assert_eq!(k.as_str(), name, "kind {raw}");
            assert_eq!(closure_type_name(raw), name);
        }
        // holes in the numbering
        assert!(ClosureType::from_u32(5).is_none());
        assert!(ClosureType::from_u32(6).is_none());
        assert!(ClosureType::from_u32(31).is_none());
        assert!(ClosureType::from_u32(39).is_none());
        assert_eq!(closure_type_name(5), "closureType(5)");
        assert_eq!(closure_type_name(39), "closureType(39)");
    }

    #[test]
    fn typed_bytes_bit_fields() {
        let tb = TypedBytes(0x1234_5601); // kind 1, length 0x123456
        assert_eq!(tb.kind_raw(), 1);
        assert_eq!(tb.kind(), Some(ClosureType::LaunchClosure));
        assert_eq!(tb.payload_length(), 0x1234_56);
        assert_eq!(
            format!("{tb}"),
            "type: launchClosure, length: 0x123456, raw: 0x12345601"
        );

        let empty = TypedBytes(0x0400_0000); // kind 0, length 0x40000? -> kind 0 unknown
        assert_eq!(empty.kind_raw(), 0);
        assert!(empty.kind().is_none());

        assert_eq!(SIZE_OF_TYPED_BYTES, 4);
    }

    #[test]
    fn count_and_has_roots() {
        let cr = CountAndHasRoots(3 | (1 << 31));
        assert_eq!(cr.count(), 3);
        assert!(cr.has_roots());
        assert_eq!(CountAndHasRoots(7).count(), 7);
        assert!(!CountAndHasRoots(7).has_roots());
    }

    #[test]
    fn lc_flags_mirrors_upstream() {
        // Upstream quirk (documented on LcFlags): all bools read bits 0..16.
        let f = LcFlags(2); // init image count 2 => every "bool" true
        assert_eq!(f.init_image_count(), 2);
        assert!(f.used_at_paths());
        assert!(f.used_fallback_paths());
        assert!(f.has_inserted_libraries());
        assert!(f.has_prog_vars());
        assert!(f.used_interposing());
        assert_eq!(f.padding(), 2);
        let zero = LcFlags(0);
        assert!(!zero.used_at_paths());
        assert!(!zero.used_fallback_paths()); // note: Display prints fallback_paths when false
        assert_eq!(
            format!("{zero}"),
            "initial_image_count: 0, flags: [fallback_paths]"
        );
    }

    #[test]
    fn c_flags_all_bits() {
        let mut f = CFlags(0);
        f = CFlags(f.0 | 0x0007); // image_num 7
        f = CFlags(f.0 | (0x5AB << 16)); // max_load_count 12 bits
        f = CFlags(f.0 | (1 << 28)); // invalid
        f = CFlags(f.0 | (1 << 29)); // 16k pages
        f = CFlags(f.0 | (1 << 30)); // 64-bit
        f = CFlags(f.0 | (1 << 31)); // objc
        f = CFlags(f.0 | (1 << 32)); // plus loads
        f = CFlags(f.0 | (1 << 33)); // encrypted
        f = CFlags(f.0 | (1 << 34)); // weak defs
        f = CFlags(f.0 | (1 << 35)); // never unload
        f = CFlags(f.0 | (1 << 36)); // cwd
        f = CFlags(f.0 | (1 << 37)); // platform binary
        f = CFlags(f.0 | (1 << 38)); // bundle
        f = CFlags(f.0 | (1 << 39)); // dylib
        f = CFlags(f.0 | (1 << 40)); // executable
        f = CFlags(f.0 | (1 << 41)); // overridable
        f = CFlags(f.0 | (1 << 42)); // in cache
        f = CFlags(f.0 | (1 << 43)); // terminators
        f = CFlags(f.0 | (1 << 44)); // ro data
        f = CFlags(f.0 | (1 << 45)); // chained fixups
        f = CFlags(f.0 | (1 << 46)); // precomputed objc
        f = CFlags(f.0 | (1 << 47)); // fixups not encoded
        f = CFlags(f.0 | (1 << 48)); // rebases not encoded
        f = CFlags(f.0 | (1 << 49)); // override image num

        assert_eq!(f.image_num(), 7);
        assert_eq!(f.max_load_count(), 0x5AB);
        assert!(f.is_invalid());
        assert!(f.has_16kb_pages());
        assert!(f.is_64());
        assert!(f.has_objc());
        assert!(f.may_have_plus_loads());
        assert!(f.is_encrypted());
        assert!(f.has_weak_defs());
        assert!(f.never_unload());
        assert!(f.cwd_same_as_this());
        assert!(f.is_platform_binary());
        assert!(f.is_bundle());
        assert!(f.is_dylib());
        assert!(f.is_executable());
        assert!(f.overridable_dylib());
        assert!(f.in_dyld_cache());
        assert!(f.has_terminators());
        assert!(f.has_read_only_data());
        assert!(f.has_chained_fixups());
        assert!(f.has_precomputed_objc());
        assert!(f.fixups_not_encoded());
        assert!(f.rebases_not_encoded());
        assert!(f.has_override_image_num());
    }

    #[test]
    fn segment_and_pattern_packings() {
        let cs = CacheSegmentType(0x1000u64 | (0x2000 << 32) | (5 << 60));
        assert_eq!(cs.cache_offset(), 0x1000);
        assert_eq!(cs.size(), 0x2000);
        assert_eq!(cs.permissions(), 5);

        let ds = DiskSegmentType(1u64 | (2 << 30) | (2 << 60));
        assert_eq!(ds.file_page_count(), 1);
        assert_eq!(ds.vm_page_count(), 2);
        assert_eq!(ds.permissions(), 2);
        assert_eq!(ds.perm_string(), "-w-"); // upstream read-only-data special case
        assert!(!ds.padding_not_seg());
        let pad = DiskSegmentType(1 << 63);
        assert!(pad.padding_not_seg());

        let rp = RebasePatternType(3 | (2 << 20) | (1 << 28));
        assert_eq!(rp.repeat_count(), 3);
        assert_eq!(rp.contig_count(), 2);
        assert_eq!(rp.skip_count(), 1);

        // resolvedSymbolTarget kinds
        let sc = ResolvedSymbolTarget(1 | (0x1234 << 2));
        assert_eq!(sc.kind(), TargetKind::SharedCache);
        assert_eq!(sc.shared_cache_offset(), 0x1234);
        assert_eq!(format!("{sc}"), "kind: shared_cache, offset: 0x1234");

        let img = ResolvedSymbolTarget(2 | (3 << 2) | (0x5000 << 24));
        assert_eq!(img.kind(), TargetKind::Image);
        assert_eq!(img.image_num(), 3);
        assert_eq!(img.image_offset(), 0x5000);
        assert_eq!(format!("{img}"), "kind: image, index: 3, offset: 0x5000");

        let abs = ResolvedSymbolTarget(3 | (0x1234_5678_9ABC << 2));
        assert_eq!(abs.kind(), TargetKind::Absolute);
        // upstream AbsoluteValue does NOT sign-extend (comment lies); mirrored
        assert_eq!(abs.absolute_value(), 0x1234_5678_9ABC);
        assert_eq!(format!("{abs}"), "kind: absolute, value: 0x123456789abc");

        let rb = ResolvedSymbolTarget(0);
        assert_eq!(rb.kind(), TargetKind::Rebase);
        assert_eq!(format!("{rb}"), "kind: rebase, raw: 0x0");

        let bp = BindPatternType(0x40 | (3 << 40) | (2 << 48));
        assert_eq!(bp.start_vm_offset(), 0x40);
        assert_eq!(bp.skip_count(), 3);
        assert_eq!(bp.repeat_count(), 2);
    }

    #[test]
    fn linked_image_and_chain_entry() {
        let li = LinkedImage(2 | (1 << 30)); // weak link to image 2
        assert_eq!(li.img_num(), 2);
        assert_eq!(li.link(), LinkKind::Weak);
        assert_eq!(LinkKind::ReExport.as_str(), "reExport");
        assert_eq!(li.link().as_str(), "weak");

        let ce = ChainEntry(7 | (3 << 24) | (1 << 31));
        assert_eq!(ce.index(), 7);
        assert_eq!(ce.next(), 3);
        assert!(ce.in_shared_cache());
        let sf = SelectorReferenceFixup(ce.0);
        assert_eq!(sf.chain_entry().index(), 7);
    }

    #[test]
    fn fixup_pattern_trait() {
        let p = ProtocolISAFixup(0x10 | (1 << 40) | (2 << 48));
        assert_eq!(FixupPattern::start_vm_offset(&p), 0x10);
        assert_eq!(FixupPattern::skip_count(&p), 1);
        assert_eq!(FixupPattern::repeat_count(&p), 2);
        let c = ClassStableSwiftFixup(0x20);
        assert_eq!(FixupPattern::start_vm_offset(&c), 0x20);
        let m = MethodListFixup(0x30);
        assert_eq!(FixupPattern::start_vm_offset(&m), 0x30);
    }

    #[test]
    fn parse_closure_contents_walks_records() {
        let mut v: Vec<u8> = Vec::new();
        put_record(&mut v, 32, &[3, 0, 0, 0]); // closureFlags + u32
        put_record(&mut v, 35, b"DYLD_X=1"); // envVar
        put_record(&mut v, 38, &[2, 0, 0, 0]); // libSystemNum
        let records = parse_closure_contents(&v, 0, v.len()).unwrap();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].kind, Some(ClosureType::ClosureFlags));
        assert_eq!(records[0].kind_raw, 32);
        assert_eq!(records[0].header_offset, 0);
        assert_eq!(records[0].payload, vec![3, 0, 0, 0]);
        assert_eq!(records[1].kind, Some(ClosureType::EnvVar));
        assert_eq!(records[1].payload, b"DYLD_X=1".to_vec());
        assert!(records[1].header_offset > 0);
        assert_eq!(records[2].kind, Some(ClosureType::LibSystemNum));

        // unknown kinds are still records at the format level
        let mut v2: Vec<u8> = Vec::new();
        put_record(&mut v2, 5, &[0xAA]);
        let records2 = parse_closure_contents(&v2, 0, v2.len()).unwrap();
        assert_eq!(records2.len(), 1);
        assert!(records2[0].kind.is_none());
        assert_eq!(records2[0].kind_name(), "closureType(5)");

        // non-zero start offset
        let mut v3 = vec![0xEE; 3];
        v3.extend_from_slice(&v);
        let records3 = parse_closure_contents(&v3, 3, v.len()).unwrap();
        assert_eq!(records3.len(), 3);
        assert_eq!(records3[0].header_offset, 0);

        // truncation errors
        assert!(parse_closure_contents(&v, 0, v.len() - 1).is_err());
        assert!(parse_closure_contents(&v, 0, 2).is_err());
        assert!(parse_closure_contents(&v, 0, v.len() + 4).is_err());
    }

    #[test]
    fn parse_launch_closure_full() {
        let mut v: Vec<u8> = Vec::new();
        // closureFlags(32): init image count 2
        put_record(&mut v, 32, &2u32.to_le_bytes());
        // dyldCacheUUID(33)
        let uuid: Vec<u8> = (0..16).collect();
        put_record(&mut v, 33, &uuid);
        // libSystemNum(38)
        put_record(&mut v, 38, &2u32.to_le_bytes());
        // topImage(36)
        put_record(&mut v, 36, &1u32.to_le_bytes());
        // libDyldEntry(37): kind=SharedCache, cache offset 0x1000
        put_record(&mut v, 37, &(1u64 | (0x1000 << 2)).to_le_bytes());
        // mainEntry(40): kind=Image, image num 2, image offset 0x2000
        put_record(&mut v, 40, &(2u64 | (2 << 2) | (0x2000 << 24)).to_le_bytes());
        // startEntry(41): kind=SharedCache, cache offset 0x1234
        put_record(&mut v, 41, &(1u64 | (0x1234 << 2)).to_le_bytes());
        // envVar(35) + missingFiles(34)
        put_record(&mut v, 35, b"DYLD_PRINT_LIBRARIES=1");
        put_record(&mut v, 34, b"/nope\0/gone\0");
        // warning(47): u32 type + message
        let mut warn = 1u32.to_le_bytes().to_vec();
        warn.extend_from_slice(b"careful");
        put_record(&mut v, 47, &warn);
        // cacheOverrides(42): one PatchEntry
        let mut patch = 5u32.to_le_bytes().to_vec();
        patch.extend_from_slice(&0x600u32.to_le_bytes());
        patch.extend_from_slice(&(1u64 | (0x800 << 2)).to_le_bytes());
        put_record(&mut v, 42, &patch);
        // skipped tables
        put_record(&mut v, 45, &[0xAA; 8]); // selectorTable
        put_record(&mut v, 46, &[0xBB; 8]); // classTable
        put_record(&mut v, 48, &[0xCC; 4]); // duplicateClassesTable
        // progVars(49)
        put_record(&mut v, 49, &6u32.to_le_bytes());
        // imageArray(2) — a full container IN the record stream (the walker
        // rewinds over its own typedBytes header and reads len+4 bytes), so
        // it must NOT be re-wrapped by put_record.
        let array = build_image_array();
        v.extend_from_slice(&array);

        let lc = parse_launch_closure(&v).unwrap();
        assert_eq!(lc.flags.init_image_count(), 2);
        assert_eq!(lc.dyld_uuid, uuid.as_slice());
        assert_eq!(lc.lib_system_num, 2);
        assert_eq!(lc.top_image, 1);
        assert_eq!(lc.lib_dyld_entry.kind(), TargetKind::SharedCache);
        assert_eq!(lc.lib_dyld_entry.shared_cache_offset(), 0x1000);
        assert_eq!(lc.main_entry.kind(), TargetKind::Image);
        assert_eq!(lc.main_entry.image_num(), 2);
        assert_eq!(lc.main_entry.image_offset(), 0x2000);
        assert_eq!(lc.start_entry.kind(), TargetKind::SharedCache);
        assert_eq!(lc.start_entry.shared_cache_offset(), 0x1234);
        assert_eq!(lc.env_vars, vec!["DYLD_PRINT_LIBRARIES=1"]);
        assert_eq!(lc.missing_files, vec!["/nope", "/gone"]);
        assert_eq!(lc.warnings.len(), 1);
        assert_eq!(lc.warnings[0].kind, 1);
        assert_eq!(lc.warnings[0].message, b"careful".to_vec());
        assert_eq!(lc.dyld_cache_fixups.len(), 1);
        assert_eq!(lc.dyld_cache_fixups[0].overridden_dylib_in_cache, 5);
        assert_eq!(lc.dyld_cache_fixups[0].export_cache_offset, 0x600);
        assert_eq!(
            lc.dyld_cache_fixups[0].replacement.kind(),
            TargetKind::SharedCache
        );
        assert_eq!(lc.prog_vars, 6);
        assert_eq!(lc.images.len(), 2); // zero-id image skipped

        // image attribute coverage
        let i0 = &lc.images[0];
        assert_eq!(i0.id, 1);
        assert_eq!(i0.get_id(), 1);
        assert_eq!(i0.page_size(), 0x1000);
        assert!(i0.flags.is_64());
        assert!(i0.flags.in_dyld_cache());
        assert_eq!(i0.name, "/usr/lib/libfoo.dylib");
        assert_eq!(i0.hash, 0x1234);
        assert_eq!(i0.uuid, (0..16).collect::<Vec<u8>>().as_slice());
        assert_eq!(i0.mapping_info.total_vm_pages, 0x40);
        assert_eq!(i0.mapping_info.slice_offset_in_4k, 0);
        assert_eq!(i0.cache_segments.len(), 1);
        assert_eq!(i0.cache_segments[0].cache_offset(), 0x1000);
        assert_eq!(i0.cache_segments[0].size(), 0x2000);
        assert_eq!(i0.cache_segments[0].permissions(), 5);
        assert_eq!(i0.disk_segments.len(), 1);
        assert_eq!(i0.disk_segments[0].perm_string(), "-w-");
        assert_eq!(i0.dependents.len(), 1);
        assert_eq!(i0.dependents[0].img_num(), 2);
        assert_eq!(i0.dependents[0].link(), LinkKind::Weak);
        assert_eq!(i0.initializer_offsets, vec![0x100, 0x200]);
        assert_eq!(i0.dof_offsets, vec![0x300]);
        assert_eq!(i0.terminator_offsets, vec![0x400]);
        assert_eq!(i0.init_order, vec![3]);
        assert_eq!(i0.initializer_sections.len(), 1);
        assert_eq!(i0.initializer_sections[0].section_offset, 0x500);
        assert_eq!(i0.code_signature_location.file_offset, 0x6000);
        assert_eq!(i0.code_signature_location.file_size, 0x100);
        assert_eq!(i0.far_play_location.range_start, 0x7000);
        assert_eq!(i0.cd_hash, vec![7u8; 20]);
        assert_eq!(i0.file_info.inode, 0x42);
        assert_eq!(i0.file_info.mod_time, 0x99);
        assert_eq!(i0.rebases.len(), 1);
        assert_eq!(i0.rebases[0].repeat_count(), 3);
        assert_eq!(i0.rebases[0].contig_count(), 2);
        assert_eq!(i0.rebases[0].skip_count(), 1);
        assert_eq!(i0.binds.len(), 1);
        assert_eq!(i0.binds[0].target.kind(), TargetKind::SharedCache);
        assert_eq!(i0.binds[0].detail.start_vm_offset(), 0x40);
        assert_eq!(i0.text_fixups.len(), 1);
        assert_eq!(i0.text_fixups[0].start_vm_offset, 0x50);
        assert_eq!(i0.text_fixups[0].repeat_count, 2);
        assert_eq!(i0.text_fixups[0].skip_count, 1);
        assert_eq!(i0.chained_fixups_targets.len(), 1);
        assert_eq!(i0.chained_fixups_targets[0].kind(), TargetKind::Absolute);
        assert_eq!(i0.chained_starts_offset, 0x8000);
        assert_eq!(i0.image_override, 9);
        assert_eq!(i0.objc_fixups.header.protocol_fixup_count, 1);
        assert_eq!(i0.objc_fixups.header.sel_ref_fixup_count, 1);
        assert_eq!(i0.objc_fixups.protocol_isa_fixups.len(), 1);
        assert_eq!(
            FixupPattern::start_vm_offset(&i0.objc_fixups.protocol_isa_fixups[0]),
            0x10
        );
        assert_eq!(i0.objc_fixups.sel_ref_fixups.len(), 1);
        assert_eq!(i0.objc_fixups.sel_ref_fixups[0].chain_entry().index(), 7);
        assert!(i0.objc_fixups.sel_ref_fixups[0].chain_entry().in_shared_cache());
        assert_eq!(i0.objc_fixups.stable_swift_fixup_count, 1);
        assert_eq!(i0.objc_fixups.class_stable_swift_fixups.len(), 1);
        assert_eq!(i0.objc_fixups.method_list_fixup_count, 1);
        assert_eq!(i0.objc_fixups.method_list_fixups.len(), 1);
        assert_eq!(i0.objc_fixups.header.image_info_vm_offset, 0x6000);

        let i1 = &lc.images[1];
        assert_eq!(i1.id, 2);
        assert!(i1.flags.is_executable());
        assert_eq!(i1.name, "/bin/ls");
        assert_eq!(i1.page_size(), 0x4000); // 16k pages flag set
    }

    /// Build the image array used by `parse_launch_closure_full` /
    /// `parse_closure_containers_roundtrip`: two real images + one zero-id
    /// image (which upstream drops).
    fn build_image_array() -> Vec<u8> {
        let mut img1: Vec<u8> = Vec::new();
        // imageFlags(7): id=1, 64-bit, in cache
        put_record(
            &mut img1,
            7,
            &(1u64 | (1 << 30) | (1 << 42)).to_le_bytes(),
        );
        // pathWithHash(8): u32 hash + NUL-terminated path
        let mut path = 0x1234u32.to_le_bytes().to_vec();
        path.extend_from_slice(b"/usr/lib/libfoo.dylib\0");
        put_record(&mut img1, 8, &path);
        // uuid(11)
        let uuid: Vec<u8> = (0..16).collect();
        put_record(&mut img1, 11, &uuid);
        // mappingInfo(12)
        let mut mi = 0x40u32.to_le_bytes().to_vec();
        mi.extend_from_slice(&0u32.to_le_bytes());
        put_record(&mut img1, 12, &mi);
        // cacheSegment(14): one u64
        put_record(
            &mut img1,
            14,
            &(0x1000u64 | (0x2000 << 32) | (5 << 60)).to_le_bytes(),
        );
        // diskSegment(13): one u64, perms 2 (read-only-data quirk)
        put_record(&mut img1, 13, &(1u64 | (2 << 30) | (2 << 60)).to_le_bytes());
        // dependents(15): one u32 — weak link to image 2
        put_record(&mut img1, 15, &(2u32 | (1 << 30)).to_le_bytes());
        // initOffsets(16) / dofOffsets(17) / termOffsets(28) / initBefores(25)
        put_record(&mut img1, 16, &0x100u32.to_le_bytes());
        put_record(&mut img1, 16, &0x200u32.to_le_bytes());
        put_record(&mut img1, 17, &0x300u32.to_le_bytes());
        put_record(&mut img1, 28, &0x400u32.to_le_bytes());
        put_record(&mut img1, 25, &3u32.to_le_bytes());
        // initsSection(26)
        let mut is = 0x500u32.to_le_bytes().to_vec();
        is.extend_from_slice(&0x10u32.to_le_bytes());
        put_record(&mut img1, 26, &is);
        // codeSignLoc(18) / farPlayLoc(19)
        let mut cs = 0x6000u32.to_le_bytes().to_vec();
        cs.extend_from_slice(&0x100u32.to_le_bytes());
        put_record(&mut img1, 18, &cs);
        let mut fp = 0x7000u32.to_le_bytes().to_vec();
        fp.extend_from_slice(&0x800u32.to_le_bytes());
        put_record(&mut img1, 19, &fp);
        // cdHash(10): exactly 20 bytes
        put_record(&mut img1, 10, &vec![7u8; 20]);
        // fileInodeAndTime(9)
        let mut fi = 0x42u64.to_le_bytes().to_vec();
        fi.extend_from_slice(&0x99u64.to_le_bytes());
        put_record(&mut img1, 9, &fi);
        // rebaseFixups(20)
        put_record(&mut img1, 20, &(3u32 | (2 << 20) | (1 << 28)).to_le_bytes());
        // bindFixups(21): target + detail
        let mut bp = (1u64 | (0x1234 << 2)).to_le_bytes().to_vec();
        bp.extend_from_slice(&(0x40u64 | (1 << 40) | (2 << 48)).to_le_bytes());
        put_record(&mut img1, 21, &bp);
        // textFixups(23): target + u32 + u16 + u16
        let mut tf = (0u64).to_le_bytes().to_vec();
        tf.extend_from_slice(&0x50u32.to_le_bytes());
        tf.extend_from_slice(&2u16.to_le_bytes());
        tf.extend_from_slice(&1u16.to_le_bytes());
        put_record(&mut img1, 23, &tf);
        // chainedFixupsTargets(27)
        put_record(
            &mut img1,
            27,
            &(3u64 | (0x1234_5678_9ABCu64 << 2)).to_le_bytes(),
        );
        // chainedStartsOffset(29)
        put_record(&mut img1, 29, &0x8000u64.to_le_bytes());
        // objcFixups(30)
        let mut of = Vec::new();
        of.extend_from_slice(&(2u64 | (3 << 2) | (0x5000 << 24)).to_le_bytes()); // protocol class target
        of.extend_from_slice(&0x6000u64.to_le_bytes()); // image info vm offset
        of.extend_from_slice(&1u32.to_le_bytes()); // protocol fixup count
        of.extend_from_slice(&1u32.to_le_bytes()); // sel ref fixup count
        of.extend_from_slice(&0x10u64.to_le_bytes()); // one protocolISAFixup
        of.extend_from_slice(&(7u32 | (3 << 24) | (1 << 31)).to_le_bytes()); // one sel ref fixup
        of.extend_from_slice(&1u32.to_le_bytes()); // stable swift count
        of.extend_from_slice(&1u32.to_le_bytes()); // method list count
        of.extend_from_slice(&0x20u64.to_le_bytes()); // one classStableSwiftFixup
        of.extend_from_slice(&0x30u64.to_le_bytes()); // one methodListFixup
        put_record(&mut img1, 30, &of);
        // imageOverride(24)
        put_record(&mut img1, 24, &9u32.to_le_bytes());

        // image 2: minimal executable
        let mut img2: Vec<u8> = Vec::new();
        put_record(
            &mut img2,
            7,
            &(2u64 | (1 << 29) | (1 << 40)).to_le_bytes(), // id=2, 16k pages, executable
        );
        let mut path2 = 0xBEEFu32.to_le_bytes().to_vec();
        path2.extend_from_slice(b"/bin/ls\0");
        put_record(&mut img2, 8, &path2);

        // image 3: zero id — upstream drops these
        let mut img3: Vec<u8> = Vec::new();
        put_record(&mut img3, 7, &0u64.to_le_bytes());

        // array blob: header + offsets + image containers
        let mut images_bytes: Vec<u8> = Vec::new();
        for img in [&img1, &img2, &img3] {
            put_record(&mut images_bytes, 3, img);
        }
        let mut v: Vec<u8> = Vec::new();
        // payload after the typedBytes header: first-image-num (4) +
        // count/roots (4) + 3 offsets (12) + the image containers
        let total_after_t = 8 + 12 + images_bytes.len(); // frst + cr + offsets + images
        v.extend_from_slice(&(((total_after_t as u32) << 8) | 2).to_le_bytes()); // typedBytes(imageArray)
        v.extend_from_slice(&1u32.to_le_bytes()); // first image num
        v.extend_from_slice(&(3u32 | (1 << 31)).to_le_bytes()); // count=3, has_roots
        v.extend_from_slice(&0xDEADu32.to_le_bytes()); // offsets[0] (unused by parser)
        v.extend_from_slice(&0xBEEFu32.to_le_bytes()); // offsets[1]
        v.extend_from_slice(&0xF00Du32.to_le_bytes()); // offsets[2]
        v.extend_from_slice(&images_bytes);
        v
    }

    #[test]
    fn parse_closure_image_array_direct() {
        let arr = build_image_array();
        let images = parse_closure_image_array(&arr).unwrap();
        assert_eq!(images.len(), 2); // zero-id image dropped
        assert_eq!(images[0].id, 1);
        assert_eq!(images[1].id, 2);
    }

    #[test]
    fn parse_closure_containers_roundtrip() {
        // container 1: image array
        let array = build_image_array();
        let mut v: Vec<u8> = Vec::new();
        v.extend_from_slice(&array); // already starts with its own typedBytes header

        // container 2: launch closure
        let mut lc_payload: Vec<u8> = Vec::new();
        put_record(&mut lc_payload, 32, &4u32.to_le_bytes());
        put_record(&mut lc_payload, 49, &1u32.to_le_bytes());
        let lc_len = lc_payload.len() as u32;
        let mut lc_container = ((lc_len << 8) | 1).to_le_bytes().to_vec();
        lc_container.extend_from_slice(&lc_payload);
        v.extend_from_slice(&lc_container);

        let containers = parse_closure_containers(&v).unwrap();
        assert_eq!(containers.len(), 2);
        match &containers[0] {
            ClosureContainer::ImageArray(images) => {
                assert_eq!(images.len(), 2);
                assert_eq!(images[0].name, "/usr/lib/libfoo.dylib");
            }
            _ => panic!("expected image array container"),
        }
        match &containers[1] {
            ClosureContainer::LaunchClosure(lc) => {
                assert_eq!(lc.flags.init_image_count(), 4);
                assert_eq!(lc.prog_vars, 1);
            }
            _ => panic!("expected launch closure container"),
        }
    }

    #[test]
    fn unsupported_and_deprecated_kinds_error() {
        // deprecated cachePatchInfo inside an image
        let mut img: Vec<u8> = Vec::new();
        put_record(&mut img, 7, &1u64.to_le_bytes());
        put_record(&mut img, 22, &[0; 4]);
        assert!(parse_closure_image(&img)
            .unwrap_err()
            .contains("deprecated"));

        // unknown image attribute
        let mut img2: Vec<u8> = Vec::new();
        put_record(&mut img2, 7, &1u64.to_le_bytes());
        put_record(&mut img2, 5, &[0; 4]);
        assert!(parse_closure_image(&img2).unwrap_err().contains("closureType(5)"));

        // unknown launch-closure attribute
        let mut lc: Vec<u8> = Vec::new();
        put_record(&mut lc, 6, &[0; 4]);
        assert!(parse_launch_closure(&lc)
            .unwrap_err()
            .contains("unsupported launch closure type"));

        // cdhash must be 20 bytes
        let mut img3: Vec<u8> = Vec::new();
        put_record(&mut img3, 10, &[0; 19]);
        assert!(parse_closure_image(&img3).unwrap_err().contains("cdhash"));

        // upstream-panic kinds become errors
        let mut lc2: Vec<u8> = Vec::new();
        put_record(&mut lc2, 43, &[0; 8]); // interposeTuples
        assert!(parse_launch_closure(&lc2).unwrap_err().contains("interposeTuples"));
        let mut lc3: Vec<u8> = Vec::new();
        put_record(&mut lc3, 44, &[0; 8]); // existingFiles
        assert!(parse_launch_closure(&lc3).unwrap_err().contains("existingFiles"));

        // unknown container type
        let mut c: Vec<u8> = Vec::new();
        put_record(&mut c, 5, &[0; 4]);
        assert!(parse_closure_containers(&c)
            .unwrap_err()
            .contains("unexpected container type"));

        // Image/DlopenClosure containers are upstream panics -> errors here
        let mut c2: Vec<u8> = Vec::new();
        put_record(&mut c2, 3, &[0; 4]);
        assert!(parse_closure_containers(&c2).is_err());
    }

    #[test]
    fn image_array_header_layout() {
        let mut buf = vec![0u8; 16];
        w32(&mut buf, 0, ((0x42u32) << 8) | 2); // typedBytes(imageArray), len 0x42
        w32(&mut buf, 4, 1); // first image num
        w32(&mut buf, 8, 5 | (1 << 31)); // count 5 + roots
        let h = ImageArrayHeader::parse(&buf, 0).unwrap();
        assert_eq!(h.t.kind(), Some(ClosureType::ImageArray));
        assert_eq!(h.t.payload_length(), 0x42);
        assert_eq!(h.first_image_num, 1);
        assert_eq!(h.count_and_has_roots.count(), 5);
        assert!(h.count_and_has_roots.has_roots());
        assert_eq!(IMAGE_ARRAY_HEADER_SIZE, 12);
        assert_eq!(FIRST_DYLD_CACHE_IMAGE_NUM, 1);
        assert_eq!(LAST_DYLD_CACHE_IMAGE_NUM, 0xFFF);
        assert_eq!(FIRST_OTHER_OS_IMAGE_NUM, 0x1001);
        assert_eq!(LAST_OTHER_OS_IMAGE_NUM, 0x1FFF);
        assert_eq!(FIRST_LAUNCH_CLOSURE_IMAGE_NUM, 0x2000);
        assert_eq!(MISSING_WEAK_LINKED_IMAGE, 0x0FFF_FFFF);
    }

    #[test]
    fn patch_entry_and_small_struct_layouts() {
        let mut buf = vec![0u8; 64];
        w32(&mut buf, 0, 5);
        w32(&mut buf, 4, 0x600);
        w64(&mut buf, 8, 1 | (0x800 << 2));
        let pe = PatchEntry::parse(&buf, 0).unwrap();
        assert_eq!(pe.overridden_dylib_in_cache, 5);
        assert_eq!(pe.export_cache_offset, 0x600);
        assert_eq!(pe.replacement.shared_cache_offset(), 0x800);
        assert_eq!(PATCH_ENTRY_SIZE, 16);

        w64(&mut buf, 24, 0x1234);
        w64(&mut buf, 32, 0x5678);
        let fi = FileInfo::parse(&buf, 24).unwrap();
        assert_eq!(fi.inode, 0x1234);
        assert_eq!(fi.mod_time, 0x5678);
        assert_eq!(FILE_INFO_SIZE, 16);

        w32(&mut buf, 40, 0x10);
        w32(&mut buf, 44, 0x20);
        let mi = MappingInfo::parse(&buf, 40).unwrap();
        assert_eq!(mi.total_vm_pages, 0x10);
        assert_eq!(mi.slice_offset_in_4k, 0x20);
        assert_eq!(MAPPING_INFO_SIZE, 8);
    }

    #[test]
    fn truncated_payloads_error() {
        let mut v: Vec<u8> = Vec::new();
        put_record(&mut v, 33, &[1u8; 16]);
        // cut one byte of the uuid payload
        assert!(parse_launch_closure(&v[..v.len() - 1]).is_err());
        // cut the typedBytes header in half
        assert!(parse_launch_closure(&v[..2]).is_err());
        // empty payload parses to defaults
        let lc = parse_launch_closure(&[]).unwrap();
        assert_eq!(lc.images.len(), 0);
        assert_eq!(lc.flags, LcFlags(0));
    }
}
