//! file — the `Dsc` container: a dyld shared cache plus its subcache
//! members and the optional `.symbols` file, with cross-member VM↔file
//! translation and rebase walking.
//!
//! Parity: ipsw `pkg/dyld/file.go Open/parseHeader/parseMappings/
//! parseImages/parseSubCaches/GetOffset/GetCacheVMAddress/parseSlideInfo`
//! + `localSymbols`.

use std::collections::BTreeMap;
use std::path::Path;

use crate::header::CacheHeader;
use crate::image::{parse_images, parse_images_text, CacheImage, CacheImageTextInfo};
use crate::localsyms::{self, LocalSymbol};
use crate::mapping::{parse_mappings, parse_mappings_with_slide, CacheMapping};
use crate::slide::{self, Rebase};
use crate::subcache::{member_path, parse_subcaches, symbols_path, SubcacheEntry};

/// One loaded cache file (main, subcache member, or `.symbols`).
#[derive(Debug, Clone)]
pub struct CacheMember {
    /// Member UUID (main cache: header UUID; subcache: entry UUID;
    /// symbols: SymbolFileUUID).
    pub uuid: [u8; 16],
    /// VM offset of this member within the shared region (main = 0).
    pub vm_offset: u64,
    /// Filesystem path it was read from.
    pub path: String,
    /// Full file bytes. (The Go tool mmaps; we read whole files — CLI-scale
    /// honest tradeoff, documented in the crate docs.)
    pub data: Vec<u8>,
}

impl CacheMember {
    /// Parse the member's own header + mappings.
    fn parse(&self) -> Result<MemberInfo, String> {
        let hdr = CacheHeader::parse(&self.data)?;
        let mappings: Vec<CacheMapping>;
        if hdr.slide_info_offset_unused > 0 {
            // Old-style: plain mappings; slide info hangs off __DATA.
            let mut ms = parse_mappings(&self.data, hdr.mapping_offset, hdr.mapping_count)?;
            for m in ms.iter_mut() {
                if m.name == "__DATA" {
                    m.slide_info_offset = hdr.slide_info_offset_unused;
                    m.slide_info_size = hdr.slide_info_size_unused;
                    m.has_slide_info = m.slide_info_size > 0;
                }
            }
            mappings = ms;
        } else if hdr.mapping_with_slide_count > 0 {
            mappings = parse_mappings_with_slide(
                &self.data,
                hdr.mapping_with_slide_offset,
                hdr.mapping_with_slide_count,
            )?;
        } else {
            mappings = parse_mappings(&self.data, hdr.mapping_offset, hdr.mapping_count)?;
        }
        Ok(MemberInfo {
            header: hdr,
            mappings,
        })
    }
}

/// Parsed per-member state.
#[derive(Debug, Clone)]
pub struct MemberInfo {
    pub header: CacheHeader,
    pub mappings: Vec<CacheMapping>,
}

/// A dyld shared cache: the main file plus every subcache member and the
/// optional `.symbols` file.
pub struct Dsc {
    /// The primary cache (index 0 of `members`).
    pub members: Vec<CacheMember>,
    /// Parsed per-member info (parallel to `members`).
    infos: Vec<MemberInfo>,
    /// Subcache table from the primary header (empty on single-file caches).
    pub subcaches: Vec<SubcacheEntry>,
    /// Main header (shortcut to `infos[0].header`).
    pub header: CacheHeader,
    images: Vec<CacheImage>,
    images_text: Vec<CacheImageTextInfo>,
}

impl Dsc {
    /// Open a cache from its main file, loading subcache members and the
    /// `.symbols` file from the same directory per the naming rules.
    pub fn open(main_path: impl AsRef<Path>) -> Result<Dsc, String> {
        let main_path = main_path.as_ref();
        let main_data = std::fs::read(main_path)
            .map_err(|e| format!("dsc: cannot read {}: {e}", main_path.display()))?;
        let header = CacheHeader::parse(&main_data)?;
        let mut members = vec![CacheMember {
            uuid: header.uuid,
            vm_offset: 0,
            path: main_path.display().to_string(),
            data: main_data,
        }];

        // Subcache members.
        let subcaches = parse_subcaches(&members[0].data, &header)?;
        if !subcaches.is_empty() {
            let dir = main_path
                .parent()
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| Path::new(".").to_path_buf());
            let file_name = main_path
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            for (i, entry) in subcaches.iter().enumerate() {
                let name = member_path(&file_name, &header, entry, i);
                let path = dir.join(&name);
                let data = std::fs::read(&path).map_err(|e| {
                    format!("dsc: cannot read subcache member {}: {e}", path.display())
                })?;
                if data.len() < 0x118 {
                    return Err(format!(
                        "dsc: subcache member {} too small",
                        path.display()
                    ));
                }
                // Member UUID sanity: each member's header UUID must match
                // the table's declaration (ipsw file.go:274+).
                let mut member_uuid = [0u8; 16];
                member_uuid.copy_from_slice(&data[0x58..0x68]);
                if member_uuid != entry.uuid {
                    return Err(format!(
                        "dsc: subcache member {} UUID mismatch (table {:?} vs file {:?})",
                        path.display(),
                        entry.uuid,
                        member_uuid
                    ));
                }
                members.push(CacheMember {
                    uuid: entry.uuid,
                    vm_offset: entry.cache_vm_offset,
                    path: path.display().to_string(),
                    data,
                });
            }
        }

        // The `.symbols` file (unmapped local symbols) — dyld4 caches.
        if let Some(sym_path) = symbols_path(&main_path.display().to_string(), &header) {
            let p = main_path
                .parent()
                .map(|d| d.join(&sym_path))
                .unwrap_or_else(|| Path::new(&sym_path).to_path_buf());
            if p.exists() {
                let data = std::fs::read(&p)
                    .map_err(|e| format!("dsc: cannot read {}: {e}", p.display()))?;
                members.push(CacheMember {
                    uuid: header.symbol_file_uuid,
                    // Unmapped member: its VM offset is one past the last
                    // mapped member's end (ipsw file.go symbols handling).
                    vm_offset: subcaches
                        .last()
                        .map(|s| {
                            s.cache_vm_offset + header.shared_region_size
                        })
                        .unwrap_or(0),
                    path: p.display().to_string(),
                    data,
                });
            }
        }

        let infos = members
            .iter()
            .map(|m| m.parse())
            .collect::<Result<Vec<MemberInfo>, String>>()?;

        let header_first = CacheHeader::parse(&members[0].data)?;

        let mut dsc = Dsc {
            members,
            infos,
            subcaches,
            header: header_first,
            images: Vec::new(),
            images_text: Vec::new(),
        };
        dsc.images = parse_images(&dsc.members[0].data, &dsc.header);
        dsc.images_text = parse_images_text(&dsc.members[0].data, &dsc.header);
        Ok(dsc)
    }

    pub fn images(&self) -> &[CacheImage] {
        &self.images
    }

    pub fn images_text(&self) -> &[CacheImageTextInfo] {
        &self.images_text
    }

    /// All mappings across all mapped members.
    pub fn mappings(&self) -> Vec<(usize, &CacheMapping)> {
        let mut out = Vec::new();
        for (i, info) in self.infos.iter().enumerate() {
            if i == self.members.len() - 1 && self.is_symbols_member(i) {
                continue; // .symbols member is unmapped
            }
            for m in &info.mappings {
                out.push((i, m));
            }
        }
        out
    }

    fn is_symbols_member(&self, idx: usize) -> bool {
        idx > 0
            && idx == self.members.len() - 1
            && self.header.symbol_file_uuid != [0u8; 16]
            && self.members[idx].uuid == self.header.symbol_file_uuid
    }

    /// VM address → (member index, file offset) across all members
    /// (ipsw `GetOffset`).
    pub fn get_offset(&self, vmaddr: u64) -> Option<(usize, u64)> {
        for (i, info) in self.infos.iter().enumerate() {
            if self.is_symbols_member(i) {
                continue;
            }
            for m in &info.mappings {
                if vmaddr >= m.address && vmaddr < m.address + m.size {
                    return Some((i, vmaddr - m.address + m.file_offset));
                }
            }
        }
        None
    }

    /// File offset (with its member) → unslid VM address (ipsw
    /// `GetCacheVMAddress` inverse).
    pub fn get_vmaddr(&self, member_idx: usize, file_offset: u64) -> Option<u64> {
        let info = self.infos.get(member_idx)?;
        for m in &info.mappings {
            if file_offset >= m.file_offset && file_offset < m.file_offset + m.size {
                return Some(file_offset - m.file_offset + m.address);
            }
        }
        None
    }

    /// Find an image by path substring (case-insensitive full-path match,
    /// mirroring the common ipsw lookups).
    pub fn find_image(&self, needle: &str) -> Option<&CacheImage> {
        let n = needle.to_lowercase();
        self.images
            .iter()
            .find(|im| im.path.to_lowercase().contains(&n))
    }

    /// Walk every mapping that carries slide info, across all members.
    ///
    /// Returns rebases plus a count of honestly-skipped pages/chains
    /// (out-of-range reads, unsupported v1 mappings).
    pub fn rebases(&self) -> Result<(Vec<Rebase>, usize), String> {
        let mut all = Vec::new();
        let mut skipped = 0usize;
        for (i, info) in self.infos.iter().enumerate() {
            if self.is_symbols_member(i) {
                continue;
            }
            for m in &info.mappings {
                if !m.has_slide_info || m.slide_info_size == 0 {
                    continue;
                }
                let o = m.slide_info_offset as usize;
                let e = o.saturating_add(m.slide_info_size as usize).min(self.members[i].data.len());
                if o >= e {
                    continue;
                }
                let blob = &self.members[i].data[o..e];
                let slide = slide::parse_slide_info(blob)?;
                let (mut r, s) = slide::walk_mapping(
                    &self.members[i].data,
                    &slide,
                    m.address,
                    m.file_offset,
                    m.size,
                );
                if s == usize::MAX / 2 {
                    skipped += 1; // one whole unsupported (v1) mapping
                } else {
                    skipped += s;
                }
                all.append(&mut r);
            }
        }
        Ok((all, skipped))
    }

    /// Local symbols: from the `.symbols` member on dyld4 caches, else the
    /// main file at `LocalSymbolsOffset`. Returns `None` when the cache
    /// carries no local-symbol blob.
    pub fn local_symbols(&self) -> Result<Option<Vec<LocalSymbol>>, String> {
        if self.header.local_symbols_size == 0 && self.header.symbol_file_uuid == [0u8; 16] {
            return Ok(None);
        }
        let blob: Option<&[u8]> = if self.header.symbol_file_uuid != [0u8; 16] {
            // dyld4: offsets are relative to the .symbols file itself.
            self.members
                .iter()
                .find(|m| m.uuid == self.header.symbol_file_uuid)
                .map(|m| m.data.as_slice())
        } else {
            let o = self.header.local_symbols_offset as usize;
            let e = o
                .saturating_add(self.header.local_symbols_size as usize)
                .min(self.members[0].data.len());
            if o < e {
                Some(&self.members[0].data[o..e])
            } else {
                None
            }
        };
        match blob {
            Some(b) => Ok(Some(localsyms::parse_symbols(b)?)),
            None => Ok(None),
        }
    }

    /// Byte-range dump: the raw bytes backing `[vmaddr, vmaddr+len)`.
    pub fn read_vm(&self, vmaddr: u64, len: usize) -> Option<Vec<u8>> {
        let (mi, off) = self.get_offset(vmaddr)?;
        let data = &self.members[mi].data;
        let off = off as usize;
        let end = off.checked_add(len)?;
        if end > data.len() {
            return None;
        }
        Some(data[off..end].to_vec())
    }

    /// A summary for CLI printing.
    pub fn summary(&self) -> BTreeMap<String, String> {
        let mut s = BTreeMap::new();
        let h = &self.header;
        s.insert("magic".into(), h.magic());
        s.insert("uuid".into(), uuid_str(&h.uuid));
        s.insert(
            "cache_type".into(),
            h.cache_type().map(|t| t.as_str().to_string()).unwrap_or_default(),
        );
        s.insert("platform".into(), format!("{}", h.platform));
        let (maj, min, patch) = crate::header::unpack_version(h.os_version);
        s.insert("os_version".into(), format!("{maj}.{min}.{patch}"));
        s.insert("is_dyld4".into(), h.is_dyld4().to_string());
        s.insert("format_version".into(), format!("{}", h.format_version));
        s.insert(
            "shared_region".into(),
            format!(
                "{:#x}..{:#x}",
                h.shared_region_start,
                h.shared_region_start + h.shared_region_size
            ),
        );
        s.insert("max_slide".into(), format!("{:#x}", h.max_slide));
        s.insert("members".into(), self.members.len().to_string());
        s.insert("images".into(), self.images.len().to_string());
        s.insert("images_text".into(), self.images_text.len().to_string());
        let mapping_count = self.infos.iter().map(|i| i.mappings.len()).sum::<usize>();
        s.insert("mappings".into(), mapping_count.to_string());
        s
    }
}

/// Format a UUID the Apple way (8-4-4-4-12).
pub fn uuid_str(u: &[u8; 16]) -> String {
    format!(
        "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7], u[8], u[9], u[10], u[11], u[12], u[13],
        u[14], u[15]
    )
}
