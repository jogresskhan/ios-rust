//! slide — slide-info (rebase) parsing and the chained-pointer walks for
//! versions 2/3/4/5. Version 1 (ancient TOC+bitmap) is parsed but its walk
//! is honestly reported as unsupported.
//!
//! The A13/T8030-relevant path is **v3** (iOS 12–14 arm64: iOS 13/14 on the
//! A13 uses `dyld_v1   arm64` with 4 KB pages and slide v3) and **v4/v5**
//! for dyld4 (iOS 15+) caches.
//!
//! Parity: ipsw `pkg/dyld/file.go:1138 parseSlideInfo` +
//! `pkg/dyld/types.go` CacheSlideInfo{2,3,4,5}/CacheSlidePointer{2,3,4,5}
//! (Apple dyld_cache_format.h).

/// A resolved rebase: where the pointer lives and where it points.
#[derive(Debug, Clone, Copy)]
pub struct Rebase {
    /// File offset of the pointer within its cache member.
    pub cache_file_offset: u64,
    /// Unslid VM address of the pointer.
    pub cache_vm_address: u64,
    /// Resolved target (unslid VM address or raw value).
    pub target: u64,
    /// Raw pointer bits before resolution.
    pub raw: u64,
}

/// Bit-extraction helper (ipsw `types.ExtractBits(value, start, count)`).
#[inline]
pub fn extract_bits(value: u64, start: u32, count: u32) -> u64 {
    if count >= 64 {
        value >> start
    } else {
        (value >> start) & ((1u64 << count) - 1)
    }
}

/// How many trailing zeros a mask has (ipsw `bits.TrailingZeros64`).
#[inline]
fn trailing_zeros64(x: u64) -> u32 {
    if x == 0 {
        64
    } else {
        x.trailing_zeros()
    }
}

// -- version 2 constants ----------------------------------------------------
pub const SLIDE_PAGE_ATTRS: u16 = 0xC000;
pub const SLIDE_PAGE_ATTR_EXTRA: u16 = 0x8000;
pub const SLIDE_PAGE_ATTR_NO_REBASE: u16 = 0x4000;
pub const SLIDE_PAGE_ATTR_END: u16 = 0x8000;

// -- version 4 constants ----------------------------------------------------
pub const SLIDE4_PAGE_NO_REBASE: u16 = 0xFFFF;
pub const SLIDE4_PAGE_USE_EXTRA: u16 = 0x8000;
pub const SLIDE4_PAGE_EXTRA_END: u16 = 0x8000;
pub const SLIDE4_PAGE_INDEX: u16 = 0x7FFF;

// -- version 3/5 constants --------------------------------------------------
pub const SLIDE_V3_PAGE_ATTR_NO_REBASE: u16 = 0xFFFF;
pub const SLIDE_V5_PAGE_ATTR_NO_REBASE: u16 = 0xFFFF;

/// Parsed slide-info header + the page-starts/extras tables.
#[derive(Debug, Clone)]
pub enum SlideInfo {
    /// v1: legacy TOC + 128-byte bitmap entries (walk unsupported).
    V1 {
        version: u32,
        toc_offset: u32,
        toc_count: u32,
        entries_offset: u32,
        entries_count: u32,
        entries_size: u32,
    },
    /// v2: u64 pointers, delta chains (iOS ≤ 11 non-arm64e).
    V2 {
        page_size: u32,
        delta_mask: u64,
        value_add: u64,
        starts: Vec<u16>,
        extras: Vec<u16>,
    },
    /// v3: u64 pointers, `page_starts` right after the 24-byte header
    /// (arm64/arm64e iOS 12–14 — the A13 iOS 13/14 case).
    V3 {
        page_size: u32,
        auth_value_add: u64,
        starts: Vec<u16>,
    },
    /// v4: u32 pointers, delta chains with extras (arm64_32 / iOS 15+).
    V4 {
        page_size: u32,
        delta_mask: u64,
        value_add: u64,
        starts: Vec<u16>,
        extras: Vec<u16>,
    },
    /// v5: u64 pointers with 34-bit runtime offsets (arm64e iOS 15+).
    V5 {
        page_size: u32,
        value_add: u64,
        starts: Vec<u16>,
    },
}

impl SlideInfo {
    pub fn version(&self) -> u32 {
        match self {
            SlideInfo::V1 { .. } => 1,
            SlideInfo::V2 { .. } => 2,
            SlideInfo::V3 { .. } => 3,
            SlideInfo::V4 { .. } => 4,
            SlideInfo::V5 { .. } => 5,
        }
    }
}

/// Parse the slide-info blob at `data` (already sliced to
/// `[slide_info_offset .. slide_info_offset + slide_info_size]` of the
/// member file).
pub fn parse_slide_info(data: &[u8]) -> Result<SlideInfo, String> {
    if data.len() < 24 {
        return Err(format!("dsc: slide info too small ({} bytes)", data.len()));
    }
    let rd32 = |o: usize| u32::from_le_bytes(data[o..o + 4].try_into().unwrap());
    let rd64 = |o: usize| u64::from_le_bytes(data[o..o + 8].try_into().unwrap());
    let version = rd32(0);
    match version {
        1 => Ok(SlideInfo::V1 {
            version,
            toc_offset: rd32(4),
            toc_count: rd32(8),
            entries_offset: rd32(12),
            entries_count: rd32(16),
            entries_size: rd32(20),
        }),
        2 => {
            if data.len() < 40 {
                return Err("dsc: slide v2 header truncated".into());
            }
            let page_size = rd32(4);
            let starts_offset = rd32(8) as usize;
            let starts_count = rd32(12) as usize;
            let extras_offset = rd32(16) as usize;
            let _extras_count = rd32(20);
            let delta_mask = rd64(24);
            let value_add = rd64(32);
            Ok(SlideInfo::V2 {
                page_size,
                delta_mask,
                value_add,
                starts: read_u16_table(data, starts_offset, starts_count)?,
                extras: read_u16_table(data, extras_offset, data.len().saturating_sub(extras_offset) / 2)?,
            })
        }
        3 => {
            let page_size = rd32(4);
            let starts_count = rd32(8) as usize;
            let auth_value_add = rd64(16);
            // Page starts sit directly after the 24-byte header.
            Ok(SlideInfo::V3 {
                page_size,
                auth_value_add,
                starts: read_u16_table(data, 24, starts_count)?,
            })
        }
        4 => {
            if data.len() < 40 {
                return Err("dsc: slide v4 header truncated".into());
            }
            let page_size = rd32(4);
            let starts_offset = rd32(8) as usize;
            let starts_count = rd32(12) as usize;
            let extras_offset = rd32(16) as usize;
            let _extras_count = rd32(20);
            let delta_mask = rd64(24);
            let value_add = rd64(32);
            Ok(SlideInfo::V4 {
                page_size,
                delta_mask,
                value_add,
                starts: read_u16_table(data, starts_offset, starts_count)?,
                extras: read_u16_table(data, extras_offset, data.len().saturating_sub(extras_offset) / 2)?,
            })
        }
        5 => {
            let page_size = rd32(4);
            let starts_count = rd32(8) as usize;
            let value_add = rd64(16);
            Ok(SlideInfo::V5 {
                page_size,
                value_add,
                starts: read_u16_table(data, 24, starts_count)?,
            })
        }
        v => Err(format!("dsc: unsupported slide info version {v}")),
    }
}

fn read_u16_table(data: &[u8], offset: usize, count: usize) -> Result<Vec<u16>, String> {
    let mut out = Vec::with_capacity(count.min(1 << 20));
    for i in 0..count {
        let o = offset + i * 2;
        if o + 2 > data.len() {
            break;
        }
        out.push(u16::from_le_bytes([data[o], data[o + 1]]));
    }
    Ok(out)
}

// -- pointer formats ---------------------------------------------------------

/// v3 regular pointer: sign-extend the 51-bit value
/// (top-8-bits << 13 | sign-extended bottom 43 bits).
fn sign_extend_51(ptr: u64) -> u64 {
    let top8 = ptr & 0x007F_8000_0000_0000;
    let bottom43 = ptr & 0x0000_07FF_FFFF_FFFF;
    (top8 << 13) | (((bottom43 << 21) >> 21) & 0x00FF_FFFF_FFFF_FFFF)
}

/// v2 target resolution (ipsw `CacheSlideInfo2.SlidePointer`).
fn slide_pointer_v2(ptr: u64, delta_mask: u64, value_add: u64) -> u64 {
    let shift = 64 - value_add.leading_zeros() as u64; // bits.Len64(ValueAdd)
    let mask = u64::MAX >> shift << shift;
    if ptr > value_add && (ptr & mask) == 0 {
        return ptr;
    }
    if (ptr & !delta_mask) != 0 {
        (ptr & !delta_mask) + value_add
    } else {
        0
    }
}

/// v4 target resolution (ipsw `CacheSlideInfo4.SlidePointer`).
fn slide_pointer_v4(ptr: u64, delta_mask: u64, value_add: u64) -> u64 {
    let mut value = ptr & !delta_mask;
    if (value & 0xFFFF_8000) == 0 {
        // small positive non-pointer, use as-is
    } else if (value & 0x3FFF_8000) == 0x3FFF_8000 {
        // small negative non-pointer
        value |= 0xC000_0000;
    } else {
        value += value_add;
    }
    value
}

/// Reader over the member file bytes used during chain walks.
struct Member<'a> {
    data: &'a [u8],
}

impl<'a> Member<'a> {
    fn read_u64(&self, off: u64) -> Option<u64> {
        let o = off as usize;
        if o + 8 <= self.data.len() {
            Some(u64::from_le_bytes(self.data[o..o + 8].try_into().unwrap()))
        } else {
            None
        }
    }
    fn read_u32(&self, off: u64) -> Option<u32> {
        let o = off as usize;
        if o + 4 <= self.data.len() {
            Some(u32::from_le_bytes(self.data[o..o + 4].try_into().unwrap()))
        } else {
            None
        }
    }
}

/// Walk one mapping's slide info, yielding every rebase. `mapping_address`
/// / `mapping_file_offset` locate the mapped region within the member.
///
/// Returns `(rebases, unsupported_pages)`: the second value counts pages
/// skipped honestly (v1 pages, or chain reads that fell out of the member).
pub fn walk_mapping(
    member_data: &[u8],
    slide: &SlideInfo,
    mapping_address: u64,
    mapping_file_offset: u64,
    mapping_size: u64,
) -> (Vec<Rebase>, usize) {
    let member = Member { data: member_data };
    let mut rebases = Vec::new();
    let mut skipped = 0usize;
    match slide {
        SlideInfo::V1 { .. } => {
            // Legacy bitmap format: walking it needs the per-entry bitmaps;
            // the modern A13 restore path never hits v1. Report honestly.
            skipped = usize::MAX / 2; // sentinel: "whole mapping unsupported"
        }
        SlideInfo::V2 {
            page_size,
            delta_mask,
            value_add,
            starts,
            extras,
        } => {
            let delta_shift = trailing_zeros64(*delta_mask) as u64 - 2;
            for (i, &start) in starts.iter().enumerate() {
                let page_addr = mapping_address + (i as u64) * *page_size as u64;
                let page_off = mapping_file_offset + (i as u64) * *page_size as u64;
                if page_addr - mapping_address >= mapping_size {
                    break;
                }
                if start & SLIDE_PAGE_ATTR_NO_REBASE != 0 {
                    continue;
                }
                let mut chain_offsets: Vec<u32> = Vec::new();
                if start & SLIDE_PAGE_ATTR_EXTRA != 0 {
                    let mut j = (start & 0x3FFF) as usize;
                    loop {
                        match extras.get(j) {
                            Some(&e) => {
                                chain_offsets.push((e & 0x3FFF) as u32 * 4);
                                if e & SLIDE_PAGE_ATTR_END != 0 {
                                    break;
                                }
                                j += 1;
                            }
                            None => {
                                skipped += 1;
                                break;
                            }
                        }
                    }
                } else {
                    chain_offsets.push((start as u32) * 4);
                }
                for start_offset in chain_offsets {
                    let mut off = start_offset as u64;
                    loop {
                        let Some(raw) = member.read_u64(page_off + off) else {
                            skipped += 1;
                            break;
                        };
                        let delta = ((raw & *delta_mask) >> delta_shift) as u32;
                        let target = slide_pointer_v2(raw, *delta_mask, *value_add);
                        rebases.push(Rebase {
                            cache_file_offset: page_off + off,
                            cache_vm_address: page_addr + off,
                            target,
                            raw,
                        });
                        if delta == 0 {
                            break;
                        }
                        off += delta as u64;
                    }
                }
            }
        }
        SlideInfo::V3 {
            page_size,
            auth_value_add,
            starts,
        } => {
            for (i, &start) in starts.iter().enumerate() {
                let page_addr = mapping_address + (i as u64) * *page_size as u64;
                let page_off = mapping_file_offset + (i as u64) * *page_size as u64;
                if page_addr - mapping_address >= mapping_size {
                    break;
                }
                let mut delta = start as u64;
                if delta == SLIDE_V3_PAGE_ATTR_NO_REBASE as u64 {
                    continue;
                }
                let mut rebase_loc = page_off;
                let mut rebase_addr = page_addr;
                loop {
                    rebase_loc += delta;
                    rebase_addr += delta;
                    let Some(raw) = member.read_u64(rebase_loc) else {
                        skipped += 1;
                        break;
                    };
                    // CacheSlidePointer3 bit layout:
                    //   pointerValue:51, offsetToNext:11, unused:2,
                    //   diversity:16, addrDiv:1, key:2, auth:1
                    let authenticated = extract_bits(raw, 63, 1) != 0;
                    let target = if authenticated {
                        auth_value_add + extract_bits(raw, 0, 32)
                    } else {
                        sign_extend_51(raw)
                    };
                    rebases.push(Rebase {
                        cache_file_offset: rebase_loc,
                        cache_vm_address: rebase_addr,
                        target,
                        raw,
                    });
                    let next = extract_bits(raw, 51, 11);
                    if next == 0 {
                        break;
                    }
                    delta = next * 8;
                }
            }
        }
        SlideInfo::V4 {
            page_size,
            delta_mask,
            value_add,
            starts,
            extras,
        } => {
            let delta_shift = trailing_zeros64(*delta_mask) as u64 - 2;
            for (i, &start) in starts.iter().enumerate() {
                let page_addr = mapping_address + (i as u64) * *page_size as u64;
                let page_off = mapping_file_offset + (i as u64) * *page_size as u64;
                if page_addr - mapping_address >= mapping_size {
                    break;
                }
                if start == SLIDE4_PAGE_NO_REBASE {
                    continue;
                }
                let mut chain_offsets: Vec<u32> = Vec::new();
                if start & SLIDE4_PAGE_USE_EXTRA != 0 {
                    let mut j = (start & SLIDE4_PAGE_INDEX) as usize;
                    loop {
                        match extras.get(j) {
                            Some(&e) => {
                                chain_offsets.push((e & SLIDE4_PAGE_INDEX) as u32 * 4);
                                if e & SLIDE4_PAGE_EXTRA_END != 0 {
                                    break;
                                }
                                j += 1;
                            }
                            None => {
                                skipped += 1;
                                break;
                            }
                        }
                    }
                } else {
                    chain_offsets.push((start & 0x7FFF) as u32 * 4);
                }
                for start_offset in chain_offsets {
                    let mut off = start_offset as u64;
                    loop {
                        let Some(raw32) = member.read_u32(page_off + off) else {
                            skipped += 1;
                            break;
                        };
                        let raw = raw32 as u64;
                        let delta = ((raw & *delta_mask) >> delta_shift) as u32;
                        let target = slide_pointer_v4(raw, *delta_mask, *value_add);
                        rebases.push(Rebase {
                            cache_file_offset: page_off + off,
                            cache_vm_address: page_addr + off,
                            target,
                            raw,
                        });
                        if delta == 0 {
                            break;
                        }
                        off += delta as u64;
                    }
                }
            }
        }
        SlideInfo::V5 {
            page_size,
            value_add,
            starts,
        } => {
            for (i, &start) in starts.iter().enumerate() {
                let page_addr = mapping_address + (i as u64) * *page_size as u64;
                let page_off = mapping_file_offset + (i as u64) * *page_size as u64;
                if page_addr - mapping_address >= mapping_size {
                    break;
                }
                let mut delta = start as u64;
                if delta == SLIDE_V5_PAGE_ATTR_NO_REBASE as u64 {
                    continue;
                }
                let mut rebase_loc = page_off;
                let mut rebase_addr = page_addr;
                loop {
                    rebase_loc += delta;
                    rebase_addr += delta;
                    let Some(raw) = member.read_u64(rebase_loc) else {
                        skipped += 1;
                        break;
                    };
                    // CacheSlidePointer5 bit layout:
                    //   runtimeOffset:34, high8:8, unused:10, next:11, auth:1
                    let authenticated = extract_bits(raw, 63, 1) != 0;
                    let target = if authenticated {
                        // diversity:34..50, addrDiv:50, keyIsData:51;
                        // target = ValueAdd + offset(bits 0..34)
                        value_add + extract_bits(raw, 0, 34)
                    } else {
                        // regular: runtimeOffset:34 | high8 << 56
                        value_add + (extract_bits(raw, 0, 34) | (extract_bits(raw, 34, 8) << 56))
                    };
                    rebases.push(Rebase {
                        cache_file_offset: rebase_loc,
                        cache_vm_address: rebase_addr,
                        target,
                        raw,
                    });
                    let next = extract_bits(raw, 52, 11);
                    if next == 0 {
                        break;
                    }
                    delta = next * 8;
                }
            }
        }
    }
    (rebases, skipped)
}
