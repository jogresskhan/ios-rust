//! dart — Apple Device Address Resolution Table, T8030 generation.
//!
//! Faithful Rust port of ChefKiss Inferno `hw/arm/apple-silicon/dart.c`
//! (AGPL-3.0, © 2024-2026 Visual Ehrmanntraut). Register offsets, field
//! positions, TTBR layout, PTE format and the page-table walk are kept
//! exactly as in the C.
//!
//! Walk geometry (verified against the C — *not* the M1-style DART):
//! `apple_dart_from_node` picks, for `page-size = 0x1000`:
//!   l_mask  = [0xC0000, 0x3FE00, 0x1FF]
//!   l_shift = [0x12,    9,      0   ]
//! `apple_dart_mapper_ptw` uses level 0 to select one of the 4 TTBRs of
//! the stream (`(iova & 0xC0000) >> 18`, 2 bits — note the C shares bit
//! 17 between the L0 and L1 masks, which is upstream behavior), then
//! walks two 64-bit PTE levels. This is a 3-read walk (TTBR + L1 + L2),
//! *not* the 4-level `[25,18,11,4]` walker of the newer apple-silicon
//! DART (see ios-sweet-rust `qemu-sweet/overlay/hw/misc/sweet_dart.c`,
//! which uses STT/L2/L3 = 10/9/9 for the T8015 "old DART" instead).
//!
//! Guest memory access during the walk goes through the caller-provided
//! `table_reader` closure (address → 64-bit LE word), the moral
//! equivalent of the C's `address_space_ldq(&address_space_memory, pa)`.
//!
//! Bypass semantics: the C's translate treats "translation disabled"
//! and "full bypass" as *no valid mapping* (entry left with
//! IOMMU_NONE), keeping its own `// TODO ... (?)` — ported as `None`.

use vm_core::Device;

pub const DART_MAX_STREAMS: usize = 16;
pub const DART_MAX_TTBR: usize = 4;
pub const DART_MAX_VA_BITS: u32 = 38;
pub const DART_MAX_TLB_OP_SETS: usize = 1;
pub const DART_TLB_OP_INVALIDATE: u32 = 0;

// REG32 map (hw/registerfields.h style, offsets verbatim).
pub const REG_DART_PARAMS1: u64 = 0x0; // PAGE_SHIFT [24:27], ACCESS_REGION_PROTECTION [31]
pub const REG_DART_PARAMS2: u64 = 0x4; // BYPASS_SUPPORT [0], LOCK_SUPPORT [1]
// 0x8..0x1C = ??
pub const REG_DART_TLB_OP: u64 = 0x20; // OP [1:0], BUSY [2], HARDWARE_FLUSH [3], WAY_INDEX [7:4], TE_INDEX [10:8], SET_INDEX [31:20]
// 0x24..0x30 = ??
pub const REG_DART_TLB_OP_SET_0_LOW: u64 = 0x34;
pub const REG_DART_TLB_OP_SET_0_HIGH: u64 = 0x38;
// 0x3C = ??
pub const REG_DART_ERROR_STATUS: u64 = 0x40;
pub const REG_DART_ERROR_ADDRESS_LOW: u64 = 0x50;
pub const REG_DART_ERROR_ADDRESS_HIGH: u64 = 0x54;
pub const REG_DART_CONFIG: u64 = 0x60; // LOCK [15]
pub const A_DART_SID_REMAP: u64 = 0x80; // + sid<<2 (u32 word per 4 remap bytes)
pub const REG_DART_SID_VALID: u64 = 0xFC;
pub const A_DART_SID_CONFIG: u64 = 0x100; // + sid*4
pub const A_DART_TLB_CONFIG: u64 = 0x180; // + sid*4
pub const A_DART_TTBR: u64 = 0x200; // + (16*sid + 4*idx) * 4

// DART_TLB_OP fields.
pub const DART_TLB_OP_OP_MASK: u32 = 0x3;
pub const DART_TLB_OP_BUSY: u32 = 1 << 2;
pub const DART_TLB_OP_HARDWARE_FLUSH: u32 = 1 << 3;
pub const DART_TLB_OP_SET_INDEX_SHIFT: u32 = 20;

// DART_ERROR_STATUS fields.
pub const DART_ERROR_TTBR_INVLD: u32 = 1 << 0;
pub const DART_ERROR_L2E_INVLD: u32 = 1 << 1;
pub const DART_ERROR_PTE_INVLD: u32 = 1 << 2;
pub const DART_ERROR_WRITE_PROT: u32 = 1 << 3;
pub const DART_ERROR_READ_PROT: u32 = 1 << 4;
pub const DART_ERROR_AXI_SLV_DECODE: u32 = 1 << 5;
pub const DART_ERROR_AXI_SLV_ERR: u32 = 1 << 6;
pub const DART_ERROR_REGION_PROT: u32 = 1 << 7;
pub const DART_ERROR_CTRR_WRITE_PROT: u32 = 1 << 8;
pub const DART_ERROR_UNKNOWN: u32 = 1 << 9;
pub const DART_ERROR_APF_REJECT: u32 = 1 << 11;
pub const DART_ERROR_SID_SHIFT: u32 = 24;
pub const DART_ERROR_FLAG: u32 = 1 << 31;

// DART_SID_CONFIG fields.
pub const DART_SIDCFG_TRANSLATION_ENABLE: u32 = 1 << 7;
pub const DART_SIDCFG_FULL_BYPASS: u32 = 1 << 8;

// TTBR / PTE formats.
pub const DART_TTBR_VALID: u32 = 1 << 31;
pub const DART_TTBR_SHIFT: u64 = 12;
pub const DART_TTBR_MASK: u32 = 0x0FFF_FFFF;
pub const DART_PTE_NO_WRITE: u64 = 1 << 7;
pub const DART_PTE_NO_READ: u64 = 1 << 8;
pub const DART_PTE_VALID: u64 = 1 << 0;
pub const DART_PTE_ADDR_MASK: u64 = 0xF_FFFF_FFFF;

// Direct-mapped translation cache size (behavioral stand-in for QEMU's
// IOMMU TLB; flushed by TLB_OP invalidates and TTBR/SID_CONFIG writes).
const TLB_ENTRIES: usize = 4096;

#[derive(Debug, Clone, Copy, Default)]
struct TlbEntry {
    iova_page: u64,
    pa_page: u64,
    sid: u32,
    valid: bool,
    readable: bool,
    writable: bool,
}

/// DART mapper instance (the C's `AppleDARTMapperInstance` with type
/// DART_DART; DAPF/SMMU dummy instances are machine-side stubs).
#[derive(Debug)]
pub struct Dart {
    pub page_shift: u32,
    pub page_size: u64,
    pub page_bits: u64,
    pub page_mask: u64,
    l_mask: [u64; 3],
    l_shift: [u64; 3],
    /// sids bitmap from the DT (`sids` prop, default 0xFFFF).
    pub sid_mask: u64,
    /// `dart-options` DT prop (bit 1 → ACCESS_REGION_PROTECTION).
    pub dart_options: u32,

    params1: u32,
    params2: u32,
    tlb_op: u32,
    tlb_op_set: [u64; DART_MAX_TLB_OP_SETS],
    error_status: u32,
    error_address: u64,
    config: u32,
    sid_remap: [u32; DART_MAX_STREAMS / 4],
    sid_config: [u32; DART_MAX_STREAMS],
    ttbr: [[u32; DART_MAX_TTBR]; DART_MAX_STREAMS],

    /// Address-space word reader (address → u64 LE). `None` reads as 0,
    /// which makes walks fail with PTE_INVLD — same as DMA to unmapped
    /// memory in the C.
    pub table_reader: Option<Box<dyn FnMut(u64) -> u64 + Send>>,

    tlb: Vec<TlbEntry>,
    /// Fault IRQ line (asserted while `error_status != 0`).
    pub irq_line: bool,

    pub walks: u64,
    pub tlb_hits: u64,
    pub faults: u64,
    pub unknown_reads: u64,
    pub unknown_writes: u64,
}

/// Translation result: (physical page base, readable, writable).
pub type Xlate = Option<(u64, bool, bool)>;

impl Dart {
    pub fn new(page_shift: u32) -> Self {
        let page_size = 1u64 << page_shift;
        let (l_mask, l_shift) = match page_shift {
            12 => ([0xC_0000u64, 0x3_FE00, 0x1_FF], [0x12u64, 9, 0]),
            14 => ([0xC0_0000u64, 0x3F_F800, 0x7_FF], [0x16u64, 11, 0]),
            _ => panic!("dart: unsupported page-shift"),
        };
        let mut d = Dart {
            page_shift,
            page_size,
            page_bits: page_size - 1,
            page_mask: !(page_size - 1),
            l_mask,
            l_shift,
            sid_mask: 0xFFFF,
            dart_options: 0,
            params1: 0,
            params2: 0,
            tlb_op: 0,
            tlb_op_set: [0; DART_MAX_TLB_OP_SETS],
            error_status: 0,
            error_address: 0,
            config: 0,
            sid_remap: [0; DART_MAX_STREAMS / 4],
            sid_config: [0; DART_MAX_STREAMS],
            ttbr: [[0; DART_MAX_TTBR]; DART_MAX_STREAMS],
            table_reader: None,
            tlb: vec![TlbEntry::default(); TLB_ENTRIES],
            irq_line: false,
            walks: 0,
            tlb_hits: 0,
            faults: 0,
            unknown_reads: 0,
            unknown_writes: 0,
        };
        d.dart_reset();
        d
    }

    /// `apple_dart_reset` for the DART_DART instance.
    pub fn dart_reset(&mut self) {
        self.params1 = (self.page_shift << 24)
            | if self.dart_options & 0b10 != 0 {
                1 << 31
            } else {
                0
            };
        self.params2 = 1; // BYPASS_SUPPORT
        self.tlb_op = 0;
        self.tlb_op_set = [0; DART_MAX_TLB_OP_SETS];
        self.error_status = 0;
        self.error_address = 0;
        self.config = 0;
        self.sid_remap = [0; DART_MAX_STREAMS / 4];
        for sid in 0..DART_MAX_STREAMS {
            self.set_sid_remap(sid, sid as u32);
            self.sid_config[sid] = 0;
            self.ttbr[sid] = [0; DART_MAX_TTBR];
        }
        self.tlb_fill(0);
        self.irq_line = false;
    }

    fn set_sid_remap(&mut self, sid: usize, val: u32) {
        let word = sid / 4;
        let byte = sid % 4;
        let shift = byte * 8;
        self.sid_remap[word] = (self.sid_remap[word] & !(0xFF << shift))
            | ((val & 0xFF) << shift);
    }

    fn get_sid_remap(&self, sid: usize) -> u32 {
        let word = sid / 4;
        let shift = (sid % 4) * 8;
        (self.sid_remap[word] >> shift) & 0xFF
    }

    pub fn ttbr_offset(sid: usize, idx: usize) -> u64 {
        A_DART_TTBR
            + (((DART_MAX_STREAMS * sid) + (DART_MAX_TTBR * idx)) << 2) as u64
    }

    fn read_word(&mut self, pa: u64) -> u64 {
        match &mut self.table_reader {
            Some(f) => f(pa),
            None => 0,
        }
    }

    fn tlb_index(&self, sid: u32, iova_page: u64) -> usize {
        ((iova_page + ((sid as u64) << 24)) & (TLB_ENTRIES as u64 - 1)) as usize
    }

    fn tlb_flush(&mut self) {
        for e in self.tlb.iter_mut() {
            *e = TlbEntry::default();
        }
    }

    fn tlb_fill(&mut self, why: u32) {
        let _ = why;
        self.tlb_flush();
    }

    /// `apple_dart_mapper_ptw` — the real page walk.
    /// Returns `Err(error_status_bits)` on fault.
    fn ptw(&mut self, sid: u32, iova: u64) -> Result<(u64, bool, bool), u32> {
        let idx0 = (iova & self.l_mask[0]) >> self.l_shift[0];
        if sid as usize >= DART_MAX_STREAMS
            || self.sid_mask & (1u64 << sid) == 0
            || idx0 as usize >= DART_MAX_TTBR
            || self.ttbr[sid as usize][idx0 as usize] & DART_TTBR_VALID == 0
        {
            return Err(DART_ERROR_FLAG | DART_ERROR_TTBR_INVLD);
        }

        let mut pte = self.ttbr[sid as usize][idx0 as usize] as u64;
        let mut pa = (pte & DART_TTBR_MASK as u64) << DART_TTBR_SHIFT;

        for level in 1..3usize {
            let idx = (iova & self.l_mask[level]) >> self.l_shift[level];
            pa += 8 * idx;

            pte = self.read_word(pa);
            if pte & DART_PTE_VALID == 0 {
                return Err(DART_ERROR_FLAG | DART_ERROR_PTE_INVLD);
            }
            pa = pte & self.page_mask & DART_PTE_ADDR_MASK;
        }

        let readable = pte & DART_PTE_NO_READ == 0;
        let writable = pte & DART_PTE_NO_WRITE == 0;
        Ok((pte & self.page_mask & DART_PTE_ADDR_MASK, readable, writable))
    }

    /// Latch a fault like the C's translate() error path.
    fn latch_fault(&mut self, status: u32, sid: u32) {
        self.error_status |= status | (sid << DART_ERROR_SID_SHIFT);
        self.irq_line = true;
        self.faults += 1;
    }

    /// `apple_dart_mapper_translate` with access flags.
    pub fn translate_access(&mut self, sid: u32, iova: u64, is_write: bool) -> Xlate {
        if self.tlb_op & DART_TLB_OP_BUSY != 0 {
            return None;
        }
        let orig_sid = sid;
        let sid = self.get_sid_remap(sid as usize) as u32;
        // Disabled translation means bypass, not error (?)
        // — the C leaves the entry unmapped; we return None.
        let cfg = self.sid_config[sid as usize];
        if cfg & DART_SIDCFG_TRANSLATION_ENABLE == 0 || cfg & DART_SIDCFG_FULL_BYPASS != 0
        {
            return None;
        }

        let iova_page = iova >> self.page_shift;
        let index = self.tlb_index(sid, iova_page);
        let cached = self.tlb[index];
        let (pa_page, readable, writable) = if cached.valid
            && cached.sid == sid
            && cached.iova_page == iova_page
        {
            self.tlb_hits += 1;
            (cached.pa_page, cached.readable, cached.writable)
        } else {
            self.walks += 1;
            match self.ptw(sid, iova_page) {
                Ok((pa_page, readable, writable)) => {
                    self.tlb[index] = TlbEntry {
                        iova_page,
                        pa_page,
                        sid,
                        valid: true,
                        readable,
                        writable,
                    };
                    (pa_page, readable, writable)
                }
                Err(status) => {
                    self.error_address = iova;
                    self.latch_fault(status, orig_sid);
                    return None;
                }
            }
        };

        // The C checks WO faults against WRITE_PROT and reuses WRITE_PROT
        // for RO faults too (upstream copy-paste) — kept verbatim.
        if is_write && !writable {
            self.error_address = iova;
            self.latch_fault(DART_ERROR_FLAG | DART_ERROR_WRITE_PROT, orig_sid);
            return None;
        }
        if !is_write && !readable {
            self.error_address = iova;
            self.latch_fault(DART_ERROR_FLAG | DART_ERROR_WRITE_PROT, orig_sid);
            return None;
        }

        Some((pa_page | (iova & self.page_bits), readable, writable))
    }

    /// Read-side translate (`translate(sid, iova) -> Option<u64>`).
    pub fn translate(&mut self, sid: u32, iova: u64) -> Option<u64> {
        self.translate_access(sid, iova, false).map(|(pa, _, _)| pa)
    }

    /// `apple_dart_update_irq`.
    fn update_irq(&mut self) {
        self.irq_line = self.error_status != 0;
    }

    fn tlb_op_write(&mut self, val: u32) {
        let op = val & DART_TLB_OP_OP_MASK;
        let set_index = (val >> DART_TLB_OP_SET_INDEX_SHIFT) as usize;
        if op != DART_TLB_OP_INVALIDATE
            || set_index == 0
            || self.tlb_op & DART_TLB_OP_BUSY != 0
        {
            return;
        }
        self.tlb_op = val | DART_TLB_OP_BUSY;

        let mut sid_mask = 0u64;
        for i in 0..DART_MAX_TLB_OP_SETS {
            if set_index & (1usize << i) == 0 {
                continue;
            }
            sid_mask |= self.tlb_op_set[i] & self.sid_mask;
        }
        if sid_mask != 0 {
            // Invalidate whole streams (QEMU: IOMMU_NOTIFIER_UNMAP all).
            self.tlb_flush();
        }
        self.tlb_op &= !DART_TLB_OP_BUSY;
    }
}

impl Device for Dart {
    fn name(&self) -> &'static str {
        "dart"
    }

    fn read(&mut self, off: u64, _size: u8) -> u64 {
        match off {
            REG_DART_PARAMS1 => self.params1 as u64,
            REG_DART_PARAMS2 => self.params2 as u64,
            REG_DART_TLB_OP => self.tlb_op as u64,
            REG_DART_TLB_OP_SET_0_LOW => self.tlb_op_set[0] & 0xFFFF_FFFF,
            REG_DART_TLB_OP_SET_0_HIGH => (self.tlb_op_set[0] >> 32) & 0xFFFF_FFFF,
            REG_DART_ERROR_STATUS => self.error_status as u64,
            REG_DART_ERROR_ADDRESS_LOW => self.error_address & 0xFFFF_FFFF,
            REG_DART_ERROR_ADDRESS_HIGH => (self.error_address >> 32) & 0xFFFF_FFFF,
            REG_DART_CONFIG => self.config as u64,
            REG_DART_SID_VALID => 0, // stored state not modeled beyond 0
            a if (A_DART_SID_REMAP..A_DART_SID_REMAP + DART_MAX_STREAMS as u64)
                .contains(&a) =>
            {
                self.sid_remap[((a - A_DART_SID_REMAP) / 4) as usize] as u64
            }
            a if (A_DART_SID_CONFIG
                ..A_DART_SID_CONFIG + DART_MAX_STREAMS as u64)
                .contains(&a) =>
            {
                self.sid_config[((a - A_DART_SID_CONFIG) / 4) as usize] as u64
            }
            a if (A_DART_TLB_CONFIG..A_DART_TLB_CONFIG + DART_MAX_STREAMS as u64)
                .contains(&a) => 0,
            a if (A_DART_TTBR
                ..A_DART_TTBR
                    + ((DART_MAX_STREAMS * DART_MAX_TTBR) << 2) as u64)
                .contains(&a) =>
            {
                let i = ((a - A_DART_TTBR) >> 2) as usize;
                let sid = i / DART_MAX_TTBR;
                let idx = i % DART_MAX_TTBR;
                self.ttbr[sid][idx] as u64
            }
            _ => {
                self.unknown_reads += 1;
                0
            }
        }
    }

    fn write(&mut self, off: u64, _size: u8, val: u64) {
        let val = val as u32;
        match off {
            REG_DART_TLB_OP => self.tlb_op_write(val),
            REG_DART_TLB_OP_SET_0_LOW => {
                if self.tlb_op & DART_TLB_OP_BUSY == 0 {
                    self.tlb_op_set[0] =
                        (self.tlb_op_set[0] & 0xFFFF_FFFF_0000_0000) | val as u64;
                }
            }
            REG_DART_TLB_OP_SET_0_HIGH => {
                if self.tlb_op & DART_TLB_OP_BUSY == 0 {
                    self.tlb_op_set[0] =
                        (self.tlb_op_set[0] & 0xFFFF_FFFF) | ((val as u64) << 32);
                }
            }
            REG_DART_ERROR_STATUS => {
                // W1C.
                self.error_status &= !val;
                self.update_irq();
            }
            REG_DART_CONFIG => self.config = val,
            a if (A_DART_SID_REMAP..A_DART_SID_REMAP + DART_MAX_STREAMS as u64)
                .contains(&a) =>
            {
                self.sid_remap[((a - A_DART_SID_REMAP) / 4) as usize] = val;
                self.tlb_flush();
            }
            a if (A_DART_SID_CONFIG
                ..A_DART_SID_CONFIG + DART_MAX_STREAMS as u64)
                .contains(&a) =>
            {
                let sid = ((a - A_DART_SID_CONFIG) / 4) as usize;
                self.sid_config[sid] = val;
                self.tlb_flush();
            }
            a if (A_DART_TTBR
                ..A_DART_TTBR
                    + ((DART_MAX_STREAMS * DART_MAX_TTBR) << 2) as u64)
                .contains(&a) =>
            {
                let i = ((a - A_DART_TTBR) >> 2) as usize;
                let sid = i / DART_MAX_TTBR;
                let idx = i % DART_MAX_TTBR;
                self.ttbr[sid][idx] = val;
                self.tlb_flush(); // safety net: no real TLB coherency
            }
            _ => self.unknown_writes += 1,
        }
    }
}

pub fn regs_documented() -> &'static [(&'static str, u64)] {
    &[
        ("REG_DART_PARAMS1", REG_DART_PARAMS1),
        ("REG_DART_PARAMS2", REG_DART_PARAMS2),
        ("REG_DART_TLB_OP", REG_DART_TLB_OP),
        ("REG_DART_TLB_OP_SET_0_LOW", REG_DART_TLB_OP_SET_0_LOW),
        ("REG_DART_TLB_OP_SET_0_HIGH", REG_DART_TLB_OP_SET_0_HIGH),
        ("REG_DART_ERROR_STATUS", REG_DART_ERROR_STATUS),
        ("REG_DART_ERROR_ADDRESS_LOW", REG_DART_ERROR_ADDRESS_LOW),
        ("REG_DART_ERROR_ADDRESS_HIGH", REG_DART_ERROR_ADDRESS_HIGH),
        ("REG_DART_CONFIG", REG_DART_CONFIG),
        ("A_DART_SID_REMAP(0)", A_DART_SID_REMAP),
        ("REG_DART_SID_VALID", REG_DART_SID_VALID),
        ("A_DART_SID_CONFIG(0)", A_DART_SID_CONFIG),
        ("A_DART_TLB_CONFIG(0)", A_DART_TLB_CONFIG),
        ("A_DART_TTBR(0,0)", Dart::ttbr_offset(0, 0)),
        ("A_DART_TTBR(0,1)", Dart::ttbr_offset(0, 1)),
        ("A_DART_TTBR(1,0)", Dart::ttbr_offset(1, 0)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Synthetic page-table memory: HashMap<pa, u64> behind the reader.
    fn table() -> HashMap<u64, u64> {
        HashMap::new()
    }

    fn reader(mem: HashMap<u64, u64>) -> Box<dyn FnMut(u64) -> u64 + Send> {
        Box::new(move |pa| mem.get(&pa).copied().unwrap_or(0))
    }

    /// Build a 2-level table for one 4K page:
    /// TTBR -> L1 (512 entries) -> L2 (512 entries) -> leaf PTE.
    fn build_walk(mem: &mut HashMap<u64, u64>, ttbr_base: u64, iova: u64, pa: u64) {
        let l1_idx = ((iova & 0x3_FE00) >> 9) as u64;
        let l2_idx = (iova & 0x1_FF) as u64;
        let l1_base = ttbr_base + 0x1000;
        let l2_base = ttbr_base + 0x2000;
        let leaf = ttbr_base + 0x3000;
        mem.insert(l1_base + 8 * l1_idx, (l2_base & DART_PTE_ADDR_MASK) | 1);
        mem.insert(l2_base + 8 * l2_idx, (leaf & DART_PTE_ADDR_MASK) | 1);
        // Leaf: physical page + valid, RW.
        mem.insert(leaf, (pa & DART_PTE_ADDR_MASK) | 1);
    }

    fn dart_with_walk(sid: usize, ttbr_idx: usize, iova: u64, pa: u64) -> (Dart, u64) {
        let ttbr_base = 0x1_0000_0000u64; // arbitrary guest PA
        let mut mem = table();
        build_walk(&mut mem, ttbr_base, iova, pa);

        let mut d = Dart::new(12);
        d.table_reader = Some(reader(mem));
        // Enable translation for the stream.
        d.write(
            A_DART_SID_CONFIG + 4 * sid as u64,
            4,
            DART_SIDCFG_TRANSLATION_ENABLE as u64,
        );
        // TTBR: valid bit 31 | (base >> 12) & 0xFFFFFFF.
        let ttbr = DART_TTBR_VALID | ((ttbr_base >> DART_TTBR_SHIFT) as u32);
        d.write(Dart::ttbr_offset(sid, ttbr_idx), 4, ttbr as u64);
        (d, ttbr_base)
    }

    #[test]
    fn params_reset_values() {
        let d = Dart::new(12);
        assert_eq!(d.read(REG_DART_PARAMS1, 4), 12 << 24);
        assert_eq!(d.read(REG_DART_PARAMS2, 4), 1);
    }

    #[test]
    fn full_walk_translates() {
        let iova = 0x0001_2345;
        let pa = 0x4000_5000u64;
        let (mut d, _) = dart_with_walk(0, 0, iova & !0xFFF, pa);
        assert_eq!(d.translate(0, iova), Some(pa | (iova & 0xFFF)));
        assert_eq!(d.walks, 1);
        // Second translation hits the TLB.
        assert_eq!(d.translate(0, iova + 4), Some(pa | (iova & 0xFFF) + 4));
        assert_eq!(d.tlb_hits, 1);
    }

    #[test]
    fn ttbr_selection_uses_l0_index() {
        // L0 index = (iova & 0xC0000) >> 18 (bits [18:17]); bit 18 set
        // → TTBR idx 1.
        let iova_hi = 0x0004_0000u64;
        let pa = 0x5000_0000u64;
        let (mut d, _) = dart_with_walk(0, 1, iova_hi, pa);
        assert_eq!(d.translate(0, iova_hi), Some(pa));
        // Same table under TTBR 1, but a low iova selects idx 0 which
        // is unset → TTBR_INVLD fault.
        let (mut d2, _) = dart_with_walk(0, 1, iova_hi, pa);
        assert!(d2.translate(0, 0x10).is_none());
        assert_eq!(d2.error_status & DART_ERROR_TTBR_INVLD, DART_ERROR_TTBR_INVLD);
    }

    #[test]
    fn invalid_pte_faults() {
        let ttbr_base = 0x1_0000_0000u64;
        let mut mem = table();
        let iova = 0x8000u64;
        let l1_idx = ((iova & 0x3_FE00) >> 9) as u64;
        let l1_base = ttbr_base + 0x1000;
        // L1 entry valid, L2 missing → PTE_INVLD.
        mem.insert(l1_base + 8 * l1_idx, ((ttbr_base + 0x2000) & DART_PTE_ADDR_MASK) | 1);
        let mut d = Dart::new(12);
        d.table_reader = Some(reader(mem));
        d.write(A_DART_SID_CONFIG, 4, DART_SIDCFG_TRANSLATION_ENABLE as u64);
        d.write(
            Dart::ttbr_offset(0, 0),
            4,
            (DART_TTBR_VALID | (ttbr_base >> 12) as u32) as u64,
        );
        assert!(d.translate(0, iova).is_none());
        assert_eq!(d.error_status & DART_ERROR_PTE_INVLD, DART_ERROR_PTE_INVLD);
        assert_eq!((d.error_status >> DART_ERROR_SID_SHIFT) & 0xF, 0);
        assert!(d.irq_line);
        // W1C clears.
        d.write(REG_DART_ERROR_STATUS, 4, DART_ERROR_FLAG as u64);
        assert!(!d.irq_line);
    }

    #[test]
    fn no_write_permission_faults() {
        let ttbr_base = 0x1_0000_0000u64;
        let mut mem = table();
        let iova = 0x9000u64;
        let l1_idx = ((iova & 0x3_FE00) >> 9) as u64;
        let l2_idx = (iova & 0x1_FF) as u64;
        let l1_base = ttbr_base + 0x1000;
        let l2_base = ttbr_base + 0x2000;
        let leaf = ttbr_base + 0x3000;
        mem.insert(l1_base + 8 * l1_idx, (l2_base & DART_PTE_ADDR_MASK) | 1);
        mem.insert(l2_base + 8 * l2_idx, (leaf & DART_PTE_ADDR_MASK) | 1);
        // Leaf: NO_WRITE (bit 7).
        mem.insert(leaf, (0x6000_0000u64 & DART_PTE_ADDR_MASK) | 1 | (1 << 7));

        let mut d = Dart::new(12);
        d.table_reader = Some(reader(mem));
        d.write(A_DART_SID_CONFIG, 4, DART_SIDCFG_TRANSLATION_ENABLE as u64);
        d.write(
            Dart::ttbr_offset(0, 0),
            4,
            (DART_TTBR_VALID | (ttbr_base >> 12) as u32) as u64,
        );
        let x = d.translate_access(0, iova, true);
        assert!(x.is_none(), "write to NO_WRITE page denied");
        assert_eq!(
            d.error_status & DART_ERROR_WRITE_PROT,
            DART_ERROR_WRITE_PROT
        );
        // Reads are fine.
        assert_eq!(d.translate_access(0, iova, false), Some((0x6000_0000, true, false)));
    }

    #[test]
    fn translation_disabled_is_bypass_none() {
        let mut d = Dart::new(12);
        // sid_config[0] = 0 → TRANSLATION_ENABLE clear → None (C's "(?)").
        assert_eq!(d.translate(0, 0x1000), None);
        // Enable then FULL_BYPASS → also None, per the C.
        d.write(A_DART_SID_CONFIG, 4, (DART_SIDCFG_TRANSLATION_ENABLE | DART_SIDCFG_FULL_BYPASS) as u64);
        assert_eq!(d.translate(0, 0x1000), None);
    }

    #[test]
    fn tlb_op_invalidate_flushes_cache() {
        let iova = 0x0001_2345;
        let (mut d, _) = dart_with_walk(0, 0, iova & !0xFFF, 0x4000_5000);
        assert_eq!(d.translate(0, iova), Some(0x4000_5000 | (iova & 0xFFF)));
        assert_eq!(d.walks, 1);
        // Rewrite the leaf to a different PA; without a flush the TLB
        // would serve the stale entry (we flush on TTBR writes, so force
        // a fresh fill then use the TLB_OP path).
        let set_index = 1 << 20; // SET_INDEX bit 0
        d.write(REG_DART_TLB_OP_SET_0_LOW, 4, 1); // sid mask bit 0
        d.write(REG_DART_TLB_OP, 4, set_index as u64);
        assert_eq!(d.read(REG_DART_TLB_OP, 4) as u32 & DART_TLB_OP_BUSY, 0);
        assert_eq!(d.translate(0, iova), Some(0x4000_5000 | (iova & 0xFFF)));
        assert_eq!(d.walks, 2, "cache was invalidated by TLB_OP");
    }
}
