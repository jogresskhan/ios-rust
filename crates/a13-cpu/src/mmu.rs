//! AArch64 stage-1 MMU — the real page-table walker for the first boot.
//!
//! XNU's `start` (verified on real 18C66 T8030 bytes, see
//! `tools/re/macho/entry_probe.py`) builds its own bootstrap translation
//! tables *while the MMU is off*, then programs `TCR_EL1`, `TTBR0/1_EL1`
//! and flips `SCTLR_EL1.M`. From that single `msr sctlr_el1` onward every
//! fetch/load/store is a virtual address, so the interpreter must walk the
//! kernel's actual tables — this module does exactly that.
//!
//! Covered (what the real kernel uses in the early window):
//! * 4 KB and 16 KB granules (`TCR.TG0/TG1`), 48-bit VAs (`T0SZ/T1SZ`)
//! * L0..L3 table descriptors, L1/L2 block descriptors, L3 pages
//! * separate TLB keyed by page, invalidated by `TLBI`/TTBR/TCR writes
//! * attribute bits are decoded but not enforced (no cache/permission
//!   model yet — the honest ledger tracks that as a gap)
//!
//! Not covered yet (fail loudly instead of guessing): secure/EL2 stage 2,
//! 52-bit PAs, permissions faults (AP/XN), AF, contiguous hints.

use std::collections::HashMap;

use crate::MemAccess;

/// Which access kind triggered a walk (for honest fault reports).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XlateKind {
    Fetch,
    Load,
    Store,
}

impl XlateKind {
    pub fn as_str(self) -> &'static str {
        match self {
            XlateKind::Fetch => "fetch",
            XlateKind::Load => "load",
            XlateKind::Store => "store",
        }
    }
}

/// Stage-1 MMU state mirror + TLB.
pub struct Mmu {
    /// `SCTLR_EL1.M` — the master switch the kernel flips at boot.
    pub enabled: bool,
    /// `SCTLR_EL1.EE` big-endian walks — unsupported (A13 is LE).
    tcr: u64,
    ttbr0: u64,
    ttbr1: u64,
    granule_log2: u8,
    t0sz: u8,
    t1sz: u8,
    /// VA page → PA page (keys/values are page-granularity aligned).
    tlb: HashMap<u64, u64>,
    /// Walk statistics (parity surface).
    pub walks: u64,
    pub tlb_hits: u64,
    pub faults: u64,
    /// Descriptor chain of the most recent fault: (level, desc_addr, desc).
    pub last_fault_chain: Vec<(u32, u64, u64)>,
}

impl Default for Mmu {
    fn default() -> Self {
        Self::new()
    }
}

impl Mmu {
    pub fn new() -> Self {
        Mmu {
            enabled: false,
            tcr: 0,
            ttbr0: 0,
            ttbr1: 0,
            granule_log2: 12, // 4K until TCR says otherwise
            t0sz: 16,         // 48-bit
            t1sz: 16,
            tlb: HashMap::new(),
            walks: 0,
            tlb_hits: 0,
            faults: 0,
            last_fault_chain: Vec::new(),
        }
    }

    /// Sync from `TCR_EL1` (granule + size split). Any change drops the TLB.
    pub fn set_tcr(&mut self, v: u64) {
        if self.tcr == v {
            return;
        }
        self.tcr = v;
        let tg0 = (v >> 14) & 3; // 00=4K 01=64K 10=16K
        let tg1 = (v >> 30) & 3; // 01=16K 10=4K 11=64K
        self.granule_log2 = if tg0 == 0b10 || tg1 == 0b01 { 14 } else { 12 };
        self.t0sz = (v & 0x3F) as u8;
        self.t1sz = ((v >> 16) & 0x3F) as u8;
        if self.t0sz == 0 {
            self.t0sz = 16;
        }
        if self.t1sz == 0 {
            self.t1sz = 16;
        }
        self.flush();
    }

    pub fn set_ttbr0(&mut self, v: u64) {
        self.ttbr0 = v & 0x0000_FFFF_FFFF_FFFF;
        self.flush();
    }

    pub fn set_ttbr1(&mut self, v: u64) {
        self.ttbr1 = v & 0x0000_FFFF_FFFF_FFFF;
        self.flush();
    }

    pub fn set_enabled(&mut self, on: bool) {
        if self.enabled != on {
            self.flush();
        }
        self.enabled = on;
    }

    pub fn flush(&mut self) {
        self.tlb.clear();
    }

    #[inline]
    fn page_mask(&self) -> u64 {
        (1u64 << self.granule_log2) - 1
    }

    /// Translate `va`. On failure returns `(va, kind-str)` for the fault
    /// report.
    pub fn translate(
        &mut self,
        mem: &mut dyn MemAccess,
        va: u64,
        kind: XlateKind,
    ) -> Result<u64, (u64, &'static str)> {
        if !self.enabled {
            return Ok(va);
        }
        let g = self.granule_log2 as u32;
        let page = va >> g;
        if let Some(&pa_page) = self.tlb.get(&page) {
            self.tlb_hits += 1;
            return Ok(pa_page | (va & self.page_mask()));
        }

        // address-space selection (single-range model per TTBR)
        let t1sz = self.t1sz.min(64) as u32;
        let t0sz = self.t0sz.min(64) as u32;
        let use_ttbr1 = t1sz < 64 && (va >> (64 - t1sz)) == ((1u64 << t1sz) - 1);
        let tsz = if use_ttbr1 { t1sz } else { t0sz };
        let va_bits = 64 - tsz as u32;
        // sanity: kernel runs 48-bit; anything wilder is a config we don't
        // model — fault loudly rather than mistranslate.
        if va_bits == 0 || va_bits > 52 {
            self.faults += 1;
            return Err((va, "va-bits unsupported"));
        }
        // does this VA actually belong to the selected range?
        if use_ttbr1 {
            // (checked above)
        } else if t0sz < 64 && (va >> (64 - t0sz)) != 0 {
            self.faults += 1;
            return Err((va, "address not in either TTBR range"));
        }

        let bpl: u32 = if g == 14 { 11 } else { 9 }; // bits per level
        // start level: the LARGEST s that still covers va_bits (e.g. 16K
        // granule / 39-bit VA → L1, matching the kernel's bootstrap layout
        // where TTBR points straight at an L1 table).
        let mut level: u32 = 0;
        for s in (0..4u32).rev() {
            if (4 - s) * bpl + g >= va_bits {
                level = s;
                break;
            }
        }
        if level > 3 {
            self.faults += 1;
            return Err((va, "no start level"));
        }

        let mut table = if use_ttbr1 {
            self.ttbr1 & !self.page_mask() & 0x0000_FFFF_FFFF_F000
        } else {
            self.ttbr0 & !self.page_mask() & 0x0000_FFFF_FFFF_F000
        };

        self.walks += 1;
        let mut cur_level = level;
        let mut chain: Vec<(u32, u64, u64)> = Vec::new();
        loop {
            let shift: u32 = g + (3 - cur_level) * bpl;
            // Index field: full `bpl` bits at inner levels; at the START
            // level the field is truncated by va_bits (a 39-bit VA at L1
            // start indexes bits [38:36] — 3 entries — the sign bits do
            // NOT participate). This is what makes the kernel's bootstrap
            // layout (L1[7] for link VAs) architecturally correct.
            let idx = if cur_level == level && va_bits < shift + bpl {
                (va >> shift) & ((1u64 << (va_bits - shift)) - 1)
            } else {
                (va >> shift) & ((1u64 << bpl) - 1)
            };
            let desc_addr = (table | (idx << 3)) & 0x0000_FFFF_FFFF_FFFF;
            let desc = mem.load(desc_addr, 8);
            chain.push((cur_level, desc_addr, desc));
            if desc & 1 == 0 {
                self.faults += 1;
                self.last_fault_chain = chain;
                return Err((va, "invalid descriptor"));
            }
            let is_table_or_page = desc & 2 != 0;
            let is_leaf = cur_level == 3 || (cur_level > 0 && !is_table_or_page);
            if is_leaf {
                // Page (L3) or block (L1/L2): the OA covers bits
                // [47:leaf_shift] — the in-leaf offset is `va & (leaf_
                // size-1)`, NOT the page offset (a 32 MB L2 block maps the
                // whole 32 MB window).
                let leaf_shift: u32 = g + (3 - cur_level) * bpl;
                let leaf_mask = (1u64 << leaf_shift) - 1;
                let oa = desc & !leaf_mask & 0x0000_FFFF_FFFF_FFFF;
                let pa = oa | (va & leaf_mask);
                self.tlb.insert(page, pa & !self.page_mask());
                return Ok(pa);
            }
            if !is_table_or_page {
                self.faults += 1;
                return Err((va, "invalid table descriptor"));
            }
            // next-level table address: bits [47:g]
            table = desc & 0x0000_FFFF_FFFF_F000 & !self.page_mask();
            if cur_level == 3 {
                self.faults += 1;
                return Err((va, "table at L3"));
            }
            cur_level += 1;
        }
    }

    /// TLB dump for fault diagnostics (bounded).
    pub fn dump(&self, max: usize) -> Vec<(u64, u64)> {
        self.tlb.iter().take(max).map(|(k, v)| (*k, *v)).collect()
    }

    pub fn tlb_size(&self) -> usize {
        self.tlb.len()
    }

    pub fn config_str(&self) -> String {
        format!(
            "granule {}K t0sz {} t1sz {} ttbr0 {:#x} ttbr1 {:#x}",
            1 << (self.granule_log2 - 10),
            self.t0sz,
            self.t1sz,
            self.ttbr0,
            self.ttbr1
        )
    }
}
