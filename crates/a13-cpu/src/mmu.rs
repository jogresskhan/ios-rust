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
//! * MAIR attribute indirection: AttrIndx[4:2] is decoded at every leaf,
//!   classified device/normal and measured (page + access counters, plus
//!   device-on-RAM / normal-on-MMIO misroute tallies). Routing itself is
//!   PA-based in the Bus — attributes are recorded, not enforced.
//! * ESR/FAR synthesis for walk faults (`synth_esr`): values land in
//!   ESR_EL1/FAR_EL1 (no vectoring yet — M4 owns VBAR delivery).
//!
//! Loud-fail instead of guessing: unsupported TCR granule encodings
//! (64K / reserved / TG0≠TG1) fault on the first walk, and T0SZ/T1SZ=0
//! is no longer remapped — it faults via the va-bits check.
//!
//! Not covered yet (tracked honestly): secure/EL2 stage 2, 52-bit PAs,
//! permission/AF/XN enforcement (gated on M4 vectoring), contiguous
//! hints, ASID-scoped TLB (all flushes are wholesale).

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
    /// `MAIR_EL1` — attribute indirection source. Stored on write (the
    /// interpreter's MRS round-trip reads it back); per-AttrIndex decoding
    /// is available via `attr_byte`. Enforcement (device-nGnRE must hit the
    /// Bus, normal must hit RAM) remains the tracked M3 gap.
    pub mair: u64,
    granule_log2: u8,
    t0sz: u8,
    t1sz: u8,
    /// VA page → (PA page, device-attr) (keys page-granularity aligned).
    tlb: HashMap<u64, (u64, bool)>,
    /// Walk statistics (parity surface).
    pub walks: u64,
    pub tlb_hits: u64,
    pub faults: u64,
    /// Per-kind walk-fault tally: [fetch, load, store].
    pub fault_kinds: [u64; 3],
    /// Leaf level histogram (L0..L3) — proves the 16K L1-start truncated
    /// index shape dominates on the real kernel tables.
    pub leaf_at_level: [u64; 4],
    /// MAIR attribute measurements (M3 bullet 1): pages = distinct leaves
    /// walked, accesses = TLB hits served with that class.
    pub attr_device_pages: u64,
    pub attr_normal_pages: u64,
    pub attr_device_accesses: u64,
    pub attr_normal_accesses: u64,
    /// Misroute tallies (need `ram_top` set): device-attr leaf landing on
    /// DRAM PAs, normal-attr leaf landing beyond DRAM.
    pub device_on_ram: u64,
    pub normal_on_mmio: u64,
    /// DRAM top PA for the misroute tallies (0 = unknown → tallies stay 0).
    pub ram_top: u64,
    /// TCR TBI0/TBI1 — decoded for the record. Masking is flag-gated
    /// (`honor_tbi`, default off: the measured kernel run sends no
    /// top-byte-tagged VAs and mid-campaign behavior changes are dishonest).
    pub tbi0: bool,
    pub tbi1: bool,
    pub honor_tbi: bool,
    /// Set when TCR carries an encoding we refuse to guess at; every walk
    /// faults with this string until a supported config is programmed.
    config_fault: Option<&'static str>,
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
            mair: 0,
            granule_log2: 12, // 4K until TCR says otherwise
            t0sz: 16,         // 48-bit
            t1sz: 16,
            tlb: HashMap::new(),
            walks: 0,
            tlb_hits: 0,
            faults: 0,
            fault_kinds: [0; 3],
            leaf_at_level: [0; 4],
            attr_device_pages: 0,
            attr_normal_pages: 0,
            attr_device_accesses: 0,
            attr_normal_accesses: 0,
            device_on_ram: 0,
            normal_on_mmio: 0,
            ram_top: 0,
            tbi0: false,
            tbi1: false,
            honor_tbi: false,
            config_fault: None,
            last_fault_chain: Vec::new(),
        }
    }

    /// Sync from `TCR_EL1` (granule + size split). Any change drops the TLB.
    ///
    /// Loud-fail policy: 64K granules (TG0=01/TG1=11), reserved encodings
    /// (TG0=11/TG1=00) and TG0≠TG1 mixes set `config_fault` — the shared-
    /// granule TLB model would mistranslate one of the ranges. T0SZ/T1SZ=0
    /// is architecturally legal (64-bit VA) but unsupported here: NO remap
    /// to 16 — the walk faults via the va-bits check instead.
    pub fn set_tcr(&mut self, v: u64) {
        if self.tcr == v {
            return;
        }
        self.tcr = v;
        let tg0 = (v >> 14) & 3; // 00=4K 01=64K 10=16K 11=rsvd
        let tg1 = (v >> 30) & 3; // 00=rsvd 01=16K 10=4K 11=64K
        self.tbi0 = (v >> 37) & 1 == 1;
        self.tbi1 = (v >> 38) & 1 == 1;
        self.config_fault = match (tg0, tg1) {
            (0b10, 0b01) | (0b00, 0b10) => None, // 16K/16K, 4K/4K
            _ => Some("TCR granule encoding unsupported (64K/reserved/TG0≠TG1)"),
        };
        self.granule_log2 = if tg0 == 0b10 || tg1 == 0b01 { 14 } else { 12 };
        self.t0sz = (v & 0x3F) as u8;
        self.t1sz = ((v >> 16) & 0x3F) as u8;
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

    /// Sync from `MAIR_EL1`. Attribute bytes do not affect existing
    /// translations, so (unlike TCR/TTBR writes) the TLB is NOT dropped.
    pub fn set_mair(&mut self, v: u64) {
        self.mair = v;
    }

    /// MAIR attribute byte for a descriptor's AttrIndx field (bits[4:2] of
    /// a stage-1 descriptor's lower attributes). Real decoding per
    /// DDI0487: AttrIndx indexes 8-bit MAIR fields `mair >> (n*8) & 0xFF`.
    pub fn attr_byte(&self, attrindx: u8) -> u8 {
        ((self.mair >> ((attrindx & 7) * 8)) & 0xFF) as u8
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

    /// Translate `va`. On failure returns `(va, detail)`; the ESR/FAR
    /// synthesis and the kind string are added by the interpreter's
    /// `vaddr` (which also records FAR_EL1/ESR_EL1).
    pub fn translate(
        &mut self,
        mem: &mut dyn MemAccess,
        va: u64,
        kind: XlateKind,
    ) -> Result<u64, (u64, &'static str)> {
        if !self.enabled {
            return Ok(va);
        }
        if let Some(cf) = self.config_fault {
            self.faults += 1;
            self.fault_kinds[kind as usize] += 1;
            return Err((va, cf));
        }
        // TBI0/TBI1 (flag-gated): a top-byte-tagged VA walks with the tag
        // stripped when honoring is enabled. Default off — behavior
        // identical to the measured baseline run.
        let mut va = va;
        if self.honor_tbi && (va >> 56) != 0 && (self.tbi0 || self.tbi1) {
            va &= !(0xFFu64 << 56);
        }
        let g = self.granule_log2 as u32;
        let page = va >> g;
        if let Some(&(pa_page, device)) = self.tlb.get(&page) {
            self.tlb_hits += 1;
            if device {
                self.attr_device_accesses += 1;
            } else {
                self.attr_normal_accesses += 1;
            }
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
            self.fault_kinds[kind as usize] += 1;
            return Err((va, "va-bits unsupported"));
        }
        // does this VA actually belong to the selected range?
        if use_ttbr1 {
            // (checked above)
        } else if t0sz < 64 && (va >> (64 - t0sz)) != 0 {
            self.faults += 1;
            self.fault_kinds[kind as usize] += 1;
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
            self.fault_kinds[kind as usize] += 1;
            return Err((va, "no start level"));
        }

        // START-level table base (TTBR): only 8-byte alignment is enforced
        // — the start table may be TRUNCATED (the kernel's 8-entry L1' is
        // exactly that), so granule-masking TTBR would corrupt legitimate
        // bootstrap table bases. Found by the walker goldens (L1' @ 0x2000
        // with 16K granule silently walked table 0). Descriptor-encoded
        // next-level table addresses below ARE granule-masked (their low
        // bits are reserved by the encoding).
        let mut table = if use_ttbr1 {
            self.ttbr1 & 0x0000_FFFF_FFFF_FFF8
        } else {
            self.ttbr0 & 0x0000_FFFF_FFFF_FFF8
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
                self.fault_kinds[kind as usize] += 1;
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
                // M3 attr measurement: AttrIndx[4:2] → MAIR byte. Device
                // = byte bits[7:4] == 0 (0x00..0x0C encodings); normal =
                // anything else. Recorded, NOT enforced (PA routing in
                // the Bus already sends MMIO PAs to devices).
                let attrindx = ((desc >> 2) & 7) as u8;
                let attr = self.attr_byte(attrindx);
                let device = attr & 0xF0 == 0;
                self.leaf_at_level[cur_level as usize] += 1;
                if device {
                    self.attr_device_pages += 1;
                } else {
                    self.attr_normal_pages += 1;
                }
                if self.ram_top != 0 {
                    if device && pa < self.ram_top {
                        self.device_on_ram += 1;
                    }
                    if !device && pa >= self.ram_top {
                        self.normal_on_mmio += 1;
                    }
                }
                self.tlb.insert(page, (pa & !self.page_mask(), device));
                return Ok(pa);
            }
            if !is_table_or_page {
                self.faults += 1;
                self.fault_kinds[kind as usize] += 1;
                return Err((va, "invalid table descriptor"));
            }
            // next-level table address: bits [47:g]
            table = desc & 0x0000_FFFF_FFFF_F000 & !self.page_mask();
            if cur_level == 3 {
                self.faults += 1;
                self.fault_kinds[kind as usize] += 1;
                return Err((va, "table at L3"));
            }
            cur_level += 1;
        }
    }

    /// TLB dump for fault diagnostics (bounded).
    pub fn dump(&self, max: usize) -> Vec<(u64, u64)> {
        self.tlb.iter().take(max).map(|(k, v)| (*k, v.0)).collect()
    }

    pub fn tlb_size(&self) -> usize {
        self.tlb.len()
    }

    /// Diagnostic accessor (M4-L #32): current TTBR bases (t0, t1) for the
    /// stop-time page-table dump. Read-only; zero behavior impact.
    pub fn ttbr_bases(&self) -> (u64, u64) {
        (self.ttbr0, self.ttbr1)
    }

    pub fn config_str(&self) -> String {
        format!(
            "granule {}K t0sz {} t1sz {} ttbr0 {:#x} ttbr1 {:#x} tbi0 {} tbi1 {}",
            1 << (self.granule_log2 - 10),
            self.t0sz,
            self.t1sz,
            self.ttbr0,
            self.ttbr1,
            self.tbi0 as u8,
            self.tbi1 as u8
        )
    }
}

/// Synthesize an `ESR_EL1` value for a stage-1 translation fault.
///
/// EC 0b100100 = Instruction Abort (fetch), 0b100101 = Data Abort
/// (load/store) with WnR set for stores; IL=1; DFSC = translation fault
/// `0b0001LL` / address-size fault `0b010LL` with LL derived from the
/// walk chain level when known. Synthesis only — vectoring is M4 work.
pub fn synth_esr(kind: XlateKind, detail: &str, level: u32) -> u64 {
    let (ec, wnr) = match kind {
        XlateKind::Fetch => (0b100100u64, false),
        XlateKind::Load => (0b100101, false),
        XlateKind::Store => (0b100101, true),
    };
    let level = level.min(3);
    let dfsc = if detail.contains("TTBR range") || detail.contains("va-bits") {
        0b010000 | level as u64 // address-size fault
    } else if detail.contains("granule") {
        0b000100u64 // translation fault L0 (config class)
    } else {
        0b000100u64 | level as u64 // translation fault level LL
    };
    (ec << 26) | (1 << 25) | ((wnr as u64) << 6) | dfsc
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal RAM backing a synthesized page-table tree.
    struct FakeMem {
        buf: Vec<u8>,
        base: u64,
    }
    impl FakeMem {
        fn new(base: u64, len: usize) -> Self {
            FakeMem { buf: vec![0; len], base }
        }
        fn wr64(&mut self, addr: u64, v: u64) {
            let off = (addr - self.base) as usize;
            self.buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
        }
    }
    impl MemAccess for FakeMem {
        fn load(&mut self, addr: u64, size: u8) -> u64 {
            let off = (addr - self.base) as usize;
            let mut v = 0u64;
            for i in 0..size as usize {
                v |= (self.buf[off + i] as u64) << (i * 8);
            }
            v
        }
        fn store(&mut self, addr: u64, size: u8, val: u64) {
            let off = (addr - self.base) as usize;
            for i in 0..size as usize {
                self.buf[off + i] = ((val >> (i * 8)) & 0xFF) as u8;
            }
        }
        fn fetch32(&mut self, addr: u64) -> u32 {
            self.load(addr, 4) as u32
        }
    }

    /// The TCR the real kernel programs (measured: 0x0008_0022_6519_A519
    /// → 16K/16K granules, T0SZ=T1SZ=25, TBI0=1, IPS=40-bit).
    const REAL_TCR: u64 = 0x0008_0022_6519_A519;

    #[test]
    fn walk_4k_l3_page() {
        let mut mmu = Mmu::new(); // 4K / 48-bit defaults, config ok
        mmu.set_mair(0xFF); // attr idx0 = normal
        let mut m = FakeMem::new(0, 0x10000);
        let va = 0x1000_0048u64;
        // Indices for 4K/48-bit: L0[0], L1[0] (va>>30=0), L2[0x80]
        // (va>>21=0x80), L3[0] (va>>12=0x100000 → &511 = 0).
        m.wr64(0x1000, 0x2000 | 0b11);
        m.wr64(0x2000, 0x3000 | 0b11); // L1[0]
        m.wr64(0x3000 + 0x80 * 8, 0x4000 | 0b11); // L2[0x80]
        m.wr64(0x4000, 0x5000 | 0b11); // L3[0]
        mmu.set_ttbr0(0x1000);
        mmu.set_enabled(true);
        let pa = match mmu.translate(&mut m, va, XlateKind::Load) {
            Ok(p) => p,
            Err(e) => panic!("walk_4k err {e:?} chain {:?}", mmu.last_fault_chain),
        };
        assert_eq!(pa, 0x5048);
        assert_eq!(mmu.walks, 1);
        assert_eq!(mmu.leaf_at_level[3], 1);
        assert_eq!(mmu.attr_normal_pages, 1);
        // TLB hit on the same page
        let pa2 = mmu.translate(&mut m, va, XlateKind::Load).unwrap();
        assert_eq!(pa2, pa);
        assert_eq!(mmu.tlb_hits, 1);
        assert_eq!(mmu.attr_normal_accesses, 1);
        // TTBR write flushes
        mmu.set_ttbr0(0x1000);
        assert_eq!(mmu.tlb_size(), 0);
    }

    #[test]
    fn walk_16k_l1_start_truncated_index() {
        // The real kernel shape: 16K granule, 39-bit VA → walk starts at
        // L1 with a truncated (8-entry) index; L2 block leaf (32 MiB).
        let mut mmu = Mmu::new();
        mmu.set_tcr(REAL_TCR);
        assert!(mmu.config_fault.is_none());
        assert_eq!(mmu.tbi0, true);
        assert_eq!(mmu.tbi1, false);
        let mut m = FakeMem::new(0, 0x100000);
        // va = 6<<36 + 0x10000: L1 idx 6 (start-level truncated bits[38:36]),
        // L2 idx 0 (va>>25 = 6*2^11 → &0x7FF = 0), 32 MiB block leaf.
        let va = 0x60_0001_0000u64;
        m.wr64(0x2000 + 6 * 8, 0x4000 | 0b11); // L1[6] → L2 table (16K aligned)
        m.wr64(0x4000, 0x8000_0000u64 | 0b01); // L2[0] block 32MB
        mmu.set_ttbr0(0x2000);
        mmu.set_enabled(true);
        let pa = match mmu.translate(&mut m, va, XlateKind::Fetch) {
            Ok(p) => p,
            Err(e) => panic!("walk_16k err {e:?} chain {:?}", mmu.last_fault_chain),
        };
        assert_eq!(pa, 0x8000_0000 | (va & 0x1FF_FFFF));
        assert_eq!(mmu.leaf_at_level[2], 1);
        assert_eq!(mmu.leaf_at_level[1], 0);
        // start level must be L1 for 39-bit/16K
        assert_eq!(mmu.walks, 1);
    }

    #[test]
    fn fault_invalid_descriptor_chain_and_tally() {
        let mut mmu = Mmu::new();
        let mut m = FakeMem::new(0, 0x10000);
        mmu.set_ttbr0(0x1000); // L0[0] = 0 → invalid
        mmu.set_enabled(true);
        let err = mmu.translate(&mut m, 0x1234, XlateKind::Load).unwrap_err();
        assert_eq!(err.1, "invalid descriptor");
        assert_eq!(mmu.faults, 1);
        assert_eq!(mmu.fault_kinds[1], 1); // load
        assert_eq!(mmu.last_fault_chain, vec![(0, 0x1000, 0)]);
        // ESR synthesis: data abort, translation fault level 0
        let esr = synth_esr(XlateKind::Load, err.1, 0);
        assert_eq!(esr >> 26, 0b100101);
        assert_eq!(esr & 0x3F, 0b000100);
    }

    #[test]
    fn fault_out_of_range_va() {
        let mut mmu = Mmu::new(); // t0sz=t1sz=16
        let mut m = FakeMem::new(0, 0x1000);
        mmu.set_enabled(true);
        // bit 48 set: neither T0 (top 16 zero) nor T1 (top 16 ones)
        let err = mmu.translate(&mut m, 0x0001_0000_0000_0000, XlateKind::Load).unwrap_err();
        assert_eq!(err.1, "address not in either TTBR range");
        let esr = synth_esr(XlateKind::Load, err.1, 0);
        assert_eq!(esr & 0x3F, 0b010000); // address-size fault
    }

    #[test]
    fn loud_fail_64k_and_mixed_tcr() {
        let mut mmu = Mmu::new();
        let mut m = FakeMem::new(0, 0x1000);
        mmu.set_enabled(true);
        // TG0=01 (64K) → unsupported
        mmu.set_tcr(1 << 14);
        let e1 = mmu.translate(&mut m, 0x1000, XlateKind::Load).unwrap_err();
        assert!(e1.1.contains("granule"));
        // TG0=16K / TG1=4K mix → unsupported (shared-granule TLB model)
        mmu.set_tcr((2 << 14) | (2 << 30));
        let e2 = mmu.translate(&mut m, 0x1000, XlateKind::Load).unwrap_err();
        assert!(e2.1.contains("granule"));
        // supported pairs clear the fault
        mmu.set_tcr(REAL_TCR);
        assert!(mmu.config_fault.is_none());
        // TCR=0: TG1=00 (reserved) → unsupported
        mmu.set_tcr(0);
        assert!(mmu.config_fault.is_some());
    }

    #[test]
    fn loud_fail_t0sz_zero_no_remap() {
        let mut mmu = Mmu::new();
        let mut m = FakeMem::new(0, 0x1000);
        mmu.set_enabled(true);
        // 16K/16K with T0SZ=0 → va_bits=64 → loud fault (no silent remap)
        mmu.set_tcr((1 << 30) | (2 << 14) | (25 << 16));
        let err = mmu.translate(&mut m, 0x1000, XlateKind::Load).unwrap_err();
        assert_eq!(err.1, "va-bits unsupported");
    }

    #[test]
    fn attr_device_vs_normal_and_misroute() {
        let mut mmu = Mmu::new();
        // MAIR idx0 = 0xFF (normal), idx1 = 0x04 (device-nGnRE)
        mmu.set_mair(0x04FF);
        mmu.ram_top = 0x1000_0000;
        let mut m = FakeMem::new(0, 0x10000);
        // L2 block (4K granule, 2 MiB) leaf @ L2: desc bits[4:2]=AttrIndx
        // device page ABOVE ram_top (no misroute), normal page BELOW.
        let l0 = 0x1000u64;
        let l1 = 0x2000u64;
        let l2 = 0x3000u64;
        // L2 index = (va>>21) & 0x1FF; block-start VAs keep the offset 0:
        let va_dev = 0x0000_0000u64; // L2 idx 0 → block OA 0x2000_0000 (device)
        let va_norm = 0x0020_0000u64; // L2 idx 1 → block OA 0x1000 (normal)
        m.wr64(l0, l1 | 0b11);
        m.wr64(l1, l2 | 0b11);
        m.wr64(l2, 0x2000_0000u64 | (1 << 2) | 0b01); // AttrIndx=1 device
        m.wr64(l2 + 8, 0x200_0000u64 | 0b01); // AttrIndx=0 normal (2MB-aligned OA, < ram_top)
        mmu.set_ttbr0(l0);
        mmu.set_enabled(true);
        assert_eq!(mmu.translate(&mut m, va_dev, XlateKind::Load).unwrap(), 0x2000_0000);
        assert_eq!(
            match mmu.translate(&mut m, va_norm, XlateKind::Load) {
                Ok(p) => p,
                Err(e) => panic!("attr err {e:?} chain {:?}", mmu.last_fault_chain),
            },
            0x200_0000
        );
        assert_eq!(mmu.attr_device_pages, 1);
        assert_eq!(mmu.attr_normal_pages, 1);
        assert_eq!(mmu.device_on_ram, 0); // device leaf is above ram_top
        assert_eq!(mmu.normal_on_mmio, 0); // normal leaf is below ram_top
        // a device-attr leaf INSIDE DRAM is the misroute the tally exists for
        m.wr64(l2 + 16, 0x800_0000u64 | (1 << 2) | 0b01); // L2 idx 2, device, in-DRAM
        assert_eq!(mmu.translate(&mut m, 0x0040_0000, XlateKind::Load).unwrap(), 0x800_0000);
        assert_eq!(mmu.device_on_ram, 1);
        // and a normal-attr leaf beyond DRAM
        m.wr64(l2 + 24, 0xF000_0000u64 | 0b01); // L2 idx 3, normal, MMIO PA
        assert_eq!(mmu.translate(&mut m, 0x0060_0000, XlateKind::Load).unwrap(), 0xF000_0000);
        assert_eq!(mmu.normal_on_mmio, 1);
    }

    #[test]
    fn tbi_masking_is_flag_gated() {
        let mut mmu = Mmu::new();
        mmu.set_tcr(REAL_TCR); // TBI0=1
        let mut m = FakeMem::new(0, 0x100000);
        m.wr64(0x2000 + 6 * 8, 0x4000 | 0b11);
        m.wr64(0x4000, 0x8000_0000u64 | 0b01);
        mmu.set_ttbr0(0x2000);
        mmu.set_enabled(true);
        let tagged = 0xAA00_0060_0001_0000u64; // top byte tag 0xAA
        // default: honor_tbi off → the tagged VA is out of range
        let err = mmu.translate(&mut m, tagged, XlateKind::Load).unwrap_err();
        assert_eq!(err.1, "address not in either TTBR range");
        // flag on → tag stripped, same walk as the untagged VA
        mmu.honor_tbi = true;
        let pa = match mmu.translate(&mut m, tagged, XlateKind::Load) {
            Ok(p) => p,
            Err(e) => panic!("tbi err {e:?} chain {:?}", mmu.last_fault_chain),
        };
        assert_eq!(pa, 0x8000_0000 | (0x60_0001_0000 & 0x1FF_FFFF));
    }

    #[test]
    fn esr_shapes() {
        // fetch: instruction abort EC, no WnR
        let e = synth_esr(XlateKind::Fetch, "invalid descriptor", 2);
        assert_eq!(e >> 26, 0b100100);
        assert_eq!(e & (1 << 6), 0);
        assert_eq!(e & 0x3F, 0b000110); // translation fault L2
        // store: data abort EC with WnR
        let s = synth_esr(XlateKind::Store, "invalid descriptor", 1);
        assert_eq!(s >> 26, 0b100101);
        assert_eq!(s & (1 << 6), 1 << 6);
        // IL bit always set
        for k in [XlateKind::Fetch, XlateKind::Load, XlateKind::Store] {
            assert_ne!(synth_esr(k, "invalid descriptor", 0) & (1 << 25), 0);
        }
    }
}
