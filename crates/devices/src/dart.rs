//! Apple DART IOMMU — structural port of `hw/misc/apple-silicon/dart.c`
//! (Inferno) cross-checked against the qemu-sweet overlay `sweet_dart.c`
//! (GPLv2+, real 4-level PTE walker for T8015, same DART family).
//!
//! Walk: TCR → TTBR → L0..L3 tables (APTE), 16 KiB granule on T8030 DART v2;
//! each level: bits 63/31 valid + fault bits, PTE[47:14]-ish → next table.
//! Verification target: replay PTE walks captured from engine traces
//! (dart-walker-gate tool exists in the ios-sweet-rust workbench).

use crate::bus::{MMIODevice, W4};

const REG_TCR: u64 = 0x0;
const REG_TTBR0: u64 = 0x200;
const REG_TTBR1: u64 = 0x208;
const REG_TTBR2: u64 = 0x210;
const REG_TTBR3: u64 = 0x218;
const REG_DAPF_LOCK: u64 = 0xF8;
const REG_DAPVT: u64 = 0xE00;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkResult {
    Translated(u64),
    Fault(&'static str),
}

#[derive(Debug, Default)]
pub struct Dart {
    tcr: u64,
    ttbr: [u64; 4],
    dapf_lock: u64,
    ///_guest-visible wired translation cache (for fast-path scanout).
    pub translations: std::collections::BTreeMap<u64, u64>,
}

impl Dart {
    pub fn new() -> Self {
        Self::default()
    }

    /// 4-level APTE walk against a flat guest-physical table store.
    /// `tables`: base_phys → bytes (the emulator's DRAM view).
    /// Structural fidelity to sweet_dart.c: levels 0..3, valid bit 63,
    /// table bit 62 (L0-L2), leaf PTE physical = bits 47:14.
    pub fn walk(tables: &std::collections::BTreeMap<u64, Vec<u8>>, iova: u64) -> WalkResult {
        let mut table_base = match tables.values().next() {
            Some(t) => 0, // resolved below from TTBR-less test helper
            None => return WalkResult::Fault("no tables"),
        };
        let _ = &mut table_base;
        let mut pte_base = 0u64; // test helper: single TTBR assumed
        let mut level = 0u8;
        while level < 4 {
            let idx = match level {
                0 => (iova >> 36) & 0x3,
                1 => (iova >> 29) & 0x7FF,
                2 => (iova >> 25) & 0xF,
                _ => (iova >> 14) & 0x7FF,
            };
            let entry_off = (pte_base as usize + (idx as usize) * 8);
            let Some(table) = tables.values().find(|t| entry_off + 8 <= t.len()) else {
                return WalkResult::Fault("table-oob");
            };
            let pte = u64::from_le_bytes(table[entry_off..entry_off + 8].try_into().unwrap());
            if pte & (1 << 63) == 0 {
                return WalkResult::Fault("invalid-pte");
            }
            if level < 3 {
                if pte & (1 << 62) == 0 {
                    return WalkResult::Fault("leaf-too-early");
                }
                pte_base = pte & 0x0000_FFFF_FFFF_C000;
            } else {
                let pa = (pte & 0x0000_FFFF_FFFF_C000) | (iova & 0x3FFF);
                return WalkResult::Translated(pa);
            }
            level += 1;
        }
        WalkResult::Fault("unreachable")
    }
}

impl MMIODevice for Dart {
    fn name(&self) -> &'static str {
        "apple-dart"
    }
    fn size(&self) -> u64 {
        0x1000
    }

    fn read(&mut self, offset: u64, _width: u32) -> u64 {
        match offset {
            REG_TCR => self.tcr,
            REG_TTBR0 => self.ttbr[0],
            REG_TTBR1 => self.ttbr[1],
            REG_TTBR2 => self.ttbr[2],
            REG_TTBR3 => self.ttbr[3],
            REG_DAPF_LOCK => self.dapf_lock,
            _ => 0,
        }
    }

    fn write(&mut self, offset: u64, value: u64, _width: u32) {
        match offset {
            REG_TCR => self.tcr = value,
            REG_TTBR0 => self.ttbr[0] = value,
            REG_TTBR1 => self.ttbr[1] = value,
            REG_TTBR2 => self.ttbr[2] = value,
            REG_TTBR3 => self.ttbr[3] = value,
            REG_DAPF_LOCK => self.dapf_lock = value,
            REG_DAPVT => {} // DAPF translation table — wire into translations
            _ => {}
        }
    }
}

pub const PARITY_PCT: u8 = 40; // reg surface + walker shape; needs golden traces + DAPF

impl crate::bus::Device for Dart {
    fn mmio(&mut self) -> &mut dyn MMIODevice {
        self
    }
    fn parity_pct(&self) -> u8 {
        PARITY_PCT
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn tcr_ttbr_rw() {
        let mut d = Dart::new();
        d.write(REG_TCR, 0xDEAD, W4);
        assert_eq!(d.read(REG_TCR, W4), 0xDEAD);
    }

    #[test]
    fn walk_invalid_pte_faults() {
        let mut tables: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        tables.insert(0, vec![0u8; 0x10000]);
        assert!(matches!(Dart::walk(&tables, 0x1000), WalkResult::Fault("invalid-pte")));
    }
}
