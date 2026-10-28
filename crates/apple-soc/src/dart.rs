//! dart — Apple DART IOMMU (port of Inferno hw/apple-silicon/dart.c +
//! the proven 4-level PTE walker from ios-sweet qemu overlay
//! sweet_dart.c). Translates stream-ID'd IOVA → physical via a 4-level
//! page table whose pages the machine copies in through `table_words`.

use vm_core::Device;

pub const REG_DART_TCR: u64 = 0x0000;
pub const REG_DART_TTBR: u64 = 0x0200; // 16 stream TTBRs, 4B each
pub const REG_DART_TLB_OP: u64 = 0x0040;
pub const REG_DART_ERROR: u64 = 0x0044;
pub const REG_DART_ERROR_ADDR_LO: u64 = 0x0050;
pub const REG_DART_ERROR_ADDR_HI: u64 = 0x0054;
pub const REG_DART_CONFIG: u64 = 0x0060;
pub const REG_DART_REMAP: u64 = 0x0080;

pub const TLB_OP_FLUSH: u32 = 0x20;

/// Level split per sweet_dart.c: [25, 18, 11, 4] bit shifts.
pub const LEVEL_SHIFT: [u32; 4] = [25, 18, 11, 4];

pub type TableReader = Box<dyn FnMut(u64) -> u64 + Send>;

pub struct Dart {
    label: &'static str,
    pub tcr: u32,
    pub ttbr: [u64; 16],
    pub config: u32,
    pub error: u32,
    pub err_addr: u64,
    /// Reads one u64 from physical memory (machine injects bus closure).
    pub read_phys: Option<TableReader>,
    pub translations_ok: u64,
    pub faults: u64,
    pub unknown_reads: u64,
}

impl Dart {
    pub fn new(label: &'static str) -> Self {
        Dart {
            label: match label {
                "dart-ans" => "dart-ans",
                "dart-disp0" => "dart-disp0",
                _ => "dart",
            },
            tcr: 0,
            ttbr: [0; 16],
            config: 0,
            error: 0,
            err_addr: 0,
            read_phys: None,
            translations_ok: 0,
            faults: 0,
            unknown_reads: 0,
        }
    }

    /// 4-level page-table walk (sweet_dart.c parity).
    pub fn translate(&mut self, sid: u32, iova: u64) -> Option<u64> {
        if self.tcr & 1 == 0 {
            // translation disabled → identity
            self.translations_ok += 1;
            return Some(iova);
        }
        let root = self.ttbr.get(sid as usize % 16).copied().unwrap_or(0) & !0xF;
        if root == 0 {
            self.faults += 1;
            self.error |= 1;
            self.err_addr = iova;
            return None;
        }
        let mut table = root;
        let mut pte = 0u64;
        for &shift in LEVEL_SHIFT.iter() {
            let idx = ((iova >> shift) & 0x1FFF) as u64;
            let entry_addr = table + idx * 8;
            let reader = self.read_phys.as_mut()?;
            pte = reader(entry_addr);
            if pte & 1 == 0 {
                self.faults += 1;
                self.error |= 1;
                self.err_addr = iova;
                return None;
            }
            // leaf at level 4 only (4K pages)
            table = pte & !0xFFF;
        }
        let phys = (pte & !0xFFF) | (iova & 0xFFF);
        self.translations_ok += 1;
        Some(phys)
    }

    pub fn regs_documented() -> &'static [(&'static str, u64)] {
        &[
            ("TCR", REG_DART_TCR),
            ("TLB_OP", REG_DART_TLB_OP),
            ("ERROR", REG_DART_ERROR),
            ("ERR_ADDR_LO", REG_DART_ERROR_ADDR_LO),
            ("ERR_ADDR_HI", REG_DART_ERROR_ADDR_HI),
            ("CONFIG", REG_DART_CONFIG),
            ("REMAP", REG_DART_REMAP),
            ("TTBR[16]", REG_DART_TTBR),
        ]
    }
}

impl Device for Dart {
    fn name(&self) -> &'static str {
        self.label
    }
    fn read(&mut self, off: u64, _size: u8) -> u64 {
        match off {
            REG_DART_TCR => self.tcr as u64,
            REG_DART_TLB_OP => 0,
            REG_DART_ERROR => self.error as u64,
            REG_DART_ERROR_ADDR_LO => self.err_addr & 0xFFFF_FFFF,
            REG_DART_ERROR_ADDR_HI => self.err_addr >> 32,
            REG_DART_CONFIG => self.config as u64,
            REG_DART_REMAP => 0,
            off if (REG_DART_TTBR..REG_DART_TTBR + 64).contains(&off) => {
                self.ttbr[((off - REG_DART_TTBR) / 4) as usize % 16] as u32 as u64
            }
            _ => {
                self.unknown_reads += 1;
                0
            }
        }
    }
    fn write(&mut self, off: u64, _size: u8, val: u64) {
        match off {
            REG_DART_TCR => self.tcr = (val & 0xFFFF_FFFF) as u32,
            REG_DART_TLB_OP => {
                if val as u32 & TLB_OP_FLUSH == TLB_OP_FLUSH {
                    self.error = 0;
                }
            }
            REG_DART_CONFIG => self.config = (val & 0xFFFF_FFFF) as u32,
            off if (REG_DART_TTBR..REG_DART_TTBR + 64).contains(&off) => {
                let i = ((off - REG_DART_TTBR) / 4) as usize % 16;
                self.ttbr[i] = (self.ttbr[i] & !0xFFFF_FFFF) | (val & 0xFFFF_FFFF);
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn fake_ram(walk: Arc<Mutex<std::collections::HashMap<u64, u64>>>) -> TableReader {
        Box::new(move |addr: u64| *walk.lock().unwrap().get(&addr).unwrap_or(&0))
    }

    #[test]
    fn four_level_walk() {
        let map = Arc::new(Mutex::new(std::collections::HashMap::new()));
        let l3 = 0x1_0000u64;
        let l2 = 0x2_0000u64;
        let l1 = 0x3_0000u64;
        let root = 0x4_0000u64;
        // iova = 0x1000 → indices for shifts [25,18,11,4] = 0,0,0,1
        map.lock().unwrap().insert(root + 0 * 8, l3 | 1);
        map.lock().unwrap().insert(l3 + 0 * 8, l2 | 1);
        let l3_idx = ((0x1000u64 >> 11) & 0x1FFF) as usize;
        map.lock().unwrap().insert(l2 + (l3_idx as u64) * 8, l1 | 1);
        let l4_idx = ((0x1000u64 >> 4) & 0x1FFF) as usize;
        map.lock().unwrap().insert(l1 + (l4_idx as u64) * 8, 0x5_7000 | 1); // phys 0x57000
        let mut d = Dart::new("dart-ans");
        d.tcr = 1;
        d.ttbr[0] = root;
        d.read_phys = Some(fake_ram(map));
        assert_eq!(d.translate(0, 0x1000), Some(0x57000));
        assert_eq!(d.translate(0, 0x2000), None); // PTE 0 → fault
        assert!(d.faults == 1);
    }
}
