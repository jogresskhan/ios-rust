//! sart — Apple SART (Secure Address Resolution Table), T8030 generation.
//!
//! Faithful Rust port of ChefKiss Inferno `hw/arm/apple-silicon/sart.c`
//! (AGPL-3.0, © 2023-2026 Visual Ehrmanntraut, Christian Inci).
//!
//! NOTE on the brief: the task sketch mentioned "REG_SART_REQ/ADDR/SIZE/
//! STATUS" — those registers belong to the *T8015* SART (ios-sweet /
//! ANS2 era). The T8030 SART in the local ChefKiss checkout is the
//! region-register-file design (16 regions; v1/v2/v3 encodings), and the
//! sePOS allocate/lock sequence is expressed by writing the SIZE/ADDR/
//! FLAGS registers of a region — which this port implements for real.
//!
//! Register file layout (offsets into the SART MMIO window, from the C):
//! * v1/v2/v3 FLAGS:  `0x0000 + region*4`  (`sart_get_region_flags`)
//! * v1/v2/v3 ADDR:   `0x0040 + region*4`  (`sart_get_region_addr`)
//! * v1/v2 SIZE:      `0x0000 + region*4`, bits [18:0]  (0x7FFFF)
//! * v2   SIZE:       `0x0000 + region*4`, bits [23:0]  (0xFFFFFF)
//! * v3   SIZE:       `0x0080 + region*4`, bits [29:0]  (0x3FFFFFFF)
//! ADDR masks: v1/v2 [23:0], v3 [29:0]. All sizes/addresses are in 4K
//! pages (the C shifts by 12 on use).
//!
//! Translation: identity per 4K page, allowed iff the page falls inside
//! a region with nonzero flags (`apple_sart_translate`).

use vm_core::Device;

pub const SART_MAX_VA_BITS: u32 = 42;
pub const SART_NUM_REGIONS: usize = 16;
pub const SART_REG_SIZE: u64 = 0x8000;

#[derive(Debug, Clone, Copy, Default, PartialEq)]
struct Region {
    addr: u64, // 4K page number
    size: u64, // 4K pages
    flags: u32,
}

/// Apple SART (T8030 `sart-node` / sePOS "SART1" — version 1).
#[derive(Debug)]
pub struct Sart {
    pub version: u32,
    reg: Vec<u32>,
    regions: [Region; SART_NUM_REGIONS],
    /// Counts region recomputes that changed something (the C's
    /// IOMMU notifier storm, one tick here).
    pub region_changes: u64,
    pub unknown_reads: u64,
    pub unknown_writes: u64,
}

impl Sart {
    /// `sart-version` DT prop (default 1; "iOS 13 => v1?" per the C).
    pub fn new(version: u32) -> Self {
        assert!((1..=3).contains(&version), "sart-version must be 1..=3");
        Sart {
            version,
            reg: vec![0; (SART_REG_SIZE / 4) as usize],
            regions: [Region::default(); SART_NUM_REGIONS],
            region_changes: 0,
            unknown_reads: 0,
            unknown_writes: 0,
        }
    }

    fn get_reg(&self, offset: usize) -> u32 {
        self.reg.get(offset).copied().unwrap_or(0)
    }

    /// `sart_get_region_addr`.
    pub fn region_addr(&self, region: usize) -> u64 {
        let v = self.get_reg(0x40 / 4 + region) as u64;
        match self.version {
            1 | 2 => v & 0xFF_FFFF,
            3 => v & 0x3FFF_FFFF,
            _ => unreachable!(),
        }
    }

    /// `sart_get_region_size`.
    pub fn region_size(&self, region: usize) -> u64 {
        match self.version {
            1 => (self.get_reg(region) as u64) & 0x7_FFFF,
            2 => (self.get_reg(region) as u64) & 0xFF_FFFF,
            3 => (self.get_reg(0x80 / 4 + region) as u64) & 0x3FFF_FFFF,
            _ => unreachable!(),
        }
    }

    /// `sart_get_region_flags`.
    pub fn region_flags(&self, region: usize) -> u32 {
        match self.version {
            1 => self.get_reg(region) & !(0x7_FFFFu32 << 12),
            2 => self.get_reg(region) & !(0xFF_FFFFu32 << 12),
            3 => self.get_reg(region),
            _ => unreachable!(),
        }
    }

    /// `base_reg_write` tail: refresh the region view, count changes.
    fn refresh_regions(&mut self) {
        for i in 0..SART_NUM_REGIONS {
            let addr = self.region_addr(i);
            let size = self.region_size(i);
            let flags = self.region_flags(i);
            if self.regions[i].addr != addr
                || self.regions[i].size != size
                || self.regions[i].flags != flags
            {
                self.regions[i] = Region { addr, size, flags };
                self.region_changes += 1;
            }
        }
    }

    /// `apple_sart_translate`: identity 4K mapping when covered.
    /// Returns the mapped page base (iova & !0xFFF) or None.
    pub fn translate(&self, iova: u64) -> Option<u64> {
        let page = iova >> 12;
        for r in &self.regions {
            if r.addr <= page && page < r.addr + r.size && r.flags != 0 {
                return Some(iova & !0xFFF);
            }
        }
        None
    }

    /// Host-side helpers mirroring the sePOS allocate/lock sequence.
    /// `size_pages`/`addr_page` are 4K units exactly like the registers.
    /// NOTE: for v1/v2 the size and flags fields physically overlap in
    /// the same word (the C masks them out of one register); the caller
    /// packs them together, like the guest does.
    pub fn set_region(&mut self, region: usize, addr_page: u64, size_pages: u64, flags: u32) {
        assert!(region < SART_NUM_REGIONS);
        self.reg[0x40 / 4 + region] = addr_page as u32;
        match self.version {
            1 => {
                self.reg[region] =
                    ((size_pages as u32) & 0x7_FFFF) | (flags & 0x8000_0FFF);
            }
            2 => {
                self.reg[region] = ((size_pages as u32) & 0xFF_FFFF) | (flags & 0xFFF);
            }
            3 => {
                self.reg[region] = flags;
                self.reg[0x80 / 4 + region] = size_pages as u32 & 0x3FFF_FFFF;
            }
            _ => unreachable!(),
        }
        self.refresh_regions();
    }
}

impl Device for Sart {
    fn name(&self) -> &'static str {
        "sart"
    }

    fn read(&mut self, addr: u64, _size: u8) -> u64 {
        if addr < SART_REG_SIZE && addr % 4 == 0 {
            self.get_reg((addr >> 2) as usize) as u64
        } else {
            self.unknown_reads += 1;
            0
        }
    }

    fn write(&mut self, addr: u64, _size: u8, data: u64) {
        if addr < SART_REG_SIZE && addr % 4 == 0 {
            self.reg[(addr >> 2) as usize] = data as u32;
            self.refresh_regions();
        } else {
            self.unknown_writes += 1;
        }
    }
}

pub fn regs_documented() -> &'static [(&'static str, u64)] {
    &[
        ("region FLAGS (v1/v2/v3)", 0x0000),
        ("region ADDR", 0x0040),
        ("region SIZE (v3)", 0x0080),
        ("reg window size", SART_REG_SIZE),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v3_allocate_translate_lock() {
        let mut s = Sart::new(3);
        // sePOS-style allocate: size → 0x80+i*4, addr → 0x40+i*4,
        // flags → 0x0+i*4 (any nonzero flags means allow).
        s.write(0x80, 4, 0x100); // 256 pages
        s.write(0x40, 4, 0x2_0000); // at page 0x20000
        s.write(0x00, 4, 0x3); // flags

        assert_eq!(s.region_size(0), 0x100);
        assert_eq!(s.region_addr(0), 0x2_0000);
        assert_eq!(s.region_flags(0), 0x3);

        let base = 0x2_0000u64 << 12;
        assert_eq!(s.translate(base), Some(base));
        assert_eq!(s.translate(base + 0x123), Some(base));
        assert_eq!(s.translate(base + 0x100 * 0x1000 - 4), Some(base + 0xFF000));
        // One page past the end → unmapped.
        assert_eq!(s.translate(base + 0x100 * 0x1000), None);
        // Below → unmapped (identity otherwise allowed in QEMU? No: the
        // C denies everything outside regions).
        assert_eq!(s.translate(0x1000), None);
    }

    #[test]
    fn v2_size_encoding_shares_flags_word() {
        let mut s = Sart::new(2);
        // v2: size bits [23:0], flags bits [11:0] — same word (the C).
        s.set_region(3, 0x1000, 0x7_FFF0, 0);
        assert_eq!(s.region_size(3), 0x7_FFF0);
        assert_eq!(s.region_addr(3), 0x1000);
        assert_eq!(s.region_flags(3), 0xFF0, "low bits of size double as flags");
        assert!(s.translate((0x1000u64) << 12).is_some());
        // Size with clear low bits → flags == 0 → region never maps.
        s.set_region(4, 0x2000, 0x1_0000, 0);
        assert_eq!(s.translate((0x2000u64) << 12), None);
    }

    #[test]
    fn v1_size_field_is_19_bits() {
        let mut s = Sart::new(1);
        s.set_region(0, 0x10, 0xFFFFF, 0);
        assert_eq!(s.region_size(0), 0x7_FFFF, "v1 clamps size to 19 bits");
        assert_eq!(s.region_flags(0), 0xFFF);
    }

    #[test]
    fn region_write_recompute_notifies_once_per_change() {
        let mut s = Sart::new(3);
        let before = s.region_changes;
        s.write(0x40, 4, 0x42);
        assert_eq!(s.region_changes, before + 1);
        // Rewriting the same value → no change.
        s.write(0x40, 4, 0x42);
        assert_eq!(s.region_changes, before + 1);
    }
}
