//! range — libqemuutil port (`qemu/util/range.c` + `qemu/include/qemu/range.h`).
//!
//! Upstream: "QEMU 64-bit address ranges", Copyright (c) 2015-2016 Red Hat,
//! Inc., GPL-2.0-or-later. Bounds are inclusive (`lob` <= `upb`); ranges must
//! not wrap around 0 but may include `UINT64_MAX`. `range_compare` treats
//! touching ranges (`a.upb + 1 == b.lob`) as equal, which is why
//! [`Range::merge`] and [`coalesce`] fuse touching neighbours the same way
//! `range_list_insert` does upstream.

/// Inclusive-bounds 64-bit range — QEMU `Range`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Range {
    /// Inclusive lower bound.
    pub lob: u64,
    /// Inclusive upper bound.
    pub upb: u64,
}

impl Range {
    /// QEMU `range_set_bounds`: span `[lob, upb]`, both inclusive.
    pub fn new(lob: u64, upb: u64) -> Result<Range, String> {
        if lob > upb {
            return Err(format!("invalid range [{lob:#x}, {upb:#x}]"));
        }
        Ok(Range { lob, upb })
    }

    /// QEMU `range_init`: span `[lob, lob + size - 1]` (size may be 0 —
    /// upstream then yields an empty range, which this simple struct
    /// represents as `None`).
    pub fn with_size(lob: u64, size: u64) -> Result<Option<Range>, String> {
        if size == 0 {
            return Ok(None);
        }
        let upb = lob.checked_add(size - 1).ok_or("range overflow")?;
        Ok(Some(Range { lob, upb }))
    }

    /// QEMU `range_size` (`upb - lob + 1`).
    pub fn size(&self) -> u64 {
        self.upb - self.lob + 1
    }

    /// QEMU `range_contains`.
    pub fn contains(&self, val: u64) -> bool {
        val >= self.lob && val <= self.upb
    }

    /// QEMU `range_contains_range`.
    pub fn contains_range(&self, other: &Range) -> bool {
        self.lob <= other.lob && self.upb >= other.upb
    }

    /// QEMU `range_overlaps_range`.
    pub fn overlaps(&self, other: &Range) -> bool {
        !(other.upb < self.lob || self.upb < other.lob)
    }

    /// QEMU `range_extend` as a value operation: smallest range covering
    /// both, `None` when they neither overlap nor touch.
    pub fn merge(&self, other: &Range) -> Option<Range> {
        if !self.overlaps(other) && self.upb.checked_add(1) != Some(other.lob) && other.upb.checked_add(1) != Some(self.lob) {
            return None;
        }
        Some(Range { lob: self.lob.min(other.lob), upb: self.upb.max(other.upb) })
    }

    /// QEMU `range_compare` ordering: -1 if self < b, 1 if self > b,
    /// 0 when touching or overlapping.
    pub fn compare(&self, b: &Range) -> std::cmp::Ordering {
        use std::cmp::Ordering;
        if self.upb < b.lob {
            return Ordering::Less;
        }
        if b.upb < self.lob {
            return Ordering::Greater;
        }
        Ordering::Equal
    }
}

/// QEMU `range_list_insert` + `range_inverse_array` pre-processing: sort by
/// lower bound and fuse overlapping/touching ranges.
pub fn coalesce(mut ranges: Vec<Range>) -> Vec<Range> {
    ranges.sort_by_key(|r| (r.lob, r.upb));
    let mut out: Vec<Range> = Vec::with_capacity(ranges.len());
    for r in ranges {
        match out.last_mut() {
            Some(last) if last.upb.checked_add(1) >= Some(r.lob) => {
                if r.upb > last.upb {
                    last.upb = r.upb;
                }
            }
            _ => out.push(r),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_and_contains() {
        let r = Range::new(0x1000, 0x1fff).unwrap();
        assert_eq!(r.size(), 0x1000);
        assert!(r.contains(0x1000) && r.contains(0x1fff));
        assert!(!r.contains(0x0fff) && !r.contains(0x2000));
        assert!(Range::new(5, 4).is_err());
        assert_eq!(Range::with_size(0x1000, 0x1000).unwrap().unwrap(), r);
        assert!(Range::with_size(0x1000, 0).unwrap().is_none());
        // upb == u64::MAX is legal, wrapping size is not.
        assert!(Range::new(0, u64::MAX).is_ok());
        assert!(Range::with_size(u64::MAX - 1, 4).is_err());
    }

    #[test]
    fn overlaps_and_merge() {
        let a = Range::new(0, 9).unwrap();
        let b = Range::new(10, 19).unwrap(); // touches a
        let c = Range::new(20, 29).unwrap(); // touches b
        assert!(a.merge(&b).is_some());
        assert_eq!(a.merge(&b).unwrap(), Range::new(0, 19).unwrap());
        assert!(a.merge(&c).is_none());
        let m = a.merge(&b).unwrap().merge(&c).unwrap();
        assert_eq!(m, Range::new(0, 29).unwrap());
        let x = Range::new(100, 200).unwrap();
        let y = Range::new(150, 250).unwrap();
        assert!(x.overlaps(&y));
        assert_eq!(x.merge(&y).unwrap(), Range::new(100, 250).unwrap());
        assert!(Range::new(0, 9).unwrap().contains_range(&Range::new(3, 5).unwrap()));
    }

    #[test]
    fn coalesce_sorts_and_fuses() {
        let input = vec![
            Range::new(40, 49).unwrap(),
            Range::new(0, 9).unwrap(),
            Range::new(10, 19).unwrap(),
            Range::new(100, 109).unwrap(),
            Range::new(19, 39).unwrap(), // bridges and overlaps
        ];
        let out = coalesce(input);
        assert_eq!(
            out,
            vec![Range::new(0, 49).unwrap(), Range::new(100, 109).unwrap()]
        );
        assert_eq!(coalesce(vec![]), vec![]);
        // QEMU range_compare: touching == equal ordering.
        assert_eq!(Range::new(0, 9).unwrap().compare(&Range::new(10, 19).unwrap()), std::cmp::Ordering::Equal);
        assert_eq!(Range::new(0, 9).unwrap().compare(&Range::new(11, 19).unwrap()), std::cmp::Ordering::Less);
    }
}
