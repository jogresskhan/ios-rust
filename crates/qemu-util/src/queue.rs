//! Port of `include/qemu/queue.h` (LIST/SLIST/TAILQ) as an intrusive-free
//! Rust equivalent: a doubly-linked ordered map keyed by MMIO base — the shape
//! every machine's device registration uses (QTAILQ of MemoryRegion + base).

use std::collections::BTreeMap;

/// Ordered device registry: the Rust stand-in for QTAILQ_INSERT_TAIL over
/// devices sorted by MMIO base. Keeps dispatch by address O(log n).
#[derive(Debug)]
pub struct DeviceQueue<T> {
    entries: BTreeMap<u64, T>,
    insertion_order: Vec<u64>,
}

impl<T> Default for DeviceQueue<T> {
    fn default() -> Self {
        Self { entries: BTreeMap::new(), insertion_order: Vec::new() }
    }
}

impl<T> DeviceQueue<T> {
    pub fn new() -> Self {
        Self::default()
    }

    /// QTAILQ_INSERT_TAIL (keeps first-insertion order for equal bases).
    pub fn insert_tail(&mut self, base: u64, dev: T) -> Option<T> {
        self.insertion_order.push(base);
        self.entries.insert(base, dev)
    }

    pub fn get(&self, base: u64) -> Option<&T> {
        self.entries.get(&base)
    }

    pub fn get_mut(&mut self, base: u64) -> Option<&mut T> {
        self.entries.get_mut(&base)
    }

    /// Find the base whose range [base, base+size) contains `addr` (mutable-dispatch
    /// helper: immutable borrow ends before the caller re-borrows for mutation).
    pub fn find_base_containing<F>(&self, addr: u64, size_of: F) -> Option<u64>
    where
        F: Fn(&T) -> u64,
    {
        self.entries
            .iter()
            .find(|(base, dev)| addr >= **base && addr < **base + size_of(dev))
            .map(|(base, _)| *base)
    }

    pub fn find_containing<F>(&self, addr: u64, size_of: F) -> Option<(u64, &T)>
    where
        F: Fn(&T) -> u64,
    {
        self.entries
            .iter()
            .find(|(base, dev)| addr >= **base && addr < **base + size_of(dev))
            .map(|(base, dev)| (*base, dev))
    }

    pub fn iter(&self) -> impl Iterator<Item = (u64, &T)> {
        self.insertion_order
            .iter()
            .filter_map(|b| self.entries.get(b).map(|d| (*b, d)))
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_by_address() {
        let mut q: DeviceQueue<&'static str> = DeviceQueue::new();
        q.insert_tail(0x2000_0000, "uart0"); // 0x4000 size
        q.insert_tail(0x23B0_4000, "dart");
        q.insert_tail(0x23D2_8000, "adp");

        let size = |d: &&'static str| 0x4000u64;
        assert_eq!(*q.find_containing(0x2000_0100, size).unwrap().1, "uart0");
        assert_eq!(*q.find_containing(0x23B0_5000, size).unwrap().1, "dart");
        assert!(q.find_containing(0x9999_0000, size).is_none());
        // insertion order preserved
        let names: Vec<_> = q.iter().map(|(_, n)| *n).collect();
        assert_eq!(names, vec!["uart0", "dart", "adp"]);
    }
}
