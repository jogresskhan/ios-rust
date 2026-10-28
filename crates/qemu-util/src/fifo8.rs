//! fifo8 — libqemuutil port (`qemu/util/fifo8.c` + `qemu/include/qemu/fifo8.h`).
//!
//! Upstream: "Generic FIFO component, implemented as a circular buffer."
//! Copyright (c) 2012 Peter A. G. Crosthwaite, GPL-2.0-or-later.
//!
//! Byte-ordering behaviour is identical to upstream: data occupies
//! `[head, head + num)` modulo capacity. Upstream `fifo8_push` /
//! `fifo8_push_all` assert on overflow; the Rust ports push what fits and
//! report the remainder through `Err(count)` so device models can mirror the
//! usual `fifo8_num_free()` guard without panicking.

/// Byte FIFO with wraparound — QEMU `Fifo8`.
#[derive(Debug, Clone, Default)]
pub struct Fifo8 {
    /// Backing store; its length is the FIFO capacity (upstream `data`).
    pub data: Vec<u8>,
    /// Read position within `data` (upstream `head`).
    pub head: usize,
    /// Number of valid bytes (upstream `num`).
    pub num: usize,
}

impl Fifo8 {
    /// QEMU `fifo8_create`.
    pub fn new(capacity: usize) -> Self {
        Fifo8 { data: vec![0; capacity], head: 0, num: 0 }
    }

    /// Capacity of the backing store (upstream `fifo->capacity`).
    pub fn capacity(&self) -> usize {
        self.data.len()
    }

    /// QEMU `fifo8_reset`: discard all data, keep the allocation.
    pub fn reset(&mut self) {
        self.num = 0;
        self.head = 0;
    }

    /// QEMU `fifo8_push`: push one byte.
    ///
    /// Returns `Err(byte)` (nothing pushed) when the FIFO is full — the
    /// Rust-safe counterpart of upstream's `assert(fifo->num < capacity)`.
    pub fn push(&mut self, byte: u8) -> Result<(), u8> {
        if self.num >= self.capacity() {
            return Err(byte);
        }
        let idx = (self.head + self.num) % self.capacity();
        self.data[idx] = byte;
        self.num += 1;
        Ok(())
    }

    /// QEMU `fifo8_push_all`: push a byte array.
    ///
    /// Pushes as many bytes as fit (handling wraparound exactly like the
    /// upstream two-`memcpy` version) and returns `Ok(())` when everything
    /// was pushed, or `Err(remaining)` with the number of bytes that did
    /// not fit.
    pub fn push_all(&mut self, data: &[u8]) -> Result<(), usize> {
        let capacity = self.capacity();
        let fits = capacity - self.num.min(capacity);
        let num = data.len().min(fits);
        let start = (self.head + self.num) % capacity;

        if start + num <= capacity {
            self.data[start..start + num].copy_from_slice(&data[..num]);
        } else {
            let avail = capacity - start;
            self.data[start..].copy_from_slice(&data[..avail]);
            self.data[..num - avail].copy_from_slice(&data[avail..num]);
        }
        self.num += num;

        if num < data.len() {
            Err(data.len() - num)
        } else {
            Ok(())
        }
    }

    /// QEMU `fifo8_pop`: pop one byte (`None` when empty instead of asserting).
    pub fn pop(&mut self) -> Option<u8> {
        if self.num == 0 {
            return None;
        }
        let ret = self.data[self.head];
        self.head = (self.head + 1) % self.capacity();
        self.num -= 1;
        Some(ret)
    }

    /// QEMU `fifo8_peek`.
    pub fn peek(&self) -> Option<u8> {
        if self.num == 0 {
            return None;
        }
        Some(self.data[self.head])
    }

    /// QEMU `fifo8_pop_buf`: pop up to `dest.len()` bytes handling wraparound.
    /// Returns the number of bytes popped.
    pub fn pop_buf(&mut self, dest: &mut [u8]) -> usize {
        let (n1, n2) = self.peekpop_buf_parts(dest, true);
        n1 + n2
    }

    /// QEMU `fifo8_peek_buf`: same as `pop_buf` without consuming.
    pub fn peek_buf(&self, dest: &mut [u8]) -> usize {
        let cap = self.capacity();
        let mut copied = 0usize;
        let mut head = self.head;
        let want = dest.len().min(self.num);
        while copied < want {
            let n = (cap - head).min(want - copied);
            dest[copied..copied + n].copy_from_slice(&self.data[head..head + n]);
            copied += n;
            head = (head + n) % cap;
        }
        copied
    }

    /// QEMU `fifo8_drop`: consume `len` bytes (clamped to what is used).
    pub fn drop_bytes(&mut self, len: usize) {
        let n = len.min(self.num);
        self.head = (self.head + n) % self.capacity();
        self.num -= n;
    }

    /// Shared helper implementing upstream `fifo8_peekpop_buf` in two
    /// contiguous parts (returns `(n1, n2)`).
    fn peekpop_buf_parts(&mut self, dest: &mut [u8], do_pop: bool) -> (usize, usize) {
        if dest.is_empty() {
            return (0, 0);
        }
        let cap = self.capacity();
        let len = dest.len().min(self.num);
        let n1 = (cap - self.head).min(len);
        dest[..n1].copy_from_slice(&self.data[self.head..self.head + n1]);

        let mut n2 = 0usize;
        if len - n1 > 0 {
            let head2 = (self.head + n1) % cap;
            n2 = (len - n1).min(cap - head2);
            dest[n1..n1 + n2].copy_from_slice(&self.data[head2..head2 + n2]);
        }

        if do_pop {
            self.head = (self.head + n1 + n2) % cap;
            self.num -= n1 + n2;
        }
        debug_assert_eq!(n1 + n2, len);
        (n1, n2)
    }

    /// QEMU `fifo8_is_empty`.
    pub fn is_empty(&self) -> bool {
        self.num == 0
    }

    /// QEMU `fifo8_is_full`.
    pub fn is_full(&self) -> bool {
        self.num == self.capacity()
    }

    /// QEMU `fifo8_num_free`.
    pub fn num_free(&self) -> usize {
        self.capacity() - self.num
    }

    /// QEMU `fifo8_num_used`.
    pub fn used(&self) -> usize {
        self.num
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_pop_order() {
        let mut f = Fifo8::new(4);
        assert!(f.is_empty() && !f.is_full());
        assert_eq!(f.capacity(), 4);
        assert_eq!(f.push(1), Ok(()));
        assert_eq!(f.push(2), Ok(()));
        assert_eq!(f.push(3), Ok(()));
        assert_eq!(f.push(4), Ok(()));
        assert!(f.is_full());
        assert_eq!(f.num_free(), 0);
        assert_eq!(f.push(5), Err(5)); // full: nothing pushed
        assert_eq!(f.used(), 4);
        assert_eq!(f.peek(), Some(1));
        assert_eq!(f.pop(), Some(1));
        assert_eq!(f.pop(), Some(2));
        assert_eq!(f.pop(), Some(3));
        assert_eq!(f.pop(), Some(4));
        assert_eq!(f.pop(), None);
    }

    #[test]
    fn wraparound() {
        let mut f = Fifo8::new(4);
        // Fill, drain two, refill — head must wrap modulo capacity.
        for b in 1..=4u8 {
            f.push(b).unwrap();
        }
        assert_eq!(f.pop(), Some(1));
        assert_eq!(f.pop(), Some(2));
        assert_eq!(f.push(5), Ok(()));
        assert_eq!(f.push(6), Ok(()));
        assert_eq!(f.head, 2);
        assert_eq!(f.num, 4);
        let mut out = [0u8; 4];
        assert_eq!(f.pop_buf(&mut out), 4);
        assert_eq!(&out, &[3, 4, 5, 6]);
        assert!(f.is_empty());
    }

    #[test]
    fn push_all_partial_and_err() {
        let mut f = Fifo8::new(4);
        assert_eq!(f.push_all(&[1, 2, 3]), Ok(()));
        // Only one byte fits; push_all pushes what fits and reports 2 left.
        assert_eq!(f.push_all(&[4, 5, 6]), Err(2));
        assert_eq!(f.used(), 4);
        let mut out = [0u8; 6];
        assert_eq!(f.peek_buf(&mut out[..4]), 4);
        assert_eq!(&out[..4], &[1, 2, 3, 4]);
    }

    #[test]
    fn pop_buf_peek_buf_drop_reset() {
        let mut f = Fifo8::new(8);
        f.push_all(&[10, 11, 12, 13, 14, 15]).unwrap();
        let mut out = [0u8; 4];
        assert_eq!(f.pop_buf(&mut out), 4);
        assert_eq!(&out, &[10, 11, 12, 13]);
        assert_eq!(f.used(), 2);
        f.drop_bytes(1);
        assert_eq!(f.used(), 1);
        assert_eq!(f.peek(), Some(15));
        assert_eq!(f.peek_buf(&mut out), 1);
        f.reset();
        assert!(f.is_empty());
        assert_eq!(f.head, 0);
        assert_eq!(f.capacity(), 8); // allocation preserved (vmstate parity)
    }
}
