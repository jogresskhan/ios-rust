//! buffer — libqemuutil port (`qemu/util/buffer.c` + `qemu/include/qemu/buffer.h`).
//!
//! Upstream: "QEMU generic buffers", Copyright (c) 2015 Red Hat, Inc.,
//! LGPL-2.1-or-later. Semantics kept:
//! - growth policy `buffer_req_size = MAX(4096, pow2ceil(offset + len))`
//!   (`BUFFER_MIN_INIT_SIZE` = 4096);
//! - `buffer_append` memcpy at the end, `buffer_advance` removes from the
//!   front (memmove), `buffer_reset` clears the used length;
//! - "zero-copy-ish" access via slices instead of raw pointers.
//!
//! The Rust `ByteBuffer` tracks a consumed prefix (`offset`) inside the same
//! allocation so `advance` does not move data until the buffer is drained,
//! then compacts like `buffer_advance`.

/// Growable byte buffer with front-consumption — QEMU `Buffer`.
#[derive(Debug, Clone, Default)]
pub struct ByteBuffer {
    buf: Vec<u8>,
    /// Consumed prefix (bytes already drained/advanced).
    offset: usize,
    /// Valid bytes `[offset, offset + len)`.
    len: usize,
}

/// QEMU `BUFFER_MIN_INIT_SIZE`.
pub const BUFFER_MIN_INIT_SIZE: usize = 4096;

impl ByteBuffer {
    /// QEMU `buffer_init` + `buffer_reserve`: pre-allocate at least `capacity`.
    pub fn allocate(capacity: usize) -> Self {
        let cap = capacity.max(BUFFER_MIN_INIT_SIZE);
        ByteBuffer { buf: vec![0; cap], offset: 0, len: 0 }
    }

    /// QEMU `buffer_req_size`.
    fn req_size(&self, extra: usize) -> usize {
        BUFFER_MIN_INIT_SIZE.max(crate::bitops::pow2ceil((self.offset + self.len + extra) as u64) as usize)
    }

    /// QEMU `buffer_reserve`: ensure room for `extra` more bytes.
    pub fn reserve(&mut self, extra: usize) {
        let needed = self.offset + self.len + extra;
        if needed > self.buf.len() {
            self.buf.resize(self.req_size(extra), 0);
        }
    }

    /// QEMU `buffer_append`: copy `data` to the end of the buffer.
    pub fn append(&mut self, data: &[u8]) {
        self.reserve(data.len());
        let end = self.offset + self.len;
        self.buf[end..end + data.len()].copy_from_slice(data);
        self.len += data.len();
    }

    /// QEMU `buffer_empty`.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// QEMU `buffer_end` usable region: the valid data as a slice.
    pub fn data(&self) -> &[u8] {
        &self.buf[self.offset..self.offset + self.len]
    }

    /// Mutable access to the valid region (for in-place protocol parsing).
    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.buf[self.offset..self.offset + self.len]
    }

    /// QEMU `buffer->offset + buffer->capacity` semantics: total allocation.
    pub fn capacity(&self) -> usize {
        self.buf.len()
    }

    /// Free space in the current allocation (`capacity - used`).
    pub fn avail(&self) -> usize {
        self.buf.len() - (self.offset + self.len)
    }

    /// Number of valid bytes (`Buffer.offset` upstream).
    pub fn size(&self) -> usize {
        self.len
    }

    /// QEMU `buffer_reset`: mark the buffer empty.
    pub fn reset(&mut self) {
        self.offset = 0;
        self.len = 0;
    }

    /// QEMU `buffer_advance`: consume `len` bytes from the front, compacting
    /// when everything is consumed (upstream memmove equivalent).
    pub fn advance(&mut self, len: usize) {
        let n = len.min(self.len);
        self.offset += n;
        self.len -= n;
        if self.len == 0 {
            self.offset = 0;
        }
    }

    /// Pop the first `len` bytes and return them (advance + copy).
    pub fn drain(&mut self, len: usize) -> Vec<u8> {
        let n = len.min(self.len);
        let out = self.buf[self.offset..self.offset + n].to_vec();
        self.advance(n);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_and_grow() {
        let mut b = ByteBuffer::default();
        assert_eq!(b.capacity(), 0);
        b.append(b"hello");
        b.append(b" world");
        assert_eq!(b.size(), 11);
        assert_eq!(b.data(), b"hello world");
        // Growth follows the pow2ceil/min-4096 upstream policy.
        assert!(b.capacity() >= BUFFER_MIN_INIT_SIZE);
        assert!(crate::bitops::is_power_of_2(b.capacity() as u64));
    }

    #[test]
    fn allocate_min_size() {
        let b = ByteBuffer::allocate(10);
        assert_eq!(b.capacity(), BUFFER_MIN_INIT_SIZE);
        assert_eq!(b.avail(), BUFFER_MIN_INIT_SIZE);
        assert!(b.is_empty());
    }

    #[test]
    fn advance_and_drain() {
        let mut b = ByteBuffer::allocate(0);
        b.append(&[1, 2, 3, 4, 5]);
        b.advance(2);
        assert_eq!(b.data(), &[3, 4, 5]);
        assert_eq!(b.drain(2), vec![3, 4]);
        assert_eq!(b.data(), &[5]);
        b.advance(1);
        assert!(b.is_empty());
        assert_eq!(b.offset, 0); // compacted once drained
    }

    #[test]
    fn reset_and_reserve() {
        let mut b = ByteBuffer::allocate(0);
        b.append(&vec![0xaa; 5000]);
        let cap_after = b.capacity();
        b.reset();
        assert_eq!(b.size(), 0);
        assert_eq!(b.avail(), cap_after);
        // Upstream only grows when free space would not cover the request.
        b.reserve(7000);
        assert_eq!(b.capacity(), cap_after);
        b.reserve(20000);
        assert!(b.capacity() >= 20_000);
        assert!(crate::bitops::is_power_of_2(b.capacity() as u64));
        b.data_mut()[0] = 0x55;
        assert_eq!(b.data()[0], 0x55);
    }
}
