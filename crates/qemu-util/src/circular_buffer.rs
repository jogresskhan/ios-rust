//! circular_buffer — libqemuutil port (`qemu/util/circbuf.c` semantics).
//!
//! Upstream QEMU shipped a small fixed-capacity ring buffer (`CircularBuffer`)
//! with `circbuf_put`/`circbuf_get`/`circbuf_count` semantics: `put` writes as
//! much as fits and returns the number of bytes actually written, `get` reads
//! as much as is available and returns the number of bytes actually read, and
//! the buffer never grows. That contract is reproduced here 1:1 (the C file
//! was removed from recent QEMU trees, so the semantic reference is the
//! historical implementation used by the Apple SPMI/serial style paths).
//!
//! Unlike [`crate::fifo8::Fifo8`] (a QEMU device FIFO), a circular buffer
//! silently drops overflow at `put` time — that is the documented upstream
//! behaviour.

/// Fixed-capacity ring buffer — QEMU `CircularBuffer`.
#[derive(Debug, Clone, Default)]
pub struct CircularBuffer {
    buf: Vec<u8>,
    /// Read position (upstream `read_pos`).
    read_pos: usize,
    /// Write position (upstream `write_pos`).
    write_pos: usize,
    /// Bytes currently stored (upstream `length`).
    len: usize,
}

impl CircularBuffer {
    /// `circbuf_init`: create a ring of `capacity` bytes.
    pub fn new(capacity: usize) -> Self {
        CircularBuffer { buf: vec![0; capacity], read_pos: 0, write_pos: 0, len: 0 }
    }

    /// Capacity in bytes.
    pub fn capacity(&self) -> usize {
        self.buf.len()
    }

    /// `circbuf_count`: number of bytes currently stored.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Free space.
    pub fn free(&self) -> usize {
        self.capacity() - self.len
    }

    /// True when empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// True when full (put will drop bytes).
    pub fn is_full(&self) -> bool {
        self.len == self.capacity()
    }

    /// `circbuf_reset`: discard all data.
    pub fn reset(&mut self) {
        self.read_pos = 0;
        self.write_pos = 0;
        self.len = 0;
    }

    /// `circbuf_put`: append `data`; returns bytes actually written
    /// (overflow is dropped, matching upstream).
    pub fn put(&mut self, data: &[u8]) -> usize {
        let mut written = 0usize;
        while written < data.len() && self.len < self.capacity() {
            self.buf[self.write_pos] = data[written];
            self.write_pos = (self.write_pos + 1) % self.capacity();
            self.len += 1;
            written += 1;
        }
        written
    }

    /// `circbuf_get`: pop into `out`; returns bytes actually read.
    pub fn get(&mut self, out: &mut [u8]) -> usize {
        let mut read = 0usize;
        while read < out.len() && self.len > 0 {
            out[read] = self.buf[self.read_pos];
            self.read_pos = (self.read_pos + 1) % self.capacity();
            self.len -= 1;
            read += 1;
        }
        read
    }

    /// Read without consuming; returns bytes actually copied.
    pub fn peek(&self, out: &mut [u8]) -> usize {
        let mut copied = 0usize;
        let mut pos = self.read_pos;
        while copied < out.len() && copied < self.len {
            out[copied] = self.buf[pos];
            pos = (pos + 1) % self.capacity();
            copied += 1;
        }
        copied
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_get_roundtrip() {
        let mut cb = CircularBuffer::new(8);
        assert_eq!(cb.capacity(), 8);
        assert_eq!(cb.put(&[1, 2, 3, 4]), 4);
        assert_eq!(cb.len(), 4);
        let mut out = [0u8; 4];
        assert_eq!(cb.get(&mut out), 4);
        assert_eq!(&out, &[1, 2, 3, 4]);
        assert!(cb.is_empty());
        assert_eq!(cb.get(&mut out), 0);
    }

    #[test]
    fn overflow_drops_silently() {
        let mut cb = CircularBuffer::new(4);
        assert_eq!(cb.put(&[1, 2, 3, 4, 5, 6]), 4); // rest dropped
        assert!(cb.is_full());
        assert_eq!(cb.free(), 0);
        let mut out = [0u8; 6];
        assert_eq!(cb.get(&mut out), 4);
        assert_eq!(&out[..4], &[1, 2, 3, 4]);
    }

    #[test]
    fn wraparound() {
        let mut cb = CircularBuffer::new(4);
        cb.put(&[1, 2, 3, 4]);
        let mut out = [0u8; 2];
        cb.get(&mut out);
        assert_eq!(&out, &[1, 2]);
        assert_eq!(cb.put(&[5, 6]), 2); // wraps write_pos to 0
        let mut out2 = [0u8; 4];
        assert_eq!(cb.peek(&mut out2), 4);
        assert_eq!(&out2, &[3, 4, 5, 6]);
        assert_eq!(cb.get(&mut out2), 4);
        assert_eq!(&out2, &[3, 4, 5, 6]);
        cb.reset();
        assert!(cb.is_empty());
    }

    #[test]
    fn partial_reads_and_peeks() {
        let mut cb = CircularBuffer::new(8);
        cb.put(b"hello");
        let mut out = [0u8; 3];
        assert_eq!(cb.peek(&mut out), 3); // peek does not consume
        assert_eq!(cb.len(), 5);
        assert_eq!(cb.get(&mut out), 3);
        assert_eq!(&out, b"hel");
        assert_eq!(cb.get(&mut out), 2); // "lo"
        assert_eq!(&out[..2], b"lo");
    }
}
