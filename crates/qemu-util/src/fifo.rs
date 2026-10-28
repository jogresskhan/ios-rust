//! Port of `util/fifo8.c` — the 8-bit FIFO every chardev model
//! (uart, mipi dsi fifo acks, disp0 command stream) in the engine uses.

#[derive(Debug)]
pub struct Fifo8 {
    data: Vec<u8>,
    head: usize,
    num: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum FifoError {
    #[error("fifo overflow ({0} free)")]
    Overflow(usize),
    #[error("fifo underflow")]
    Underflow,
}

impl Default for Fifo8 {
    fn default() -> Self {
        Self::new(1024)
    }
}

impl Fifo8 {
    pub fn new(capacity: usize) -> Self {
        Self { data: vec![0; capacity.max(1)], head: 0, num: 0 }
    }

    pub fn capacity(&self) -> usize {
        self.data.len()
    }

    /// Bytes currently buffered (fifo8_num_used).
    pub fn used(&self) -> usize {
        self.num
    }

    pub fn is_empty(&self) -> bool {
        self.num == 0
    }

    pub fn free(&self) -> usize {
        self.data.len() - self.num
    }

    pub fn reset(&mut self) {
        self.head = 0;
        self.num = 0;
    }

    /// fifo8_push — one byte.
    pub fn push(&mut self, byte: u8) -> Result<(), FifoError> {
        if self.free() == 0 {
            return Err(FifoError::Overflow(0));
        }
        let idx = (self.head + self.num) % self.data.len();
        self.data[idx] = byte;
        self.num += 1;
        Ok(())
    }

    /// fifo8_pop.
    pub fn pop(&mut self) -> Result<u8, FifoError> {
        if self.num == 0 {
            return Err(FifoError::Underflow);
        }
        let b = self.data[self.head];
        self.head = (self.head + 1) % self.data.len();
        self.num -= 1;
        Ok(b)
    }

    /// fifo8_push_all.
    pub fn push_all(&mut self, bytes: &[u8]) -> Result<(), FifoError> {
        if bytes.len() > self.free() {
            return Err(FifoError::Overflow(self.free()));
        }
        for &b in bytes {
            self.push(b)?;
        }
        Ok(())
    }

    /// fifo8_pop_buf — drain up to `max` bytes into a contiguous Vec.
    pub fn pop_buf(&mut self, max: usize) -> Vec<u8> {
        let n = max.min(self.num);
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            if let Ok(b) = self.pop() {
                out.push(b);
            }
        }
        out
    }

    /// fifo8_peek (non-destructive head byte).
    pub fn peek(&self) -> Result<u8, FifoError> {
        if self.num == 0 {
            return Err(FifoError::Underflow);
        }
        Ok(self.data[self.head])
    }

    /// Does the buffer start with `prefix`? (used for DSI short/long packet
    /// detection in the synopsys mipi model).
    pub fn starts_with(&self, prefix: &[u8]) -> bool {
        if prefix.len() > self.num {
            return false;
        }
        (0..prefix.len()).all(|i| self.data[(self.head + i) % self.data.len()] == prefix[i])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraparound() {
        let mut f = Fifo8::new(4);
        for b in [1u8, 2, 3, 4] {
            f.push(b).unwrap();
        }
        assert!(f.is_full_or(4));
        assert_eq!(f.pop().unwrap(), 1);
        f.push(5).unwrap();
        assert_eq!(f.used(), 4);
        assert_eq!(f.pop_buf(4), vec![2, 3, 4, 5]);
    }

    #[test]
    fn overflow_and_underflow() {
        let mut f = Fifo8::new(2);
        assert!(f.push_all(&[1, 2, 3]).is_err());
        assert!(f.pop().is_err());
        f.push(9).unwrap();
        assert_eq!(f.peek().unwrap(), 9);
    }

    #[test]
    fn prefix_detect() {
        let mut f = Fifo8::new(8);
        f.push_all(&[0x39, 0x00]).unwrap();
        assert!(f.starts_with(&[0x39]));
        assert!(f.starts_with(&[0x39, 0x00]));
        assert!(!f.starts_with(&[0x39, 0x00, 0x01]));
    }

    impl Fifo8 {
        fn is_full_or(&self, cap: usize) -> bool {
            self.used() == cap
        }
    }
}
