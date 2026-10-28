//! iov — libqemuutil port (`qemu/util/iov.c` + `qemu/include/qemu/iov.h`,
//! subset). Scatter/gather primitives: the engine's nvme/ans and network
//! backends move data as iovecs; the restore pipeline needs the same shape
//! when streaming ramdisk/rootfs bytes.
//!
//! Unlike raw C `struct iovec` (base pointer + len into some address
//! space), the Rust [`IoVec`] owns its bytes and carries the logical
//! `offset` of the segment inside the aggregate stream — DMA code maps
//! `offset` to a device address, host-side code treats the vector as a
//! fragmented buffer with the same `iov_from_buf`/`iov_to_buf` semantics as
//! upstream (copy as much as fits, return the byte count).

/// One owned scatter/gather segment.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IoVec {
    /// Logical offset of this segment inside the aggregate byte stream
    /// (device address for DMA-style consumers).
    pub offset: usize,
    /// Segment bytes.
    pub data: Vec<u8>,
}

/// A list of segments — the Rust stand-in for `struct iovec *` + `iovcnt`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IoVector {
    pub iovs: Vec<IoVec>,
}

/// Total bytes across a segment list (upstream `iov_size`).
pub fn iov_size(iov: &[IoVec]) -> usize {
    iov.iter().map(|s| s.data.len()).sum()
}

/// `iov_from_buf_full` semantics: copy `bytes` into the scatter list
/// starting at logical `offset`; returns the bytes actually copied
/// (clamped by the remaining vector space).
pub fn iov_from_buf(iov: &mut [IoVec], offset: usize, bytes: &[u8]) -> usize {
    let mut written = 0usize;
    let mut src = bytes;
    let mut skip = offset;
    for seg in iov.iter_mut() {
        if src.is_empty() {
            break;
        }
        if skip >= seg.data.len() {
            skip -= seg.data.len();
            continue;
        }
        let dst = &mut seg.data[skip..];
        let n = dst.len().min(src.len());
        dst[..n].copy_from_slice(&src[..n]);
        written += n;
        src = &src[n..];
        skip = 0;
    }
    written
}

/// `iov_to_buf_full` semantics: read out of the scatter list (starting at
/// logical `offset`) into `out`; returns bytes actually copied.
pub fn iov_to_buf(iov: &[IoVec], offset: usize, out: &mut [u8]) -> usize {
    let mut copied = 0usize;
    let mut skip = offset;
    let mut dst = out;
    for seg in iov {
        if dst.is_empty() {
            break;
        }
        if skip >= seg.data.len() {
            skip -= seg.data.len();
            continue;
        }
        let src = &seg.data[skip..];
        let n = src.len().min(dst.len());
        dst[..n].copy_from_slice(src);
        copied += n;
        dst = &mut dst[n..];
        skip = 0;
    }
    copied
}

/// Allocate `count` zeroed segments of `chunk` bytes each (DMA scatter for
/// e.g. NVMe PRP pages).
pub fn iov_make(count: usize, chunk: usize) -> Vec<IoVec> {
    (0..count)
        .map(|i| IoVec { offset: i * chunk, data: vec![0; chunk] })
        .collect()
}

impl IoVector {
    pub fn new() -> Self {
        IoVector { iovs: Vec::new() }
    }

    /// Build from contiguous slices; segment `offset`s are the running
    /// positions inside the aggregate stream.
    pub fn from_slices(slices: &[&[u8]]) -> Self {
        let mut pos = 0usize;
        let iovs = slices
            .iter()
            .map(|s| {
                let v = IoVec { offset: pos, data: s.to_vec() };
                pos += v.data.len();
                v
            })
            .collect();
        IoVector { iovs }
    }

    /// Upstream `iov_size`.
    pub fn total_len(&self) -> usize {
        iov_size(&self.iovs)
    }

    /// Flatten back into one contiguous buffer (upstream `iov_to_buf` with
    /// a large enough destination).
    pub fn to_vec(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.total_len());
        for seg in &self.iovs {
            out.extend_from_slice(&seg.data);
        }
        out
    }

    /// Copy the sub-stream starting at logical `offset` into `buf`;
    /// returns the number of bytes copied (`min(total_len - offset, buf.len())`).
    pub fn copy_to_buf(&self, offset: usize, buf: &mut [u8]) -> usize {
        iov_to_buf(&self.iovs, offset, buf)
    }

    /// Append an owned segment at the current end of the stream.
    pub fn push(&mut self, data: Vec<u8>) {
        let offset = self.total_len();
        self.iovs.push(IoVec { offset, data });
    }

    /// Number of segments.
    pub fn len(&self) -> usize {
        self.iovs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.iovs.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_slices_total_len_and_flatten() {
        let v = IoVector::from_slices(&[b"hello ".as_slice(), b"world".as_slice()]);
        assert_eq!(v.len(), 2);
        assert_eq!(v.total_len(), 11);
        assert_eq!(v.iovs[1].offset, 6);
        assert_eq!(v.to_vec(), b"hello world".to_vec());
        assert!(IoVector::new().is_empty());
    }

    #[test]
    fn copy_to_buf_respects_offset() {
        let v = IoVector::from_slices(&[&[1u8, 2, 3, 4], &[5, 6, 7, 8]]);
        let mut out = [0u8; 4];
        assert_eq!(v.copy_to_buf(0, &mut out), 4);
        assert_eq!(out, [1, 2, 3, 4]);
        assert_eq!(v.copy_to_buf(6, &mut out), 2); // crosses the segment seam
        assert_eq!(out[..2], [7, 8]);
        assert_eq!(v.copy_to_buf(100, &mut out), 0); // past the end
        let mut big = [0u8; 16];
        assert_eq!(v.copy_to_buf(2, &mut big), 6); // clamped by total_len
        assert_eq!(&big[..6], &[3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn from_buf_roundtrip_across_segments() {
        let mut iov = iov_make(3, 4); // 3 pages of 4 bytes
        assert_eq!(iov.len(), 3);
        assert_eq!(iov_size(&iov), 12);
        assert_eq!(iov_from_buf(&mut iov, 2, &[0xAA; 6]), 6);
        let mut out = [0u8; 6];
        assert_eq!(iov_to_buf(&iov, 2, &mut out), 6);
        assert_eq!(out, [0xAA; 6]);
        // Writing past the end is clamped and reported.
        assert_eq!(iov_from_buf(&mut iov, 10, &[1, 2, 3]), 2);
    }

    #[test]
    fn push_extends_stream() {
        let mut v = IoVector::new();
        v.push(vec![1, 2]);
        v.push(vec![3]);
        assert_eq!(v.iovs[1].offset, 2);
        assert_eq!(v.total_len(), 3);
        assert_eq!(v.to_vec(), vec![1, 2, 3]);
    }
}
