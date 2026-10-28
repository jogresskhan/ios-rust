//! Port of `util/iov.c` — scatter/gather primitives. The engine's nvme/ans and
//! network backends move data as iovecs; the restore pipeline needs the same
//! shape when streaming ramdisk/rootfs bytes.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoVec {
    pub base: usize, // offset into a backing buffer
    pub len: usize,
}

/// Total bytes across the vector (iov_size).
pub fn iov_size(iov: &[IoVec]) -> usize {
    iov.iter().map(|s| s.len).sum()
}

/// iov_from_buf_full semantics: copy `bytes` into the scatter list starting at
/// `offset`, returns bytes actually copied.
pub fn iov_from_buf(iov: &[IoVec], backing: &mut [u8], offset: usize, bytes: &[u8]) -> usize {
    let mut written = 0usize;
    let mut src = bytes;
    let mut skip = offset;
    for seg in iov {
        if src.is_empty() {
            break;
        }
        let seg_start = seg.base;
        let seg_end = seg.base + seg.len;
        if skip >= seg.len {
            skip -= seg.len;
            continue;
        }
        let dst = &mut backing[seg_start + skip..seg_end];
        let n = dst.len().min(src.len());
        dst[..n].copy_from_slice(&src[..n]);
        written += n;
        src = &src[n..];
        skip = 0;
    }
    written
}

/// iov_to_buf_full semantics: read out of the scatter list into `out`.
pub fn iov_to_buf(iov: &[IoVec], backing: &[u8], offset: usize, out: &mut [u8]) -> usize {
    let mut copied = 0usize;
    let mut skip = offset;
    let mut dst = out;
    for seg in iov {
        if dst.is_empty() {
            break;
        }
        if skip >= seg.len {
            skip -= seg.len;
            continue;
        }
        let src_slice = &backing[seg.base + skip..seg.base + seg.len];
        let n = src_slice.len().min(dst.len());
        dst[..n].copy_from_slice(&src_slice[..n]);
        copied += n;
        dst = &mut dst[n..];
        skip = 0;
    }
    copied
}

/// Split a flat byte slice into iovecs of at most `max` len (DMA scatter).
pub fn iov_make(total: usize, max: usize) -> Vec<IoVec> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off < total {
        let len = (total - off).min(max);
        out.push(IoVec { base: off, len });
        off += len;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_scatter() {
        let mut backing = [0u8; 16];
        let iov = iov_make(16, 6); // 6+6+4
        assert_eq!(iov.len(), 3);
        assert_eq!(iov_size(&iov), 16);

        let n = iov_from_buf(&iov, &mut backing, 0, &[0xAA; 10]);
        assert_eq!(n, 10);
        let mut out = [0u8; 4];
        // offset 4..8 lies fully inside the 10 written bytes
        let n = iov_to_buf(&iov, &backing, 4, &mut out);
        assert_eq!(n, 4);
        assert_eq!(out, [0xAA; 4]);
    }

    #[test]
    fn offset_respected() {
        let mut backing = [0u8; 8];
        let iov = vec![IoVec { base: 0, len: 8 }];
        iov_from_buf(&iov, &mut backing, 4, &[1, 2]);
        assert_eq!(&backing[4..6], &[1, 2]);
    }
}
