//! Shared framebuffer — the guest-visible display surface.
//! QEMU: qemu_console + display surface; here one Arc<Mutex<FrameBuffer>>
//! the ADP v4 device paints into and the GUI/frontend reads.

use std::sync::{Arc, Mutex};

#[derive(Clone, Debug)]
pub struct FrameBuffer {
    pub width: u32,
    pub height: u32,
    /// RGBA8888, row-major, width*height*4 bytes.
    pub rgba: Vec<u8>,
    pub sequence: u64,
}

impl FrameBuffer {
    pub fn new(width: u32, height: u32) -> Self {
        FrameBuffer {
            width,
            height,
            rgba: vec![0u8; (width as usize) * (height as usize) * 4],
            sequence: 0,
        }
    }

    pub fn fill(&mut self, rgba: [u8; 4]) {
        for px in self.rgba.chunks_exact_mut(4) {
            px.copy_from_slice(&rgba);
        }
        self.sequence += 1;
    }

    /// Blit an RGBA image at (x, y), clipped.
    pub fn blit(&mut self, x: i64, y: i64, w: u32, h: u32, src: &[u8]) {
        for row in 0..h as i64 {
            let dy = y + row;
            if dy < 0 || dy >= self.height as i64 {
                continue;
            }
            for col in 0..w as i64 {
                let dx = x + col;
                if dx < 0 || dx >= self.width as i64 {
                    continue;
                }
                let s = ((row * w as i64 + col) * 4) as usize;
                if s + 4 > src.len() {
                    continue;
                }
                let d = ((dy * self.width as i64 + dx) * 4) as usize;
                self.rgba[d..d + 4].copy_from_slice(&src[s..s + 4]);
            }
        }
        self.sequence += 1;
    }
}

/// Handle shared between the emulated display controller and the frontend.
pub type FrameSink = Arc<Mutex<FrameBuffer>>;

pub fn new_sink(width: u32, height: u32) -> FrameSink {
    Arc::new(Mutex::new(FrameBuffer::new(width, height)))
}

/// Dump the framebuffer to an uncompressed 32-bit BMP (zero-dep, CI-friendly).
pub fn write_bmp(fb: &FrameBuffer, path: &str) -> std::io::Result<()> {
    let (w, h) = (fb.width as usize, fb.height as usize);
    let row = w * 4;
    let data_size = row * h;
    let file_size = 54 + data_size;
    let mut out = Vec::with_capacity(file_size);
    out.extend_from_slice(b"BM");
    out.extend_from_slice(&(file_size as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&54u32.to_le_bytes());
    out.extend_from_slice(&40u32.to_le_bytes()); // BITMAPINFOHEADER
    out.extend_from_slice(&(w as i32).to_le_bytes());
    out.extend_from_slice(&(h as i32).to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&32u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // BI_RGB
    out.extend_from_slice(&(data_size as u32).to_le_bytes());
    out.extend_from_slice(&2835u32.to_le_bytes());
    out.extend_from_slice(&2835u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    // BMP is bottom-up BGRA.
    for row_i in (0..h).rev() {
        for px in fb.rgba[row_i * row..(row_i + 1) * row].chunks_exact(4) {
            out.push(px[2]); // B
            out.push(px[1]); // G
            out.push(px[0]); // R
            out.push(px[3]); // A
        }
    }
    std::fs::write(path, out)
}
