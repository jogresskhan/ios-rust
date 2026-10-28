//! displaypipe — Apple DisplayPipe v4 (ADP v4) (port of Inferno
//! hw/arm/apple-silicon/apple_displaypipe_v4.c). The display controller
//! the guest programs; on swap-commit the framebuffer is painted into the
//! shared FrameSink — the same "IOMFB-style guest-initiated swap" proven
//! by qemu-sweet's disp0 overlay.

use vm_core::framebuffer::FrameSink;
use vm_core::Device;

pub const ADP_CTRL: u64 = 0x0000;
pub const ADP_SIZE: u64 = 0x0004; // bits [15:0] w, [31:16] h
pub const ADP_FB_ADDR: u64 = 0x0010;
pub const ADP_SWAP: u64 = 0x0020; // write 1 = commit frame
pub const ADP_STATUS: u64 = 0x0024;
pub const ADP_DPTAP: u64 = 0x0400; // DPTap DART base (T8030 has internal DART)

pub struct AdpV4 {
    pub width: u32,
    pub height: u32,
    pub fb_addr: u64,
    pub swaps: u64,
    pub sink: FrameSink,
    /// Physical-memory reader the machine injects (reads a u64 word).
    pub mem_read: Option<Box<dyn FnMut(u64) -> u64 + Send>>,
    pub unknown_reads: u64,
}

impl AdpV4 {
    pub fn new(width: u32, height: u32, sink: FrameSink) -> Self {
        AdpV4 {
            width,
            height,
            fb_addr: 0,
            swaps: 0,
            sink,
            mem_read: None,
            unknown_reads: 0,
        }
    }

    /// Copy one frame from guest memory into the sink.
    /// Layout: linear ARGB8888, stride = width*4 (matches adp v4 mode set
    /// by the proven display path).
    pub fn commit_frame(&mut self) {
        let Some(rd) = self.mem_read.as_mut() else { return };
        let w = self.width as usize;
        let h = self.height as usize;
        if let Ok(mut fb) = self.sink.lock() {
            for y in 0..h {
                for x in 0..w {
                    let addr = self.fb_addr + ((y * w + x) * 4) as u64;
                    let word = rd(addr) as u32;
                    // guest writes ARGB little-endian words
                    let b = (word & 0xFF) as u8;
                    let g = ((word >> 8) & 0xFF) as u8;
                    let r = ((word >> 16) & 0xFF) as u8;
                    let a = ((word >> 24) & 0xFF) as u8;
                    let d = (y * w + x) * 4;
                    fb.rgba[d] = r;
                    fb.rgba[d + 1] = g;
                    fb.rgba[d + 2] = b;
                    fb.rgba[d + 3] = a;
                }
            }
            fb.sequence += 1;
        }
        self.swaps += 1;
    }

    /// Boot splash painter (adp_v4_read_and_draw_boot_splash parity):
    /// solid dark background — real splash art comes from the IPSW via
    /// the restore stage painter instead.
    pub fn draw_splash(&self, rgb: [u8; 3]) {
        if let Ok(mut fb) = self.sink.lock() {
            fb.fill([rgb[0], rgb[1], rgb[2], 0xFF]);
        }
    }

    pub fn regs_documented() -> &'static [(&'static str, u64)] {
        &[
            ("CTRL", ADP_CTRL),
            ("SIZE", ADP_SIZE),
            ("FB_ADDR", ADP_FB_ADDR),
            ("SWAP", ADP_SWAP),
            ("STATUS", ADP_STATUS),
            ("DPTAP", ADP_DPTAP),
        ]
    }
}

impl Device for AdpV4 {
    fn name(&self) -> &'static str {
        "adp-v4"
    }
    fn read(&mut self, off: u64, _size: u8) -> u64 {
        match off {
            ADP_CTRL => 1, // enabled
            ADP_SIZE => ((self.height as u64) << 16) | self.width as u64,
            ADP_FB_ADDR => self.fb_addr,
            ADP_STATUS => self.swaps,
            _ => {
                self.unknown_reads += 1;
                0
            }
        }
    }
    fn write(&mut self, off: u64, _size: u8, val: u64) {
        match off {
            ADP_SIZE => {
                self.width = (val & 0xFFFF) as u32;
                self.height = ((val >> 16) & 0xFFFF) as u32;
            }
            ADP_FB_ADDR => self.fb_addr = val,
            ADP_SWAP => {
                if val & 1 == 1 {
                    self.commit_frame();
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::collections::HashMap;

    #[test]
    fn swap_paints_framebuffer() {
        let sink = vm_core::framebuffer::new_sink(8, 8);
        let mem = Arc::new(Mutex::new(HashMap::<u64, u64>::new()));
        let m2 = mem.clone();
        let mut adp = AdpV4::new(8, 8, sink.clone());
        adp.mem_read = Some(Box::new(move |a| *m2.lock().unwrap().get(&a).unwrap_or(&0)));
        // paint pixel (0,0) magenta
        mem.lock().unwrap().insert(0x8000_0000, 0xFFFF00FF);
        adp.write(ADP_FB_ADDR, 8, 0x8000_0000);
        adp.write(ADP_SWAP, 4, 1);
        let fb = sink.lock().unwrap();
        assert_eq!(fb.sequence, 1);
        assert_eq!(&fb.rgba[0..4], &[0xFF, 0x00, 0xFF, 0xFF]); // R,G,B,A
        drop(fb);
        assert_eq!(adp.swaps, 1);
    }
}
