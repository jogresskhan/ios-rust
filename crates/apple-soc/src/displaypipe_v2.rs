//! displaypipe_v2 — Apple Display Pipe v2 (port of hw/display/
//! apple_displaypipe_v2.c): the A7–A11 era display controller — the tiny
//! /backend/ timing bank (VFTG control, screen size, porches, constant
//! colour), an unimplemented /frontend/ (SPDS version 0x13) and the
//! aap/pixel-bl/dither/prc dummy banks. Upstream splits these across six
//! MMIO regions created from the DT "reg" property; this port flattens
//! them into one offset space (the machine attaches the banks at their
//! DT bases). Frame output mirrors `adp_v2_gfx_update`: linear ARGB8888,
//! stride = width*4, copied from guest memory into the shared FrameSink.

use vm_core::framebuffer::FrameSink;
use vm_core::Device;

// ---- /frontend/ bank (C: frontend_reg_ops) ----
pub const REG_SPDS_VERSION: u64 = 0x1014;

// ---- /backend/ bank (C: backend_reg_ops) ----
pub const REG_DBE_VFTG_CTRL: u64 = 0x8;
pub const REG_DBE_SCREEN_SIZE: u64 = 0xC;
pub const DBE_VFTG_CTRL_VFTG_ENABLE: u32 = 1 << 31;
pub const DBE_VFTG_CTRL_VFTG_STATUS: u32 = 1 << 30;
pub const DBE_VFTG_CTRL_UPDATE_ENABLE_TIMING: u32 = 1 << 15;
pub const DBE_VFTG_CTRL_UPDATE_REQ_TIMING: u32 = 1 << 14;
pub const REG_DBE_FRONT_PORCH: u64 = 0x10;
pub const REG_DBE_SYNC_PULSE: u64 = 0x14;
pub const REG_DBE_BACK_PORCH: u64 = 0x18;
pub const REG_DBE_CONST_COLOUR: u64 = 0x34;

/// C property defaults: iPhone 4/4S panel.
pub const ADP_V2_DEFAULT_WIDTH: u32 = 640;
pub const ADP_V2_DEFAULT_HEIGHT: u32 = 960;

pub struct AdpV2 {
    pub width: u32,
    pub height: u32,
    /// VRAM base in guest physical memory (C: the vram region the machine
    /// maps via adp_v2_update_vram_mapping).
    pub fb_base: u64,
    /// C: dbe_state.vftg_ctl.
    pub vftg_ctl: u32,
    /// C: dbe_state.const_colour.
    pub const_colour: u32,
    pub swaps: u64,
    pub sink: FrameSink,
    /// Physical-memory reader the machine injects (reads a u64 word).
    pub mem_read: Option<Box<dyn FnMut(u64) -> u64 + Send>>,
    /// C: irqs[9] — initialized upstream, never driven.
    pub irqs: [bool; 9],
    pub guest_errors: u64,
    pub unknown_reads: u64,
    pub unknown_writes: u64,
}

impl AdpV2 {
    pub fn new(width: u32, height: u32, sink: FrameSink) -> Self {
        let mut adp = AdpV2 {
            width,
            height,
            fb_base: 0,
            vftg_ctl: 0,
            const_colour: 0,
            swaps: 0,
            sink,
            mem_read: None,
            irqs: [false; 9],
            guest_errors: 0,
            unknown_reads: 0,
            unknown_writes: 0,
        };
        // C adp_v2_realize: the back end comes up with VFTG enabled.
        adp.vftg_ctl = DBE_VFTG_CTRL_VFTG_ENABLE
            | DBE_VFTG_CTRL_VFTG_STATUS
            | DBE_VFTG_CTRL_UPDATE_ENABLE_TIMING
            | DBE_VFTG_CTRL_UPDATE_REQ_TIMING;
        adp
    }

    /// C: `adp_v2_gfx_update` + `adp_v2_draw_row` — copy one frame of
    /// linear ARGB8888 (stride = width*4) from guest memory into the sink.
    pub fn commit_frame(&mut self) {
        let Some(rd) = self.mem_read.as_mut() else { return };
        let w = self.width as usize;
        let h = self.height as usize;
        if w == 0 || h == 0 {
            return;
        }
        if let Ok(mut fb) = self.sink.lock() {
            for y in 0..h {
                for x in 0..w {
                    let addr = self.fb_base + ((y * w + x) * 4) as u64;
                    let word = rd(addr) as u32;
                    // guest writes ARGB little-endian words (C: ldl_le_p)
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

    pub fn regs_documented() -> &'static [(&'static str, u64)] {
        &[
            ("SPDS_VERSION", REG_SPDS_VERSION),
            ("DBE_VFTG_CTRL", REG_DBE_VFTG_CTRL),
            ("DBE_SCREEN_SIZE", REG_DBE_SCREEN_SIZE),
            ("DBE_FRONT_PORCH", REG_DBE_FRONT_PORCH),
            ("DBE_SYNC_PULSE", REG_DBE_SYNC_PULSE),
            ("DBE_BACK_PORCH", REG_DBE_BACK_PORCH),
            ("DBE_CONST_COLOUR", REG_DBE_CONST_COLOUR),
        ]
    }
}

impl Default for AdpV2 {
    fn default() -> Self {
        Self::new(
            ADP_V2_DEFAULT_WIDTH,
            ADP_V2_DEFAULT_HEIGHT,
            vm_core::framebuffer::new_sink(ADP_V2_DEFAULT_WIDTH, ADP_V2_DEFAULT_HEIGHT),
        )
    }
}

impl Device for AdpV2 {
    fn name(&self) -> &'static str {
        "adp-v2"
    }
    /// Backend + frontend banks flattened (see module docs); the dummy
    /// banks (aap/pixel-bl/dither/prc) fall through to unknown_reads.
    fn read(&mut self, off: u64, _size: u8) -> u64 {
        match off {
            REG_DBE_VFTG_CTRL => self.vftg_ctl as u64,
            REG_DBE_SCREEN_SIZE => (self.width as u64) | ((self.height as u64) << 16),
            // Hardcoded iPhone 4/4S timing, exactly as upstream.
            REG_DBE_FRONT_PORCH => 102 | (536 << 16),
            REG_DBE_SYNC_PULSE => 32 | (3 << 16),
            REG_DBE_BACK_PORCH => 4 | (4 << 16),
            REG_DBE_CONST_COLOUR => self.const_colour as u64,
            REG_SPDS_VERSION => {
                // C logs LOG_GUEST_ERROR here (SPDS read on a v2 pipe).
                self.guest_errors += 1;
                0x13
            }
            _ => {
                self.unknown_reads += 1;
                0
            }
        }
    }
    fn write(&mut self, off: u64, _size: u8, val: u64) {
        match off {
            REG_DBE_VFTG_CTRL => {
                let mut data = val as u32;
                if data & DBE_VFTG_CTRL_VFTG_ENABLE != 0 {
                    data |= DBE_VFTG_CTRL_VFTG_STATUS;
                }
                self.vftg_ctl = data;
            }
            REG_DBE_SCREEN_SIZE => {
                // "attempted to set screen size, this is NOT supported!"
                self.guest_errors += 1;
            }
            REG_DBE_CONST_COLOUR => {
                self.const_colour = val as u32;
            }
            _ => {
                self.unknown_writes += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    #[test]
    fn backend_reset_values_and_timing_constants() {
        let mut adp = AdpV2::default();
        // realize-time VFTG value: ENABLE|STATUS|UPDATE_ENABLE|UPDATE_REQ
        assert_eq!(
            adp.vftg_ctl,
            DBE_VFTG_CTRL_VFTG_ENABLE
                | DBE_VFTG_CTRL_VFTG_STATUS
                | DBE_VFTG_CTRL_UPDATE_ENABLE_TIMING
                | DBE_VFTG_CTRL_UPDATE_REQ_TIMING
        );
        assert_eq!(adp.read(REG_DBE_VFTG_CTRL, 4), 0xC000_C000);
        // iPhone 4/4S panel geometry + fixed timing words.
        assert_eq!(adp.read(REG_DBE_SCREEN_SIZE, 4), 640 | (960 << 16));
        assert_eq!(adp.read(REG_DBE_FRONT_PORCH, 4), 102 | (536 << 16));
        assert_eq!(adp.read(REG_DBE_SYNC_PULSE, 4), 32 | (3 << 16));
        assert_eq!(adp.read(REG_DBE_BACK_PORCH, 4), 4 | (4 << 16));
        // /frontend/ SPDS version reads 0x13 (and counts the guest error).
        assert_eq!(adp.read(REG_SPDS_VERSION, 4), 0x13);
        assert_eq!(adp.guest_errors, 1);
    }

    #[test]
    fn vftg_status_follows_enable_and_const_colour_roundtrip() {
        let mut adp = AdpV2::default();
        // Clearing the control register clears STATUS too.
        adp.write(REG_DBE_VFTG_CTRL, 4, 0);
        assert_eq!(adp.read(REG_DBE_VFTG_CTRL, 4), 0);
        // Writing ENABLE without STATUS still reads back STATUS set.
        adp.write(REG_DBE_VFTG_CTRL, 4, DBE_VFTG_CTRL_VFTG_ENABLE as u64);
        assert_eq!(
            adp.read(REG_DBE_VFTG_CTRL, 4),
            (DBE_VFTG_CTRL_VFTG_ENABLE | DBE_VFTG_CTRL_VFTG_STATUS) as u64
        );
        // CONST_COLOUR roundtrip.
        adp.write(REG_DBE_CONST_COLOUR, 4, 0x00FF8040);
        assert_eq!(adp.read(REG_DBE_CONST_COLOUR, 4), 0x00FF8040);
        // Screen size writes are rejected (handled register → no unknown).
        adp.write(REG_DBE_SCREEN_SIZE, 4, 0x1234_5678);
        assert_eq!(adp.read(REG_DBE_SCREEN_SIZE, 4), 640 | (960 << 16));
        assert_eq!(adp.guest_errors, 1); // only the size-write rejection
        // Truly unimplemented offsets land in the unknown buckets.
        let _ = adp.read(0x4000, 4);
        adp.write(0x4000, 4, 1);
        assert_eq!(adp.unknown_reads, 1);
        assert_eq!(adp.unknown_writes, 1);
    }

    #[test]
    fn commit_paints_framebuffer() {
        let sink = vm_core::framebuffer::new_sink(4, 4);
        let mem = Arc::new(Mutex::new(HashMap::<u64, u64>::new()));
        let m2 = mem.clone();
        let mut adp = AdpV2::new(4, 4, sink.clone());
        adp.mem_read = Some(Box::new(move |a| *m2.lock().unwrap().get(&a).unwrap_or(&0)));
        // paint pixel (0,0) magenta and (3,3) green in guest memory
        mem.lock().unwrap().insert(0x8000_0000, 0xFFFF00FF);
        mem.lock().unwrap().insert(0x8000_0000 + 15 * 4, 0xFF00FF00);
        adp.fb_base = 0x8000_0000;
        adp.commit_frame();
        let fb = sink.lock().unwrap();
        assert_eq!(fb.sequence, 1);
        assert_eq!(&fb.rgba[0..4], &[0xFF, 0x00, 0xFF, 0xFF]); // magenta, R,G,B,A
        assert_eq!(&fb.rgba[60..64], &[0x00, 0xFF, 0x00, 0xFF]); // green
        drop(fb);
        assert_eq!(adp.swaps, 1);
        // Second commit bumps both counters.
        adp.commit_frame();
        assert_eq!(adp.swaps, 2);
        assert_eq!(sink.lock().unwrap().sequence, 2);
    }
}
