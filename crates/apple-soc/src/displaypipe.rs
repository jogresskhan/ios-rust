//! Apple Display Pipe V4 — the T8030 display controller.
//!
//! Port of ChefKiss Inferno `hw/display/apple_displaypipe_v4.c`.
//!
//! Block layout (DisplayTarget5, from the upstream header comment):
//! ```text
//! 0x08000 M3 Control Mailbox   0x40000 Control
//! 0x48000 V Frame Timing Gen   0x50000/0x58000 Generic Pixel Pipe 0/1
//! 0x60000 Blend Unit           0x70000 White Point Correction
//! 0x7C000 Pixel Response Corr  0x80000/0x82000/0x83000 Dither
//! 0x84000 CDFD                 0x88000 SPLR
//! 0x90000 Burn-In Comp Sampler 0x98000 Sub-Pixel Uniformity Corr
//! 0xA0000 PDC                  0xB0000 PCC   0xD0000 PCC Mailbox
//! 0xF0000 DBM
//! ```
//! Addresses ≥ 0x200000 mirror down (`if (addr >= 0x200000) addr -= 0x200000;`).
//!
//! The critical behavior — the swap/commit path — is ported: writing bit 12
//! of REG 0x4602C schedules a display update; each enabled+running genpipe
//! reads its layer out of the (machine-filled) [`AdpV4::frame_source`] and
//! composites it into the [`FrameSink`] honoring the BGRA/ARGB pixel-format
//! bits, source dimensions and stride; FRAME_PROCESSED is then raised.
//!
//! Parity gaps: pixman scaling/positioning is reduced to a 1:1 blit at (0,0)
//! (`TODO: handle source/dest position` upstream), compressed frames are
//! dropped exactly like upstream, and `adp_v4_read_and_draw_boot_splash`
//! becomes [`draw_splash`] with a synthesized logo instead of the bundled
//! PNG (documented in PARITY.md).
//!
//! License: AGPL-3.0-or-later (derived work).

use std::sync::{Arc, Mutex};

use vm_core::framebuffer::{FrameBuffer, FrameSink};
use vm_core::Device;

// Control block.
pub const CONTROL_INT_STATUS: u64 = 0x45818;
pub const CONTROL_INT_ENABLE: u64 = 0x4581C;
pub const CONTROL_VERSION: u64 = 0x46020;
pub const CONTROL_VERSION_A0: u32 = 0x70044;
pub const CONTROL_VERSION_A1: u32 = 0x70045;
pub const CONTROL_SWAP_TRIGGER: u64 = 0x4602C; // bit 12 → schedule update
pub const CONTROL_SWAP_TRIGGER_BIT: u32 = 1 << 12;
pub const CONTROL_FRAME_SIZE: u64 = 0x4603C;

// INT_STATUS fields.
pub const INT_MODE_CHANGED: u32 = 1 << 1;
pub const INT_UNDERRUN: u32 = 1 << 3;
pub const INT_OUTPUT_READY: u32 = 1 << 10;
pub const INT_SUB_FRAME_OVERFLOW: u32 = 1 << 11;
pub const INT_M3: u32 = 1 << 13;
pub const INT_PCC: u32 = 1 << 17;
pub const INT_CDFD: u32 = 1 << 19;
pub const INT_FRAME_PROCESSED: u32 = 1 << 20;
pub const INT_AXI_READ_ERR: u32 = 1 << 30;
pub const INT_AXI_WRITE_ERR: u32 = 1 << 31;

// GenPipe blocks.
pub const GP_BLOCK_BASE: u64 = 0x50000;
pub const GP_BLOCK_SIZE: u64 = 0x8000;
pub const GP_COUNT: usize = 2;

pub const GP_CONFIG_CONTROL: u64 = 0x4;
pub const GP_CONFIG_CONTROL_RUN: u32 = 1 << 0;
pub const GP_CONFIG_CONTROL_USE_DMA: u32 = 1 << 18;
pub const GP_CONFIG_CONTROL_HDR: u32 = 1 << 24;
pub const GP_CONFIG_CONTROL_ENABLED: u32 = 1 << 31;
pub const GP_PIXEL_FORMAT: u64 = 0x1C;
pub const GP_LAYER_0_HTPC_CONFIG: u64 = 0x28;
pub const GP_LAYER_1_HTPC_CONFIG: u64 = 0x2C;
pub const GP_LAYER_0_DATA_START: u64 = 0x30;
pub const GP_LAYER_1_DATA_START: u64 = 0x34;
pub const GP_LAYER_0_DATA_END: u64 = 0x40;
pub const GP_LAYER_1_DATA_END: u64 = 0x44;
pub const GP_LAYER_0_HEADER_BASE: u64 = 0x48;
pub const GP_LAYER_1_HEADER_BASE: u64 = 0x4C;
pub const GP_LAYER_0_HEADER_END: u64 = 0x58;
pub const GP_LAYER_1_HEADER_END: u64 = 0x5C;
pub const GP_LAYER_0_STRIDE: u64 = 0x60;
pub const GP_LAYER_1_STRIDE: u64 = 0x64;
pub const GP_LAYER_0_POSITION: u64 = 0x68;
pub const GP_LAYER_1_POSITION: u64 = 0x6C;
pub const GP_LAYER_0_DIMENSIONS: u64 = 0x70;
pub const GP_LAYER_1_DIMENSIONS: u64 = 0x74;
pub const GP_SRC_POSITION: u64 = 0x78;
pub const GP_DEST_POSITION: u64 = 0x7C;
pub const GP_DEST_DIMENSIONS: u64 = 0x80;
pub const GP_CRC_DATA: u64 = 0x160;
pub const GP_DMA_BANDWIDTH_RATE: u64 = 0x170;
pub const GP_STATUS: u64 = 0x184;

// GP_PIXEL_FORMAT bit patterns (upstream #defines).
pub const GP_FMT_BGRA: u32 = (1 << 26) | (1 << 24) | (3 << 13);
pub const GP_FMT_ARGB: u32 = (1 << 26) | (1 << 24);
pub const GP_FMT_COMPRESSED: u32 = 1 << 30;

// Blend block.
pub const BLEND_BLOCK_BASE: u64 = 0x60000;
pub const BLEND_BLOCK_SIZE: u64 = 0x8000;
pub const BLEND_CONFIG: u64 = 0x4;
pub const BLEND_BG: u64 = 0x8;
pub const BLEND_LAYER_0_BG: u64 = 0xC;
pub const BLEND_LAYER_1_BG: u64 = 0x10;
pub const BLEND_LAYER_0_CONFIG: u64 = 0x14;
pub const BLEND_LAYER_1_CONFIG: u64 = 0x18;
pub const BLEND_DEGAMMA_TABLE_R: u64 = 0x1C;
pub const BLEND_DEGAMMA_TABLE_G: u64 = 0x1024;
pub const BLEND_DEGAMMA_TABLE_B: u64 = 0x202C;
pub const BLEND_PIXCAP_CONFIG: u64 = 0x303C;

// Blend layer-config modes.
pub const BLEND_MODE_NONE: u32 = 0;
pub const BLEND_MODE_ALPHA: u32 = 1;
pub const BLEND_MODE_PREMULT: u32 = 2;
pub const BLEND_MODE_BYPASS: u32 = 3;

pub const SHADOW_MIRROR: u64 = 0x200000;

/// Interrupt indices (upstream: 9 lines, index 0 = "maybe VBlank").
pub const ADP_IRQ_COUNT: usize = 9;

#[derive(Clone, Copy, Default)]
pub struct GenPipe {
    pub config_control: u32,
    pub pixel_format: u32,
    pub dest_width: u16,
    pub dest_height: u16,
    pub data_start: u32,
    pub data_end: u32,
    pub stride: u32,
    pub src_width: u16,
    pub src_height: u16,
}

/// Apple Display Pipe V4.
///
/// Self-containment contract (batch 16-c): the device never touches the bus.
/// The machine copies the guest framebuffer into [`frame_source`] (or a test
/// fills it), then the guest-visible commit register triggers [`AdpV4::swap`]
/// which paints into the shared [`FrameSink`].
pub struct AdpV4 {
    pub width: u32,
    pub height: u32,
    pub fb: FrameSink,
    /// Guest-visible framebuffer bytes the compositor reads from.
    /// Indexed by the genpipe `data_start` register.
    pub frame_source: Vec<u8>,

    pub int_status: u32,
    pub int_enable: u32,
    pub genpipe: [GenPipe; GP_COUNT],
    pub blend_layer_config: [u32; 2],
    pub blend_bg: u32,
    /// irq line 0 (OUTPUT_READY/FRAME_PROCESSED OR-ed by int enable).
    pub int_line: bool,
    /// Census: swaps painted, frames dropped (compressed), etc.
    pub swaps_painted: u64,
    pub frames_dropped: u64,

    regs: Vec<u32>,
}

impl AdpV4 {
    pub fn new(width: u32, height: u32, fb: FrameSink) -> Self {
        AdpV4 {
            width,
            height,
            fb,
            frame_source: Vec::new(),
            int_status: 0,
            int_enable: 0,
            genpipe: [GenPipe::default(); GP_COUNT],
            blend_layer_config: [0; 2],
            blend_bg: 0,
            int_line: false,
            swaps_painted: 0,
            frames_dropped: 0,
            regs: vec![0u32; 0x80000 / 4],
        }
    }

    fn update_irq(&mut self) {
        self.int_line = (self.int_enable & self.int_status) != 0;
    }

    /// Port of `adp_v4_gp_draw` + `adp_v4_update_disp_bh`.
    pub fn swap(&mut self) {
        for i in 0..GP_COUNT {
            let gp = self.genpipe[i];
            if gp.config_control & GP_CONFIG_CONTROL_RUN == 0
                || gp.config_control & GP_CONFIG_CONTROL_ENABLED == 0
            {
                continue;
            }
            // Compressed frames are dropped (upstream: "dropping frame").
            if gp.pixel_format & GP_FMT_COMPRESSED != 0 {
                self.frames_dropped += 1;
                self.int_status |= INT_AXI_READ_ERR;
                self.update_irq();
                continue;
            }
            let src_w = gp.src_width.max(1) as usize;
            let src_h = gp.src_height.max(1) as usize;
            let stride = if gp.stride != 0 {
                gp.stride as usize
            } else {
                src_w * 4
            };
            let start = gp.data_start as usize;
            let need = (src_h - 1) * stride + src_w * 4;
            if self.frame_source.len() < start + need {
                continue;
            }
            let bgra = gp.pixel_format & GP_FMT_BGRA == GP_FMT_BGRA;
            // Build the RGBA source row-major from the frame source.
            let mut rgba = vec![0u8; src_w * src_h * 4];
            for y in 0..src_h {
                let row = &self.frame_source[start + y * stride..];
                for x in 0..src_w {
                    let p = &row[x * 4..x * 4 + 4];
                    let d = (y * src_w + x) * 4;
                    if bgra {
                        // B G R A → R G B A
                        rgba[d] = p[2];
                        rgba[d + 1] = p[1];
                        rgba[d + 2] = p[0];
                        rgba[d + 3] = p[3];
                    } else {
                        // A R G B → R G B A
                        rgba[d] = p[1];
                        rgba[d + 1] = p[2];
                        rgba[d + 2] = p[3];
                        rgba[d + 3] = p[0];
                    }
                }
            }
            if let Ok(mut fb) = self.fb.lock() {
                let dw = if gp.dest_width != 0 {
                    gp.dest_width as i64
                } else {
                    src_w as i64
                };
                let dh = if gp.dest_height != 0 {
                    gp.dest_height as i64
                } else {
                    src_h as i64
                };
                // 1:1 composite (scaling is a documented gap) — draw at the
                // genpipe's dest size only when it matches the source, else
                // blit the source unclipped at the origin.
                if dw == src_w as i64 && dh == src_h as i64 {
                    fb.blit(0, 0, src_w as u32, src_h as u32, &rgba);
                } else {
                    fb.blit(0, 0, src_w as u32, src_h as u32, &rgba);
                }
            }
            self.swaps_painted += 1;
        }
        self.int_status |= INT_FRAME_PROCESSED | INT_OUTPUT_READY;
        self.update_irq();
    }

    /// Machine-side paint entry point (contract: `pub fn paint(&mut self)`).
    /// Copies `data` into [`frame_source`] then composites immediately.
    pub fn paint(&mut self, data: &[u8]) {
        self.frame_source.clear();
        self.frame_source.extend_from_slice(data);
        self.swap();
    }

    fn gp_write(&mut self, idx: usize, addr: u64, val: u32) {
        let gp = &mut self.genpipe[idx];
        match addr {
            GP_CONFIG_CONTROL => gp.config_control = val,
            GP_PIXEL_FORMAT => gp.pixel_format = val,
            GP_LAYER_0_DATA_START => gp.data_start = val,
            GP_LAYER_0_DATA_END => gp.data_end = val,
            GP_LAYER_0_STRIDE => gp.stride = val,
            GP_LAYER_0_DIMENSIONS => {
                gp.src_height = (val & 0xFFFF) as u16;
                gp.src_width = ((val >> 16) & 0xFFFF) as u16;
            }
            GP_DEST_DIMENSIONS => {
                gp.dest_height = (val & 0xFFFF) as u16;
                gp.dest_width = ((val >> 16) & 0xFFFF) as u16;
            }
            _ => {}
        }
    }

    fn gp_read(&self, idx: usize, addr: u64) -> u32 {
        let gp = &self.genpipe[idx];
        match addr {
            GP_CONFIG_CONTROL => gp.config_control,
            GP_PIXEL_FORMAT => gp.pixel_format,
            GP_LAYER_0_DATA_START => gp.data_start,
            GP_LAYER_0_DATA_END => gp.data_end,
            GP_LAYER_0_STRIDE => gp.stride,
            GP_LAYER_0_DIMENSIONS => {
                ((gp.src_width as u32) << 16) | gp.src_height as u32
            }
            GP_DEST_DIMENSIONS => {
                ((gp.dest_width as u32) << 16) | gp.dest_height as u32
            }
            GP_STATUS => 0,
            _ => 0,
        }
    }

    pub fn regs_documented() -> &'static [(&'static str, u64)] {
        &[
            ("CONTROL_INT_STATUS", CONTROL_INT_STATUS),
            ("CONTROL_INT_ENABLE", CONTROL_INT_ENABLE),
            ("CONTROL_VERSION", CONTROL_VERSION),
            ("CONTROL_VERSION_A1", CONTROL_VERSION_A1 as u64),
            ("CONTROL_SWAP_TRIGGER", CONTROL_SWAP_TRIGGER),
            ("CONTROL_FRAME_SIZE", CONTROL_FRAME_SIZE),
            ("GP_BLOCK_BASE", GP_BLOCK_BASE),
            ("GP_CONFIG_CONTROL", GP_CONFIG_CONTROL),
            ("GP_PIXEL_FORMAT", GP_PIXEL_FORMAT),
            ("GP_LAYER_0_DATA_START", GP_LAYER_0_DATA_START),
            ("GP_LAYER_0_DATA_END", GP_LAYER_0_DATA_END),
            ("GP_LAYER_0_STRIDE", GP_LAYER_0_STRIDE),
            ("GP_LAYER_0_DIMENSIONS", GP_LAYER_0_DIMENSIONS),
            ("GP_DEST_DIMENSIONS", GP_DEST_DIMENSIONS),
            ("GP_STATUS", GP_STATUS),
            ("BLEND_BLOCK_BASE", BLEND_BLOCK_BASE),
            ("BLEND_CONFIG", BLEND_CONFIG),
            ("BLEND_BG", BLEND_BG),
            ("BLEND_LAYER_0_CONFIG", BLEND_LAYER_0_CONFIG),
            ("BLEND_LAYER_1_CONFIG", BLEND_LAYER_1_CONFIG),
            ("INT_FRAME_PROCESSED", INT_FRAME_PROCESSED as u64),
            ("INT_OUTPUT_READY", INT_OUTPUT_READY as u64),
        ]
    }
}

impl Device for AdpV4 {
    fn name(&self) -> &'static str {
        "adp-v4"
    }

    fn read(&mut self, off: u64, size: u8) -> u64 {
        let _ = size;
        let off = if off >= SHADOW_MIRROR {
            off - SHADOW_MIRROR
        } else {
            off
        };
        if (GP_BLOCK_BASE..GP_BLOCK_BASE + GP_BLOCK_SIZE).contains(&off) {
            return self.gp_read(0, off - GP_BLOCK_BASE) as u64;
        }
        if (GP_BLOCK_BASE + GP_BLOCK_SIZE
            ..GP_BLOCK_BASE + 2 * GP_BLOCK_SIZE)
            .contains(&off)
        {
            return self.gp_read(1, off - GP_BLOCK_BASE - GP_BLOCK_SIZE) as u64;
        }
        if (BLEND_BLOCK_BASE..BLEND_BLOCK_BASE + BLEND_BLOCK_SIZE)
            .contains(&off)
        {
            return match off - BLEND_BLOCK_BASE {
                BLEND_CONFIG => self.regs[(BLEND_BLOCK_BASE + BLEND_CONFIG) as usize / 4] as u64,
                BLEND_BG | BLEND_LAYER_0_BG | BLEND_LAYER_1_BG => {
                    self.regs[(BLEND_BLOCK_BASE + off - BLEND_BLOCK_BASE) as usize / 4]
                        as u64
                }
                BLEND_LAYER_0_CONFIG => self.blend_layer_config[0] as u64,
                BLEND_LAYER_1_CONFIG => self.blend_layer_config[1] as u64,
                _ => 0,
            };
        }
        match off {
            CONTROL_VERSION => CONTROL_VERSION_A1 as u64,
            CONTROL_FRAME_SIZE => {
                ((self.width as u64) << 16) | self.height as u64
            }
            CONTROL_INT_STATUS => self.int_status as u64,
            CONTROL_INT_ENABLE => self.int_enable as u64,
            _ => 0,
        }
    }

    fn write(&mut self, off: u64, size: u8, val: u64) {
        let _ = size;
        let off = if off >= SHADOW_MIRROR {
            off - SHADOW_MIRROR
        } else {
            off
        };
        let val = val as u32;
        if (GP_BLOCK_BASE..GP_BLOCK_BASE + GP_BLOCK_SIZE).contains(&off) {
            self.gp_write(0, off - GP_BLOCK_BASE, val);
            return;
        }
        if (GP_BLOCK_BASE + GP_BLOCK_SIZE
            ..GP_BLOCK_BASE + 2 * GP_BLOCK_SIZE)
            .contains(&off)
        {
            self.gp_write(1, off - GP_BLOCK_BASE - GP_BLOCK_SIZE, val);
            return;
        }
        if (BLEND_BLOCK_BASE..BLEND_BLOCK_BASE + BLEND_BLOCK_SIZE)
            .contains(&off)
        {
            match off - BLEND_BLOCK_BASE {
                BLEND_LAYER_0_CONFIG => self.blend_layer_config[0] = val,
                BLEND_LAYER_1_CONFIG => self.blend_layer_config[1] = val,
                other => {
                    self.regs[(BLEND_BLOCK_BASE + other) as usize / 4] = val;
                }
            }
            return;
        }
        match off {
            CONTROL_INT_STATUS => {
                self.int_status &= !val;
                self.update_irq();
            }
            CONTROL_INT_ENABLE => {
                self.int_enable = val;
                self.update_irq();
            }
            CONTROL_SWAP_TRIGGER => {
                if val & CONTROL_SWAP_TRIGGER_BIT != 0 {
                    self.swap();
                }
            }
            other => {
                if (other as usize / 4) < self.regs.len() {
                    self.regs[other as usize / 4] = val;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Boot splash
// ---------------------------------------------------------------------------

/// Port of `adp_v4_read_and_draw_boot_splash`: black fill, then a centered
/// synthesized logo scaled to `width / 1.5` like upstream's PNG asset
/// (dest_width = disp/1.5, centered). The PNG itself is a documented gap —
/// we draw the ChefKiss "K-in-a-box" placeholder deterministically.
pub fn draw_splash(fb: &mut FrameBuffer, _asset_rgba: Option<&[u8]>) {
    let (w, h) = (fb.width, fb.height);
    // pixman fill rect black (QEMU_PIXMAN_COLOR_BLACK)
    fb.fill([0, 0, 0, 0xFF]);

    let dest = (w as f64 / 1.5) as i64;
    let dest_x = (w as i64) / 2 - dest / 2;
    let dest_y = (h as i64) / 2 - dest / 2;

    // 1024x1024 source logo (upstream asset is 512x512@2x).
    let logo: u32 = 1024;
    let s = |x: i64, y: i64| -> [u8; 4] {
        let x = x * logo / dest;
        let y = y * logo / dest;
        // Rounded-corner white box with a magenta "K" wedge.
        let margin = logo / 8;
        let inside = x >= margin
            && y >= margin
            && x < logo - margin
            && y < logo - margin;
        let corner = logo / 6;
        let cx = (x - margin).min(logo - margin - 1 - x);
        let cy = (y - margin).min(logo - margin - 1 - y);
        let near_corner = cx < corner && cy < corner
            && (corner - cx) * (corner - cy) > corner * corner / 2;
        if !inside || near_corner {
            return [0, 0, 0, 0];
        }
        // K glyph: vertical bar + two diagonals
        let bar = logo * 3 / 16;
        let in_bar = x >= logo / 3 && x < logo / 3 + bar && y >= logo / 4
            && y < logo * 3 / 4;
        let diag_top = {
            let t = y; // y from 1/4..1/2 maps to x from bar+1/3..2/3
            x >= logo / 3 + bar
                && x < logo * 2 / 3
                && y >= logo / 4
                && y < logo / 2
                && (x - (logo / 3 + bar)) >= (logo / 2 - y) * (bar * 2) / (logo / 4)
                && (x - (logo / 3 + bar)) <= (logo / 2 - y) * (bar * 2) / (logo / 4) + bar
        };
        let diag_bot = {
            x >= logo / 3 + bar
                && x < logo * 2 / 3
                && y >= logo / 2
                && y < logo * 3 / 4
                && (x - (logo / 3 + bar)) >= (y - logo / 2) * (bar * 2) / (logo / 4)
                && (x - (logo / 3 + bar)) <= (y - logo / 2) * (bar * 2) / (logo / 4) + bar
        };
        if in_bar || diag_top || diag_bot {
            [0xE8, 0x17, 0x5D, 0xFF] // ChefKiss magenta-ish
        } else {
            [0xFF, 0xFF, 0xFF, 0xFF]
        }
    };

    // Build the scaled logo and blit.
    let mut scaled = Vec::with_capacity((dest * dest) as usize * 4);
    for y in 0..dest {
        for x in 0..dest {
            scaled.extend_from_slice(&s(x, y));
        }
    }
    fb.blit(dest_x, dest_y, dest as u32, dest as u32, &scaled);
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use vm_core::framebuffer::new_sink;

    fn setup() -> (AdpV4, FrameSink) {
        let fb = new_sink(2436, 1125);
        let adp = AdpV4::new(2436, 1125, fb.clone());
        (adp, fb)
    }

    #[test]
    fn frame_size_and_version() {
        let (mut adp, _fb) = setup();
        assert_eq!(adp.read(CONTROL_VERSION, 4), CONTROL_VERSION_A1 as u64);
        assert_eq!(
            adp.read(CONTROL_FRAME_SIZE, 4),
            ((2436u64) << 16) | 1125
        );
    }

    #[test]
    fn swap_paints_bgra_layer() {
        let (mut adp, fb) = setup();
        // 4x2 BGRA source: red rows (B,G,R,A = 00 00 FF FF)
        let (sw, sh) = (4u32, 2u32);
        let mut src = Vec::new();
        for _ in 0..sw * sh {
            src.extend_from_slice(&[0x00, 0x00, 0xFF, 0xFF]);
        }
        adp.frame_source = src;

        // genpipe 0: run + enabled, BGRA, dims 4x2, stride 16
        adp.write(GP_BLOCK_BASE + GP_CONFIG_CONTROL, 4,
            (GP_CONFIG_CONTROL_RUN | GP_CONFIG_CONTROL_ENABLED) as u64);
        adp.write(GP_BLOCK_BASE + GP_PIXEL_FORMAT, 4, GP_FMT_BGRA as u64);
        adp.write(GP_BLOCK_BASE + GP_LAYER_0_DATA_START, 4, 0);
        adp.write(GP_BLOCK_BASE + GP_LAYER_0_STRIDE, 4, 16);
        adp.write(GP_BLOCK_BASE + GP_LAYER_0_DIMENSIONS, 4,
            ((sw << 16) | sh) as u64);

        // Commit via the swap trigger register (the real guest path).
        adp.write(CONTROL_SWAP_TRIGGER, 4, CONTROL_SWAP_TRIGGER_BIT as u64);
        assert_eq!(adp.swaps_painted, 1);

        let got = fb.lock().unwrap();
        // RGBA of the first pixel must be red.
        assert_eq!(&got.rgba[0..4], &[0xFF, 0x00, 0x00, 0xFF]);
        // FRAME_PROCESSED raised.
        assert_eq!(adp.read(CONTROL_INT_STATUS, 4) as u32 & INT_FRAME_PROCESSED, INT_FRAME_PROCESSED);
        assert!(adp.int_line);
    }

    #[test]
    fn compressed_frames_dropped() {
        let (mut adp, _fb) = setup();
        adp.frame_source = vec![0; 64];
        adp.write(GP_BLOCK_BASE + GP_CONFIG_CONTROL, 4,
            (GP_CONFIG_CONTROL_RUN | GP_CONFIG_CONTROL_ENABLED) as u64);
        adp.write(GP_BLOCK_BASE + GP_PIXEL_FORMAT, 4,
            (GP_FMT_BGRA | GP_FMT_COMPRESSED) as u64);
        adp.write(GP_BLOCK_BASE + GP_LAYER_0_DIMENSIONS, 4, (4 << 16) | 4);
        adp.swap();
        assert_eq!(adp.swaps_painted, 0);
        assert_eq!(adp.frames_dropped, 1);
    }

    #[test]
    fn genpipe1_block_addressing() {
        let (mut adp, _fb) = setup();
        let g1 = GP_BLOCK_BASE + GP_BLOCK_SIZE;
        adp.write(g1 + GP_LAYER_0_DATA_START, 4, 0x1234);
        assert_eq!(adp.read(g1 + GP_LAYER_0_DATA_START, 4), 0x1234);
        // genpipe 0 unchanged
        assert_eq!(adp.read(GP_BLOCK_BASE + GP_LAYER_0_DATA_START, 4), 0);
        // shadow mirror maps down
        adp.write(g1 + GP_LAYER_0_DATA_START + SHADOW_MIRROR, 4, 0x55AA);
        assert_eq!(adp.read(g1 + GP_LAYER_0_DATA_START, 4), 0x55AA);
    }

    #[test]
    fn splash_covers_center() {
        let mut fb = FrameBuffer::new(64, 48);
        draw_splash(&mut fb, None);
        // Center pixel is part of the logo (white box or magenta glyph).
        let (w, h) = (fb.width as usize, fb.height as usize);
        let px = &fb.rgba[((h / 2) * w + w / 2) * 4..][..4];
        assert!(
            px == [0xFF, 0xFF, 0xFF, 0xFF] || px == [0xE8, 0x17, 0x5D, 0xFF],
            "center pixel should be logo-colored, got {px:?}"
        );
        // Corner stays black.
        let px = &fb.rgba[0..4];
        assert_eq!(px, &[0, 0, 0, 0xFF]);
    }
}
