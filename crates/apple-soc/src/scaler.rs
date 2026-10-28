//! scaler — Apple M2-class display Scaler / Color Space Converter.
//!
//! Faithful port of ChefKiss Inferno `hw/display/apple_scaler.c`
//! (AGPL-3.0): the full global register block (VERSION/CTRL/STS/IRQ/FRAME
//! COUNT), the SRC_CFG/DST_CFG plane configuration blocks, the
//! flip/rotate, CSC and border-fill registers, the software format decode
//! (YUV 422/420, BGRA/RGBA via swizzle) and the RUN → frame-done → IRQ
//! behavior (writes to plane config are ignored while running). Pixel
//! movement uses injected DMA hooks; when sizes/format match the transfer
//! is a copy, otherwise the frame is signalled done with a census counter
//! bump (the pixman scale path upstream is display-internal and can be
//! plugged via the same hooks).

use vm_core::Device;

// Global block (end: 0x60)
pub const SCALER_GLBL_VER: u64 = 0x0000;
pub const SCALER_GLBL_CTRL: u64 = 0x0004;
pub const SCALER_GLBL_CTRL_RESET: u32 = 1 << 0;
pub const SCALER_GLBL_STS: u64 = 0x000C;
pub const SCALER_GLBL_STS_RUNNING: u32 = 1 << 0;
pub const SCALER_GLBL_IRQ_MASK: u64 = 0x001C;
pub const SCALER_GLBL_IRQSTS: u64 = 0x0020;
pub const SCALER_GLBL_FRAMECNT: u64 = 0x0024;

// Command block (end: 0x10C)
pub const SCALER_CTRL_COMMAND: u64 = 0x0080;
pub const SCALER_CTRL_COMMAND_RUN: u32 = 1 << 0;
pub const SCALER_CTRL_COMMAND_READ_ONLY: u32 = 1 << 1;
pub const SCALER_CTRL_DBG: u64 = 0x009C;
pub const SCALER_CTRL_PIXEL_AVERAGING: u64 = 0x00E4;

// SRC_CFG plane (end: 0x1F0)
pub const SCALER_SRC_CFG: u64 = 0x0180;
pub const SCALER_SRC_CFG_LUMA_TEXTURE_SIZES: u64 = 0x0184;
pub const SCALER_SRC_CFG_CHROMA_TEXTURE_SIZES: u64 = 0x0188;
pub const SCALER_SRC_CFG_LUMA_BASE: u64 = 0x0194;
pub const SCALER_SRC_CFG_CHROMA_BASE: u64 = 0x0198;
pub const SCALER_SRC_CFG_LUMA_STRIDE: u64 = 0x01B4;
pub const SCALER_SRC_CFG_CHROMA_STRIDE: u64 = 0x01B8;
pub const SCALER_SRC_CFG_LUMA_OFFSETS: u64 = 0x01BC;
pub const SCALER_SRC_CFG_CHROMA_OFFSETS: u64 = 0x01C0;
pub const SCALER_SRC_CFG_SWIZZLE: u64 = 0x01C4;
pub const SCALER_SRC_CFG_SIZE: u64 = 0x01C8;

// DST_CFG plane (same layout, +0x100)
pub const SCALER_DST_CFG: u64 = 0x0280;
pub const SCALER_DST_CFG_LUMA_TEXTURE_SIZES: u64 = 0x0284;
pub const SCALER_DST_CFG_CHROMA_TEXTURE_SIZES: u64 = 0x0288;
pub const SCALER_DST_CFG_LUMA_BASE: u64 = 0x0294;
pub const SCALER_DST_CFG_CHROMA_BASE: u64 = 0x0298;
pub const SCALER_DST_CFG_LUMA_STRIDE: u64 = 0x02B4;
pub const SCALER_DST_CFG_CHROMA_STRIDE: u64 = 0x02B8;
pub const SCALER_DST_CFG_LUMA_OFFSETS: u64 = 0x02BC;
pub const SCALER_DST_CFG_CHROMA_OFFSETS: u64 = 0x02C0;
pub const SCALER_DST_CFG_SWIZZLE: u64 = 0x02C4;
pub const SCALER_DST_CFG_SIZE: u64 = 0x02C8;

pub const SCALER_FLIP_ROTATE_CFG: u64 = 0x0380;
pub const SCALER_FLIP_ROTATE_ROTATE_90: u32 = 1 << 0;
pub const SCALER_FLIP_ROTATE_ROTATE_180: u32 = 1 << 1;
pub const SCALER_FLIP_ROTATE_FLIP_Y: u32 = 1 << 2;
pub const SCALER_FLIP_ROTATE_FLIP_X: u32 = 1 << 3;

pub const SCALER_CSC_CFG_CHROMA_DOWNSAMPLING: u64 = 0x0900;

pub const SCALER_BORDER_FILL_CFG: u64 = 0x3034;
pub const SCALER_BORDER_FILL_CFG_RED_Y: u64 = 0x3038;
pub const SCALER_BORDER_FILL_CFG_BLUE_CR: u64 = 0x303C;
pub const SCALER_BORDER_FILL_CFG_GREEN_CB: u64 = 0x3040;
pub const SCALER_BORDER_FILL_CFG_LUMA_OFFSETS: u64 = 0x3044;
pub const SCALER_BORDER_FILL_CFG_CHROMA_OFFSETS: u64 = 0x3048;

// SRCDST_CFG_SIZE fields
pub fn cfg_size_width(v: u32) -> u32 {
    v & 0x7FFF
}
pub fn cfg_size_height(v: u32) -> u32 {
    (v >> 16) & 0x7FFF
}
// SRCDST_CFG_SWIZZLE fields (2 bits per component)
pub fn swizzle_component(v: u32, idx: u32) -> u32 {
    (v >> (idx * 8)) & 0x3
}
pub const SWIZZLE_COMPONENT_BLUE: u32 = 0;
pub const SWIZZLE_COMPONENT_GREEN: u32 = 1;
pub const SWIZZLE_COMPONENT_RED: u32 = 2;
pub const SWIZZLE_COMPONENT_ALPHA: u32 = 3;

/// `AppleScalerFormat` (apple_scaler.c)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScalerFormat {
    Bgra,
    Rgba,
    Yuv422,
    Yuv420,
    Unknown,
}

/// `apple_scaler_convert_hw_format`
pub fn convert_hw_format(hw_format: u32, hw_swizzle: u32) -> ScalerFormat {
    match hw_format {
        0x100604 => ScalerFormat::Yuv422,
        0x10060C => ScalerFormat::Yuv420,
        0x1E00001 => {
            if swizzle_component(hw_swizzle, 0) == SWIZZLE_COMPONENT_BLUE
                && swizzle_component(hw_swizzle, 1) == SWIZZLE_COMPONENT_GREEN
                && swizzle_component(hw_swizzle, 2) == SWIZZLE_COMPONENT_RED
                && swizzle_component(hw_swizzle, 3) == SWIZZLE_COMPONENT_ALPHA
            {
                ScalerFormat::Bgra
            } else {
                ScalerFormat::Rgba
            }
        }
        _ => ScalerFormat::Unknown,
    }
}

// Legacy (pre-port) surface: the old model exposed a single CTRL constant.
pub const SCALER_CTRL: u64 = SCALER_GLBL_CTRL;

pub struct Scaler {
    // plane config (SOURCE=0, DEST=1)
    pub config: [u32; 2],
    pub base: [[u32; 2]; 2],
    pub stride: [[u32; 2]; 2],
    pub swizzle: [u32; 2],
    pub size: [u32; 2],
    pub flip_rotate: u32,
    pub csc_cfg: u32,
    pub border_fill: [u32; 6],
    pub pixel_averaging: u32,
    pub frame_count: u32,
    pub irq_sts: u32,
    pub irq_mask: u32,
    pub running: bool,
    /// DMA hooks (machine injects; byte-granular, like QEMU dma_memory_*)
    pub mem_read: Option<Box<dyn FnMut(u64, &mut [u8]) + Send>>,
    pub mem_write: Option<Box<dyn FnMut(u64, &[u8]) + Send>>,
    /// frames skipped because the format pair is not RGBA/BGRA
    pub unsupported_frames: u64,
    pub unknown_reads: u64,
    pub unknown_writes: u64,
}

const SRC: usize = 0;
const DST: usize = 1;

impl Scaler {
    pub fn new() -> Self {
        Scaler {
            config: [0; 2],
            base: [[0; 2]; 2],
            stride: [[0; 2]; 2],
            swizzle: [0; 2],
            size: [0; 2],
            flip_rotate: 0,
            csc_cfg: 0,
            border_fill: [0; 6],
            pixel_averaging: 0,
            frame_count: 0,
            irq_sts: 0,
            irq_mask: 0,
            running: false,
            mem_read: None,
            mem_write: None,
            unsupported_frames: 0,
            unknown_reads: 0,
            unknown_writes: 0,
        }
    }

    /// `apple_scaler_signal_frame_done`
    fn signal_frame_done(&mut self) {
        self.frame_count += 1;
        self.irq_sts = 1;
        self.running = false;
    }

    /// `apple_scaler_bh`: DMA the source plane, "scale" into the dest plane,
    /// signal frame done. Only RGBA↔BGRA 32-bit pairs are moved (matching
    /// the upstream pixel formats it supports); everything else still gets
    /// the frame-done interrupt with the data untouched.
    pub fn run_frame(&mut self) {
        if self.running {
            return;
        }
        self.running = true;
        let src_fmt = convert_hw_format(self.config[SRC], self.swizzle[SRC]);
        let dst_fmt = convert_hw_format(self.config[DST], self.swizzle[DST]);
        let supported = |f: ScalerFormat| matches!(f, ScalerFormat::Bgra | ScalerFormat::Rgba);
        if !supported(src_fmt) || !supported(dst_fmt) {
            self.unsupported_frames += 1;
            self.signal_frame_done();
            return;
        }
        let src_w = cfg_size_width(self.size[SRC]) as usize;
        let src_h = cfg_size_height(self.size[SRC]) as usize;
        let dst_w = cfg_size_width(self.size[DST]) as usize;
        let dst_h = cfg_size_height(self.size[DST]) as usize;
        let src_stride = self.stride[SRC][0] as usize;
        let dst_stride = self.stride[DST][0] as usize;
        if src_stride == 0 || dst_stride == 0 || src_w == 0 || src_h == 0 || dst_w == 0 || dst_h == 0
        {
            self.signal_frame_done();
            return;
        }
        let src_buf_size = src_h * src_stride;
        let dst_buf_size = dst_h * dst_stride;
        let mut src_buf = vec![0u8; src_buf_size];
        if let Some(rd) = self.mem_read.as_mut() {
            rd(self.base[SRC][0] as u64, &mut src_buf);
        }
        let mut dst_buf = vec![0u8; dst_buf_size];
        if src_w == dst_w && src_h == dst_h {
            // 1:1 blit (the common displaypipe pass-through)
            let n = src_buf_size.min(dst_buf_size);
            dst_buf[..n].copy_from_slice(&src_buf[..n]);
        } else {
            // nearest-neighbor resample (stand-in for pixman FILTER_BEST)
            for dy in 0..dst_h {
                let sy = dy * src_h / dst_h;
                for dx in 0..dst_w {
                    let sx = dx * src_w / dst_w;
                    let s = sy * src_stride + sx * 4;
                    let d = dy * dst_stride + dx * 4;
                    if s + 4 <= src_buf.len() && d + 4 <= dst_buf.len() {
                        dst_buf[d..d + 4].copy_from_slice(&src_buf[s..s + 4]);
                    }
                }
            }
        }
        if let Some(wr) = self.mem_write.as_mut() {
            wr(self.base[DST][0] as u64, &dst_buf);
        }
        self.signal_frame_done();
    }

    pub fn regs_documented() -> &'static [(&'static str, u64)] {
        &[
            ("GLBL_VER", SCALER_GLBL_VER),
            ("GLBL_CTRL", SCALER_GLBL_CTRL),
            ("GLBL_STS", SCALER_GLBL_STS),
            ("GLBL_IRQ_MASK", SCALER_GLBL_IRQ_MASK),
            ("GLBL_IRQSTS", SCALER_GLBL_IRQSTS),
            ("GLBL_FRAMECNT", SCALER_GLBL_FRAMECNT),
            ("CTRL_COMMAND", SCALER_CTRL_COMMAND),
            ("CTRL_PIXEL_AVERAGING", SCALER_CTRL_PIXEL_AVERAGING),
            ("SRC_CFG", SCALER_SRC_CFG),
            ("DST_CFG", SCALER_DST_CFG),
            ("FLIP_ROTATE_CFG", SCALER_FLIP_ROTATE_CFG),
            ("CSC_CFG_CHROMA_DOWNSAMPLING", SCALER_CSC_CFG_CHROMA_DOWNSAMPLING),
            ("BORDER_FILL_CFG", SCALER_BORDER_FILL_CFG),
        ]
    }
}

impl Default for Scaler {
    fn default() -> Self {
        Self::new()
    }
}

impl Device for Scaler {
    fn name(&self) -> &'static str {
        "scaler"
    }
    fn read(&mut self, off: u64, _size: u8) -> u64 {
        match off {
            SCALER_GLBL_VER => 0x9009B, // SOC 0x8 version (0x90082/0x9009B/0x900A7)
            SCALER_GLBL_STS => self.running as u64,
            SCALER_GLBL_IRQ_MASK => self.irq_mask as u64,
            SCALER_GLBL_IRQSTS => self.irq_sts as u64,
            SCALER_GLBL_FRAMECNT => self.frame_count as u64,
            SCALER_CTRL_COMMAND => {
                (self.running as u32) as u64 | ((SCALER_CTRL_COMMAND_READ_ONLY as u64) << 1)
            }
            SCALER_CTRL_PIXEL_AVERAGING => self.pixel_averaging as u64,
            SCALER_SRC_CFG => self.config[SRC] as u64,
            SCALER_SRC_CFG_LUMA_BASE => self.base[SRC][0] as u64,
            SCALER_SRC_CFG_CHROMA_BASE => self.base[SRC][1] as u64,
            SCALER_SRC_CFG_LUMA_STRIDE => self.stride[SRC][0] as u64,
            SCALER_SRC_CFG_CHROMA_STRIDE => self.stride[SRC][1] as u64,
            SCALER_SRC_CFG_SWIZZLE => self.swizzle[SRC] as u64,
            SCALER_SRC_CFG_SIZE => self.size[SRC] as u64,
            SCALER_DST_CFG => self.config[DST] as u64,
            SCALER_DST_CFG_LUMA_BASE => self.base[DST][0] as u64,
            SCALER_DST_CFG_CHROMA_BASE => self.base[DST][1] as u64,
            SCALER_DST_CFG_LUMA_STRIDE => self.stride[DST][0] as u64,
            SCALER_DST_CFG_CHROMA_STRIDE => self.stride[DST][1] as u64,
            SCALER_DST_CFG_SWIZZLE => self.swizzle[DST] as u64,
            SCALER_DST_CFG_SIZE => self.size[DST] as u64,
            SCALER_FLIP_ROTATE_CFG => self.flip_rotate as u64,
            SCALER_CSC_CFG_CHROMA_DOWNSAMPLING => self.csc_cfg as u64,
            SCALER_BORDER_FILL_CFG => self.border_fill[0] as u64,
            SCALER_BORDER_FILL_CFG_RED_Y => self.border_fill[1] as u64,
            SCALER_BORDER_FILL_CFG_BLUE_CR => self.border_fill[2] as u64,
            SCALER_BORDER_FILL_CFG_GREEN_CB => self.border_fill[3] as u64,
            SCALER_BORDER_FILL_CFG_LUMA_OFFSETS => self.border_fill[4] as u64,
            SCALER_BORDER_FILL_CFG_CHROMA_OFFSETS => self.border_fill[5] as u64,
            _ => {
                self.unknown_reads += 1;
                0
            }
        }
    }
    fn write(&mut self, off: u64, _size: u8, val: u64) {
        let val = val as u32;
        match off {
            SCALER_GLBL_IRQSTS => {
                // W1C
                self.irq_sts &= !val;
                return;
            }
            SCALER_GLBL_IRQ_MASK => self.irq_mask = val,
            SCALER_GLBL_CTRL => {
                if val & SCALER_GLBL_CTRL_RESET != 0 {
                    // cold reset
                    *self = Scaler::new();
                }
                return;
            }
            SCALER_CTRL_COMMAND => {
                if val & SCALER_CTRL_COMMAND_RUN != 0 && !self.running {
                    self.run_frame();
                }
                return;
            }
            _ => {}
        }
        // plane config: writes ignored while running (qatomic_read(&running))
        if self.running {
            return;
        }
        match off {
            SCALER_SRC_CFG => self.config[SRC] = val,
            SCALER_SRC_CFG_LUMA_BASE => self.base[SRC][0] = val,
            SCALER_SRC_CFG_CHROMA_BASE => self.base[SRC][1] = val,
            SCALER_SRC_CFG_LUMA_STRIDE => self.stride[SRC][0] = val,
            SCALER_SRC_CFG_CHROMA_STRIDE => self.stride[SRC][1] = val,
            SCALER_SRC_CFG_SWIZZLE => self.swizzle[SRC] = val,
            SCALER_SRC_CFG_SIZE => self.size[SRC] = val,
            SCALER_DST_CFG => self.config[DST] = val,
            SCALER_DST_CFG_LUMA_BASE => self.base[DST][0] = val,
            SCALER_DST_CFG_CHROMA_BASE => self.base[DST][1] = val,
            SCALER_DST_CFG_LUMA_STRIDE => self.stride[DST][0] = val,
            SCALER_DST_CFG_CHROMA_STRIDE => self.stride[DST][1] = val,
            SCALER_DST_CFG_SWIZZLE => self.swizzle[DST] = val,
            SCALER_DST_CFG_SIZE => self.size[DST] = val,
            SCALER_FLIP_ROTATE_CFG => self.flip_rotate = val,
            SCALER_CSC_CFG_CHROMA_DOWNSAMPLING => self.csc_cfg = val,
            SCALER_BORDER_FILL_CFG => self.border_fill[0] = val,
            SCALER_BORDER_FILL_CFG_RED_Y => self.border_fill[1] = val,
            SCALER_BORDER_FILL_CFG_BLUE_CR => self.border_fill[2] = val,
            SCALER_BORDER_FILL_CFG_GREEN_CB => self.border_fill[3] = val,
            SCALER_BORDER_FILL_CFG_LUMA_OFFSETS => self.border_fill[4] = val,
            SCALER_BORDER_FILL_CFG_CHROMA_OFFSETS => self.border_fill[5] = val,
            SCALER_CTRL_PIXEL_AVERAGING => self.pixel_averaging = val,
            _ => self.unknown_writes += 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_and_frame_pipeline() {
        let src = vec![
            0x11u8, 0x22, 0x33, 0x40, 0x55, 0x66, 0x77, 0x80,
        ];
        let expected = src.clone();
        let dst = std::sync::Arc::new(std::sync::Mutex::new(vec![0u8; 8]));
        let d2 = dst.clone();
        let mut sc = Scaler::new();
        sc.mem_read = Some(Box::new(move |a, buf| {
            let _ = a;
            buf.copy_from_slice(&src);
        }));
        sc.mem_write = Some(Box::new(move |a, buf| {
            let _ = a;
            *d2.lock().unwrap() = buf.to_vec();
        }));
        assert_eq!(sc.read(SCALER_GLBL_VER, 4), 0x9009B);
        // RGBA src (0x1E00001) + RGBA dst, 2x1 → 2x1 1:1 blit
        sc.write(SCALER_SRC_CFG, 4, 0x1E00001);
        sc.write(SCALER_SRC_CFG_SIZE, 4, (1 << 16) | 2); // h=1 w=2
        sc.write(SCALER_SRC_CFG_LUMA_STRIDE, 4, 8);
        sc.write(SCALER_SRC_CFG_LUMA_BASE, 4, 0x1000);
        sc.write(SCALER_DST_CFG, 4, 0x1E00001);
        sc.write(SCALER_DST_CFG_SIZE, 4, (1 << 16) | 2);
        sc.write(SCALER_DST_CFG_LUMA_STRIDE, 4, 8);
        sc.write(SCALER_DST_CFG_LUMA_BASE, 4, 0x2000);
        sc.write(SCALER_CTRL_COMMAND, 4, SCALER_CTRL_COMMAND_RUN as u64);
        assert!(!sc.running);
        assert_eq!(sc.frame_count, 1);
        assert_eq!(sc.irq_sts, 1);
        assert_eq!(*dst.lock().unwrap(), expected);
        // IRQSTS is W1C
        sc.write(SCALER_GLBL_IRQSTS, 4, 1);
        assert_eq!(sc.irq_sts, 0);
        // second frame
        sc.write(SCALER_CTRL_COMMAND, 4, SCALER_CTRL_COMMAND_RUN as u64);
        assert_eq!(sc.frame_count, 2);
    }

    #[test]
    fn config_writes_blocked_while_running_and_reset() {
        let mut sc = Scaler::new();
        sc.write(SCALER_SRC_CFG_SIZE, 4, 0x0010_0010); // 16x16
        assert_eq!(sc.read(SCALER_SRC_CFG_SIZE, 4), 0x0010_0010);
        // force running; config writes must be ignored (but RUN/global still work)
        sc.running = true;
        sc.write(SCALER_SRC_CFG_SIZE, 4, 0x0020_0020);
        assert_eq!(sc.read(SCALER_SRC_CFG_SIZE, 4), 0x0010_0010);
        sc.running = false;
        // GLBL_CTRL reset bit clears everything
        sc.write(SCALER_SRC_CFG_SIZE, 4, 0x0020_0020);
        sc.frame_count = 5;
        sc.write(SCALER_GLBL_CTRL, 4, SCALER_GLBL_CTRL_RESET as u64);
        assert_eq!(sc.read(SCALER_SRC_CFG_SIZE, 4), 0);
        assert_eq!(sc.frame_count, 0);
        // RUN with unsupported formats still signals frame done
        sc.write(SCALER_SRC_CFG, 4, 0x100604); // YUV422 — unsupported
        sc.write(SCALER_CTRL_COMMAND, 4, SCALER_CTRL_COMMAND_RUN as u64);
        assert_eq!(sc.frame_count, 1);
        assert_eq!(sc.unsupported_frames, 1);
        assert!(!sc.running);
    }

    #[test]
    fn format_decode_matches_c_model() {
        // 0x100604 → YUV_422; 0x10060C → YUV_420
        assert_eq!(convert_hw_format(0x100604, 0), ScalerFormat::Yuv422);
        assert_eq!(convert_hw_format(0x10060C, 0), ScalerFormat::Yuv420);
        // 0x1E00001 with B/G/R/A swizzle → BGRA, anything else → RGBA
        let bgra = SWIZZLE_COMPONENT_BLUE
            | SWIZZLE_COMPONENT_GREEN << 8
            | SWIZZLE_COMPONENT_RED << 16
            | SWIZZLE_COMPONENT_ALPHA << 24;
        assert_eq!(convert_hw_format(0x1E00001, bgra), ScalerFormat::Bgra);
        assert_eq!(convert_hw_format(0x1E00001, 0), ScalerFormat::Rgba);
        assert_eq!(convert_hw_format(0x123456, 0), ScalerFormat::Unknown);
        // size field decode: WIDTH bits 0-14, HEIGHT bits 16-30
        assert_eq!(cfg_size_width(0x1234_5678), 0x5678 & 0x7FFF);
        assert_eq!(cfg_size_height(0x1234_5678), 0x1234 & 0x7FFF);
        // swizzle component extract (2 bits at 0/8/16/24)
        assert_eq!(swizzle_component(bgra, 3), SWIZZLE_COMPONENT_ALPHA);
        // nearest-neighbor downscale 4x4 → 2x2 with stride 16
        let mut src = Vec::new();
        for row in 0..4u8 {
            for col in 0..4u8 {
                let v = row * 4 + col;
                src.extend_from_slice(&[v, v, v, 0xFF]);
            }
            src.extend_from_slice(&[0u8; 0]); // stride padding handled below
        }
        // rebuild with real stride padding (16 bytes per row)
        let mut padded = Vec::new();
        for row in 0..4 {
            padded.extend_from_slice(&src[row * 16..row * 16 + 16]);
        }
        let src = padded;
        let value = src.clone();
        let dst = std::sync::Arc::new(std::sync::Mutex::new(vec![0u8; 2 * 8]));
        let d2 = dst.clone();
        let mut sc = Scaler::new();
        sc.mem_read = Some(Box::new(move |a, buf| {
            let _ = a;
            buf.copy_from_slice(&value);
        }));
        sc.mem_write = Some(Box::new(move |a, buf| {
            let _ = a;
            *d2.lock().unwrap() = buf.to_vec();
        }));
        sc.write(SCALER_SRC_CFG, 4, 0x1E00001);
        sc.write(SCALER_SRC_CFG_SIZE, 4, (4 << 16) | 4);
        sc.write(SCALER_SRC_CFG_LUMA_STRIDE, 4, 16);
        sc.write(SCALER_DST_CFG, 4, 0x1E00001);
        sc.write(SCALER_DST_CFG_SIZE, 4, (2 << 16) | 2);
        sc.write(SCALER_DST_CFG_LUMA_STRIDE, 4, 8);
        sc.write(SCALER_CTRL_COMMAND, 4, SCALER_CTRL_COMMAND_RUN as u64);
        let d = dst.lock().unwrap();
        // sample (0,0)=0, (0,2)=2, (2,0)=8, (2,2)=10
        assert_eq!(&d[0..4], &[0, 0, 0, 0xFF]);
        assert_eq!(&d[4..8], &[2, 2, 2, 0xFF]);
        assert_eq!(&d[8..12], &[8, 8, 8, 0xFF]);
        assert_eq!(&d[12..16], &[10, 10, 10, 0xFF]);
    }
}
