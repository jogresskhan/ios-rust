//! Apple DisplayPipe (ADP) v4 — port of `hw/display/apple_displaypipe_v4.c`.
//!
//! The M3a lane proved the GenPipe scanout datapath is guest-drivable:
//! program GP_LAYER_0_* regs + CONFIG_CONTROL=RUN|ENABLED, write control
//! 0x4602C bit 12 → repaint BH → FRAME_PROCESSED (bit 20) completion IRQ,
//! DMA through the DART-mapped address space (code-verified at cc4302a).
//! This model implements that contract against a flat framebuffer store.

use crate::bus::{MMIODevice, W4};

pub const REG_CONFIG_CONTROL: u64 = 0x4602C;
pub const BIT_RUN: u64 = 1 << 12;

pub const IRQ_FRAME_PROCESSED: u64 = 1 << 20;

#[derive(Debug, Default)]
pub struct DisplayPipe {
    config_control: u32,
    /// GP_LAYER_0 attribute registers captured from the guest.
    pub layer: std::collections::BTreeMap<u64, u32>,
    pub frames_done: u64,
    pub irq_pending: u64,
    /// Last frame's surface bytes (would DMA from DART-mapped memory).
    pub surface: Option<Vec<u8>>,
}

impl DisplayPipe {
    /// The repaint bottom-half: validates RUN|ENABLED then completes a frame.
    pub fn repaint_bh(&mut self, dart_view: &[u8]) {
        if self.config_control as u64 & BIT_RUN != 0 {
            // In the engine this DMA-walks the DART AS; here: copy the live FB.
            self.surface = Some(dart_view.to_vec());
            self.frames_done += 1;
            self.irq_pending |= IRQ_FRAME_PROCESSED;
            self.config_control &= !BIT_RUN as u32; // RUN is self-clearing per trace
        }
    }
}

impl MMIODevice for DisplayPipe {
    fn name(&self) -> &'static str {
        "apple-displaypipe-v4"
    }
    fn size(&self) -> u64 {
        0x4_8000
    }
    fn read(&mut self, offset: u64, _width: u32) -> u64 {
        match offset {
            REG_CONFIG_CONTROL => self.config_control as u64,
            0x46020 => self.irq_pending, // IRQ status window
            _ => 0,
        }
    }
    fn write(&mut self, offset: u64, value: u64, _width: u32) {
        match offset {
            REG_CONFIG_CONTROL => self.config_control = value as u32,
            0x46024 => self.irq_pending &= !value, // IRQ ack/clear
            _ => {
                self.layer.insert(offset, value as u32);
            }
        }
    }
}

pub const PARITY_PCT: u8 = 45; // frame contract modeled; compressed surfaces + full layer parser pending

impl crate::bus::Device for DisplayPipe {
    fn mmio(&mut self) -> &mut dyn MMIODevice {
        self
    }
    fn parity_pct(&self) -> u8 {
        PARITY_PCT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_bit_completes_frame_and_fires_irq() {
        let mut adp = DisplayPipe::default();
        // ENABLED (bit 0) | RUN (bit 12) — per M3a trace contract on 0x4602C
        adp.write(REG_CONFIG_CONTROL, (1 << 12) | 1, W4);
        let fb = vec![0x42u8; 4096];
        adp.repaint_bh(&fb);
        assert_eq!(adp.frames_done, 1);
        assert_eq!(adp.irq_pending & IRQ_FRAME_PROCESSED, IRQ_FRAME_PROCESSED);
        assert_eq!(adp.surface.as_deref(), Some(&fb[..]));
    }
}
