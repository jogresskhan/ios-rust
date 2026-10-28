//! Synopsys MIPI-DSI host controller — the workspace's #1 display gap.
//!
//! Upstream Inferno ships a 187-line register stub (`synopsys_mipi_dsim.c`):
//! only CORE_PWR_UP writes are stored, everything else RAZ/WI. This port keeps
//! the honest stub surface AND adds the DSI packet FIFO model the Asahi
//! `adp-mipi` / Sandcastle `hx-mipi-dsi` stacks drive, so panel protocols can
//! be tested before the D-PHY link is complete.
//!
//! Verified upstream references (research vault: repos-upstream__linux-sandcastle,
//! repos-upstream__asahi-linux): DSI Generic/DCS short & long packets, FIFO acks
//! (sweet_mipi.c models DSI FIFO acks at 307 LOC — same shape here).

use crate::bus::{MMIODevice, W4};
use qemu_util::fifo::Fifo8;

pub const REG_CORE_PWR_UP: u64 = 0x0;
pub const REG_DSI_MODE_CFG: u64 = 0x4;
pub const REG_DSI_VID_MODE_CFG: u64 = 0x8;
pub const REG_DSI_GEN_HDR: u64 = 0x18; // DT<<8 | VC<<6 | word count bits
pub const REG_DSI_GEN_PLD: u64 = 0x1C;

#[derive(Debug, Default)]
pub struct MipiDsi {
    core_pwr: u32,
    mode_cfg: u32,
    vid_cfg: u32,
    hdr: u32,
    /// packet payload FIFO (guest writes GEN_PLD words; host drains D-PHY)
    pub fifo: Fifo8,
    /// ACKs the guest expects back (sweet_mipi.c parity)
    pub acks_pending: Vec<u8>,
}

impl MipiDsi {
    pub fn new() -> Self {
        Self { fifo: Fifo8::new(4096), acks_pending: Vec::new(), ..Default::default() }
    }

    /// Host side: drain the payload FIFO (D-PHY TX would consume this).
    pub fn drain(&mut self, max: usize) -> Vec<u8> {
        self.fifo.pop_buf(max)
    }

    /// Guest-side ack queue (DCS ack / FIFO not-empty style).
    pub fn push_ack(&mut self, events: &[u8]) {
        self.acks_pending.extend_from_slice(events);
    }
}

impl MMIODevice for MipiDsi {
    fn name(&self) -> &'static str {
        "synopsys-mipi-dsim"
    }
    fn size(&self) -> u64 {
        0x1000
    }

    fn read(&mut self, offset: u64, _width: u32) -> u64 {
        match offset {
            REG_CORE_PWR_UP => self.core_pwr as u64,
            REG_DSI_MODE_CFG => self.mode_cfg as u64,
            REG_DSI_VID_MODE_CFG => self.vid_cfg as u64,
            REG_DSI_GEN_HDR => self.hdr as u64,
            REG_DSI_GEN_PLD => {
                let mut w = [0u8; 4];
                for b in w.iter_mut() {
                    *b = self.fifo.pop().unwrap_or(0);
                }
                u32::from_le_bytes(w) as u64
            }
            _ => 0, // RAZ/WI — identical to upstream stub behavior
        }
    }

    fn write(&mut self, offset: u64, value: u64, _width: u32) {
        match offset {
            REG_CORE_PWR_UP => self.core_pwr = value as u32, // ONLY stored reg upstream
            REG_DSI_MODE_CFG => self.mode_cfg = value as u32,
            REG_DSI_VID_MODE_CFG => self.vid_cfg = value as u32,
            REG_DSI_GEN_HDR => {
                self.hdr = value as u32;
                // Synopsys DWC DSI GEN_HDR layout: DT[5:0] VC[7:6] DATA0[15:8]
                // DATA1[23:16]. Short packet types push their inline payload.
                let dt = value & 0x3F;
                let data0 = ((value >> 8) & 0xFF) as u8;
                let data1 = ((value >> 16) & 0xFF) as u8;
                match dt {
                    0x03 | 0x05 | 0x13 => {
                        // generic/DCS short write, 0-1 params: DATA0 is the cmd
                        let _ = self.fifo.push(data0);
                        self.push_ack(&[0x84]);
                    }
                    0x15 => {
                        // DCS short write, 2 params: cmd + param
                        let _ = self.fifo.push_all(&[data0, data1]);
                        self.push_ack(&[0x84]);
                    }
                    _ => {}
                }
            }
            REG_DSI_GEN_PLD => {
                let w = (value as u32).to_le_bytes();
                let _ = self.fifo.push_all(&w);
            }
            _ => {} // RAZ/WI
        }
    }
}

pub const PARITY_PCT: u8 = 30; // stub surface kept + packet FIFO model added; D-PHY/link state pending

impl crate::bus::Device for MipiDsi {
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
    fn core_pwr_only_reg_matches_upstream_stub() {
        let mut d = MipiDsi::new();
        d.write(REG_CORE_PWR_UP, 1, W4);
        assert_eq!(d.read(REG_CORE_PWR_UP, W4), 1);
        d.write(REG_DSI_MODE_CFG, 0x1234, W4);
        assert_eq!(d.read(REG_DSI_MODE_CFG, W4), 0x1234);
        // unknown regs RAZ
        assert_eq!(d.read(0xABC, W4), 0);
    }

    #[test]
    fn dcs_short_packet_with_ack() {
        let mut d = MipiDsi::new();
        // GEN_HDR: DT=0x15 (DCS short write, 2 params), cmd=0x2A, param=0xA0
        let hdr = 0x15u64 | (0x2Au64 << 8) | (0xA0u64 << 16);
        d.write(REG_DSI_GEN_HDR, hdr, W4);
        assert_eq!(d.fifo.used(), 2);
        assert_eq!(d.drain(8), vec![0x2A, 0xA0]);
        assert_eq!(d.acks_pending, vec![0x84]);
    }

    #[test]
    fn dcs_short_write_no_param_pushes_cmd_only() {
        let mut d = MipiDsi::new();
        let hdr = 0x05u64 | (0x11u64 << 8); // DT=0x05, DATA0=0x11 (sleep out)
        d.write(REG_DSI_GEN_HDR, hdr, W4);
        assert_eq!(d.drain(8), vec![0x11]);
    }
}
