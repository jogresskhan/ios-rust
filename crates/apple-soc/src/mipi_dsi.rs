//! mipi_dsi — Synopsys MIPI-DSI host controller (faithful port of
//! Inferno hw/arm/ synopsys_mipi_dsim.c: 187-line register stub).
//! Upstream stores CORE_PWR_UP and RAZ/WIs everything else — this port
//! reproduces that EXACTLY and documents the real D-PHY gap
//! (PARITY.md row `mipi-dsi`: the #1 display frontier).

use vm_core::Device;

pub const DSI_CORE_PWR_UP: u64 = 0x0000;
pub const DSI_PWH: u64 = 0x0004;
pub const DSI_ESC_MODE: u64 = 0x0008;
pub const DSI_DSI_MODE: u64 = 0x000C;
pub const DSI_PKTHLN: u64 = 0x0010;
pub const DSI_PKTXMT: u64 = 0x0014;

pub struct MipiDsi {
    pub pwr: u32,
    pub dcs_writes: u64,
    pub unknown_reads: u64,
    pub unknown_writes: u64,
}

impl MipiDsi {
    pub fn new() -> Self {
        MipiDsi { pwr: 0, dcs_writes: 0, unknown_reads: 0, unknown_writes: 0 }
    }

    pub fn regs_documented() -> &'static [(&'static str, u64)] {
        &[
            ("CORE_PWR_UP", DSI_CORE_PWR_UP),
            ("PWH", DSI_PWH),
            ("ESC_MODE", DSI_ESC_MODE),
            ("DSI_MODE", DSI_DSI_MODE),
            ("PKTHLN", DSI_PKTHLN),
            ("PKTXMT", DSI_PKTXMT),
        ]
    }
}

impl Default for MipiDsi {
    fn default() -> Self {
        Self::new()
    }
}

impl Device for MipiDsi {
    fn name(&self) -> &'static str {
        "mipi-dsi"
    }
    fn read(&mut self, off: u64, _size: u8) -> u64 {
        match off {
            DSI_CORE_PWR_UP => self.pwr as u64,
            _ => {
                self.unknown_reads += 1;
                0 // RAZ, exactly like upstream synopsys_mipi_dsim.c
            }
        }
    }
    fn write(&mut self, off: u64, _size: u8, val: u64) {
        match off {
            DSI_CORE_PWR_UP => self.pwr = val as u32, // only stored reg upstream
            DSI_PKTXMT => self.dcs_writes += 1,
            _ => self.unknown_writes += 1, // WI, exactly like upstream
        }
    }
}
