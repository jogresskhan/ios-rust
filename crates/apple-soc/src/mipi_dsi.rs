//! mipi_dsi — Synopsys MIPI-DSI host controller.
//!
//! Faithful port of ChefKiss Inferno `hw/display/synopsys_mipi_dsim.c`
//! (AGPL-3.0) — the complete upstream file, which is honestly a stub:
//! it stores only CORE_PWR_UP, synthesizes CORE_VERSION, the command-packet
//! status (GEN_CMD_EMPTY) and the general/PLL controls, reads everything
//! else as 0xFFFFFFFF and leaves the second (swmpr) region entirely
//! unimplemented. Reset defaults the display to powered-on (SHUTDOWNZ=1).
//!
//! Parity note: upstream implements no GEN_HDR/GEN_PLD/D-PHY FIFOs —
//! those are documented gaps in the C model itself (PARITY.md row
//! `mipi-dsi`), so none are invented here. The pre-port synthetic
//! DSI_PWH/ESC_MODE/DSI_MODE/PKTHLN/PKTXMT offsets are kept as constants
//! but now follow upstream semantics (WIs / 0xFFFFFFFF reads).

use vm_core::Device;

// Real upstream register file (REG32 defines in synopsys_mipi_dsim.c)
pub const DSI_CORE_VERSION: u64 = 0x0000; // reads 0x3133302A
pub const DSI_CORE_PWR_UP: u64 = 0x0004; // SHUTDOWNZ bit0 — the only stored reg
pub const DSI_CORE_CMD_PKT_STATUS: u64 = 0x0074; // GEN_CMD_EMPTY bit0
pub const DSI_GENERAL_CTRL: u64 = 0x80004; // PHYLOCK_HW_LOCK bit4
pub const DSI_TOP_PLL_CTRL: u64 = 0x80034; // reads 0

pub const DSI_CORE_VERSION_VAL: u32 = 0x3133_302A;
pub const CORE_PWR_UP_SHUTDOWNZ: u32 = 1 << 0;
pub const CORE_CMD_PKT_STATUS_GEN_CMD_EMPTY: u32 = 1 << 0;
pub const GENERAL_CTRL_PHYLOCK_HW_LOCK: u32 = 1 << 4;

/// Legacy (pre-port) synthetic offsets — kept exported for compat. These
/// do not exist upstream; reads at these offsets now follow upstream's
/// 0xFFFFFFFF default except DSI_CORE_PWR_UP which upstream owns at 0x4.
pub const DSI_PWH: u64 = 0x0004;
pub const DSI_ESC_MODE: u64 = 0x0008;
pub const DSI_DSI_MODE: u64 = 0x000C;
pub const DSI_PKTHLN: u64 = 0x0010;
pub const DSI_PKTXMT: u64 = 0x0014;

pub struct MipiDsi {
    /// CORE_PWR_UP (SHUTDOWNZ); reset default = display powered on
    pub pwr: u32,
    pub dcs_writes: u64,
    pub unknown_reads: u64,
    pub unknown_writes: u64,
}

impl MipiDsi {
    pub fn new() -> Self {
        // synopsys_mipi_dsim_reset_hold: default to display powered on
        MipiDsi {
            pwr: CORE_PWR_UP_SHUTDOWNZ,
            dcs_writes: 0,
            unknown_reads: 0,
            unknown_writes: 0,
        }
    }

    /// Primary register region read (`synopsys_mipi_dsim_reg_read`).
    pub fn regs_read(&mut self, addr: u64) -> u64 {
        match addr {
            DSI_CORE_VERSION => DSI_CORE_VERSION_VAL as u64,
            DSI_CORE_PWR_UP => self.pwr as u64,
            DSI_CORE_CMD_PKT_STATUS => CORE_CMD_PKT_STATUS_GEN_CMD_EMPTY as u64,
            DSI_GENERAL_CTRL => GENERAL_CTRL_PHYLOCK_HW_LOCK as u64,
            DSI_TOP_PLL_CTRL => 0,
            _ => {
                self.unknown_reads += 1;
                u32::MAX as u64 // upstream default: UINT32_MAX
            }
        }
    }

    /// Primary register region write (`synopsys_mipi_dsim_reg_write`).
    pub fn regs_write(&mut self, addr: u64, val: u32) {
        match addr {
            DSI_CORE_PWR_UP => self.pwr = val,
            DSI_PKTXMT => self.dcs_writes += 1, // legacy census hook
            _ => {
                self.unknown_writes += 1; // WI, exactly like upstream
            }
        }
    }

    /// Secondary swmpr region (`synopsys_mipi_dsim_swmpr_reg_ops`): all
    /// reads 0xFFFFFFFF, writes dropped.
    pub fn swmpr_read(&mut self, _addr: u64) -> u64 {
        self.unknown_reads += 1;
        u32::MAX as u64
    }

    pub fn swmpr_write(&mut self, _addr: u64, _val: u32) {
        self.unknown_writes += 1;
    }

    pub fn regs_documented() -> &'static [(&'static str, u64)] {
        &[
            ("CORE_VERSION", DSI_CORE_VERSION),
            ("CORE_PWR_UP", DSI_CORE_PWR_UP),
            ("CORE_CMD_PKT_STATUS", DSI_CORE_CMD_PKT_STATUS),
            ("GENERAL_CTRL", DSI_GENERAL_CTRL),
            ("TOP_PLL_CTRL", DSI_TOP_PLL_CTRL),
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
        self.regs_read(off)
    }
    fn write(&mut self, off: u64, _size: u8, val: u64) {
        self.regs_write(off, val as u32);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_register_semantics() {
        let mut d = MipiDsi::new();
        // reset default: SHUTDOWNZ=1 (display powered on)
        assert_eq!(d.read(DSI_CORE_PWR_UP, 4), CORE_PWR_UP_SHUTDOWNZ as u64);
        // version is synthesized
        assert_eq!(d.read(DSI_CORE_VERSION, 4), 0x3133_302A);
        // command packet status: GEN_CMD_EMPTY
        assert_eq!(d.read(DSI_CORE_CMD_PKT_STATUS, 4), 1);
        // general ctrl: PHYLOCK_HW_LOCK
        assert_eq!(d.read(DSI_GENERAL_CTRL, 4), 1 << 4);
        // PLL ctrl reads 0
        assert_eq!(d.read(DSI_TOP_PLL_CTRL, 4), 0);
        // power toggle round trip
        d.write(DSI_CORE_PWR_UP, 4, 0);
        assert_eq!(d.read(DSI_CORE_PWR_UP, 4), 0);
        d.write(DSI_CORE_PWR_UP, 4, CORE_PWR_UP_SHUTDOWNZ as u64);
        assert_eq!(d.read(DSI_CORE_PWR_UP, 4), 1);
        // everything else reads UINT32_MAX and counts (upstream default)
        let before = d.unknown_reads;
        assert_eq!(d.read(0x18, 4), u32::MAX as u64);
        assert_eq!(d.unknown_reads, before + 1);
        // PKTXMT is WI upstream — the census counter still moves
        d.write(DSI_PKTXMT, 4, 0x2C);
        assert_eq!(d.dcs_writes, 1);
        assert_eq!(d.unknown_writes, 0);
        // other writes are WI
        d.write(DSI_ESC_MODE, 4, 1);
        assert_eq!(d.unknown_writes, 1);
    }

    #[test]
    fn swmpr_region_and_reset_default() {
        let mut d = MipiDsi::new();
        // swmpr: reads 0xFFFFFFFF, writes dropped
        assert_eq!(d.swmpr_read(0x0), u32::MAX as u64);
        d.swmpr_write(0x8, 0xFF);
        assert_eq!(d.swmpr_read(0x8), u32::MAX as u64);
        assert_eq!(d.unknown_writes, 1);
        // a fresh device powers the panel on (upstream reset_hold)
        let mut d2 = MipiDsi::default();
        assert_eq!(d2.pwr, CORE_PWR_UP_SHUTDOWNZ);
        assert_eq!(d2.read(DSI_CORE_PWR_UP, 4), 1);
    }
}
