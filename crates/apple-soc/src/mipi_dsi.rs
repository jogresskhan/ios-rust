//! Synopsys MIPI DSIM (T8030 panel bridge).
//!
//! Faithful port of ChefKiss Inferno `hw/display/synopsys_mipi_dsim.c`
//! (187 lines upstream — a deliberate register stub): CORE_VERSION reads
//! `0x3133302A`, CORE_PWR_UP stores the SHUTDOWNZ bit, CORE_CMD_PKT_STATUS
//! reports GEN_CMD_EMPTY, GENERAL_CTRL reports PHYLOCK_HW_LOCK, TOP_PLL_CTRL
//! reads 0, everything else reads UINT32_MAX; the second region ("swmpr")
//! is write-ignored / reads UINT32_MAX. Reset defaults to the display
//! powered on (`SHUTDOWNZ = 1`).
//!
//! **PARITY GAP (PARITY.md row `mipi-dsi` = 15/50):** the real D-PHY is not
//! modeled — no DSI command transport, no video timing, no panel. The DSIM
//! is the glue between ADP v4 and the panel; all functional behavior lives
//! in the ADP port.
//!
//! License: AGPL-3.0-or-later (derived work).

use vm_core::Device;

pub const CORE_VERSION: u64 = 0x0;
pub const CORE_PWR_UP: u64 = 0x4;
pub const CORE_PWR_UP_SHUTDOWNZ: u32 = 1 << 0;
pub const CORE_CMD_PKT_STATUS: u64 = 0x74;
pub const CORE_CMD_PKT_STATUS_GEN_CMD_EMPTY: u32 = 1 << 0;
pub const GENERAL_CTRL: u64 = 0x80004;
pub const GENERAL_CTRL_PHYLOCK_HW_LOCK: u32 = 1 << 4;
pub const TOP_PLL_CTRL: u64 = 0x80034;

/// Two MMIO regions upstream: `.regs` (reg[1] size) and `.swmpr_regs`
/// (reg[3] size). This port merges them into one span with `swmpr` starting
/// at [`SMPR_REGION_OFF`] (the ADT layout keeps them apart).
pub const SMPR_REGION_OFF: u64 = 0x81000;

pub struct MipiDsi {
    pub power_up: u32,
    pub regs_size: u64,
    pub swmpr_size: u64,
}

impl MipiDsi {
    pub fn new() -> Self {
        // synopsys_mipi_dsim_reset_hold: default to display powered on.
        MipiDsi {
            power_up: CORE_PWR_UP_SHUTDOWNZ,
            regs_size: 0x80000,
            swmpr_size: 0x1000,
        }
    }

    fn in_smpr(&self, off: u64) -> bool {
        (SMPR_REGION_OFF..SMPR_REGION_OFF + self.swmpr_size).contains(&off)
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

    fn read(&mut self, off: u64, size: u8) -> u64 {
        let _ = size;
        if self.in_smpr(off) {
            // swmpr reads return UINT32_MAX upstream
            return u32::MAX as u64;
        }
        match off {
            CORE_VERSION => 0x3133_302A,
            CORE_PWR_UP => self.power_up as u64,
            CORE_CMD_PKT_STATUS => {
                CORE_CMD_PKT_STATUS_GEN_CMD_EMPTY as u64
            }
            GENERAL_CTRL => GENERAL_CTRL_PHYLOCK_HW_LOCK as u64,
            TOP_PLL_CTRL => 0,
            _ => u32::MAX as u64,
        }
    }

    fn write(&mut self, off: u64, size: u8, val: u64) {
        let _ = size;
        if self.in_smpr(off) {
            return; // swmpr writes dropped
        }
        match off {
            CORE_PWR_UP => self.power_up = val as u32,
            _ => {}
        }
    }
}

impl MipiDsi {
    pub fn regs_documented() -> &'static [(&'static str, u64)] {
        &[
            ("CORE_VERSION", CORE_VERSION),
            ("CORE_PWR_UP", CORE_PWR_UP),
            ("CORE_CMD_PKT_STATUS", CORE_CMD_PKT_STATUS),
            ("GENERAL_CTRL", GENERAL_CTRL),
            ("TOP_PLL_CTRL", TOP_PLL_CTRL),
            ("SMPR_REGION_OFF", SMPR_REGION_OFF),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_semantics() {
        let mut d = MipiDsi::new();
        assert_eq!(d.read(CORE_VERSION, 4), 0x3133_302A);
        // powered on by default
        assert_eq!(d.read(CORE_PWR_UP, 4), 1);
        d.write(CORE_PWR_UP, 4, 0); // SHUTDOWNZ cleared
        assert_eq!(d.read(CORE_PWR_UP, 4), 0);
        assert_eq!(
            d.read(CORE_CMD_PKT_STATUS, 4),
            CORE_CMD_PKT_STATUS_GEN_CMD_EMPTY as u64
        );
        assert_eq!(
            d.read(GENERAL_CTRL, 4),
            GENERAL_CTRL_PHYLOCK_HW_LOCK as u64
        );
        assert_eq!(d.read(TOP_PLL_CTRL, 4), 0);
        // unknown + swmpr read UINT32_MAX, swmpr writes dropped
        assert_eq!(d.read(0x1234, 4), u32::MAX as u64);
        assert_eq!(d.read(SMPR_REGION_OFF + 0x8, 4), u32::MAX as u64);
        d.write(SMPR_REGION_OFF + 0x8, 4, 0x1234);
        assert_eq!(d.read(SMPR_REGION_OFF + 0x8, 4), u32::MAX as u64);
    }
}
