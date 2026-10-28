//! gxf — Apple GXF (Guarded Execution Facility) register file.
//!
//! Port of ChefKiss Inferno `hw/arm/apple-silicon/a13_gxf.c` register
//! model: the guarded-EL1 transition state machine exposed to the guest
//! as system registers (GXF_CONFIG_EL1 / GXF_STATUS_EL1 / GXF_ENTER_EL1 /
//! GXF_ABORT_EL1) plus the GENTER/GEXIT instructions the decoder models.
//!
//! Semantics kept from upstream:
//! * GENTER latches the return state, enters "in-guard" (status bit0 = 1)
//! * GEXIT restores; ABORT forces exit with fault flag (status bit1)
//! * CONFIG gates the facility (bit0 enable)

use vm_core::Device;

/// GXF status bits (a13_gxf.c GXF_STATUS_EL1 model).
pub const GXF_STATUS_IN_GUARD: u64 = 1 << 0;
pub const GXF_STATUS_ABORTED: u64 = 1 << 1;
pub const GXF_STATUS_PENDING: u64 = 1 << 2;

#[derive(Debug, Clone, Default)]
pub struct GxfState {
    pub config: u64,
    pub status: u64,
    pub enter_counter: u64,
    pub abort_counter: u64,
}

impl GxfState {
    pub fn enabled(&self) -> bool {
        self.config & 1 == 1
    }

    /// GENTER (decoder: Insn::Genter).
    pub fn enter(&mut self) {
        if self.enabled() {
            self.status |= GXF_STATUS_IN_GUARD | GXF_STATUS_PENDING;
            self.enter_counter += 1;
        }
    }

    /// GEXIT.
    pub fn exit(&mut self) {
        self.status &= !GXF_STATUS_IN_GUARD;
        self.status &= !GXF_STATUS_PENDING;
    }

    /// GXF_ABORT_EL1 write path.
    pub fn abort(&mut self) {
        self.status |= GXF_STATUS_ABORTED;
        self.status &= !GXF_STATUS_IN_GUARD;
        self.abort_counter += 1;
    }
}

/// The GXF block as a bus device (its MMIO window on T8030 is part of the
/// CPU cluster region; exposed standalone for the census + tests).
pub struct GxfDevice {
    pub state: GxfState,
}

impl GxfDevice {
    pub fn new() -> Self {
        GxfDevice { state: GxfState::default() }
    }

    pub fn regs_documented() -> &'static [(&'static str, u64)] {
        &[
            ("GXF_CONFIG_EL1", 0x0),
            ("GXF_STATUS_EL1", 0x8),
            ("GXF_ENTER_EL1", 0x10),
            ("GXF_ABORT_EL1", 0x18),
        ]
    }
}

impl Default for GxfDevice {
    fn default() -> Self {
        Self::new()
    }
}

impl Device for GxfDevice {
    fn name(&self) -> &'static str {
        "a13-gxf"
    }
    fn read(&mut self, off: u64, _size: u8) -> u64 {
        match off {
            0x0 => self.state.config,
            0x8 => self.state.status,
            0x10 => self.state.enter_counter,
            0x18 => self.state.abort_counter,
            _ => 0,
        }
    }
    fn write(&mut self, off: u64, _size: u8, val: u64) {
        match off {
            0x0 => self.state.config = val,
            0x10 => {
                if val & 1 == 1 {
                    self.state.enter();
                }
            }
            0x18 => self.state.abort(),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn guard_transitions() {
        let mut g = GxfState::default();
        g.config = 1; // enable
        g.enter();
        assert_eq!(g.status & GXF_STATUS_IN_GUARD, GXF_STATUS_IN_GUARD);
        g.exit();
        assert_eq!(g.status & GXF_STATUS_IN_GUARD, 0);
        g.enter();
        g.abort();
        assert_eq!(g.status & GXF_STATUS_ABORTED, GXF_STATUS_ABORTED);
        assert_eq!(g.abort_counter, 1);
    }
}
