//! IRQ wiring — AIC input lines.

/// Global interrupt state fed by every device into the AIC.
/// QEMU: qemu_set_irq → device gpio; here a plain level table.
#[derive(Debug, Default)]
pub struct IrqState {
    /// num → level
    pub levels: std::collections::BTreeMap<u32, bool>,
    /// set when any level rose since last ack (the CPU polls or AIC raises).
    pub pending: bool,
}

impl IrqState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&mut self, num: u32, level: bool) {
        let old = self.levels.insert(num, level).unwrap_or(false);
        if level && !old {
            self.pending = true;
        }
        self.pending |= self.levels.values().any(|&l| l);
    }

    /// Highest asserted line number (AIC performs that arbitration itself
    /// in hardware; we keep it simple and deterministic here).
    pub fn active(&self) -> Option<u32> {
        self.levels
            .iter()
            .filter(|(_, &l)| l)
            .map(|(&n, _)| n)
            .next_back()
    }
}
