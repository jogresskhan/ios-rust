//! machine_boot — the honest CPU-execution story.
//!
//! The engine (QEMU TCG) executes guest AArch64; porting TCG is the largest
//! single ledger item. The contract here is what the exec loop must satisfy,
//! and an interpretive stub backend that the parity gate fails loudly on
//! instead of pretending to boot.

use crate::Machine;

/// What a CPU backend must deliver per the restore/boot flow.
pub trait CpuBackend {
    /// Execute `steps` instructions or until a MMIO/IRQ exit.
    /// Returns (steps_executed, exit_reason).
    fn run(&mut self, steps: u64) -> (u64, ExitReason);
    /// Register file access (the boot gate needs PC + general regs for traces).
    fn regs(&self) -> &[u64; 32];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitReason {
    Halted,
    Mmio(u64),
    Irq,
    NotPorted,
}

/// Interpretive stub: reports honestly that TCG-in-Rust is pending.
#[derive(Debug, Default)]
pub struct TcgStub {
    pub pc: u64,
    regs: [u64; 32],
}

impl CpuBackend for TcgStub {
    fn run(&mut self, _steps: u64) -> (u64, ExitReason) {
        (0, ExitReason::NotPorted)
    }
    fn regs(&self) -> &[u64; 32] {
        &self.regs
    }
}

/// Boot gate for the machine: attach devices, then try the CPU.
/// Honest output: device count + the exact exec status.
pub fn boot(m: &mut Machine) -> BootReport {
    let attached = m.attach_devices();
    let mut cpu = TcgStub::default();
    let (_, reason) = cpu.run(1);
    BootReport {
        soc: m.soc_banner(),
        devices_attached: attached,
        exec_status: reason,
    }
}

#[derive(Debug)]
pub struct BootReport {
    pub soc: String,
    pub devices_attached: usize,
    pub exec_status: ExitReason,
}

impl std::fmt::Display for BootReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "soc: {}", self.soc)?;
        writeln!(f, "devices attached: {}", self.devices_attached)?;
        write!(f, "cpu exec: {:?}", self.exec_status)?;
        if self.exec_status == ExitReason::NotPorted {
            write!(
                f,
                "\nNOTE: TCG-in-Rust is the largest open ledger item (PARITY.md §cpu); \
                 the C engine (Inferno/QEMU) remains the executor until this flips."
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MachineConfig;

    #[test]
    fn boot_reports_honestly() {
        let mut m = Machine::new(MachineConfig::default());
        let rep = boot(&mut m);
        assert_eq!(rep.devices_attached, 5);
        assert_eq!(rep.exec_status, ExitReason::NotPorted);
        assert!(rep.soc.contains("T8030"));
    }
}
