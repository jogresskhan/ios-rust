//! a13-cpu — Apple A13 CPU core for the T8030 machine.
//!
//! The A13 is 6 cores: 2× Vortex (performance) + 4× Tempest (efficiency),
//! ARMv8.4-A with Apple-specific extensions (GXF — Guarded Execution
//! Facility, Apple MMU features, AMX v1 optional in userspace).
//!
//! Backends:
//! * [`interp::Interpreter`] — pure-Rust ARMv8 interpreter (always built).
//!   Real decoder for the boot-critical instruction subset; unknown
//!   instructions are reported, never silently skipped.
//! * [`accel::HvfAccel`] / [`accel::KvmAccel`] — hardware virtualization
//!   backends (macOS Hypervisor.framework / Linux KVM). These run the
//!   *actual* A13 code at native speed; compiled behind features, enabled
//!   at runtime when available (this is the "replace the qemu binary"
//!   performance path).

pub mod accel;
pub mod crypto;
pub mod decode;
pub mod gxf;
pub mod interp;
pub mod isa;
pub mod simd;

#[cfg(test)]
mod goldens;

/// CPU backend contract (QEMU: CPUClass + CPUArchState).
pub trait CpuBackend: Send {
    /// Run until a stop condition (max instructions, halted, panic).
    fn run(&mut self, budget: InterpBudget) -> RunResult;
    /// Physical memory access (bus injected at construction).
    fn set_reset_vector(&mut self, pc: u64);
    fn regs(&self) -> Vec<u64>;
    fn pc(&self) -> u64;
    fn set_irq(&mut self, level: bool);
    fn name(&self) -> &'static str {
        "a13-cpu"
    }
}

#[derive(Clone, Copy, Debug)]
pub struct InterpBudget {
    pub max_insn: u64,
    pub max_ns: u64,
}

impl Default for InterpBudget {
    fn default() -> Self {
        InterpBudget {
            max_insn: 1_000_000,
            max_ns: 250_000_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopReason {
    Budget,
    Halted,
    Panic,
    UnknownInsn { pc: u64, insn: u32 },
}

#[derive(Clone, Debug)]
pub struct RunResult {
    pub stop: StopReason,
    pub executed: u64,
}

impl RunResult {
    pub fn stopped_cleanly(&self) -> bool {
        !matches!(self.stop, StopReason::Panic | StopReason::UnknownInsn { .. })
    }
}

/// Memory interface the CPU drives (usually the machine Bus behind MMU).
pub trait MemAccess: Send {
    fn load(&mut self, addr: u64, size: u8) -> u64;
    fn store(&mut self, addr: u64, size: u8, val: u64);
    fn fetch32(&mut self, addr: u64) -> u32;
}




