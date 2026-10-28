//! accel — hardware-virtualization backends (the native-speed path).
//!
//! The interpreter boots early code; HVF/KVM run the *actual* A13 code at
//! native speed once the workspace earns it. Both backends are feature-
//! gated skeletons that report honest Err at runtime when not compiled —
//! the selection API is stable so devices/machine never change.

use crate::{CpuBackend, MemAccess};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccelKind {
    Interpreter,
    Hvf,
    Kvm,
}

/// What this build supports at runtime.
pub fn available() -> Vec<AccelKind> {
    let mut v = vec![AccelKind::Interpreter];
    #[cfg(target_os = "macos")]
    v.push(AccelKind::Hvf);
    #[cfg(target_os = "linux")]
    if std::path::Path::new("/dev/kvm").exists() {
        v.push(AccelKind::Kvm);
    }
    v
}

pub struct AccelCpu {
    inner: Box<dyn CpuBackend>,
    pub kind: AccelKind,
}

impl AccelCpu {
    /// Auto-select: HVF on macOS, KVM on Linux when /dev/kvm exists,
    /// interpreter otherwise. Accelerator backends are behind features:
    /// `kvm` / `hvf` (compile the real binding crates when enabled).
    pub fn new_auto(_mem: Box<dyn MemAccess>) -> Result<Self, String> {
        #[cfg(feature = "hvf")]
        {
            return Err("hvf backend: skeleton — enable feature + bind Hypervisor.framework (see PARITY.md accel row)".into());
        }
        #[cfg(feature = "kvm")]
        {
            return Err("kvm backend: skeleton — enable feature + bind kvm-ioctls (see PARITY.md accel row)".into());
        }
        #[cfg(not(any(feature = "hvf", feature = "kvm")))]
        {
            Err("no accel backend compiled in; interpreter is the default path".into())
        }
    }

    pub fn interpreter(inner: Box<dyn CpuBackend>) -> Self {
        AccelCpu { inner, kind: AccelKind::Interpreter }
    }

    pub fn backend(&mut self) -> &mut dyn CpuBackend {
        &mut *self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn interpreter_always_available() {
        assert!(available().contains(&AccelKind::Interpreter));
    }
}
