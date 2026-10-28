//! host-linux — Linux host integration for the iOS emulator: capability checks,
//! the distro dependency manifest and the reference QEMU darwin-vm command builder.
//!
//! Parity: see PARITY.md row `host-linux`.
//! Source: ios-emulator-linux scripts/00-install-deps.sh (deps), darwin-vm run scripts (qemu)

pub mod check;
pub mod deps;
pub mod qemu;
