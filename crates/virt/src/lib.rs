//! virt — the virtualization library that replaces the QEMU binary for the
//! T8030 restore/boot flow. One machine (`apple-t8030`), one CPU family
//! (`apple-a13`), the device bus, and the exec loop contract.

pub mod cli;
pub mod machine;
pub mod machine_boot;

/// Version string reported by the `run` subcommand (`--version` compat).
pub const QEMU_COMPAT_VERSION: &str =
    concat!("ios-rust ", env!("CARGO_PKG_VERSION"), " (qemu-system-aarch64 compatible subset)");

pub use cli::{QemuCli, QemuCli as Cli};
pub use machine::{Machine, MachineConfig};
