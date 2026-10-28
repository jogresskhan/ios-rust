//! macho — Mach-O parse + kernelcache fileset loader.
//!
//! Port of Inferno `boot.c` fileset loading (MH_FILESET entries,
//! segment/section placement at vmaddrs, chained-fixups handling for
//! keyless iOS 14+ kernelcaches).

pub mod fileset;
pub mod header;

pub use header::MachHeader;
