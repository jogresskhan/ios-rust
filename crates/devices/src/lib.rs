//! devices — Rust device models replacing the Inferno/QEMU C objects.
//!
//! Provenance & license: structural ports with register semantics taken from
//! the pinned research sources (ChefKiss Inferno AGPL-3.0/GPL, qemu-sweet
//! overlay GPLv2+, Asahi Linux GPL-2.0). This workspace is therefore
//! GPL-2.0-or-later. Every module records its C counterpart and parity %.
//!
//! Status legend in PARITY.md; per-module doc comments carry the gate.

pub mod aic;
pub mod bus;
pub mod dart;
pub mod disp_pipe;
pub mod mipi_dsi;
pub mod nvme_ans;
pub mod uart;
pub mod wdt;

pub use bus::{Bus, Device, MMIODevice};
