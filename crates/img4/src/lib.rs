//! img4 — Apple IMG4/IM4P/IM4M containers.
//!
//! Port of ChefKiss Inferno `boot.c` IMG4 handling (IMG4 parse, IM4P
//! payload extraction, fourcc + version + board/tag checks) plus a
//! builder for research tickets. Parity: see PARITY.md row `img4`.

pub mod im4p;
pub mod der;

pub use im4p::{Im4p, IM4P_MAGIC};
