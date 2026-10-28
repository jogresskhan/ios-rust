//! gui — display frontends for the emulated T8030.
//!
//! * [`headless`] — always available: snapshots the framebuffer to BMP on
//!   frame-counter milestones and at exit (CI-verifiable GUI output).
//! * [`window`] — feature `gui`: opens a real window (minifb) that mirrors
//!   the framebuffer at vsync — the "GUI emulator" mode on a desktop.

pub mod headless;

#[cfg(feature = "gui")]
pub mod window;
