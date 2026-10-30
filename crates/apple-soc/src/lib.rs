//! apple-soc — T8030 (A13 Bionic) SoC in Rust.
//!
//! Device models ported from ChefKiss Inferno (`hw/`, AGPL-3.0) into the
//! vm-core Device contract. Device placement is **ADT-driven**: at boot the
//! machine parses the IPSW's devicetree (`/arm-io` children), matches
//! `compatible` strings and attaches each model at the real MMIO address —
//! the same way XNU discovers hardware. A static fallback map
//! ([`t8030::FALLBACK_MAP`]) covers headless smoke tests.
//!
//! License notes:
//! * QEMU-derived plumbing: GPL-2.0-or-later (see crate LICENSE note in repo).
//! * apple-silicon-derived device models: AGPL-3.0-or-later (this crate).

pub mod aic;
pub mod buttons;
pub mod roswell;
pub mod mic_tempsensor;
pub mod tempsensor;
pub mod spmi_baseband;
pub mod chestnut;
pub mod fan53740;
pub mod lm_backlight;
pub mod ans2_nvme;
pub mod apcie;
pub mod aes;
pub mod aop;
pub mod a7iop;
pub mod a7iop_mailbox;
pub mod displaypipe_v2;
pub mod pmu_d2255;
pub mod dart;
pub mod dapf;
pub mod dockchannel;
pub mod gpio_i2c_spi;
pub mod mca;
pub mod mipi_dsi;
pub mod nvram;
pub mod pmgr;
pub mod rtkit;
pub mod s3c_uart;
pub mod sart;
pub mod scaler;
pub mod sep_sim;
pub mod smc;
pub mod spmi_pmu;
pub mod t8030;
pub mod typec_otg;
pub mod wdt;
pub mod mt_spi;
pub mod baseband;

pub mod displaypipe;
pub mod inventory;

pub use vm_core::{Bus, Device, FrameBuffer, framebuffer::FrameSink};
