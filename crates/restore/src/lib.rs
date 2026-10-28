//! restore — one IPSW in, installed-and-bootable machine state out.
//!
//! Pipeline (mirrors idevicerestore + ChefKiss Inferno restore lane):
//! 1. [`ipsw::Ipsw`] open the zip, index components
//! 2. [`ipsw`] extract BuildManifest.plist → verify per-file digests
//! 3. [`lzfse`] (vendored Apple C, BSD-3) decompress kernelcache/rootfs
//! 4. [`im4p`] unwrap IMG4/IM4P containers
//! 5. [`stage`] paint boot logo → hello → homescreen wall into the
//!    framebuffer exactly as the proven ios-sweet display path does,
//!    driven by real IPSW assets
//! 6. [`bootargs`] compose boot args + device tree for the machine

//! Host restore stack (the X-gaps from the ios-sweet-rust parity matrix,
//! closed here so the Rust engine can drive the full restore flow):
//! * [`plist_lite`] — the wire codec every protocol below shares
//! * [`usbmux`] — libusbmuxd-class daemon client: listen/connect tunnel
//! * [`restored_proto`] — `restored` protocol v14 client (Hello,
//!   QueryValue, StartRestore, Status/Error checkpoints)
//! * [`asr`] — ASR validation + payload streaming (Initiate → packet
//!   info → OOBData → Payload → raw image push)
//! * [`tss`] — libauthinstall-class TSS request building + ApImg4Ticket
//!   (IM4M) extraction/validation
//!
//! Honest gaps live in PARITY.md (APFS mount, AES-XTS keys, 'restored'
//! RestoreOptions wall).

pub mod bootargs;
pub mod lzfse;
pub mod stage;
pub mod trustcache;

pub mod ipsw;

pub mod plist_lite;

pub mod usbmux;

pub mod restored_proto;

pub mod asr;

pub mod tss;
