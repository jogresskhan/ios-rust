//! kernelcache — kernelcache decompression + metadata in pure Rust.
//!
//! A port of the core of blacktop/ipsw `pkg/kernelcache`:
//! * [`compress`] — IM4P unwrap + LZFSE (vendored Apple C via
//!   `restore::lzfse`) / `complzss` LZSS (the xnu `libkern/mkext.c`
//!   decoder ported in [`lzss`]) / uncompressed passthrough + single-slice
//!   fat thinning;
//! * [`version`] — the `Darwin Kernel Version …` + `Apple LLVM …` string
//!   scan over `__TEXT.__const` (fileset-aware);
//! * [`prelink`] — the `__PRELINK_INFO.__info` KEXT inventory;
//! * [`sections`] — a small named-section walker (the `macho` crate tracks
//!   segments without names).
//!
//! What this buys the T8030 project: every restore lane stage that needs
//! the kernel (ramdisk-variant matrix, boot-args composition, symbol
//! grounding for the A13 CPU engine) now has one Rust call:
//! `compress::decompress` → `version::kernel_version` → `prelink::kexts`.
//!
//! Honest boundaries: KEXT *extraction to standalone Mach-O* (ipsw's
//! `openKext` + chained-fixups export path) and the syscall/MIG table
//! discovery in `__DATA_CONST.__const` are not ported yet — see PARITY.md.

pub mod compress;
pub mod lzss;
pub mod prelink;
pub mod sections;
pub mod version;

pub use compress::{decompress, detect, Compression};
pub use lzss::LzssHeader;
pub use prelink::Kext;
pub use version::KernelVersion;

/// Convenience: decompress + summarize a kernelcache payload in one call.
pub fn analyze(data: &[u8]) -> Result<KernelInfo, String> {
    let img = decompress(data)?;
    let version = version::kernel_version(&img);
    let kexts = prelink::kexts(&img)?;
    let is_fileset = sections::is_fileset(&img);
    let compression = detect(data);
    Ok(KernelInfo {
        compression,
        is_fileset,
        version,
        kexts,
        size: img.len(),
    })
}

/// Decompressed kernel summary (CLI-facing).
#[derive(Debug, Clone, Default)]
pub struct KernelInfo {
    /// Compression detected in the raw payload.
    pub compression: Option<Compression>,
    /// True for MH_FILESET kernel collections (iOS 15+ / krnl filesets).
    pub is_fileset: bool,
    /// Parsed version strings, when found.
    pub version: Option<KernelVersion>,
    /// Prelinked KEXT inventory.
    pub kexts: Vec<Kext>,
    /// Decompressed image size.
    pub size: usize,
}
