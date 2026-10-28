//! dsc — dyld shared cache reader in pure Rust.
//!
//! A port of the core of blacktop/ipsw's `pkg/dyld` (the in-repo Go library
//! that replaced go-dyld): the `dyld_cache_header` with its exact byte
//! offsets and version gates, mappings (plain + with-slide), image lists
//! (old and dyld4 styles), subcache member tables (v1/v2) with the on-disk
//! naming rules, the `.symbols` unmapped member, local symbols
//! (`nlist_64`), and the slide-info (rebase) walkers for versions 2/3/4/5.
//!
//! What this buys the T8030 project:
//! * reading iOS 13/14 A13 caches (`dyld_v1   arm64`, slide **v3**, 4 KB
//!   pages — the restore-lane generation) and iOS 15+ dyld4 split caches;
//! * VM↔file-offset translation across every member for the CPU engine's
//!   loader and for symbol-backed tracing;
//! * the exact rebase list (file offset → target) so a host-side loader can
//!   pre-slide pointers the way dyld would at runtime.
//!
//! Honest boundaries (see PARITY.md): PrebuiltLoaderSet/launch-closure
//! parsing, patch-info (v1–v4) walkers, ObjC optimization hash tables, and
//! image *extraction to standalone Mach-O* are not implemented here yet —
//! the reader covers discovery, metadata, and rebasing.
//!
//! Memory note: the Go tool mmaps members; this reader loads whole files
//! with `std::fs::read`. A13-era single-file caches are 1–2 GiB; dyld4
//! splits spread that across members. CLI-scale use is fine; embedders
//! wanting mmap should wrap their own allocator.

pub mod file;
pub mod header;
pub mod image;
pub mod localsyms;
pub mod mapping;
pub mod slide;
pub mod subcache;

pub use file::{Dsc, CacheMember};
pub use header::{CacheHeader, CacheType, FormatVersion};
pub use image::{CacheImage, CacheImageTextInfo};
pub use mapping::{CacheMapping, VmProtection};
pub use slide::Rebase;
pub use subcache::SubcacheEntry;
