//! ipsw — the restore/install pipeline: fetch, parse, variant-build, verify.
//! Real parsing for IM4P + BuildManifest; the ramdisk variant matrix mirrors
//! the M2 bisection (v0..v8) so the QEMU-replacement can drive the same diag.

pub mod fetch;
pub mod im4p;
pub mod manifest;
pub mod ramdisk_variants;
