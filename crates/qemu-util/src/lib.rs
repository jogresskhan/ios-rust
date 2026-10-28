//! qemu-util — Rust port of the libqemuutil layer used by the QEMU/Inferno
//! engine. This is the foundation every other crate in the workspace builds on:
//! the same primitives the C engine gets from `libqemuutil` (subprojects/libcutil),
//! re-expressed in safe Rust.
//!
//! Ported modules (libqemuutil → qemu-util):
//!   util/bitops.h      → bitops    (ctz/clz/rot, bit iterators, bitmap ops)
//!   util/iov.c         → iov       (scatter/gather vector ops)
//!   util/fifo8.c       → fifo      (byte FIFO used by serial/mipi/disp models)
//!   include/qemu/queue → queue     (LIST/SLIST/TAILQ equivalents)
//!   util/error.c       → error     (Error struct + result helpers)
//!
//! Everything here is generic, dependency-free and unit-tested against the same
//! invariants the C tests assert.

pub mod bitops;
pub mod error;
pub mod fifo;
pub mod iov;
pub mod queue;

pub use error::QemuError;
