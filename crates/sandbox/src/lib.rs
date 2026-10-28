//! sandbox — Rust port of Cellebrite Labs' **SandBlaster** (the iOS binary
//! sandbox-profile decompiler), distilled to the core pipeline:
//!
//! ```text
//! binary profile ──▶ SandboxData (header + section tables)
//!                ──▶ operation nodes (8-byte records → terminal/non-terminal)
//!                ──▶ per-operation rule graphs
//!                ──▶ SBPL (Sandbox Profile Language) text
//! ```
//!
//! # Provenance
//!
//! Ported from `cellebrite-labs/sandblaster` (GPL-2.0, Yarden Hamami /
//! Cellebrite Labs; original research by Dionysus Blazakis and Stefan
//! Esser): `reverse_sandbox.py` (header/section layout, both the legacy
//! `type == 0x8000` format and the iOS 18+ `<HHBBBBBBHHH>` header),
//! `operation_node.py` (the 8-byte node record: terminal allow/deny with
//! modifier flags + inline modifiers; non-terminal with filter argument,
//! match/unmatch offsets), `reverse_string.py` (iOS 10+ string table).
//!
//! # Honest subset
//!
//! * header + all section tables: full (both formats)
//! * node records: full (terminal/non-terminal, inline modifiers)
//! * graph build + not-edge normalization: full
//! * SBPL emission: the core forms — terminal decisions, non-terminal
//!   filter chains with `require`/`allow`/`deny`, literal string filters,
//!   subpath/prefix joins. Regex-table decompilation (sandbox_regex.py's
//!   automaton → PCRE) is a follow-up; the regex table is extracted and
//!   reported but not yet re-syntactified.
//! * the 200+ operation-name table ships as a KB slice (see `ops`).

pub mod header;
pub mod node;
pub mod ops;

#[cfg(test)]
mod tests;
pub mod sbpl;

pub use header::{SandboxData, SandboxError};
pub use node::{NodeKind, OperationNode, TerminalType};
pub use sbpl::decompile_profile;

/// Decompile a binary sandbox profile to SBPL text (the SandBlaster main
/// path). `operation_names` supplies the sb-op table (see [`ops`]).
pub fn reverse_sandbox(binary: &[u8], operation_names: &[&str]) -> Result<String, SandboxError> {
    let data = SandboxData::parse(binary)?;
    let nodes = data.parse_operation_nodes(binary)?;
    sbpl::decompile_profile(&data, &nodes, binary, operation_names)
}
