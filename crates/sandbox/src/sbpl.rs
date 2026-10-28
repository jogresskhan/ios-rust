//! sbpl — the SBPL (Sandbox Profile Language) emitter: walks each
//! operation's node graph and prints the rule chain as Scheme-like SBPL,
//! mirroring SandBlaster's `reduce_operation_node_graph` +
//! `print_vertices_with_operation` output shape.

use crate::header::{SandboxData, SandboxError};
use crate::node::{NodeKind, OperationNode, TerminalType};
use crate::ops::op_name;

/// Extract a literal string from the profile data area (SandBlaster's
/// `SandboxString` for the iOS 10+ format: length-prefixed at the filter
/// argument address).
fn data_string(buf: &[u8], base: usize, addr: usize) -> Option<String> {
    let off = base.checked_add(addr)?;
    if off + 2 > buf.len() {
        return None;
    }
    let len = u16::from_le_bytes([buf[off], buf[off + 1]]) as usize;
    let s = buf.get(off + 2..off + 2 + len)?;
    Some(String::from_utf8_lossy(s).into_owned())
}

/// Decompile one operation's graph into an SBPL rule list.
fn emit_operation(
    out: &mut String,
    nodes: &[OperationNode],
    start: usize,
    default_ty: TerminalType,
    op: &str,
    buf: &[u8],
    data_base: usize,
    depth: usize,
) {
    // Walk the match chain, printing (deny|allow …) filters; the unmatch
    // edge continues the parent chain (SandBlaster's graph reduction).
    let mut idx = Some(start);
    let mut guard = 0usize;
    while let Some(i) = idx {
        guard += 1;
        if guard > nodes.len() {
            break; // cycle guard — real profiles are acyclic per operation
        }
        match &nodes[i].kind {
            NodeKind::Terminal { ty, .. } => {
                if *ty != default_ty {
                    let d = match ty {
                        TerminalType::Allow => "allow",
                        TerminalType::Deny => "deny",
                    };
                    out.push_str(&"  ".repeat(depth));
                    out.push_str(&format!("({d} {op})\n"));
                }
                break;
            }
            NodeKind::NonTerminal { filter_arg, .. } => {
                let filter = data_string(buf, data_base, usize::from(*filter_arg))
                    .unwrap_or_else(|| format!("filter@{:04x}", filter_arg));
                out.push_str(&"  ".repeat(depth));
                out.push_str(&format!("; {op}: filter {filter}\n"));
                // Follow the match edge; the unmatch edge is the chain tail.
                idx = nodes[i].match_idx.or(nodes[i].unmatch_idx);
            }
        }
    }
}

/// Decompile a full profile: header + node table + per-op graphs → SBPL.
pub fn decompile_profile(
    data: &SandboxData,
    nodes: &[OperationNode],
    buf: &[u8],
    operation_names: &[&str],
) -> Result<String, SandboxError> {
    let offsets = data.sb_ops_offsets(buf)?;
    let data_base = data.data_addr();

    // default decision: node 0's terminal (SandBlaster prints "(default)")
    let default_idx = nodes
        .iter()
        .find(|n| n.offset == offsets.first().copied().unwrap_or(0))
        .map(|n| n.index)
        .unwrap_or(0);
    let default_ty = nodes[default_idx]
        .terminal_type()
        .unwrap_or(TerminalType::Deny);

    let mut out = String::new();
    out.push_str(&format!(
        "; SBPL — decompiled by ios-rust sandbox (SandBlaster port)\n\
         ; format: {:?} header_size={} op_nodes={} sb_ops={} vars={} regex={}\n\
         (version 1)\n(deny default)\n",
        data.format, data.header_size, data.op_nodes_count, data.sb_ops_count,
        data.vars_count, data.regex_count,
    ));

    for (op_idx, &off) in offsets.iter().enumerate().skip(1) {
        let name = operation_names
            .get(op_idx)
            .copied()
            .map(str::to_string)
            .unwrap_or_else(|| op_name(op_idx));
        let Some(start) = nodes.iter().find(|n| n.offset == off).map(|n| n.index) else {
            continue;
        };
        // Operations whose start node is a terminal differing from the
        // default get a one-line rule; others expand the filter chain.
        emit_operation(&mut out, nodes, start, default_ty, &name, buf, data_base, 0);
    }
    Ok(out)
}
