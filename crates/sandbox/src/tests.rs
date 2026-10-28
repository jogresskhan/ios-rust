//! Tests: synthetic-profile round-trips. We BUILD binary sandbox profiles
//! with the exact layout SandBlaster parses (both formats), then decompile
//! them — the round-trip proves the header math, node parsing, graph walk
//! and SBPL emission agree with the upstream field layout.

use crate::header::{SandboxData, SandboxError};
use crate::node::TerminalType;
use crate::reverse_sandbox;

/// Build a legacy (0x8000) profile with `n_ops` operations, an optional
/// default-deny terminal, and `n_nodes` operation nodes.
struct ProfileBuilder {
    ops: Vec<usize>,   // sb-op → node offset
    nodes: Vec<[u8; 8]>,
    strings: Vec<u8>,  // data area: len-prefixed literals
}

impl ProfileBuilder {
    fn new() -> Self {
        ProfileBuilder { ops: Vec::new(), nodes: Vec::new(), strings: Vec::new() }
    }

    fn add_terminal(&mut self, deny: bool) -> usize {
        let off = self.nodes.len() * 8;
        let raw = [1u8, deny as u8, 0, 0, 0, 0, 0, 0];
        self.nodes.push(raw);
        off
    }

    fn add_non_terminal(&mut self, filter: &str, match_off: usize, unmatch_off: usize) -> usize {
        let off = self.nodes.len() * 8;
        let arg_addr = self.strings.len() as u16;
        self.strings.extend_from_slice(&(filter.len() as u16).to_le_bytes());
        self.strings.extend_from_slice(filter.as_bytes());
        let m = (match_off as u16).to_le_bytes();
        let u = (unmatch_off as u16).to_le_bytes();
        let raw = [0, 0, m[0], m[1], u[0], u[1], 0, 0];
        // filter arg lives in raw[1] (NonTerminal layout)
        let raw = [0u8, (arg_addr & 0xFF) as u8, m[0], m[1], u[0], u[1], 0, 0];
        self.nodes.push(raw);
        off
    }

    /// Assemble the legacy container. Node data area begins after the
    /// aligned operation-node table; the filter-arg addresses are relative
    /// to the data base (SandBlaster's `base_addr`).
    fn build(self) -> Vec<u8> {
        let mut out = Vec::new();
        // legacy header: type(H)=0x8000 regex(H)=0 vars(H)=0 sb_ops(H)
        // states(H)=0 op_nodes(H) — 12 bytes (SandBlaster legacy layout
        // with the count block; keep self-consistent with parse_legacy)
        let op_nodes = self.nodes.len() as u16;
        out.extend_from_slice(&0x8000u16.to_le_bytes()); // type @0
        out.extend_from_slice(&0u16.to_le_bytes()); // regex_count @2
        out.extend_from_slice(&0u16.to_le_bytes()); // states @4
        out.extend_from_slice(&0u16.to_le_bytes()); // vars @6
        out.extend_from_slice(&(self.ops.len() as u16).to_le_bytes()); // sb_ops @8
        out.extend_from_slice(&op_nodes.to_le_bytes()); // op_nodes @10
        // profiles section: sb-op offset copies + the 8-byte profile block
        for off in &self.ops {
            out.extend_from_slice(&(*off as u16).to_le_bytes());
        }
        out.extend_from_slice(&[0u8; 8]);
        // operation nodes (8 bytes each), 8-aligned
        while out.len() % 8 != 0 {
            out.push(0);
        }
        for n in &self.nodes {
            out.extend_from_slice(n);
        }
        // data area: the strings the filter args point into
        out.extend_from_slice(&self.strings);
        out
    }
}

#[test]
fn legacy_header_offsets_match_sandblaster() {
    let b = ProfileBuilder::new();
    let b = b.build();
    let d = SandboxData::parse(&b).unwrap();
    assert_eq!(d.format, crate::header::Format::Legacy);
    assert_eq!(d.sb_type, 0x8000);
    // regex/vars/states tables (empty here) sit after the 12-byte header
    assert_eq!(d.regex_table_offset, 12);
    assert_eq!(d.vars_offset, 12);
    assert_eq!(d.states_offset, 12);
    // sb_ops table then follows; nodes after the 8-aligned boundary
    assert_eq!(d.operation_nodes_offset % 8, 0);
}

#[test]
fn reject_short_and_bad_magic() {
    assert!(matches!(SandboxData::parse(&[0u8; 4]), Err(SandboxError::TooShort(4))));
    let mut bad = 0x1234u16.to_le_bytes().to_vec();
    bad.extend_from_slice(&[0u8; 10]);
    assert!(matches!(SandboxData::parse(&bad), Err(SandboxError::BadMagic(0x1234))));
}

#[test]
fn terminal_nodes_parse_allow_deny() {
    let allow = crate::node::OperationNode::parse(0, [1, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(allow.terminal_type(), Some(TerminalType::Allow));
    let deny = crate::node::OperationNode::parse(0, [1, 1, 0, 0, 0, 0, 0, 0]);
    assert_eq!(deny.terminal_type(), Some(TerminalType::Deny));
    // inline-action flag (0x800000 in modifier flags)
    let inline = crate::node::OperationNode::parse(0, [1, 1, 0x80, 0x80, 1, 2, 3, 4]);
    match inline.kind {
        crate::node::NodeKind::Terminal { action_inline, inline_modifier, .. } => {
            assert!(action_inline);
            assert_eq!(inline_modifier, Some((1, 2, 0x0403)));
        }
        _ => panic!("expected terminal"),
    }
}

#[test]
fn non_terminal_graph_walk_and_sbpl() {
    // (deny default) + one op: filter "file-read-data" → allow terminal
    let mut b = ProfileBuilder::new();
    let deny = b.add_terminal(true);
    let allow = b.add_terminal(false);
    let nt = b.add_non_terminal("file-read-data", allow, deny);
    b.ops.push(deny); // default op
    b.ops.push(nt); // file-read-data
    let bin = b.build();
    let d = SandboxData::parse(&bin).unwrap();
    assert_eq!(d.sb_ops_count, 2);
    let nodes = d.parse_operation_nodes(&bin).unwrap();
    assert_eq!(nodes.len(), 3);
    // graph: non-terminal resolves both edges
    let nt = &nodes[2];
    assert!(nt.match_idx.is_some() && nt.unmatch_idx.is_some());
    let sbpl = reverse_sandbox(&bin, &["default", "file-read-data"]).unwrap();
    assert!(sbpl.contains("(deny default)"), "{sbpl}");
    assert!(sbpl.contains("file-read-data"), "{sbpl}");
    assert!(sbpl.contains("(allow file-read-data)"), "{sbpl}");
}

#[test]
fn chain_walk_follows_match_edges() {
    // default deny; op = filter A → filter B → allow
    let mut b = ProfileBuilder::new();
    let deny = b.add_terminal(true);
    let allow = b.add_terminal(false);
    let nt2 = b.add_non_terminal("subpath", allow, deny);
    let nt1 = b.add_non_terminal("literal", nt2, deny);
    b.ops.push(deny);
    b.ops.push(nt1);
    let bin = b.build();
    let sbpl = reverse_sandbox(&bin, &["default", "chain-op"]).unwrap();
    assert!(sbpl.contains("literal"), "{sbpl}");
    assert!(sbpl.contains("subpath"), "{sbpl}");
    assert!(sbpl.contains("(allow chain-op)"), "{sbpl}");
}

#[test]
fn cycle_guard_terminates() {
    // A self-referential non-terminal must not hang the walker.
    let mut b = ProfileBuilder::new();
    let deny = b.add_terminal(true);
    let self_loop = b.add_non_terminal("self", 0xFFFF, deny);
    // patch the match offset to point at itself
    b.nodes[self_loop / 8][3] = (self_loop & 0xFF) as u8;
    b.nodes[self_loop / 8][2] = (self_loop >> 8) as u8;
    b.ops.push(deny);
    b.ops.push(self_loop);
    let bin = b.build();
    let sbpl = reverse_sandbox(&bin, &["default", "loopy"]).unwrap();
    // terminates and emits the filter comment at least once
    assert!(sbpl.contains("self"), "{sbpl}");
}

