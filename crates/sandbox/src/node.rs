//! node — the 8-byte operation-node record (SandBlaster
//! `operation_node.py::OperationNode.parse_raw` + `TerminalNode`):
//!
//! ```text
//! raw[0] = type (0 = non-terminal, 1 = terminal)
//! terminal:      raw[1] bit0 = allow/deny; modifier_flags = r1|r2<<8|r3<<16;
//!                0x800000 = inline action (r4 = modifier id, r5 = policy op,
//!                r6|r7<<8 = argument)
//! non-terminal:  r1 = filter argument address, r2|r3 = match offset,
//!                r4|r5 = unmatch offset (layout per SandBlaster's
//!                NonTerminal.parse_raw — offsets are node-relative)
//! ```

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalType {
    Allow,
    Deny,
}

#[derive(Debug, Clone)]
pub enum NodeKind {
    Terminal {
        ty: TerminalType,
        modifier_flags: u32,
        action_inline: bool,
        inline_modifier: Option<(u8, u8, u16)>,
    },
    NonTerminal {
        /// filter-argument address (into the data area past `base_addr`)
        filter_arg: u16,
        match_offset: usize,
        unmatch_offset: usize,
    },
}

#[derive(Debug, Clone)]
pub struct OperationNode {
    /// index in the node table
    pub index: usize,
    /// byte offset (SandBlaster uses offset == index * 8 as the identity)
    pub offset: usize,
    pub kind: NodeKind,
    /// resolved table indices (filled by the container after parse)
    pub match_idx: Option<usize>,
    pub unmatch_idx: Option<usize>,
}

impl OperationNode {
    pub fn parse(index: usize, raw: [u8; 8]) -> OperationNode {
        let offset = index * 8;
        let kind = if raw[0] & 1 == 1 {
            let modifier_flags =
                raw[1] as u32 | (raw[2] as u32) << 8 | (raw[3] as u32) << 16;
            let action_inline = modifier_flags & 0x8000_00 != 0;
            let inline_modifier = if action_inline {
                Some((raw[4], raw[5], u16::from_le_bytes([raw[6], raw[7]])))
            } else {
                None
            };
            let ty = if raw[1] & 1 == 1 { TerminalType::Deny } else { TerminalType::Allow };
            NodeKind::Terminal { ty, modifier_flags, action_inline, inline_modifier }
        } else {
            // Non-terminal (SandBlaster NonTerminal.parse_raw):
            // r1 = filter arg address; match = r2|r3<<8; unmatch = r4|r5<<8
            let filter_arg = raw[1] as u16;
            let match_offset = raw[2] as usize | (raw[3] as usize) << 8;
            let unmatch_offset = raw[4] as usize | (raw[5] as usize) << 8;
            NodeKind::NonTerminal { filter_arg, match_offset, unmatch_offset }
        };
        OperationNode { index, offset, kind, match_idx: None, unmatch_idx: None }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self.kind, NodeKind::Terminal { .. })
    }

    /// The terminal decision, if this is a terminal node.
    pub fn terminal_type(&self) -> Option<TerminalType> {
        match self.kind {
            NodeKind::Terminal { ty, .. } => Some(ty),
            _ => None,
        }
    }
}

/// Build the rule graph reachability from a start node (SandBlaster's
/// `build_operation_node_graph` walk, iterative to avoid recursion on
/// the ~50k-node real profiles).
pub fn walk_graph(
    nodes: &[OperationNode],
    start: usize,
    default_ty: TerminalType,
) -> Vec<usize> {
    let mut seen = vec![false; nodes.len()];
    let mut order = Vec::new();
    let mut stack = vec![start];
    while let Some(idx) = stack.pop() {
        if idx >= nodes.len() || seen[idx] {
            continue;
        }
        seen[idx] = true;
        order.push(idx);
        match &nodes[idx].kind {
            NodeKind::Terminal { ty, .. } => {
                // A terminal equal to the default decision ends the path;
                // different terminals are the operation's explicit rule.
                let _ = ty;
                let _ = default_ty;
            }
            NodeKind::NonTerminal { .. } => {
                if let Some(m) = nodes[idx].match_idx {
                    stack.push(m);
                }
                if let Some(u) = nodes[idx].unmatch_idx {
                    stack.push(u);
                }
            }
        }
    }
    order
}
