//! header — the binary sandbox profile container: header parsing and
//! section-offset computation for both formats (legacy pre-iOS18
//! `type == 0x8000` and the iOS 18+ `<HHBBBBBBHHH>` header), ported from
//! SandBlaster `reverse_sandbox.py::SandboxData`.

use crate::node::{NodeKind, OperationNode};

#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error("profile too short ({0} bytes)")]
    TooShort(usize),
    #[error("bad header magic {0:#06x}")]
    BadMagic(u16),
    #[error("section out of bounds: {0} + {1} > {2}")]
    OutOfBounds(usize, usize, usize),
    #[error("node index {0} out of range (count {1})")]
    NodeIndex(usize, usize),
}

/// Parsed container header with all derived section offsets.
///
/// Layout (iOS 18+ `<HHBBBBBBHHH>` little-endian, from SandBlaster):
/// `struct_size, type, op_nodes_count, sb_ops_count, vars_count,
/// states_flag, states_count, profile_flag, unknown_byte, num_profiles,
/// regex_count, instructions_count` — the legacy format is the same
/// logical table with fixed 10-byte header (type at offset 0).
#[derive(Debug, Clone)]
pub struct SandboxData {
    pub header_size: usize,
    pub format: Format,
    /// magic (0x8000 legacy / baked into the iOS18 header)
    pub sb_type: u16,
    pub op_nodes_count: usize,
    pub sb_ops_count: usize,
    pub vars_count: usize,
    pub states_count: usize,
    pub num_profiles: usize,
    pub regex_count: usize,
    pub instructions_count: usize,
    // derived section offsets
    pub regex_table_offset: usize,
    pub vars_offset: usize,
    pub states_offset: usize,
    pub profile_flag_offset: usize,
    pub instructions_offset: usize,
    pub profiles_offset: usize,
    pub profiles_end_offset: usize,
    pub operation_nodes_offset: usize,
    pub operation_nodes_size: usize,
    pub base_addr: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Legacy,
    Ios18,
}

const PROFILE_OPS_OFFSET: usize = 8;
const OPERATION_NODE_SIZE: usize = 8;
const INDEX_SIZE: usize = 2;

impl SandboxData {
    /// Parse either format. The iOS 18 header starts with its own size
    /// (`header_size == 14`); the legacy header is a fixed 10 bytes with
    /// `type` first (0x8000).
    pub fn parse(buf: &[u8]) -> Result<SandboxData, SandboxError> {
        if buf.len() < 12 {
            return Err(SandboxError::TooShort(buf.len()));
        }
        let le16 = |o: usize| u16::from_le_bytes([buf[o], buf[o + 1]]) as usize;
        let header_size = le16(0);
        if header_size == 14 {
            Self::parse_ios18(buf)
        } else {
            Self::parse_legacy(buf)
        }
    }

    /// Legacy pre-iOS18 format: `type(H) num_regex(H) num_vars(H)
    /// num_sb_ops?? …` — SandBlaster offsets: type@0 (0x8000),
    /// regex_count@2, vars@6, ops@8-ish with a fixed 10-byte header.
    fn parse_legacy(buf: &[u8]) -> Result<SandboxData, SandboxError> {
        if buf.len() < 12 {
            return Err(SandboxError::TooShort(buf.len()));
        }
        let le16 = |o: usize| u16::from_le_bytes([buf[o], buf[o + 1]]) as usize;
        let sb_type = le16(0);
        if sb_type != 0x8000 {
            return Err(SandboxError::BadMagic(sb_type as u16));
        }
        let sb_type = sb_type as u16;
        let regex_count = le16(2);
        let vars_count = le16(6);
        let sb_ops_count = le16(8);
        let op_nodes_count = le16(10);
        let states_count = le16(4);
        let num_profiles = 1;
        let instructions_count = 0;
        Ok(Self::assemble(
            Format::Legacy,
            12,
            sb_type,
            op_nodes_count,
            sb_ops_count,
            vars_count,
            states_count,
            num_profiles,
            regex_count,
            instructions_count,
        ))
    }

    /// iOS 18+ format: `<HHBBBBBBHHH>` = 14-byte header.
    fn parse_ios18(buf: &[u8]) -> Result<SandboxData, SandboxError> {
        if buf.len() < 14 {
            return Err(SandboxError::TooShort(buf.len()));
        }
        let le16 = |o: usize| u16::from_le_bytes([buf[o], buf[o + 1]]) as usize;
        let header_size = le16(0);
        let sb_type = le16(2) as u16;
        let op_nodes_count = buf[4] as usize
            | (buf[5] as usize) << 8
            | (buf[6] as usize) << 16
            | (buf[7] as usize) << 24;
        let sb_ops_count = buf[8] as usize | (buf[9] as usize) << 8;
        let vars_count = buf[10] as usize | (buf[11] as usize) << 8;
        let states_flag = buf[12] as usize;
        let states_count = buf[13] as usize;
        let profile_flag = le16(14.min(buf.len() - 2));
        let num_profiles = le16(16.min(buf.len() - 2));
        let regex_count = le16(18.min(buf.len() - 2));
        let instructions_count = le16(20.min(buf.len() - 2));
        let _ = profile_flag;
        Ok(Self::assemble(
            Format::Ios18,
            header_size,
            sb_type,
            op_nodes_count,
            sb_ops_count,
            vars_count,
            states_count + states_flag,
            num_profiles,
            regex_count,
            instructions_count,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn assemble(
        format: Format,
        header_size: usize,
        sb_type: u16,
        op_nodes_count: usize,
        sb_ops_count: usize,
        vars_count: usize,
        states_count: usize,
        num_profiles: usize,
        regex_count: usize,
        instructions_count: usize,
    ) -> SandboxData {
        let regex_table_offset = header_size;
        let vars_offset = regex_table_offset + regex_count * INDEX_SIZE;
        let states_offset = vars_offset + vars_count * INDEX_SIZE;
        let profile_flag_offset = states_offset + states_count * INDEX_SIZE;
        let instructions_offset = profile_flag_offset + states_count * INDEX_SIZE;
        let profiles_offset = instructions_offset + instructions_count * INDEX_SIZE;
        let profiles_end_offset =
            profiles_offset + num_profiles * (sb_ops_count * INDEX_SIZE + PROFILE_OPS_OFFSET);
        let operation_nodes_size = op_nodes_count * OPERATION_NODE_SIZE;
        let mut operation_nodes_offset = profiles_end_offset;
        if sb_type != 0x8000 {
            operation_nodes_offset += sb_ops_count * INDEX_SIZE;
        }
        let align_delta = operation_nodes_offset & 7;
        if align_delta != 0 {
            operation_nodes_offset += 8 - align_delta;
        }
        let base_addr = operation_nodes_offset + operation_nodes_size;
        SandboxData {
            header_size,
            format,
            sb_type,
            op_nodes_count,
            sb_ops_count,
            vars_count,
            states_count,
            num_profiles,
            regex_count,
            instructions_count,
            regex_table_offset,
            vars_offset,
            states_offset,
            profile_flag_offset,
            instructions_offset,
            profiles_offset,
            profiles_end_offset,
            operation_nodes_offset,
            operation_nodes_size,
            base_addr,
        }
    }

    /// Parse the `op_nodes_count` 8-byte operation-node records.
    pub fn parse_operation_nodes(&self, buf: &[u8]) -> Result<Vec<OperationNode>, SandboxError> {
        let end = self.operation_nodes_offset + self.operation_nodes_size;
        if end > buf.len() {
            return Err(SandboxError::OutOfBounds(
                self.operation_nodes_offset,
                self.operation_nodes_size,
                buf.len(),
            ));
        }
        let mut nodes = Vec::with_capacity(self.op_nodes_count);
        for i in 0..self.op_nodes_count {
            let off = self.operation_nodes_offset + i * OPERATION_NODE_SIZE;
            let raw: [u8; 8] = buf[off..off + 8].try_into().unwrap();
            nodes.push(OperationNode::parse(i, raw));
        }
        // Resolve match/unmatch references by node offset.
        let by_offset: std::collections::HashMap<usize, usize> =
            nodes.iter().map(|n| (n.offset, n.index)).collect();
        for n in &mut nodes {
            if let NodeKind::NonTerminal { match_offset, unmatch_offset, .. } = n.kind {
                n.match_idx = by_offset.get(&match_offset).copied();
                n.unmatch_idx = by_offset.get(&unmatch_offset).copied();
            }
        }
        Ok(nodes)
    }

    /// Read the per-profile sb-op offset table (index → node offset).
    pub fn sb_ops_offsets(&self, buf: &[u8]) -> Result<Vec<usize>, SandboxError> {
        let start = if self.sb_type == 0x8000 {
            self.profiles_offset
        } else {
            self.profiles_end_offset - self.sb_ops_count * INDEX_SIZE
        };
        let end = start + self.sb_ops_count * INDEX_SIZE;
        if end > buf.len() {
            return Err(SandboxError::OutOfBounds(start, end - start, buf.len()));
        }
        Ok((0..self.sb_ops_count)
            .map(|i| {
                u16::from_le_bytes([buf[start + i * 2], buf[start + i * 2 + 1]]) as usize
            })
            .collect())
    }

    /// The operation-node base address (SandBlaster `base_addr`): string
    /// and filter data live beyond this offset inside the node records.
    pub fn data_addr(&self) -> usize {
        self.base_addr
    }
}
