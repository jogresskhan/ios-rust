//! ADT node tree — Apple DeviceTree parse / serialise / query.
//!
//! Wire format (ChefKiss Inferno `hw/arm/apple-silicon/dt.c` +
//! sweet-core `mkadt.rs`/`adt.rs`, identical to m1n1 `src/adt.h`):
//!
//! ```text
//! node   := u32 nprops, u32 nchildren, prop[nprops], node[nchildren]
//! prop   := char name[32], u32 len (bit31 = placeholder hint), u8 data[len] (padded to 4)
//! ```
//!
//! All integers are **little-endian**. There are no `NODE`/`PROP`/`END `
//! magics in this format — nodes and properties are self-counted (see
//! `apple_dt_deserialise_node`, m1n1 `struct adt_node_hdr`, and
//! `mkadt.rs serialize_into`, which all agree). The node name is carried as
//! an ordinary `"name"` property (Inferno `apple_dt_node_new`), mirrored
//! here into [`AdtNode::name`] and written back out on [`AdtNode::to_bytes`].
//!
//! Placeholder properties (bit31) are parsed by masking the flag off; the
//! flag itself is an Inferno builder-time hint and is not preserved by this
//! port (the required `AdtProp { name, data }` has nowhere to keep it —
//! real IPSW device trees never carry it).

use crate::prop::{cstr, cstr_lossy, AdtProp};

/// Maximum node nesting accepted by [`AdtNode::parse`] (real trees are < 10
/// deep; the cap turns corrupt-blob cycles into an error instead of a stack
/// overflow).
const MAX_DEPTH: usize = 128;

/// Name field width on the wire (Inferno `APPLE_DT_PROP_NAME_LEN`).
const PROP_NAME_LEN: usize = 32;

/// One node of the Apple DeviceTree.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AdtNode {
    /// Node name (the `"name"` property, e.g. `"arm-io"`, `"uart0"`; the
    /// root is often `"device-tree"`).
    pub name: String,
    /// Properties in file order (the `"name"` property included).
    pub props: Vec<AdtProp>,
    /// Child nodes in file order.
    pub children: Vec<AdtNode>,
}

fn read_u32(buf: &[u8], off: usize) -> Result<u32, String> {
    if off + 4 > buf.len() {
        return Err(format!("ADT: u32 read out of bounds at {off:#x}"));
    }
    Ok(u32::from_le_bytes(buf[off..off + 4].try_into().unwrap()))
}

impl AdtNode {
    /// New node carrying only its `"name"` property (mkadt `Node::new`).
    pub fn new(name: &str) -> Self {
        AdtNode {
            name: name.to_string(),
            props: vec![AdtProp { name: "name".into(), data: cstr(name) }],
            children: Vec::new(),
        }
    }

    /// Parse a whole device tree blob; returns the root node.
    pub fn parse(buf: &[u8]) -> Result<AdtNode, String> {
        let (node, consumed) = Self::parse_at(buf, 0, 0)?;
        if consumed != buf.len() {
            // Tolerate trailing padding; only reject obvious garbage.
            if buf[consumed..].iter().any(|&b| b != 0) {
                return Err(format!(
                    "ADT: {} trailing bytes after root node at {consumed:#x}",
                    buf.len() - consumed
                ));
            }
        }
        Ok(node)
    }

    fn parse_at(buf: &[u8], off: usize, depth: usize) -> Result<(AdtNode, usize), String> {
        if depth > MAX_DEPTH {
            return Err(format!("ADT: node nesting deeper than {MAX_DEPTH} at {off:#x}"));
        }
        if off + 8 > buf.len() {
            return Err(format!("ADT: node header out of bounds at {off:#x}"));
        }
        let nprops = read_u32(buf, off)? as usize;
        let nchildren = read_u32(buf, off + 4)? as usize;
        let mut node = AdtNode::default();
        let mut off = off + 8;

        for _ in 0..nprops {
            if off + 36 > buf.len() {
                return Err(format!("ADT: property header out of bounds at {off:#x}"));
            }
            let name: String = buf[off..off + PROP_NAME_LEN]
                .iter()
                .take_while(|&&c| c != 0)
                .map(|&c| c as char)
                .collect();
            let size_word = read_u32(buf, off + PROP_NAME_LEN)?;
            // bit31 is Inferno's placeholder hint; the real length is the
            // low 31 bits.
            let len = (size_word & 0x7fff_ffff) as usize;
            if off + 36 + len > buf.len() {
                return Err(format!("ADT: property `{name}` value out of bounds at {off:#x}"));
            }
            node.props.push(AdtProp {
                name,
                data: buf[off + 36..off + 36 + len].to_vec(),
            });
            off += 36 + ((len + 3) & !3);
        }

        node.name = node
            .props
            .iter()
            .find(|p| p.name == "name")
            .map(|p| cstr_lossy(&p.data))
            .unwrap_or_default();

        for _ in 0..nchildren {
            let (child, next) = Self::parse_at(buf, off, depth + 1)?;
            node.children.push(child);
            off = next;
        }
        Ok((node, off))
    }

    /// Serialise the node (and its subtree) back into wire format.
    ///
    /// The `"name"` property is (re)generated from [`AdtNode::name`], the
    /// same invariant Inferno's builder maintains. Property payloads are
    /// padded to a 4-byte boundary like `mkadt.rs serialize_into`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.serialize_into(&mut out);
        out
    }

    fn serialize_into(&self, out: &mut Vec<u8>) {
        let mut props: Vec<AdtProp> = Vec::with_capacity(self.props.len() + 1);
        if !self.name.is_empty() {
            props.push(AdtProp { name: "name".into(), data: cstr(&self.name) });
        }
        for p in &self.props {
            if p.name == "name" {
                if self.name.is_empty() {
                    props.push(p.clone()); // keep a root without a name field intact
                }
                continue;
            }
            props.push(p.clone());
        }

        out.extend_from_slice(&(props.len() as u32).to_le_bytes());
        out.extend_from_slice(&(self.children.len() as u32).to_le_bytes());
        for p in &props {
            let mut name = [0u8; PROP_NAME_LEN];
            let nb = p.name.as_bytes();
            let n = nb.len().min(PROP_NAME_LEN);
            name[..n].copy_from_slice(&nb[..n]);
            out.extend_from_slice(&name);
            out.extend_from_slice(&(p.data.len() as u32).to_le_bytes());
            out.extend_from_slice(&p.data);
            out.extend(std::iter::repeat(0u8).take(p.data.len().wrapping_neg() & 3));
        }
        for c in &self.children {
            c.serialize_into(out);
        }
    }

    /// Resolve a path like `"/arm-io/uart0"` (leading slash optional,
    /// empty segments skipped — Inferno `apple_dt_get_node` semantics).
    pub fn find(&self, path: &str) -> Option<&AdtNode> {
        let mut cur = self;
        for seg in path.split('/').filter(|s| !s.is_empty()) {
            cur = cur.children.iter().find(|c| c.name == seg)?;
        }
        Some(cur)
    }

    /// Direct child by node name (Inferno `apple_dt_get_node` single step).
    pub fn child(&self, name: &str) -> Option<&AdtNode> {
        self.children.iter().find(|c| c.name == name)
    }

    /// Property lookup (Inferno `apple_dt_get_prop`).
    pub fn get_prop(&self, name: &str) -> Option<&AdtProp> {
        self.props.iter().find(|p| p.name == name)
    }

    /// Raw property payload (None when the property is absent).
    pub fn prop_bytes(&self, name: &str) -> Option<&[u8]> {
        self.get_prop(name).map(|p| p.data.as_slice())
    }

    /// Property payload as a string (trailing NUL trimmed, lossy UTF-8).
    /// `None` when the property is absent.
    pub fn prop_string(&self, name: &str) -> Option<String> {
        self.prop_bytes(name).map(cstr_lossy)
    }

    /// First 4 payload bytes as little-endian `u32` (Inferno
    /// `apple_dt_get_prop_u32`: errors on short properties, reads LE).
    pub fn prop_u32(&self, name: &str) -> Option<u32> {
        self.get_prop(name)?.as_u32()
    }

    /// First 8 payload bytes as little-endian `u64` (Inferno
    /// `apple_dt_get_prop_u64`).
    pub fn prop_u64(&self, name: &str) -> Option<u64> {
        self.get_prop(name)?.as_u64()
    }

    /// `reg` property as `(base, size)` pairs.
    ///
    /// Apple ADTs encode `reg` as u64 pairs (`#address-cells = 2`,
    /// `#size-cells = 2`) under `/arm-io`; a few nodes use u32 pairs, which
    /// are detected by payload length and widened.
    pub fn reg_entries(&self) -> Vec<(u64, u64)> {
        let Some(reg) = self.prop_bytes("reg") else {
            return Vec::new();
        };
        let mut out = Vec::new();
        if reg.len() % 16 == 0 {
            for c in reg.chunks_exact(16) {
                out.push((
                    u64::from_le_bytes(c[..8].try_into().unwrap()),
                    u64::from_le_bytes(c[8..].try_into().unwrap()),
                ));
            }
        } else if reg.len() % 8 == 0 {
            for c in reg.chunks_exact(8) {
                out.push((
                    u32::from_le_bytes(c[..4].try_into().unwrap()) as u64,
                    u32::from_le_bytes(c[4..].try_into().unwrap()) as u64,
                ));
            }
        }
        out
    }

    /// `compatible` property split on NULs (e.g.
    /// `"apple,t8030\0arm,pl192\0"` -> `["apple,t8030", "arm,pl192"]`).
    pub fn compatible(&self) -> Vec<String> {
        match self.prop_bytes("compatible") {
            Some(data) => data
                .split(|&b| b == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect(),
            None => Vec::new(),
        }
    }

    /// Insert or replace a raw-bytes property (Inferno
    /// `apple_dt_set_prop` upsert semantics). Builder-style: returns
    /// `&mut Self` so calls chain.
    pub fn set_prop_bytes(&mut self, name: impl Into<String>, data: Vec<u8>) -> &mut Self {
        self.upsert(AdtProp { name: name.into(), data });
        self
    }

    /// Insert or replace a NUL-terminated string property.
    pub fn set_prop_string(&mut self, name: impl Into<String>, value: &str) -> &mut Self {
        self.upsert(AdtProp { name: name.into(), data: cstr(value) });
        self
    }

    /// Insert or replace a little-endian `u32` property.
    pub fn set_prop_u32(&mut self, name: impl Into<String>, value: u32) -> &mut Self {
        self.upsert(AdtProp { name: name.into(), data: value.to_le_bytes().to_vec() });
        self
    }

    /// Insert or replace a little-endian `u64` property.
    pub fn set_prop_u64(&mut self, name: impl Into<String>, value: u64) -> &mut Self {
        self.upsert(AdtProp { name: name.into(), data: value.to_le_bytes().to_vec() });
        self
    }

    fn upsert(&mut self, prop: AdtProp) {
        match self.props.iter_mut().find(|p| p.name == prop.name) {
            Some(slot) => slot.data = prop.data,
            None => self.props.push(prop),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_tree() -> AdtNode {
        let mut root = AdtNode::new("device-tree");
        root.set_prop_string("product", "iPhone11,8");
        root.set_prop_u32("chip-revision", 0xb1);

        let mut uart = AdtNode::new("uart0");
        uart.set_prop_u64("reg", 0x2200_0000).set_prop_u64("reg-size", 0x4000);
        // multi-u64 reg prop: base 0x22000000 size 0x4000
        let mut reg_data = Vec::new();
        reg_data.extend_from_slice(&0x2200_0000u64.to_le_bytes());
        reg_data.extend_from_slice(&0x4000u64.to_le_bytes());
        uart.props.retain(|p| p.name != "reg" && p.name != "reg-size");
        uart.set_prop_bytes("reg", reg_data);
        uart.set_prop_bytes("compatible", b"apple,s5l-uart\0arm,pl011\0".to_vec());

        let mut io = AdtNode::new("arm-io");
        io.children.push(uart);
        root.children.push(io);
        root
    }

    #[test]
    fn parse_to_bytes_roundtrip() {
        let tree = sample_tree();
        let blob = tree.to_bytes();
        let parsed = AdtNode::parse(&blob).expect("parse");
        assert_eq!(parsed, tree);
        assert_eq!(parsed.to_bytes(), blob); // stable re-serialisation
    }

    #[test]
    fn find_child_and_prop_accessors() {
        let tree = sample_tree();
        let uart = tree.find("/arm-io/uart0").expect("path resolve");
        assert_eq!(tree.find("arm-io/uart0").unwrap().name, "uart0");
        assert!(tree.find("/arm-io/i2c1").is_none());
        assert_eq!(tree.child("arm-io").unwrap().name, "arm-io");
        assert_eq!(tree.prop_string("product").as_deref(), Some("iPhone11,8"));
        assert_eq!(tree.prop_u32("chip-revision"), Some(0xb1));
        assert_eq!(uart.prop_u64("reg"), Some(0x2200_0000));
        assert_eq!(tree.prop_string("missing"), None);
        // u32 read needs at least 4 payload bytes (Inferno len-mismatch rule)
        let mut tiny = AdtNode::new("t");
        tiny.set_prop_bytes("half", vec![0x01, 0x02]);
        assert_eq!(tiny.prop_u32("half"), None);
    }

    #[test]
    fn reg_entries_and_compatible() {
        let tree = sample_tree();
        let uart = tree.find("/arm-io/uart0").unwrap();
        assert_eq!(uart.reg_entries(), vec![(0x2200_0000, 0x4000)]);
        assert_eq!(
            uart.compatible(),
            vec!["apple,s5l-uart".to_string(), "arm,pl011".to_string()]
        );
        // u32 reg fallback (8-byte entry)
        let mut n = AdtNode::new("n");
        n.set_prop_bytes("reg", vec![0x00, 0x00, 0xb0, 0x10, 0x00, 0x10, 0x00, 0x00]);
        assert_eq!(n.reg_entries(), vec![(0x10b0_0000, 0x1000)]);
        // missing reg -> empty
        assert!(AdtNode::new("empty").reg_entries().is_empty());
        // len % 8 != 0 -> unparsable reg ignored
        let mut odd = AdtNode::new("odd");
        odd.set_prop_bytes("reg", vec![0; 12]);
        assert!(odd.reg_entries().is_empty());
    }

    #[test]
    fn set_builders_upsert_and_chain() {
        let mut n = AdtNode::new("x");
        n.set_prop_u32("a", 1).set_prop_u32("b", 2);
        n.set_prop_u32("a", 3); // replace, keeps file order
        assert_eq!(n.prop_u32("a"), Some(3));
        let order: Vec<&str> = n.props.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(order, vec!["name", "a", "b"]);
        n.set_prop_string("name", "renamed"); // upsert of the name prop
        assert_eq!(n.name, "x"); // .name field unchanged until reparse
        let reparsed = AdtNode::parse(&n.to_bytes()).unwrap();
        assert_eq!(reparsed.name, "x"); // name prop wins on parse
    }

    #[test]
    fn corrupt_blobs_error() {
        assert!(AdtNode::parse(&[]).is_err());
        assert!(AdtNode::parse(&[0x01, 0x00, 0x00, 0x00]).is_err());
        // nprops = 1 but no prop header follows
        let bad = 1u32.to_le_bytes().chain(0u32.to_le_bytes()).collect::<Vec<u8>>();
        assert!(AdtNode::parse(&bad).is_err());
        // len lies past the end of the buffer
        let mut bad2 = Vec::new();
        bad2.extend_from_slice(&1u32.to_le_bytes());
        bad2.extend_from_slice(&0u32.to_le_bytes());
        bad2.extend_from_slice(b"reg\0");
        bad2.resize(32, 0);
        bad2.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        assert!(AdtNode::parse(&bad2).is_err());
    }
}
