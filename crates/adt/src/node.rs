//! ADT node tree — parse + build + query (path find, reg entries,
//! compatible strings). This is the hardware-discovery backbone: the
//! T8030 machine attaches devices by walking `/arm-io` children.

use super::{prop::AdtProp, END_MAGIC, NODE_MAGIC, PROP_MAGIC};

#[derive(Debug, Clone, Default, PartialEq)]
pub struct AdtNode {
    pub name: String,
    pub props: Vec<AdtProp>,
    pub children: Vec<AdtNode>,
}

fn dt_name(buf: &[u8], off: usize) -> String {
    let end = (off + 32).min(buf.len());
    let raw = &buf[off..end];
    let s = std::str::from_utf8(raw).unwrap_or("");
    s.trim_end_matches('\0').trim().to_string()
}

fn be32(buf: &[u8], off: usize) -> Option<u32> {
    if off + 4 > buf.len() {
        return None;
    }
    Some(u32::from_be_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]))
}

impl AdtNode {
    /// Parse one node at `off`; returns (node, offset after END magic).
    fn parse_at(buf: &[u8], off: usize) -> Result<(AdtNode, usize), String> {
        if off + 8 > buf.len() {
            return Err("adt: truncated node header".into());
        }
        if &buf[off..off + 4] != NODE_MAGIC {
            return Err(format!("adt: bad node magic at 0x{off:x}"));
        }
        let _total_len = be32(buf, off + 4).ok_or("adt: no node len")?;
        let mut node = AdtNode::default();
        // name: 8-byte NUL-padded field right after the header
        node.name = dt_name(buf, off + 8);
        let mut p = off + 40;
        loop {
            if p + 4 > buf.len() {
                return Err("adt: truncated node body".into());
            }
            let magic = &buf[p..p + 4];
            if magic == END_MAGIC {
                return Ok((node, p + 4));
            } else if magic == NODE_MAGIC {
                // Child nodes appear inline without PROP wrapper in some
                // generators; support both layouts.
                let (child, next) = Self::parse_at(buf, p)?;
                node.children.push(child);
                p = next;
            } else if magic == PROP_MAGIC {
                let plen = be32(buf, p + 4).ok_or("adt: no prop len")?;
                let name = dt_name(buf, p + 8);
                let voff = p + 40;
                let vend = voff + plen as usize;
                if vend > buf.len() {
                    return Err("adt: prop overruns buffer".into());
                }
                node.props.push(AdtProp {
                    name,
                    data: buf[voff..vend].to_vec(),
                });
                // 4-byte alignment
                p = (vend + 3) & !3;
            } else {
                return Err(format!("adt: unknown magic 0x{} at 0x{p:x}", hex_str(magic)));
            }
        }
    }

    pub fn parse(buf: &[u8]) -> Result<AdtNode, String> {
        Self::parse_at(buf, 0).map(|(n, _)| n)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write_into(&mut out);
        out
    }

    fn write_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(NODE_MAGIC);
        out.extend_from_slice(&0u32.to_be_bytes()); // patched below
        let len_mark = out.len() - 4;
        let mut name = [0u8; 32];
        for (i, b) in self.name.as_bytes().iter().take(32).enumerate() {
            name[i] = *b;
        }
        out.extend_from_slice(&name);
        for prop in &self.props {
            out.extend_from_slice(PROP_MAGIC);
            out.extend_from_slice(&(prop.data.len() as u32).to_be_bytes());
            let mut name = [0u8; 32];
            for (i, b) in prop.name.as_bytes().iter().take(32).enumerate() {
                name[i] = *b;
            }
            out.extend_from_slice(&name);
            out.extend_from_slice(&prop.data);
            while out.len() % 4 != 0 {
                out.push(0);
            }
        }
        for child in &self.children {
            child.write_into(out);
        }
        out.extend_from_slice(END_MAGIC);
        let total = (out.len() - len_mark - 4) as u32 + 4;
        out[len_mark..len_mark + 4].copy_from_slice(&total.to_be_bytes());
    }

    pub fn find(&self, path: &str) -> Option<&AdtNode> {
        let path = path.trim_start_matches('/');
        match path.split_once('/') {
            None => self.child(path),
            Some((seg, rest)) => self.child(seg).and_then(|c| c.find(rest)),
        }
    }

    pub fn child(&self, name: &str) -> Option<&AdtNode> {
        self.children.iter().find(|c| c.name == name)
    }

    pub fn prop(&self, name: &str) -> Option<&AdtProp> {
        self.props.iter().find(|p| p.name == name)
    }

    pub fn prop_bytes(&self, name: &str) -> Option<&[u8]> {
        self.prop(name).map(|p| p.data.as_slice())
    }

    pub fn prop_string(&self, name: &str) -> Option<String> {
        self.prop(name)?.as_string()
    }

    pub fn prop_u32(&self, name: &str) -> Option<u32> {
        self.prop(name)?.as_u32()
    }

    pub fn prop_u64(&self, name: &str) -> Option<u64> {
        self.prop(name)?.as_u64()
    }

    /// Parse `reg` into (addr, size) pairs. arm-io children on Apple SoCs
    /// use address-cells=1 size-cells=1 with u64 entries; tolerate u32.
    pub fn reg_entries(&self) -> Vec<(u64, u64)> {
        let Some(data) = self.prop_bytes("reg") else {
            return Vec::new();
        };
        let mut out = Vec::new();
        let all_u32 = data.len() % 8 != 0
            || data
                .chunks_exact(8)
                .any(|c| u64::from_be_bytes(c.try_into().unwrap()) > 0x4_0000_0000);
        if all_u32 {
            for c in data.chunks_exact(8) {
                let a = u32::from_be_bytes(c[0..4].try_into().unwrap()) as u64;
                let s = u32::from_be_bytes(c[4..8].try_into().unwrap()) as u64;
                out.push((a, s));
            }
        } else {
            for c in data.chunks_exact(16) {
                let a = u64::from_be_bytes(c[0..8].try_into().unwrap());
                let s = u64::from_be_bytes(c[8..16].try_into().unwrap());
                out.push((a, s));
            }
        }
        out
    }

    /// `compatible` = NUL-terminated string blob (4-byte padded).
    pub fn compatible(&self) -> Vec<String> {
        let Some(data) = self.prop_bytes("compatible") else {
            return Vec::new();
        };
        data.split(|&b| b == 0)
            .filter(|s| !s.is_empty())
            .filter_map(|s| std::str::from_utf8(s).ok().map(|s| s.to_string()))
            .collect()
    }

    // ---- builder side (bootargs / synthesized trees) ----

    pub fn set_prop_bytes(&mut self, name: &str, data: Vec<u8>) {
        match self.props.iter_mut().find(|p| p.name == name) {
            Some(p) => p.data = data,
            None => self.props.push(AdtProp { name: name.to_string(), data }),
        }
    }

    pub fn set_prop_string(&mut self, name: &str, val: &str) {
        let mut v = val.as_bytes().to_vec();
        v.push(0);
        self.set_prop_bytes(name, v);
    }

    pub fn set_prop_u32(&mut self, name: &str, val: u32) {
        self.set_prop_bytes(name, 1u32.to_be_bytes().to_vec().into_iter().chain(val.to_be_bytes()).collect());
    }

    pub fn set_prop_u64(&mut self, name: &str, val: u64) {
        self.set_prop_bytes(name, 2u32.to_be_bytes().to_vec().into_iter().chain(val.to_be_bytes()).collect());
    }
}

fn hex_str(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_tree() -> Vec<u8> {
        let mut root = AdtNode::default();
        root.name = "devtree".into();
        root.set_prop_string("target-type", "T8030");
        let mut armio = AdtNode { name: "arm-io".into(), ..Default::default() };
        armio.set_prop_string("compatible", "arm-io,t8030\0arm-io\0");
        let mut aic = AdtNode { name: "aic".into(), ..Default::default() };
        aic.set_prop_string("compatible", "aic,1\0ARM,aic\0");
        let mut reg = Vec::new();
        reg.extend_from_slice(&0x23B100000u64.to_be_bytes());
        reg.extend_from_slice(&0x8000u64.to_be_bytes());
        aic.set_prop_bytes("reg", reg);
        armio.children.push(aic);
        root.children.push(armio);
        root.to_bytes()
    }

    #[test]
    fn roundtrip_parse_find() {
        let buf = sample_tree();
        let root = AdtNode::parse(&buf).expect("parse");
        assert_eq!(root.name, "devtree");
        let soc = root.find("arm-io").expect("arm-io");
        assert!(soc.compatible().iter().any(|c| c.contains("t8030")));
        let aic = soc.child("aic").expect("aic");
        let reg = aic.reg_entries();
        assert_eq!(reg[0].0, 0x23B100000);
        assert_eq!(reg[0].1, 0x8000);
        // re-serialize parses identically
        let root2 = AdtNode::parse(&root.to_bytes()).expect("reparse");
        assert_eq!(root.find("arm-io/aic").unwrap().reg_entries(), root2.find("arm-io/aic").unwrap().reg_entries());
    }
}
