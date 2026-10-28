//! ADT property — the 8-char fourcc name + type-tagged value system.

#[derive(Debug, Clone, PartialEq)]
pub struct AdtProp {
    pub name: String,
    pub data: Vec<u8>,
}

impl AdtProp {
    /// value type tag stored in the first u32 of the property blob:
    /// 0 = kPropTypeData, 1 = kPropTypeUInt32, 2 = kPropTypeUInt32Pair,
    /// 3 = kPropTypeString...
    pub fn type_tag(&self) -> u32 {
        if self.data.len() >= 4 {
            u32::from_be_bytes([self.data[0], self.data[1], self.data[2], self.data[3]])
        } else {
            0
        }
    }

    pub fn as_u32(&self) -> Option<u32> {
        if self.data.len() >= 8 {
            let v = &self.data[4..8];
            Some(u32::from_be_bytes([v[0], v[1], v[2], v[3]]))
        } else if self.data.len() == 4 {
            Some(u32::from_be_bytes([self.data[0], self.data[1], self.data[2], self.data[3]]))
        } else {
            None
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        if self.data.len() >= 12 {
            let v = &self.data[4..12];
            let mut a = [0u8; 8];
            a.copy_from_slice(v);
            Some(u64::from_be_bytes(a))
        } else if self.data.len() == 8 {
            let mut a = [0u8; 8];
            a.copy_from_slice(&self.data);
            Some(u64::from_be_bytes(a))
        } else {
            self.as_u32().map(|v| v as u64)
        }
    }

    pub fn as_string(&self) -> Option<String> {
        let s = std::str::from_utf8(&self.data).ok()?;
        Some(s.trim_end_matches('\0').to_string())
    }
}
