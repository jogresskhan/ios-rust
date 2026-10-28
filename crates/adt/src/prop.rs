//! ADT property — Apple DeviceTree "property" record.
//!
//! Wire format (ChefKiss Inferno `hw/arm/apple-silicon/dt.c`,
//! `APPLE_DT_PROP_NAME_LEN = 32`, `APPLE_DT_PROP_PLACEHOLDER = 1 << 31`):
//!
//! ```text
//! char   name[32];   // NUL-padded, max 31 chars + NUL
//! u32    len;        // LE; bit31 = placeholder hint (Inferno), masked off here
//! u8     data[len];  // padded up to a 4-byte boundary with zeros
//! ```
//!
//! Integers inside property payloads are **little-endian** (Inferno
//! `apple_dt_set_prop_u32` stores `cpu_to_le32`, and the guest is LE).

/// An Apple DeviceTree property: a (up to 32-byte) name and raw payload.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AdtProp {
    /// Property name, e.g. `"reg"`, `"compatible"`, `"name"`.
    pub name: String,
    /// Raw payload bytes (already unpadded; padding is re-added on serialise).
    pub data: Vec<u8>,
}

/// NUL-terminated byte string (`mkadt.rs cstr()` / Inferno
/// `apple_dt_set_prop_str` semantics: `strlen(val) + 1` bytes).
pub fn cstr(s: &str) -> Vec<u8> {
    let mut v = s.as_bytes().to_vec();
    v.push(0);
    v
}

/// Decode a NUL-terminated payload into a `String` (lossy UTF-8, single
/// trailing NUL trimmed). Returns the input unchanged when it does not end
/// in a NUL byte.
pub fn cstr_lossy(data: &[u8]) -> String {
    let end = if data.last() == Some(&0) { data.len() - 1 } else { data.len() };
    String::from_utf8_lossy(&data[..end]).into_owned()
}

impl AdtProp {
    /// Raw bytes property.
    pub fn new(name: impl Into<String>, data: Vec<u8>) -> Self {
        AdtProp { name: name.into(), data }
    }

    /// NUL-terminated string property (Inferno `apple_dt_set_prop_str`).
    pub fn with_string(name: impl Into<String>, value: &str) -> Self {
        AdtProp { name: name.into(), data: cstr(value) }
    }

    /// Little-endian `u32` property (Inferno `apple_dt_set_prop_u32`).
    pub fn with_u32(name: impl Into<String>, value: u32) -> Self {
        AdtProp { name: name.into(), data: value.to_le_bytes().to_vec() }
    }

    /// Little-endian `u64` property (Inferno `apple_dt_set_prop_u64`).
    pub fn with_u64(name: impl Into<String>, value: u64) -> Self {
        AdtProp { name: name.into(), data: value.to_le_bytes().to_vec() }
    }

    /// Payload length in bytes (the value stored in the wire `len` field).
    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Payload interpreted as a NUL-terminated string.
    pub fn as_string(&self) -> String {
        cstr_lossy(&self.data)
    }

    /// First 4 payload bytes as little-endian `u32` (None when short).
    pub fn as_u32(&self) -> Option<u32> {
        if self.data.len() < 4 {
            return None;
        }
        Some(u32::from_le_bytes(self.data[..4].try_into().unwrap()))
    }

    /// First 8 payload bytes as little-endian `u64` (None when short).
    pub fn as_u64(&self) -> Option<u64> {
        if self.data.len() < 8 {
            return None;
        }
        Some(u64::from_le_bytes(self.data[..8].try_into().unwrap()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_constructors_are_le_and_cstr() {
        let p32 = AdtProp::with_u32("chip-id", 0x8110);
        assert_eq!(p32.data, [0x10, 0x81, 0x00, 0x00]);
        assert_eq!(p32.as_u32(), Some(0x8110));

        let p64 = AdtProp::with_u64("reg", 0x0100_0000);
        assert_eq!(p64.data.len(), 8);
        assert_eq!(p64.as_u64(), Some(0x0100_0000));
        assert_eq!(p32.as_u64(), None); // too short

        let ps = AdtProp::with_string("name", "uart0");
        assert_eq!(ps.data, b"uart0\0".to_vec());
        assert_eq!(ps.as_string(), "uart0");
    }

    #[test]
    fn cstr_lossy_trims_single_nul() {
        assert_eq!(cstr_lossy(b"abc\0"), "abc");
        assert_eq!(cstr_lossy(b"ab\0cd\0"), "ab\0cd"); // only trailing NUL trimmed
        assert_eq!(cstr_lossy(b"abc"), "abc"); // unterminated passes through
        assert_eq!(cstr_lossy(b""), "");
    }
}
