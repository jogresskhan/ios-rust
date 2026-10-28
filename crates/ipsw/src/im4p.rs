//! IM4P container parsing (Apple image personalization payload).
//! Format: magic "IM4P" | type[4] | desc[16] | data_len(u32 BE) | data
//! The lane's toolkit handles full IMG4 (IM4M signatures); the emulator path
//! needs the payload container — implemented here for rdsk/krnl types.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Im4p {
    pub fourcc_type: [u8; 4],
    pub description: [u8; 16],
    pub data: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum Im4pError {
    #[error("bad magic (want IM4P, got {0:?})")]
    BadMagic([u8; 4]),
    #[error("truncated at {0}")]
    Truncated(usize),
    #[error("declared length {declared} exceeds buffer {have}")]
    LengthMismatch { declared: usize, have: usize },
}

impl Im4p {
    pub fn parse(buf: &[u8]) -> Result<Self, Im4pError> {
        if buf.len() < 28 {
            return Err(Im4pError::Truncated(buf.len()));
        }
        let mut magic = [0u8; 4];
        magic.copy_from_slice(&buf[0..4]);
        if &magic != b"IM4P" {
            return Err(Im4pError::BadMagic(magic));
        }
        let mut fourcc = [0u8; 4];
        fourcc.copy_from_slice(&buf[4..8]);
        let mut desc = [0u8; 16];
        desc.copy_from_slice(&buf[8..24]);
        let declared = u32::from_be_bytes(buf[24..28].try_into().unwrap()) as usize;
        if 28 + declared > buf.len() {
            return Err(Im4pError::LengthMismatch { declared, have: buf.len() });
        }
        Ok(Self { fourcc_type: fourcc, description: desc, data: buf[28..28 + declared].to_vec() })
    }

    pub fn build(fourcc: &[u8; 4], desc: &[u8], data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(28 + data.len());
        out.extend_from_slice(b"IM4P");
        out.extend_from_slice(fourcc);
        let mut d = [0u8; 16];
        d[..desc.len().min(16)].copy_from_slice(&desc[..desc.len().min(16)]);
        out.extend_from_slice(&d);
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(data);
        out
    }

    /// Is this a ramdisk payload? (rdsk / rdsk-adjacent types)
    pub fn is_ramdisk(&self) -> bool {
        &self.fourcc_type == b"rdsk"
    }

    pub fn is_kernel(&self) -> bool {
        &self.fourcc_type == b"krnl" || &self.fourcc_type == b"krnm"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let payload = b"hello-ramdisk";
        let raw = Im4p::build(b"rdsk", b"v0-stock", payload);
        let parsed = Im4p::parse(&raw).unwrap();
        assert!(parsed.is_ramdisk());
        assert_eq!(parsed.data, payload);
        assert_eq!(&parsed.description[..9], b"v0-stock\0");
    }

    #[test]
    fn rejects_garbage() {
        assert!(Im4p::parse(b"NOPE_junk_junk_junk_junk_junk").is_err());
        assert!(Im4p::parse(b"IM4P_short").is_err());
        let mut raw = Im4p::build(b"rdsk", b"t", b"abc");
        raw[24] = 0xFF; // declared len lie
        assert!(matches!(
            Im4p::parse(&raw),
            Err(Im4pError::LengthMismatch { .. })
        ));
    }
}
