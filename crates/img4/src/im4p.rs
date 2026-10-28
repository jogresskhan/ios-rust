//! IM4P payload container (magic b'IM4P').
pub const IM4P_MAGIC: &[u8; 4] = b"IM4P";

#[derive(Debug, Clone, Default)]
pub struct Im4p {
    pub fourcc: String,
    pub version: String,
    pub data: Vec<u8>,
}
