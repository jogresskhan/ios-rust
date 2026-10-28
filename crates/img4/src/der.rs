//! Minimal DER encode/decode for IMG4.
#[derive(Debug, Clone, Default)]
pub struct DerItem {
    pub tag: u8,
    pub value: Vec<u8>,
}
