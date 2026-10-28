//! adt — Apple DeviceTree (ADT) parse + build.
//!
//! The T8030 machine walks the ADT's `/arm-io` node to discover every
//! peripheral at its real MMIO base (`reg` property) with its `compatible`
//! string — this is what makes "one IPSW" work: the hardware map comes
//! from the IPSW itself, exactly like on real hardware / XNU / Inferno.
//!
//! Binary format ported from xnu's pexpert DT + Inferno apple_dt helpers,
//! cross-checked against sweet-core mkadt.rs (MIT).

pub mod node;
pub mod prop;

pub use node::AdtNode;
pub use prop::AdtProp;

pub const NODE_MAGIC: &[u8; 4] = b"NODE";
pub const END_MAGIC: &[u8; 4] = b"END ";
pub const PROP_MAGIC: &[u8; 4] = b"PROP";
