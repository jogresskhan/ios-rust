//! adt — Apple DeviceTree (ADT).
//!
//! The T8030 machine walks the ADT's `/arm-io` node to discover every
//! peripheral at its real MMIO base (`reg` property) with its `compatible`
//! string — this is what makes "one IPSW" work: the hardware map comes
//! from the IPSW itself, exactly like on real hardware / XNU / Inferno.
//!
//! Port of Inferno's apple_dt_* helpers + sweet-core mkadt builder logic.

pub mod node;
pub mod prop;

pub use node::AdtNode;
pub use prop::AdtProp;
