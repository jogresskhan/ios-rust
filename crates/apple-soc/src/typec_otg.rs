//! typec_otg — Apple Type-C / OTG (ATC) USB subsystem.
//!
//! Port of ChefKiss Inferno `hw/usb/apple_typec.c` + `hw/usb/apple_otg.c`
//! (AGPL-3.0): the ATC container layout (PHY regs @0x0, DWC3 core @0x10000,
//! config regs @0x20000, DWC2 core @0x100000) with the byte-accurate
//! passthrough register files and the two power-on defaults (pipe ready,
//! OTG cable connected), the AUSB OTG USB2.0 PHY register map (CTL/
//! OTGSIG/CFG0/CFG1/BATCTL/TEST) plus the widget QOS/cache/addr registers
//! incl. the OTG_ADDR high-address latch, and the Roswell CP-auth
//! command/response coprocessor (delegated to [`crate::roswell`], the
//! dedicated port of `hw/misc/apple-silicon/roswell.c`).
//!
//! The pre-port session state machine ([`UsbSession`], `plug`,
//! OTG_CTRL/OTG_STS/TYPEC_CC_STS offsets) is kept for backward
//! compatibility; usbmux host framing lives outside the device.

use crate::roswell::AppleRoswell;
use vm_core::Device;

// ---------------------------------------------------------------------------
// ATC container (apple_typec.c)
// ---------------------------------------------------------------------------
pub const ATC_USB_MMIO_SIZE: u64 = 0x200000;
pub const ATC_PHY_BASE: u64 = 0x0000; // phy_reg[0x100]
pub const ATC_DWC3_BASE: u64 = 0x10000; // DWC3 (xHCI) core
pub const ATC_CONFIG_BASE: u64 = 0x20000; // config_reg[0x4000]
pub const ATC_DWC2_BASE: u64 = 0x100000; // DWC2 (OTG) core

pub const ATC_CONFIG_PIPE_READY_OFF: u64 = 0x20;
pub const ATC_CONFIG_PIPE_READY: u32 = 0x4000_0000;
pub const ATC_PHY_OTG_CABLE_CONNECTED_OFF: u64 = 0x64;
pub const ATC_PHY_OTG_CABLE_CONNECTED: u32 = 1 << 16;

// ---------------------------------------------------------------------------
// AUSB OTG (apple_otg.c): USB2.0 PHY + widget registers
// ---------------------------------------------------------------------------
pub const REG_AUSB_USB20PHY_CTL: u64 = 0x00;
pub const REG_AUSB_USB20PHY_OTGSIG: u64 = 0x04;
pub const AUSB_OTGSIG_CABLE_CONNECTED: u32 = 1 << 8;
pub const REG_AUSB_USB20PHY_CFG0: u64 = 0x08;
pub const REG_AUSB_USB20PHY_CFG1: u64 = 0x0C;
pub const REG_AUSB_USB20PHY_BATCTL: u64 = 0x10;
pub const REG_AUSB_USB20PHY_TEST: u64 = 0x1C;

pub const REG_AUSB_WIDGET_OTG_QOS: u64 = 0x14;
pub const REG_AUSB_WIDGET_OTG_CACHE: u64 = 0x18;
pub const REG_AUSB_WIDGET_OTG_ADDR: u64 = 0x1C;
pub const REG_AUSB_WIDGET_EHCI0_QOS: u64 = 0x34;
pub const REG_AUSB_WIDGET_EHCI0_CACHE: u64 = 0x38;
pub const REG_AUSB_WIDGET_EHCI0_ADDR: u64 = 0x3C;
pub const REG_AUSB_WIDGET_OHCI0_QOS: u64 = 0x54;
pub const REG_AUSB_WIDGET_OHCI0_CACHE: u64 = 0x58;
pub const REG_AUSB_WIDGET_OHCI0_ADDR: u64 = 0x5C;
pub const REG_AUSB_WIDGET_EHCI1_QOS: u64 = 0x74;
pub const REG_AUSB_WIDGET_EHCI1_CACHE: u64 = 0x78;
pub const REG_AUSB_WIDGET_EHCI1_ADDR: u64 = 0x7C;
pub const WIDGET_ADDR_HIGH_EN: u32 = 1 << 8;

// ---------------------------------------------------------------------------
// Legacy synthetic surface (pre-port; kept for compat)
// ---------------------------------------------------------------------------
pub const OTG_CTRL: u64 = 0x0000; // == REG_AUSB_USB20PHY_CTL
pub const OTG_STS: u64 = 0x0004; // == REG_AUSB_USB20PHY_OTGSIG
pub const DWC3_GUSBPAR: u64 = 0x0C2C0 >> 0; // DWC3 global USB phy reg window
pub const TYPEC_CC_STS: u64 = 0x0100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbSession {
    Disconnected,
    Attached,
    Powered,
    Configured,
}

pub struct TypecOtg {
    // legacy session surface
    pub session: UsbSession,
    pub vbus: bool,
    pub cc_polarity: u32,
    pub resets: u64,
    pub unknown_reads: u64,

    // upstream state
    /// ATC PHY register file (0x100 bytes, byte-accurate passthrough)
    pub phy_reg: [u8; 0x100],
    /// ATC config register file (0x4000 bytes, passthrough)
    pub config_reg: [u8; 0x4000],
    /// AUSB OTG USB2.0 PHY file (0x20 bytes)
    pub otg_phy_reg: [u8; 0x20],
    /// AUSB usbctl file (0x1000 bytes)
    pub usbctl_reg: [u8; 0x1000],
    /// AUSB widget file (0x100 bytes)
    pub widget_reg: [u8; 0x100],
    /// non-DART high-address latch from WIDGET_OTG_ADDR
    pub dma_high_addr: u64,
    /// Roswell CP-auth coprocessor on the sidecar I2C bus
    pub cp_auth: AppleRoswell,
    pub cp_auth_bytes: u64,
    pub unknown_writes: u64,
}

fn rd_bytes(buf: &[u8], off: usize, size: u8) -> u64 {
    let n = (size as usize).min(8).max(1);
    let end = (off + n).min(buf.len());
    let mut v = 0u64;
    for (i, b) in buf[off..end].iter().enumerate() {
        v |= (*b as u64) << (i * 8);
    }
    v
}

fn wr_bytes(buf: &mut [u8], off: usize, size: u8, val: u64) {
    let n = (size as usize).min(8).max(1);
    for i in 0..n {
        if off + i < buf.len() {
            buf[off + i] = (val >> (i * 8)) as u8;
        }
    }
}

impl TypecOtg {
    pub fn new() -> Self {
        let mut t = TypecOtg {
            session: UsbSession::Disconnected,
            vbus: false,
            cc_polarity: 0,
            resets: 0,
            unknown_reads: 0,
            phy_reg: [0; 0x100],
            config_reg: [0; 0x4000],
            otg_phy_reg: [0; 0x20],
            usbctl_reg: [0; 0x1000],
            widget_reg: [0; 0x100],
            dma_high_addr: 0,
            cp_auth: AppleRoswell::new(),
            cp_auth_bytes: 0,
            unknown_writes: 0,
        };
        // apple_typec_init power-on defaults
        let pipe = ATC_CONFIG_PIPE_READY as u32;
        t.config_reg[ATC_CONFIG_PIPE_READY_OFF as usize..ATC_CONFIG_PIPE_READY_OFF as usize + 4]
            .copy_from_slice(&pipe.to_le_bytes());
        let cable = ATC_PHY_OTG_CABLE_CONNECTED as u32;
        t.phy_reg[ATC_PHY_OTG_CABLE_CONNECTED_OFF as usize
            ..ATC_PHY_OTG_CABLE_CONNECTED_OFF as usize + 4]
            .copy_from_slice(&cable.to_le_bytes());
        // apple_otg_from_node: OTGSIG bit8 = cable connected
        let sig = AUSB_OTGSIG_CABLE_CONNECTED as u32;
        t.otg_phy_reg[REG_AUSB_USB20PHY_OTGSIG as usize
            ..REG_AUSB_USB20PHY_OTGSIG as usize + 4]
            .copy_from_slice(&sig.to_le_bytes());
        t
    }

    /// Host cable events.
    pub fn plug(&mut self, vbus: bool) {
        self.vbus = vbus;
        self.session = if vbus { UsbSession::Powered } else { UsbSession::Attached };
    }

    /// Roswell CP-auth command byte (returns 0 ok / -1 unknown / 0 busy,
    /// exactly `apple_roswell_tx`).
    pub fn cp_auth_tx(&mut self, data: u8) -> i32 {
        self.cp_auth_bytes += 1;
        self.cp_auth.i2c_tx(data)
    }

    /// Roswell CP-auth response byte pop (`apple_roswell_rx`).
    pub fn cp_auth_rx(&mut self) -> u8 {
        self.cp_auth_bytes += 1;
        self.cp_auth.i2c_rx()
    }

    /// `apple_otg` widget write incl. the OTG_ADDR high-address latch that
    /// re-bases non-DART DMA.
    pub fn widget_write(&mut self, addr: u64, val: u32) {
        if addr == REG_AUSB_WIDGET_OTG_ADDR && val & WIDGET_ADDR_HIGH_EN != 0 {
            self.dma_high_addr = ((val & 0xF) as u64) << 32;
        }
        wr_bytes(&mut self.widget_reg, addr as usize, 4, val as u64);
    }

    pub fn regs_documented() -> &'static [(&'static str, u64)] {
        &[
            ("USB20PHY_CTL", REG_AUSB_USB20PHY_CTL),
            ("USB20PHY_OTGSIG", REG_AUSB_USB20PHY_OTGSIG),
            ("USB20PHY_CFG0", REG_AUSB_USB20PHY_CFG0),
            ("USB20PHY_CFG1", REG_AUSB_USB20PHY_CFG1),
            ("USB20PHY_BATCTL", REG_AUSB_USB20PHY_BATCTL),
            ("USB20PHY_TEST", REG_AUSB_USB20PHY_TEST),
            ("WIDGET_OTG_QOS", REG_AUSB_WIDGET_OTG_QOS),
            ("WIDGET_OTG_ADDR", REG_AUSB_WIDGET_OTG_ADDR),
            ("ATC_CONFIG", ATC_CONFIG_BASE),
            ("ATC_DWC3", ATC_DWC3_BASE),
            ("ATC_DWC2", ATC_DWC2_BASE),
            ("CC_STS", TYPEC_CC_STS),
        ]
    }
}

impl Default for TypecOtg {
    fn default() -> Self {
        Self::new()
    }
}

impl Device for TypecOtg {
    fn name(&self) -> &'static str {
        "typec-otg"
    }
    fn read(&mut self, off: u64, size: u8) -> u64 {
        match off {
            // legacy session status rides on the OTGSIG offset; upstream
            // would return the raw stored value, we OR the session bits in
            // the high byte to keep both surfaces observable
            OTG_STS => {
                let raw = rd_bytes(&self.otg_phy_reg, off as usize, size);
                let sess = match self.session {
                    UsbSession::Disconnected => 0x0u64,
                    UsbSession::Attached => 0x1,
                    UsbSession::Powered => 0x3,
                    UsbSession::Configured => 0x7,
                };
                raw | (sess << 16)
            }
            TYPEC_CC_STS => self.cc_polarity as u64 | 0x2, // cc connected
            o if o < 0x100 => rd_bytes(&self.phy_reg, o as usize, size),
            o if (ATC_CONFIG_BASE..ATC_CONFIG_BASE + 0x4000).contains(&o) => {
                rd_bytes(&self.config_reg, (o - ATC_CONFIG_BASE) as usize, size)
            }
            o if o < 0x20 => rd_bytes(&self.otg_phy_reg, o as usize, size),
            _ => {
                self.unknown_reads += 1;
                0
            }
        }
    }
    fn write(&mut self, off: u64, size: u8, val: u64) {
        match off {
            OTG_CTRL => {
                // phy passthrough + legacy reset semantics
                wr_bytes(&mut self.otg_phy_reg, off as usize, size, val);
                if val & 1 == 1 {
                    self.resets += 1;
                    self.session = UsbSession::Disconnected;
                }
            }
            TYPEC_CC_STS => self.cc_polarity = (val & 0x3) as u32,
            o if o < 0x100 => wr_bytes(&mut self.phy_reg, o as usize, size, val),
            o if (ATC_CONFIG_BASE..ATC_CONFIG_BASE + 0x4000).contains(&o) => {
                wr_bytes(&mut self.config_reg, (o - ATC_CONFIG_BASE) as usize, size, val)
            }
            o if o < 0x20 => wr_bytes(&mut self.otg_phy_reg, o as usize, size, val),
            _ => {
                self.unknown_writes += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atc_power_on_defaults_and_passthrough() {
        let mut t = TypecOtg::new();
        // config+0x20 = pipe ready
        let cfg = t.read(ATC_CONFIG_BASE + ATC_CONFIG_PIPE_READY_OFF, 4) as u32;
        assert_eq!(cfg & ATC_CONFIG_PIPE_READY, ATC_CONFIG_PIPE_READY);
        // phy+0x64 = OTG cable connected
        let phy = t.read(ATC_PHY_OTG_CABLE_CONNECTED_OFF, 4) as u32;
        assert_eq!(phy & ATC_PHY_OTG_CABLE_CONNECTED, ATC_PHY_OTG_CABLE_CONNECTED);
        // byte-accurate passthrough: partial dwords survive round trips
        t.write(0x10, 2, 0xBEEF);
        assert_eq!(t.read(0x10, 2), 0xBEEF);
        t.write(0x30, 1, 0x5A);
        assert_eq!(t.read(0x30, 1), 0x5A);
        // config region accepts arbitrary writes
        t.write(ATC_CONFIG_BASE + 0x100, 4, 0x1234_5678);
        assert_eq!(t.read(ATC_CONFIG_BASE + 0x100, 4), 0x1234_5678);
        // DWC2/DWC3 core windows are NOT handled by this device (census)
        let before = t.unknown_reads;
        assert_eq!(t.read(ATC_DWC3_BASE, 4), 0);
        assert_eq!(t.unknown_reads, before + 1);
    }

    #[test]
    fn otg_phy_regs_and_widget_high_addr() {
        let mut t = TypecOtg::new();
        // OTGSIG default: cable connected (bit 8), with session bits OR'd
        let sig = t.read(REG_AUSB_USB20PHY_OTGSIG, 4) as u32;
        assert_eq!(sig & AUSB_OTGSIG_CABLE_CONNECTED, AUSB_OTGSIG_CABLE_CONNECTED);
        // plug host cable → session powered
        t.plug(true);
        assert_eq!(t.session, UsbSession::Powered);
        // USB20PHY_CTL write + legacy reset counter
        t.write(REG_AUSB_USB20PHY_CTL, 4, 0x1);
        assert_eq!(t.resets, 1);
        assert_eq!(t.session, UsbSession::Disconnected);
        // widget registers store; OTG_ADDR latches the high address
        t.widget_write(REG_AUSB_WIDGET_OTG_QOS, 0x2);
        assert_eq!(rd_bytes(&t.widget_reg, REG_AUSB_WIDGET_OTG_QOS as usize, 4), 0x2);
        t.widget_write(REG_AUSB_WIDGET_OTG_ADDR, WIDGET_ADDR_HIGH_EN | 0x3);
        assert_eq!(t.dma_high_addr, 0x3 << 32);
        t.widget_write(REG_AUSB_WIDGET_OTG_ADDR, 0x1); // no EN bit: no latch
        assert_eq!(t.dma_high_addr, 0x3 << 32);
        // EHCI/OHCI widget windows exist as constants per apple_otg.c
        assert_eq!(REG_AUSB_WIDGET_EHCI0_ADDR, 0x3C);
        assert_eq!(REG_AUSB_WIDGET_OHCI0_ADDR, 0x5C);
        assert_eq!(REG_AUSB_WIDGET_EHCI1_ADDR, 0x7C);
    }

    #[test]
    fn roswell_cp_auth_device_info_and_idsn() {
        let mut t = TypecOtg::new();
        // GET_DEVICE_INFO: 8 bytes — versions + 0xDEADBEEF device id
        assert_eq!(t.cp_auth_tx(0x00), 0);
        let mut got = Vec::new();
        for _ in 0..8 {
            got.push(t.cp_auth_rx());
        }
        assert_eq!(got, vec![0x0, 0x0, 0x2, 0x0, 0xDE, 0xAD, 0xBE, 0xEF]);
        // response exhausted → command auto-resets (upstream behavior)
        assert_eq!(t.cp_auth_rx(), 0x00);
        // EXTENDED = GET_IDSN: 9 zeros + 0xE3 ack + "CKRosw"
        assert_eq!(t.cp_auth_tx(0x60), 0);
        let mut idsn = Vec::new();
        for _ in 0..16 {
            idsn.push(t.cp_auth_rx());
        }
        assert!(idsn[..9].iter().all(|&b| b == 0));
        assert_eq!(idsn[9], 0xE3);
        assert_eq!(&idsn[10..16], b"CKRosw");
        // unknown command byte is rejected
        assert_eq!(t.cp_auth_tx(0x77), -1);
        assert!(t.cp_auth_bytes > 0);
    }
}
