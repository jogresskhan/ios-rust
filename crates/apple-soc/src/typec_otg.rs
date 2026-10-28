//! typec_otg — Apple Type-C / DWC3 OTG controller (port of Inferno
//! hw/usb/apple_otg.c + apple_typec.c). Session/link state machine;
//! usbmux host framing lives outside the device.

use vm_core::Device;

pub const OTG_CTRL: u64 = 0x0000;
pub const OTG_STS: u64 = 0x0004;
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
    pub session: UsbSession,
    pub vbus: bool,
    pub cc_polarity: u32,
    pub resets: u64,
    pub unknown_reads: u64,
}

impl TypecOtg {
    pub fn new() -> Self {
        TypecOtg { session: UsbSession::Disconnected, vbus: false, cc_polarity: 0, resets: 0, unknown_reads: 0 }
    }

    /// Host cable events.
    pub fn plug(&mut self, vbus: bool) {
        self.vbus = vbus;
        self.session = if vbus { UsbSession::Powered } else { UsbSession::Attached };
    }

    pub fn regs_documented() -> &'static [(&'static str, u64)] {
        &[("CTRL", OTG_CTRL), ("STS", OTG_STS), ("GUSBPAR", DWC3_GUSBPAR), ("CC_STS", TYPEC_CC_STS)]
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
    fn read(&mut self, off: u64, _size: u8) -> u64 {
        match off {
            OTG_STS => match self.session {
                UsbSession::Disconnected => 0x0,
                UsbSession::Attached => 0x1,
                UsbSession::Powered => 0x3,
                UsbSession::Configured => 0x7,
            },
            TYPEC_CC_STS => self.cc_polarity as u64 | 0x2, // cc connected
            _ => {
                self.unknown_reads += 1;
                0
            }
        }
    }
    fn write(&mut self, off: u64, _size: u8, val: u64) {
        match off {
            OTG_CTRL => {
                if val & 1 == 1 {
                    self.resets += 1;
                    self.session = UsbSession::Disconnected;
                }
            }
            TYPEC_CC_STS => self.cc_polarity = (val & 0x3) as u32,
            _ => {}
        }
    }
}
