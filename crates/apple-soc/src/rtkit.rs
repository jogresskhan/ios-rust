//! rtkit — Apple RTKit IOP protocol (port of hw/misc/apple-silicon/
//! a7iop + Asahi m1n1 rtkit semantics used by ANS/AOP). Endpoint-mapped
//! message rings: MGMT (boot, syslog, crash, io-report) + device EPs.

use vm_core::Device;

pub const RTKIT_MGMT_EP: u32 = 2;
pub const RTKIT_SYSLOG_EP: u32 = 1;
pub const RTKIT_IO_REPORT_EP: u32 = 4;
pub const RTKIT_CRASH_EP: u32 = 3;

pub const MGMT_MSG_BOOT: u64 = 0x8 << 56;
pub const MGMT_MSG_HELLO: u64 = 0x1 << 56;
pub const MGMT_MSG_HELLO_ACK: u64 = 0x2 << 56;
pub const MGMT_MSG_START_EP: u64 = 0xB << 56;
pub const MGMT_MSG_INIT: u64 = 0x80 << 56;

pub struct RtkitDevice {
    label: &'static str,
    pub booted: bool,
    pub started_eps: Vec<u32>,
    /// EP → queued messages (ring buffer, 0x100 msgs)
    pub rings: std::collections::BTreeMap<u32, std::collections::VecDeque<u64>>,
    pub unknown_reads: u64,
}

impl RtkitDevice {
    pub fn new(label: &'static str) -> Self {
        RtkitDevice {
            label,
            booted: false,
            started_eps: Vec::new(),
            rings: std::collections::BTreeMap::new(),
            unknown_reads: 0,
        }
    }

    /// Co-processor receives a message from the application core.
    pub fn send(&mut self, ep: u32, msg: u64) {
        if msg == MGMT_MSG_BOOT {
            self.booted = true;
            // hello handshake, like the real firmware
            let r = self.rings.entry(RTKIT_MGMT_EP).or_default();
            r.push_back(MGMT_MSG_HELLO);
            return;
        }
        if msg == MGMT_MSG_HELLO_ACK {
            let r = self.rings.entry(RTKIT_MGMT_EP).or_default();
            r.push_back(MGMT_MSG_INIT | 0x20); // version 0x20
            return;
        }
        if msg >> 56 == 0xB {
            self.started_eps.push((msg & 0xFF) as u32);
        }
        let r = self.rings.entry(ep).or_default();
        if r.len() < 0x100 {
            r.push_back(msg);
        }
    }

    /// Application core polls for a message from the co-processor.
    pub fn recv(&mut self, ep: u32) -> Option<u64> {
        self.rings.get_mut(&ep)?.pop_front()
    }

    pub fn regs_documented() -> &'static [(&'static str, u64)] {
        &[("MGMT_EP", RTKIT_MGMT_EP as u64), ("MAILBOX", 0x1000)]
    }
}

impl Device for RtkitDevice {
    fn name(&self) -> &'static str {
        self.label
    }
    fn read(&mut self, off: u64, _size: u8) -> u64 {
        match off {
            0x0000 => self.booted as u64,
            _ => {
                self.unknown_reads += 1;
                0
            }
        }
    }
    fn write(&mut self, off: u64, _size: u8, val: u64) {
        match off {
            // mailbox send: ep in [39:32], msg in low 56
            0x1000 => {
                let ep = ((val >> 32) & 0xFF) as u32;
                self.send(ep, val & 0x00FF_FFFF_FFFF_FFFF);
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn boot_handshake() {
        let mut r = RtkitDevice::new("rtkit-ans");
        r.send(RTKIT_MGMT_EP, MGMT_MSG_BOOT);
        assert!(r.booted);
        assert_eq!(r.recv(RTKIT_MGMT_EP), Some(MGMT_MSG_HELLO));
        r.send(RTKIT_MGMT_EP, MGMT_MSG_HELLO_ACK);
        assert_eq!(r.recv(RTKIT_MGMT_EP).unwrap() >> 56, 0x80);
    }
}
