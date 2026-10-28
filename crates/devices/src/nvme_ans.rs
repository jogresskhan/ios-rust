//! ANS2/NVMe storage — port shape of `hw/block/apple-silicon/ans.c`.
//! The restore lane's ramdisk+rootfs go through this controller (admin queues
//! + RTT entries; Apple NVM Express command format). Queue-pair skeleton here;
//! full command path = ledger item.

use crate::bus::{MMIODevice, W4};
use qemu_util::iov::{iov_from_buf, iov_make, IoVec};

#[derive(Debug, Default)]
pub struct AnsNvme {
    pub admin_sq: Vec<[u8; 64]>, // 64B NVMe commands
    pub iocsq: Vec<[u8; 64]>,
    rtt_base: u64,
    pub submitted: u64,
}

impl AnsNvme {
    pub fn submit_admin(&mut self, cmd: [u8; 64]) {
        self.admin_sq.push(cmd);
        self.submitted += 1;
    }

    /// Scatter the response into the DART-translated PRP list (structural).
    pub fn complete_into(&self, prp_regions: &mut [u8], data: &[u8]) -> usize {
        let iovs: Vec<IoVec> = iov_make(prp_regions.len(), 4096);
        iov_from_buf(&iovs, prp_regions, 0, data)
    }
}

impl MMIODevice for AnsNvme {
    fn name(&self) -> &'static str {
        "apple-ans2-nvme"
    }
    fn size(&self) -> u64 {
        0x10_000
    }
    fn read(&mut self, offset: u64, _width: u32) -> u64 {
        match offset {
            0x0 => 1, // CAP: version
            _ => 0,
        }
    }
    fn write(&mut self, offset: u64, value: u64, _width: u32) {
        match offset {
            0x100 => self.rtt_base = value, // RTT region base (structural)
            _ => {}
        }
    }
}

pub const PARITY_PCT: u8 = 25; // queue skeleton; Apple command format port pending

impl crate::bus::Device for AnsNvme {
    fn mmio(&mut self) -> &mut dyn MMIODevice {
        self
    }
    fn parity_pct(&self) -> u8 {
        PARITY_PCT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scatter_completion() {
        let ans = AnsNvme::default();
        let mut regions = [0u8; 10];
        let n = ans.complete_into(&mut regions, &[0xAA; 4]);
        assert_eq!(n, 4);
        assert_eq!(&regions[..4], &[0xAA; 4]);
    }
}
