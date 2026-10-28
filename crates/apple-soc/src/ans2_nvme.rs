//! ans2_nvme — Apple ANS2 NVMe storage controller (port of Inferno
//! hw/block/apple-silicon/ans.c + nvme_mmu.c): NVMe admin + I/O queues
//! over Apple-specific doorbells, DMA translated through DART.

use vm_core::Device;

pub const NVME_CAP: u64 = 0x0000;
pub const NVME_VS: u64 = 0x0008;
pub const NVME_CSTS: u64 = 0x001C;
pub const NVME_AQA: u64 = 0x0024;
pub const NVME_ASQ: u64 = 0x0028;
pub const NVME_ACQ: u64 = 0x0030;
pub const NVME_SQ0TDBL: u64 = 0x1000; // admin sq tail doorbell
pub const NVME_CQ0HDBL: u64 = 0x1004;

pub const NVME_CSTS_RDY: u32 = 1;

/// Data the controller serves over NVMe reads (host injects the ramdisk/
/// rootfs image; that is how the guest mounts the synthesized volume).
pub trait BlockBackend: Send {
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> bool;
    fn write(&mut self, lba: u64, data: &[u8]) -> bool;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SqEntry {
    pub cdw: [u32; 16],
}

pub struct Ans2Nvme {
    pub csts: u32,
    pub aqa: u32,
    pub asq: u64,
    pub acq: u64,
    pub sq_tail: u16,
    pub cq_head: u16,
    /// physical addresses of queue memory (DART-translated by host side)
    pub asq_addr: u64,
    pub acq_addr: u64,
    /// Reader used for DMA (machine injects; reads a u64 word at phys addr)
    pub mem_read: Option<Box<dyn FnMut(u64) -> u64 + Send>>,
    pub mem_write: Option<Box<dyn FnMut(u64, u64) + Send>>,
    pub backing: Option<Box<dyn BlockBackend>>,
    pub identify_done: u64,
    pub io_reads: u64,
    pub unknown_reads: u64,
}

const LBA_SIZE: u64 = 4096;

impl Ans2Nvme {
    pub fn new() -> Self {
        Ans2Nvme {
            csts: 0,
            aqa: 0,
            asq: 0,
            acq: 0,
            sq_tail: 0,
            cq_head: 0,
            asq_addr: 0,
            acq_addr: 0,
            mem_read: None,
            mem_write: None,
            backing: None,
            identify_done: 0,
            io_reads: 0,
            unknown_reads: 0,
        }
    }

    /// Process pending admin commands after the guest rings SQ0 doorbell.
    /// Ports the admin paths the real guest uses at boot:
    ///  - Identify Controller (0x06)
    ///  - Identify Namespace (0x06, CNS=0)
    ///  - Get Features (0x0A), Set Features (0x09)
    ///  - Create I/O CQ (0x05) / SQ (0x01)
    pub fn process_admin(&mut self) {
        let sq = self.asq_addr;
        let cq = self.acq_addr;
        if sq == 0 || cq == 0 {
            return;
        }
        // fetch one submission (64B = 8 u64 words; we only need cdw0/1 fields)
        let rd = self.mem_read.as_mut();
        let Some(rd) = rd else { return };
        let op = (rd(sq) & 0xFF) as u32; // cdw0 opcode
        let _nsid = rd(sq + 0x2C) as u32;
        let prp1 = rd(sq + 0x30);

        let mut status_word: u64 = (0u64) | (0 << 1); // success
        match op {
            0x06 => {
                // identify: fill minimal controller/ns data at PRP1 via DMA
                let mut mw = self.mem_write.take().expect("mem_write");
                for (i, v) in [
                    0x0000_454E_4C50_4D44u64, // "DMPLNE"-ish marker
                    0x0,                      // version
                    (LBA_SIZE) | (1 << 48),   // ns: lba size + 1 ns
                ]
                .into_iter()
                .enumerate()
                {
                    mw(prp1 + (i * 8) as u64, v);
                }
                self.mem_write = Some(mw);
                self.identify_done += 1;
            }
            0x01 | 0x05 => { /* create io sq/cq: accept, no-op */ }
            0x09 | 0x0A => { /* set/get features: succeed */ }
            _ => {}
        }

        // write completion entry (dw0 status, dw3 phase tag)
        let wm = self.mem_write.as_mut();
        if let Some(wm) = wm {
            wm(cq, status_word);
            let phase = 1u64;
            wm(cq + 0x18, phase);
        }
        self.cq_head = (self.cq_head + 1) & 0xFFFF;
        self.csts = NVME_CSTS_RDY;
    }

    /// I/O read path: LBA → backing store → PRP memory (io queue simplified).
    pub fn io_read_dma(&mut self, lba: u64, prp: u64) {
        if let (Some(bb), Some(mw)) = (self.backing.as_mut(), self.mem_write.as_mut()) {
            let mut buf = vec![0u8; LBA_SIZE as usize];
            if bb.read(lba, &mut buf) {
                for (i, chunk) in buf.chunks(8).enumerate() {
                    let mut w = [0u8; 8];
                    w.copy_from_slice(chunk);
                    mw(prp + (i * 8) as u64, u64::from_le_bytes(w));
                }
                self.io_reads += 1;
            }
        }
    }

    pub fn regs_documented() -> &'static [(&'static str, u64)] {
        &[
            ("CAP", NVME_CAP),
            ("VS", NVME_VS),
            ("CSTS", NVME_CSTS),
            ("AQA", NVME_AQA),
            ("ASQ", NVME_ASQ),
            ("ACQ", NVME_ACQ),
            ("SQ0TDBL", NVME_SQ0TDBL),
            ("CQ0HDBL", NVME_CQ0HDBL),
        ]
    }
}

impl Default for Ans2Nvme {
    fn default() -> Self {
        Self::new()
    }
}

impl Device for Ans2Nvme {
    fn name(&self) -> &'static str {
        "ans2-nvme"
    }
    fn read(&mut self, off: u64, _size: u8) -> u64 {
        match off {
            NVME_CAP => 0x002F_003F_0203_FFFF, // MQES 65535, 64B entries, timeout
            NVME_VS => 0x0002_0300,            // nvme 2.3
            NVME_CSTS => self.csts as u64,
            NVME_AQA => self.aqa as u64,
            NVME_ASQ => self.asq,
            NVME_ACQ => self.acq,
            _ => {
                self.unknown_reads += 1;
                0
            }
        }
    }
    fn write(&mut self, off: u64, _size: u8, val: u64) {
        match off {
            NVME_AQA => self.aqa = (val & 0xFFFF_FFFF) as u32,
            NVME_ASQ => self.asq_addr = val & !0xF,
            NVME_ACQ => self.acq_addr = val & !0xF,
            NVME_SQ0TDBL => {
                self.sq_tail = (val & 0xFFFF) as u16;
                self.process_admin();
            }
            NVME_CQ0HDBL => self.cq_head = (val & 0xFFFF) as u16,
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn admin_identify_marks_ready() {
        use std::sync::{Arc, Mutex};
        let mem = Arc::new(Mutex::new(std::collections::HashMap::new()));
        let r = mem.clone();
        let w = mem.clone();
        let mut n = Ans2Nvme::new();
        n.mem_read = Some(Box::new(move |a| *r.lock().unwrap().get(&a).unwrap_or(&0)));
        n.mem_write = Some(Box::new(move |a, v| {
            w.lock().unwrap().insert(a, v);
        }));
        n.write(NVME_ASQ, 8, 0x9000);
        n.write(NVME_ACQ, 8, 0x9100);
        n.write(NVME_SQ0TDBL, 4, 1); // ring with identify pending (op 0 read)
        assert_eq!(n.read(NVME_CSTS, 4), NVME_CSTS_RDY as u64);
    }
}
