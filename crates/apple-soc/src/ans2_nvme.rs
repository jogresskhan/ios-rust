//! ans2_nvme — Apple ANS2 NVMe storage controller.
//!
//! Port of ChefKiss Inferno `hw/block/apple-silicon/ans.c` (the ANS2
//! wrapper: RTKit start, the Apple vendor register block, the NVMe MMIO
//! alias at 0..0x1200) plus the NVMe admin command format the guest
//! drives: 64-byte submission entries (opcode/FUSE/CID, PRPs, CDW10-15),
//! doorbell pairs at 0x1000+8*qid, phase-tagged completions, Identify
//! Controller/Namespace, Create/Delete IO CQ/SQ and Set/Get Features.
//! DMA is translated through DART by the host side.
//!
//! The pre-port surface ([`BlockBackend`], [`SqEntry`], `mem_read`/
//! `mem_write` hooks, [`Ans2Nvme::process_admin`]/[`Ans2Nvme::io_read_dma`])
//! is kept for backward compatibility.

use std::collections::BTreeMap;

use vm_core::Device;

// NVMe register offsets (inside the 0..0x1200 NVMe window)
pub const NVME_CAP: u64 = 0x0000;
pub const NVME_VS: u64 = 0x0008;
pub const NVME_INTMS: u64 = 0x000C;
pub const NVME_INTMC: u64 = 0x0010;
pub const NVME_CC: u64 = 0x0014;
pub const NVME_CSTS: u64 = 0x001C;
pub const NVME_AQA: u64 = 0x0024;
pub const NVME_ASQ: u64 = 0x0028;
pub const NVME_ACQ: u64 = 0x0030;
pub const NVME_SQ0TDBL: u64 = 0x1000; // admin sq tail doorbell
pub const NVME_CQ0HDBL: u64 = 0x1004;

pub const NVME_CSTS_RDY: u32 = 1;
pub const NVME_CSTS_CFS: u32 = 1 << 1;
pub const NVME_CC_EN: u32 = 1;

// Apple ANS2 vendor registers (ans.c)
pub const NVME_APPLE_VENDOR_REG_SIZE: u64 = 0x60000;
pub const NVME_APPLE_MAX_PEND_CMDS: u64 = 0x1210;
pub const NVME_APPLE_MAX_PEND_CMDS_VAL: u32 = (64 << 16) | 64;
pub const NVME_APPLE_BOOT_STATUS: u64 = 0x1300;
pub const NVME_APPLE_BOOT_STATUS_OK: u32 = 0xde71ce55;
pub const NVME_APPLE_BASE_CMD_ID: u64 = 0x1308;
pub const NVME_APPLE_BASE_CMD_ID_MASK: u32 = 0xFFFF;
pub const NVME_APPLE_BASE_CMD_ID_VAL: u32 = 0x6000;
pub const NVME_APPLE_MODESEL: u64 = 0x1304;
pub const NVME_APPLE_LINEAR_SQ_CTRL: u64 = 0x24908;
pub const NVME_APPLE_LINEAR_SQ_CTRL_EN: u32 = 1 << 0;

/// The NVMe MMIO window upstream aliases at the base of the vendor BAR.
pub const NVME_MMIO_WINDOW_SIZE: u64 = 0x1200;

// Admin opcodes
pub const ADMIN_DELETE_IO_SQ: u8 = 0x00;
pub const ADMIN_CREATE_IO_SQ: u8 = 0x01;
pub const ADMIN_GET_LOG_PAGE: u8 = 0x02;
pub const ADMIN_DELETE_IO_CQ: u8 = 0x04;
pub const ADMIN_CREATE_IO_CQ: u8 = 0x05;
pub const ADMIN_IDENTIFY: u8 = 0x06;
pub const ADMIN_ABORT: u8 = 0x08;
pub const ADMIN_SET_FEATURES: u8 = 0x09;
pub const ADMIN_GET_FEATURES: u8 = 0x0A;
// Identify CNS values
pub const CNS_IDENTIFY_NAMESPACE: u32 = 0;
pub const CNS_IDENTIFY_CONTROLLER: u32 = 1;

/// One ANS2 IO queue pair (admin is qid 0).
#[derive(Clone, Copy, Debug, Default)]
pub struct NvmeQueue {
    pub base: u64,
    pub size: u16,
    pub phase: bool,
    pub created: bool,
}

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

impl SqEntry {
    pub fn opcode(&self) -> u8 {
        (self.cdw[0] & 0xFF) as u8
    }
    pub fn cid(&self) -> u16 {
        (self.cdw[0] >> 16) as u16
    }
    pub fn nsid(&self) -> u32 {
        self.cdw[1]
    }
    pub fn prp1(&self) -> u64 {
        self.cdw[6] as u64 | ((self.cdw[7] as u64) << 32)
    }
    pub fn prp2(&self) -> u64 {
        self.cdw[8] as u64 | ((self.cdw[9] as u64) << 32)
    }
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

    // upstream ANS2 state
    /// RTKit start/wakeup ran (apple_ans_start)
    pub started: bool,
    /// Apple vendor register file (NVME_APPLE_VENDOR_REG_SIZE window,
    /// sparse: only written offsets exist)
    pub vendor_reg: BTreeMap<u64, u32>,
    /// completion phase tag for the admin CQ
    pub admin_phase: bool,
    /// created IO completion queues by QID
    pub io_cqs: BTreeMap<u16, NvmeQueue>,
    /// created IO submission queues by QID
    pub io_sqs: BTreeMap<u16, NvmeQueue>,
    /// last admin completion fields (cid, status) for the census
    pub last_cid: u16,
    pub last_status: u16,
    pub admin_completions: u64,
    /// NVMe controller knobs (apple_ans_from_node properties)
    pub max_ioqpairs: u16,
    pub mdts: u8,
    pub logical_block_size: u32,
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
            started: false,
            vendor_reg: BTreeMap::new(),
            admin_phase: true, // CQ phase starts 1 (controller-side init)
            io_cqs: BTreeMap::new(),
            io_sqs: BTreeMap::new(),
            last_cid: 0,
            last_status: 0,
            admin_completions: 0,
            max_ioqpairs: 7, // apple_ans_from_node
            mdts: 8,
            logical_block_size: 4096,
        }
    }

    /// `apple_ans_start` / RTKit wakeup: enable the NVMe PCI function.
    pub fn rtkit_start(&mut self) {
        self.started = true;
    }

    fn fetch_sq_entry(&mut self, base: u64, tail: u16) -> Option<SqEntry> {
        let rd = self.mem_read.as_mut()?;
        // ringing tail N means entries [0, N) are pending; the model serves
        // the newest one (index tail-1), matching the legacy single-entry
        // behavior when the guest rings 1 after filling slot 0
        let idx = tail.wrapping_sub(1);
        let mut e = SqEntry::default();
        for (i, w) in e.cdw.iter_mut().enumerate() {
            *w = rd(base + (idx as u64 * 64) + (i as u64) * 4) as u32;
        }
        Some(e)
    }

    fn put_completion(&mut self, base: u64, head: u16, dw0: u32, sqhd: u16, cid: u16, status: u16) {
        let Some(wm) = self.mem_write.as_mut() else {
            return;
        };
        let c = base + (head as u64) * 64;
        // NVMe completion: dw3 = phase(tag) | cid<<1 | status<<8
        let dw3 = (self.admin_phase as u32)
            | ((cid as u32) << 1)
            | ((status as u32) << 8);
        wm(c, dw0 as u64);
        wm(c + 0x08, dw2(sqhd, 0));
        wm(c + 0x18, dw3 as u64);
        self.last_cid = cid;
        self.last_status = status;
        self.admin_completions += 1;
    }

    /// Process pending admin commands after the guest rings SQ0 doorbell.
    /// Ports the admin paths the real guest uses at boot:
    ///  - Identify Controller (0x06, CNS=1) / Identify Namespace (CNS=0)
    ///  - Get Features (0x0A), Set Features (0x09)
    ///  - Create I/O CQ (0x05) / SQ (0x01), Delete I/O CQ (0x04) / SQ (0x00)
    pub fn process_admin(&mut self) {
        let sq = self.asq_addr;
        let cq = self.acq_addr;
        if sq == 0 || cq == 0 {
            return;
        }
        let Some(entry) = self.fetch_sq_entry(sq, self.sq_tail) else {
            return;
        };
        let op = entry.opcode();
        let cid = entry.cid();
        let prp1 = entry.prp1();
        let cns = entry.cdw[10] & 0xFF;
        let dw0: u32 = 0;
        let mut status: u16 = 0; // success

        match op {
            ADMIN_IDENTIFY => {
                // identify: fill minimal controller/ns data at PRP1 via DMA
                let Some(mw) = self.mem_write.as_mut() else {
                    return;
                };
                if cns == CNS_IDENTIFY_CONTROLLER {
                    // dword0/1: VID=Apple, DID (ChefKiss-ANS build)
                    let w0 = 0x0001_0000_106B_u64; // DID:VID little-endian halves
                    mw(prp1, w0);
                    // VER (offset 8): NVMe 2.3
                    mw(prp1 + 8, 0x0002_0300);
                    // bytes 24..64: MN "ChefKiss-ANS"
                    let mn = b"ChefKiss-ANS";
                    let mut w = 0u64;
                    for (i, b) in mn.iter().enumerate() {
                        w |= (*b as u64) << ((i % 8) * 8);
                        if i % 8 == 7 {
                            mw(prp1 + 24 + (i / 8) as u64 * 8, w);
                            w = 0;
                        }
                    }
                    // FR "1.0" at 64
                    mw(prp1 + 64, 0x002E_0000_0000_3130);
                    // byte 76..: MDTS = 8 (=> 1MB at MPS 0)
                    mw(prp1 + 72, (8_u64) << (8 * (77 - 72)));
                    // SQES/CQES at 512/513
                    mw(prp1 + 512, 0x4444_0000_0000_0066);
                    // NN at 519, ONCS at 520 (support nothing exotic)
                    mw(prp1 + 512 + 8, 1 | (0_u64 << 8));
                } else if cns == CNS_IDENTIFY_NAMESPACE {
                    // nsze/ncap in 4K LBAs
                    mw(prp1, 0x0010_0000); // nsze
                    mw(prp1 + 8, 0x0010_0000); // ncap
                    // FLBAS at byte 26 (format 0), LBAF0 at 128: lbads=12
                    mw(prp1 + 24, 0);
                    mw(prp1 + 128, 12 << 16);
                }
                self.identify_done += 1;
            }
            ADMIN_CREATE_IO_CQ => {
                let qid = ((entry.cdw[10] >> 16) & 0xFFF) as u16;
                let size = ((entry.cdw[10] & 0xFFFF) as u16).wrapping_add(1);
                self.io_cqs.insert(
                    qid,
                    NvmeQueue { base: prp1, size, phase: true, created: true },
                );
            }
            ADMIN_CREATE_IO_SQ => {
                let qid = ((entry.cdw[10] >> 16) & 0xFFF) as u16;
                let size = ((entry.cdw[10] & 0xFFFF) as u16).wrapping_add(1);
                let cqid = ((entry.cdw[11] >> 16) & 0xFFF) as u16;
                let _ = cqid;
                self.io_sqs.insert(
                    qid,
                    NvmeQueue { base: prp1, size, phase: true, created: true },
                );
            }
            ADMIN_DELETE_IO_SQ => {
                let qid = ((entry.cdw[10] >> 16) & 0xFFF) as u16;
                self.io_sqs.remove(&qid);
            }
            ADMIN_DELETE_IO_CQ => {
                let qid = ((entry.cdw[10] >> 16) & 0xFFF) as u16;
                self.io_cqs.remove(&qid);
            }
            ADMIN_SET_FEATURES | ADMIN_GET_FEATURES | ADMIN_GET_LOG_PAGE
            | ADMIN_ABORT => { /* succeed */ }
            _ => {
                status = 1; // invalid command opcode
            }
        }

        // write completion entry: dw0 result, dw2 SQHD, dw3 phase|cid<<1|status<<8
        let head = self.cq_head;
        self.put_completion(cq, head, dw0, self.sq_tail, cid, status);
        self.last_cid = cid;
        self.cq_head = self.cq_head.wrapping_add(1) & 0xFFFF;
        if self.cq_head == 0 {
            self.admin_phase = !self.admin_phase;
        }
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

    /// Apple vendor register read (`apple_ans_vendor_reg_read`).
    pub fn vendor_read(&mut self, addr: u64) -> u64 {
        if addr < NVME_MMIO_WINDOW_SIZE {
            // NVMe MMIO alias at the base of the vendor window
            return self.read(addr & 0xFFF, 4);
        }
        match addr {
            NVME_APPLE_MAX_PEND_CMDS => NVME_APPLE_MAX_PEND_CMDS_VAL as u64,
            NVME_APPLE_BOOT_STATUS => NVME_APPLE_BOOT_STATUS_OK as u64,
            NVME_APPLE_BASE_CMD_ID => NVME_APPLE_BASE_CMD_ID_VAL as u64,
            _ => self.vendor_reg.get(&addr).copied().unwrap_or(0) as u64,
        }
    }

    /// Apple vendor register write (`apple_ans_vendor_reg_write`).
    pub fn vendor_write(&mut self, addr: u64, val: u32) {
        if addr < NVME_MMIO_WINDOW_SIZE {
            self.write(addr & 0xFFF, 4, val as u64);
            return;
        }
        self.vendor_reg.insert(addr, val);
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
            ("APPLE_MAX_PEND_CMDS", NVME_APPLE_MAX_PEND_CMDS),
            ("APPLE_BOOT_STATUS", NVME_APPLE_BOOT_STATUS),
            ("APPLE_BASE_CMD_ID", NVME_APPLE_BASE_CMD_ID),
            ("APPLE_MODESEL", NVME_APPLE_MODESEL),
            ("APPLE_LINEAR_SQ_CTRL", NVME_APPLE_LINEAR_SQ_CTRL),
        ]
    }
}

/// completion dword2: SQ head (16b) | SQ id (16b)
fn dw2(sqhd: u16, sqid: u16) -> u64 {
    (sqhd as u64) | ((sqid as u64) << 16)
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
            NVME_INTMS | NVME_INTMC => 0,
            NVME_CC => self.started as u64, // EN follows the RTKit start
            NVME_CSTS => self.csts as u64,
            NVME_AQA => self.aqa as u64,
            NVME_ASQ => self.asq,
            NVME_ACQ => self.acq,
            NVME_SQ0TDBL => self.sq_tail as u64,
            NVME_CQ0HDBL => self.cq_head as u64,
            // Apple vendor specials (guest pokes these through the BAR)
            NVME_APPLE_MAX_PEND_CMDS => NVME_APPLE_MAX_PEND_CMDS_VAL as u64,
            NVME_APPLE_BOOT_STATUS => NVME_APPLE_BOOT_STATUS_OK as u64,
            NVME_APPLE_BASE_CMD_ID => NVME_APPLE_BASE_CMD_ID_VAL as u64,
            NVME_APPLE_MODESEL | NVME_APPLE_LINEAR_SQ_CTRL => {
                self.vendor_reg.get(&off).copied().unwrap_or(0) as u64
            }
            _ => {
                if off < NVME_APPLE_VENDOR_REG_SIZE {
                    self.vendor_reg.get(&off).copied().unwrap_or(0) as u64
                } else {
                    self.unknown_reads += 1;
                    0
                }
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
            NVME_APPLE_LINEAR_SQ_CTRL => {
                self.vendor_reg
                    .insert(off, (val as u32 & NVME_APPLE_LINEAR_SQ_CTRL_EN) | 0);
            }
            NVME_APPLE_MODESEL
            | NVME_APPLE_MAX_PEND_CMDS
            | NVME_APPLE_BOOT_STATUS
            | NVME_APPLE_BASE_CMD_ID => {
                // stored upstream (reads are overridden)
                self.vendor_reg.insert(off, val as u32);
            }
            _ => {
                if off < NVME_APPLE_VENDOR_REG_SIZE {
                    self.vendor_reg.insert(off, val as u32);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn mem_backend() -> (
        Arc<Mutex<std::collections::HashMap<u64, u64>>>,
        impl FnMut(u64) -> u64 + Send,
        impl FnMut(u64, u64) + Send,
    ) {
        let mem = Arc::new(Mutex::new(std::collections::HashMap::new()));
        let r = mem.clone();
        let w = mem.clone();
        let rd = move |a| *r.lock().unwrap().get(&a).unwrap_or(&0);
        let wr = move |a, v| {
            w.lock().unwrap().insert(a, v);
        };
        (mem, rd, wr)
    }

    fn put_dwords(mem: &Arc<Mutex<std::collections::HashMap<u64, u64>>>, base: u64, dw: &[u32]) {
        let mut m = mem.lock().unwrap();
        for (i, d) in dw.iter().enumerate() {
            m.insert(base + (i as u64) * 4, *d as u64);
        }
    }

    #[test]
    fn admin_identify_marks_ready() {
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

    #[test]
    fn apple_vendor_register_block() {
        let mut n = Ans2Nvme::new();
        // the three boot-synchronous specials upstream overrides
        assert_eq!(n.read(NVME_APPLE_MAX_PEND_CMDS, 4), NVME_APPLE_MAX_PEND_CMDS_VAL as u64);
        assert_eq!(n.read(NVME_APPLE_BOOT_STATUS, 4), NVME_APPLE_BOOT_STATUS_OK as u64);
        assert_eq!(n.read(NVME_APPLE_BASE_CMD_ID, 4), NVME_APPLE_BASE_CMD_ID_VAL as u64);
        // MODESEL + LINEAR_SQ_CTRL store/roundtrip
        n.write(NVME_APPLE_MODESEL, 4, 0x33);
        assert_eq!(n.read(NVME_APPLE_MODESEL, 4), 0x33);
        n.write(NVME_APPLE_LINEAR_SQ_CTRL, 4, NVME_APPLE_LINEAR_SQ_CTRL_EN as u64 | 2);
        assert_eq!(
            n.read(NVME_APPLE_LINEAR_SQ_CTRL, 4),
            NVME_APPLE_LINEAR_SQ_CTRL_EN as u64
        );
        // generic vendor regs are stored
        n.write(0x4000, 4, 0xABCD);
        assert_eq!(n.read(0x4000, 4), 0xABCD);
        // outside the vendor window → unknown counter
        let before = n.unknown_reads;
        assert_eq!(n.read(NVME_APPLE_VENDOR_REG_SIZE + 4, 4), 0);
        assert_eq!(n.unknown_reads, before + 1);
        // rtkit start is visible in CC.EN
        assert_eq!(n.read(NVME_CC, 4), 0);
        n.rtkit_start();
        assert_eq!(n.read(NVME_CC, 4), 1);
    }

    #[test]
    fn identify_controller_and_completion_format() {
        let (mem, rd, wr) = mem_backend();
        let mut n = Ans2Nvme::new();
        n.mem_read = Some(Box::new(rd));
        n.mem_write = Some(Box::new(wr));
        n.write(NVME_ASQ, 8, 0x8000);
        n.write(NVME_ACQ, 8, 0x8100);
        // Identify Controller: opcode 0x06, CID 0x1337, cdw10 CNS=1
        put_dwords(&mem, 0x8000, &[
            ADMIN_IDENTIFY as u32 | (0x1337 << 16),
            0, 0, 0, 0, 0, 0x8200, 0, // prp1 = 0x8200
            0, 0, CNS_IDENTIFY_CONTROLLER, 0, 0, 0, 0, 0,
        ]);
        n.write(NVME_SQ0TDBL, 4, 1);
        assert_eq!(n.identify_done, 1);
        assert_eq!(n.last_cid, 0x1337);
        assert_eq!(n.last_status, 0);
        // VID:DID written at prp1
        let m = mem.lock().unwrap();
        assert_eq!(*m.get(&0x8200).unwrap() & 0xFFFF, 0x106B);
        assert_eq!(*m.get(&0x8208).unwrap(), 0x0002_0300); // ver 2.3
        // completion dw3: phase | cid<<1
        assert_eq!(*m.get(&0x8118).unwrap(), (0x1337u64 << 1) | 1);
        // MDTS byte 77 == 8
        assert_eq!((*m.get(&(0x8200 + 72)).unwrap() >> 8 * 5) & 0xFF, 8);
        drop(m);
        // second completion (slot 1): invalid opcode 0xF
        put_dwords(&mem, 0x8040, &[0x0000_000F, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        n.write(NVME_SQ0TDBL, 4, 2);
        assert_eq!(n.last_status, 1); // invalid command opcode
    }

    #[test]
    fn io_queue_creation_and_doorbell_pairs() {
        let (mem, rd, wr) = mem_backend();
        let mut n = Ans2Nvme::new();
        n.mem_read = Some(Box::new(rd));
        n.mem_write = Some(Box::new(wr));
        n.write(NVME_ASQ, 8, 0x8000);
        n.write(NVME_ACQ, 8, 0x8100);
        // Create IO CQ qid 1, size 3 (dw10 = size-1 | qid<<16), base 0xA000
        put_dwords(&mem, 0x8000, &[
            ADMIN_CREATE_IO_CQ as u32 | (0x111 << 16),
            0, 0, 0, 0, 0, 0xA000, 0,
            0, 0, 2 | (1 << 16), 0, 0, 0, 0, 0,
        ]);
        n.write(NVME_SQ0TDBL, 4, 1);
        assert!(n.io_cqs.contains_key(&1));
        assert_eq!(n.io_cqs[&1].base, 0xA000);
        assert_eq!(n.io_cqs[&1].size, 3);
        // Create IO SQ qid 2, size 7, base 0xB000 (dw11 cqid 1) — slot 1
        put_dwords(&mem, 0x8040, &[
            ADMIN_CREATE_IO_SQ as u32 | (0x222 << 16),
            0, 0, 0, 0, 0, 0xB000, 0,
            0, 0, 6 | (2 << 16), 1 << 16, 0, 0, 0, 0,
        ]);
        n.write(NVME_SQ0TDBL, 4, 2);
        assert!(n.io_sqs.contains_key(&2));
        assert_eq!(n.io_sqs[&2].size, 7);
        // Delete IO SQ removes it — slot 2
        put_dwords(&mem, 0x8080, &[
            ADMIN_DELETE_IO_SQ as u32 | (0x222 << 16),
            0, 0, 0, 0, 0, 0, 0, 0, 0, 2 << 16, 0, 0, 0, 0, 0,
        ]);
        n.write(NVME_SQ0TDBL, 4, 3);
        assert!(!n.io_sqs.contains_key(&2));
        // doorbell pairs: admin q0 at 0x1000/0x1004 (legacy consts)
        assert_eq!(NVME_SQ0TDBL, 0x1000);
        assert_eq!(NVME_CQ0HDBL, 0x1004);
        n.write(NVME_CQ0HDBL, 4, 5);
        assert_eq!(n.read(NVME_CQ0HDBL, 4), 5);
    }
}
