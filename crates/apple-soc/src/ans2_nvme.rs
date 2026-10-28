//! Apple ANS2 (Apple NAND Storage) controller + minimal NVMe core.
//!
//! Port of ChefKiss Inferno `hw/block/apple-silicon/ans.c` (the ANS wrapper:
//! RTKit mailbox + ascv2-core + IOP-autoboot + vendor registers with the
//! NVMe PCI BAR aliased at offset 0) and `nvme_mmu.c` (the common-reg block
//! with the TCB addresses).
//!
//! Upstream instantiates QEMU's full NVMe PCI device; this port implements a
//! **minimal NVMe admin/IO queue engine** in its place:
//!   * CAP/VS/CC/CSTS/AQA/ASQ/ACQ + doorbells,
//!   * admin loop: IDENTIFY (controller + namespace synthesized), CREATE/DELETE
//!     IO SQ/CQ accepted, SET/GET FEATURES ok, reads served from the
//!     injectable [`BlockBackend`],
//!   * AS-specific vendor registers (`NVME_APPLE_*` from ans.c lines 51-60).
//!
//! Parity gaps (documented): no PCI config space / MSI-X (the ANS PCI device
//! is not exposed on the APCIE ECAM here), queue/PRP guest memory is
//! shadowed into [`Ans2Nvme::qmem`] (bounded window) instead of true DMA —
//! completion data outside the window is recorded in
//! [`NvmeCore::pending_dma_writes`]. Firmware is not executed (RTKit sim).
//!
//! License: AGPL-3.0-or-later (derived work).

use vm_core::Device;

use crate::rtkit::Rtkit;

// ---------------------------------------------------------------------------
// ANS2 AS-specific registers (ans.c lines 51-60)
// ---------------------------------------------------------------------------

pub const NVME_APPLE_MAX_PEND_CMDS: u64 = 0x1210;
pub const NVME_APPLE_MAX_PEND_CMDS_VAL: u32 = (64 << 16) | 64;
pub const NVME_APPLE_BOOT_STATUS: u64 = 0x1300;
pub const NVME_APPLE_BOOT_STATUS_OK: u32 = 0xDE71_CE55;
pub const NVME_APPLE_BASE_CMD_ID: u64 = 0x1308;
pub const NVME_APPLE_LINEAR_SQ_CTRL: u64 = 0x24908;
pub const NVME_APPLE_LINEAR_SQ_CTRL_EN: u32 = 1 << 0;
pub const NVME_APPLE_MODESEL: u64 = 0x1304;
/// Vendor register block size (ans.c `NVME_APPLE_VENDOR_REG_SIZE`).
pub const NVME_APPLE_VENDOR_REG_SIZE: u64 = 0x60000;
/// NVMe BAR size aliased over the vendor block (ans.c: 0x1200).
pub const NVME_REG_SIZE: u64 = 0x1200;

// ---------------------------------------------------------------------------
// NVMe registers (within the NVMe BAR)
// ---------------------------------------------------------------------------

pub const NVME_CAP: u64 = 0x0;
pub const NVME_VS: u64 = 0x8;
pub const NVME_INTMS: u64 = 0xC;
pub const NVME_INTMC: u64 = 0x10;
pub const NVME_CC: u64 = 0x14;
pub const NVME_CSTS: u64 = 0x1C;
pub const NVME_NSSR: u64 = 0x20;
pub const NVME_AQA: u64 = 0x24;
pub const NVME_ASQ: u64 = 0x28; // 64-bit
pub const NVME_ACQ: u64 = 0x30; // 64-bit
pub const NVME_SQ0TDBL: u64 = 0x1000;
pub const NVME_CQ0HDBL: u64 = 0x1004;

// Admin opcodes.
pub const NVME_ADMIN_DELETE_SQ: u8 = 0x00;
pub const NVME_ADMIN_CREATE_SQ: u8 = 0x01;
pub const NVME_ADMIN_GET_LOG_PAGE: u8 = 0x02;
pub const NVME_ADMIN_DELETE_CQ: u8 = 0x04;
pub const NVME_ADMIN_CREATE_CQ: u8 = 0x05;
pub const NVME_ADMIN_IDENTIFY: u8 = 0x06;
pub const NVME_ADMIN_SET_FEATURES: u8 = 0x09;
pub const NVME_ADMIN_GET_FEATURES: u8 = 0x0A;
pub const NVME_ADMIN_ASYNC_EVENT_REQ: u8 = 0x12;
// I/O opcodes.
pub const NVME_IO_FLUSH: u8 = 0x00;
pub const NVME_IO_WRITE: u8 = 0x01;
pub const NVME_IO_READ: u8 = 0x02;

pub const NVME_CMD_DW0_OPCODE: usize = 0x00;
pub const NVME_CMD_CID: usize = 0x02; // dw1
pub const NVME_CMD_PRP1: usize = 0x08; // dw2:3
pub const NVME_CMD_PRP2: usize = 0x10; // dw4:5
pub const NVME_CMD_SLBA: usize = 0x10; // (r/w) dw4:5
pub const NVME_CMD_NLB: usize = 0x14; // (r/w) dw6 low 16 bits

pub const NVME_SQE_SIZE: usize = 64;
pub const NVME_CQE_SIZE: usize = 16;

/// Backing store for NVMe I/O reads (injectable; the machine wires the
/// future APFS/disk provider here).
pub trait BlockBackend: Send {
    /// Read `bufs.len()` bytes starting at logical block `lba`.
    /// Returns `false` when the read fails (CQE status ≠ 0).
    fn read(&mut self, lba: u64, bufs: &mut [u8]) -> bool;
}

/// RAM-backed default backend (all zeros) used when nothing is injected.
pub struct NullBlock {
    pub lba_size: u32,
    pub num_lbas: u64,
}

impl Default for NullBlock {
    fn default() -> Self {
        NullBlock { lba_size: 4096, num_lbas: 0x40_0000 } // 16 GiB of zeros
    }
}

impl BlockBackend for NullBlock {
    fn read(&mut self, lba: u64, bufs: &mut [u8]) -> bool {
        let _ = (lba, self);
        bufs.fill(0);
        true
    }
}

/// A DMA write the engine would have performed into guest RAM.
pub type PendingDmaWrite = (u64, Vec<u8>);

/// Minimal NVMe controller core (admin + IO queues over a shadow window).
pub struct NvmeCore {
    /// NVMe BAR registers (u32-indexed, covers CAP..0x1300).
    pub regs: Vec<u32>,
    /// Shadow memory window the queue/PRP structures live in.
    pub qmem: Vec<u8>,
    /// Physical base address the guest programmed *minus* qmem offset 0 —
    /// i.e. guest address of qmem[0]. 0 disables in-window accesses.
    pub qmem_base: u64,
    /// 4096-byte synthesized IDENTIFY controller structure.
    pub id_ctrl: Vec<u8>,
    /// 4096-byte synthesized IDENTIFY namespace structure.
    pub id_ns: Vec<u8>,

    admin_sq_base: u64,
    admin_cq_base: u64,
    admin_sq_entries: u32,
    admin_cq_entries: u32,
    sq_tail: u16,
    cq_head: u16,
    cq_phase: bool,

    /// Created IO queue pairs (qid, sq/cq recorded for the census).
    pub io_queues: Vec<(u16, u64, u64)>,
    next_doorbell: u32,

    pub backend: Box<dyn BlockBackend>,
    pub lba_size: u32,

    /// Writes the guest would have observed in RAM.
    pub pending_dma_writes: Vec<PendingDmaWrite>,
    /// Completion census: (name of opcode, count).
    pub op_census: Vec<(&'static str, u32)>,
    irq_masked: bool,
}

impl NvmeCore {
    pub fn new() -> Self {
        let mut regs = vec![0u32; 0x1300 / 4];
        // CAP: MQES=63, CQR=1, TO=2 (500ms units), CSS: NVM (bit 45), MPSMIN 0.
        let cap: u64 = 0x3F | (1 << 16) | (2 << 20) | (1 << 37);
        regs[NVME_CAP as usize / 4] = cap as u32;
        regs[NVME_CAP as usize / 4 + 1] = (cap >> 32) as u32;
        // VS 1.3.0
        regs[NVME_VS as usize / 4] = 0x0001_0300;
        NvmeCore {
            regs,
            qmem: vec![0u8; 0x40_0000], // 4 MiB shadow window
            qmem_base: 0,
            id_ctrl: vec![0u8; 4096],
            id_ns: vec![0u8; 4096],
            admin_sq_base: 0,
            admin_cq_base: 0,
            admin_sq_entries: 0,
            admin_cq_entries: 0,
            sq_tail: 0,
            cq_head: 0,
            cq_phase: true,
            io_queues: Vec::new(),
            next_doorbell: 0,
            backend: Box::new(NullBlock::default()),
            lba_size: 4096,
            pending_dma_writes: Vec::new(),
            op_census: Vec::new(),
            irq_masked: false,
        }
    }

    /// Point the shadow window at the physical address the guest will place
    /// queues/PRPs at. Must be called before the guest programs ASQ/ACQ.
    pub fn set_dma_window(&mut self, base: u64) {
        self.qmem_base = base;
    }

    fn census(&mut self, op: &'static str) {
        for e in self.op_census.iter_mut() {
            if e.0 == op {
                e.1 += 1;
                return;
            }
        }
        self.op_census.push((op, 1));
    }

    /// Interpret a qmem-relative address, or None when out of window.
    fn window_off(&self, guest_addr: u64) -> Option<usize> {
        if self.qmem_base == 0 || guest_addr < self.qmem_base {
            return None;
        }
        let off = (guest_addr - self.qmem_base) as usize;
        if off + NVME_SQE_SIZE <= self.qmem.len() {
            Some(off)
        } else {
            None
        }
    }

    fn in_window(&self, guest_addr: u64, len: usize) -> bool {
        if self.qmem_base == 0 || guest_addr < self.qmem_base {
            return false;
        }
        let off = (guest_addr - self.qmem_base) as usize;
        off + len <= self.qmem.len()
    }

    fn read_window(&self, guest_addr: u64, buf: &mut [u8]) {
        if self.in_window(guest_addr, buf.len()) {
            let off = (guest_addr - self.qmem_base) as usize;
            buf.copy_from_slice(&self.qmem[off..off + buf.len()]);
        } else {
            buf.fill(0);
        }
    }

    fn write_window(&mut self, guest_addr: u64, data: &[u8]) {
        if self.in_window(guest_addr, data.len()) {
            let off = (guest_addr - self.qmem_base) as usize;
            self.qmem[off..off + data.len()].copy_from_slice(data);
        } else {
            self.pending_dma_writes
                .push((guest_addr, data.to_vec()));
        }
    }

    /// Synthesize the IDENTIFY structures ("ChefKiss-ANS" like upstream).
    fn synthesize_identify(&mut self) {
        let id = &mut self.id_ctrl;
        id.fill(0);
        id[4..8].copy_from_slice(b"CKID"); // VID (vendor)
        id[8..10].copy_from_slice(&0xFFFFu16.to_le_bytes());
        id[24..64].copy_from_slice(b"ChefKiss-ANS\0\0\0\0"); // serial (20)
        id[64..104].copy_from_slice(b"Inferno NVMe Model\0\0\0\0"); // model (40)
        id[168..172].copy_from_slice(b"1.0 "); // firmware rev
        // Maximum Data Transfer Size (mdts = 8 → 2^8 pages = 1 MiB)
        id[77] = 8;
        id[261] = 4; // SGL not required, 128-byte entry
        // Power state descriptors start at 512, all zero = fine.

        let ns = &mut self.id_ns;
        ns.fill(0);
        let num_lbas = 0x40_0000u64; // 16 GiB @ 4 KiB
        ns[0..8].copy_from_slice(&num_lbas.to_le_bytes()); // NSZE
        ns[8..16].copy_from_slice(&num_lbas.to_le_bytes()); // NCAP
        ns[16..24].copy_from_slice(&num_lbas.to_le_bytes()); // NUSE
        ns[26] = 1; // NLBAF count+1
        // LBA format 0: data size 4096 (MS 16 bits), metadata 0 (LS 16 bits)
        let lbaf: u32 = (12 << 16) | 0;
        ns[128..132].copy_from_slice(&lbaf.to_le_bytes());
    }

    /// Handle one admin command from the queue; returns the CQE (result dw0,
    /// result dw1, status, cid).
    fn admin_command(&mut self, cmd: &[u8; NVME_SQE_SIZE]) -> (u32, u32, u16, u16) {
        let opcode = cmd[NVME_CMD_DW0_OPCODE] & 0x7F;
        let cid = u16::from_le_bytes(
            cmd[NVME_CMD_CID * 2..NVME_CMD_CID * 2 + 2].try_into().unwrap(),
        );
        let prp1 = u64::from_le_bytes(
            cmd[NVME_CMD_PRP1..NVME_CMD_PRP1 + 8].try_into().unwrap(),
        );
        match opcode {
            NVME_ADMIN_IDENTIFY => {
                self.census("identify");
                let cns = u32::from_le_bytes(cmd[0x1C..0x20].try_into().unwrap());
                let buf = match cns {
                    0 => self.id_ctrl.clone(),
                    1 => self.id_ns.clone(),
                    _ => {
                        self.census("identify-bad-cns");
                        vec![0u8; 4096]
                    }
                };
                self.write_window(prp1, &buf);
                (0, 0, 0, cid)
            }
            NVME_ADMIN_CREATE_SQ | NVME_ADMIN_CREATE_CQ => {
                self.census(if opcode == NVME_ADMIN_CREATE_SQ {
                    "create-io-sq"
                } else {
                    "create-io-cq"
                });
                let qid = (u32::from_le_bytes(
                    cmd[0x24..0x28].try_into().unwrap(),
                ) >> 16) as u16;
                let size = u32::from_le_bytes(
                    cmd[0x18..0x1C].try_into().unwrap(),
                );
                let base = u64::from_le_bytes(
                    cmd[0x20..0x28].try_into().unwrap(),
                );
                self.io_queues.push((qid, base, size as u64));
                (0, 0, 0, cid)
            }
            NVME_ADMIN_DELETE_SQ | NVME_ADMIN_DELETE_CQ => {
                self.census("delete-io-q");
                (0, 0, 0, cid)
            }
            NVME_ADMIN_SET_FEATURES | NVME_ADMIN_GET_FEATURES => {
                self.census("features");
                (0, 0, 0, cid)
            }
            NVME_ADMIN_ASYNC_EVENT_REQ => {
                self.census("async-event");
                (0, 0, 0, cid)
            }
            NVME_ADMIN_GET_LOG_PAGE => {
                self.census("get-log-page");
                let len =
                    (u32::from_le_bytes(cmd[0x30..0x34].try_into().unwrap())
                        & 0xFF_FFFF) as usize;
                let len = (len + 1) * 4;
                let buf = vec![0u8; len.min(0x1000)];
                self.write_window(prp1, &buf);
                (0, 0, 0, cid)
            }
            _ => {
                self.census("admin-unknown");
                // Invalid opcode
                (0, 0, 1, cid)
            }
        }
    }

    /// Serve one I/O READ from the block backend (opcode 2). Returns status.
    fn io_read(&mut self, cmd: &[u8; NVME_SQE_SIZE]) -> u16 {
        self.census("io-read");
        let slba = u64::from_le_bytes(
            cmd[NVME_CMD_SLBA..NVME_CMD_SLBA + 8].try_into().unwrap(),
        );
        let nlb = (u32::from_le_bytes(
            cmd[NVME_CMD_NLB..NVME_CMD_NLB + 4].try_into().unwrap(),
        ) & 0xFFFF) as usize;
        let mut buf = vec![0u8; (nlb + 1) * self.lba_size as usize];
        let prp1 = u64::from_le_bytes(
            cmd[NVME_CMD_PRP1..NVME_CMD_PRP1 + 8].try_into().unwrap(),
        );
        let ok = self.backend.read(slba, &mut buf);
        if !ok {
            return 0x2; // IO error status
        }
        // Simplified PRP handling: single-page and chained PRPs both start at
        // PRP1; data longer than one page is split at page boundaries.
        let page = 4096usize;
        let mut addr = prp1 & !0xFFF;
        let mut off = 0usize;
        let mut chain = [0u8; 8];
        loop {
            let chunk = (buf.len() - off).min(page - (addr as usize & 0xFFF));
            self.write_window(addr, &buf[off..off + chunk]);
            off += chunk;
            if off >= buf.len() {
                break;
            }
            // follow PRP list
            let next = addr & !0xFFF;
            self.read_window(next, &mut chain);
            addr = u64::from_le_bytes(chain);
            if addr == 0 {
                // truncated transfer (shouldn't happen with mdts=8)
                return 0x0;
            }
        }
        0
    }

    /// Process the admin queue after the guest rang SQ0 doorbell.
    fn process_admin(&mut self) {
        if self.admin_sq_base == 0 || self.admin_cq_base == 0 {
            return;
        }
        while self.sq_tail != self.regs[NVME_SQ0TDBL as usize / 4] as u16 {
            let sq_off = self.admin_sq_base
                + self.sq_tail as u64 * NVME_SQE_SIZE as u64;
            let mut cmd = [0u8; NVME_SQE_SIZE];
            self.read_window(sq_off, &mut cmd);

            let opcode = cmd[NVME_CMD_DW0_OPCODE] & 0x7F;
            let (d0, d1, status, cid) = match opcode {
                NVME_IO_READ => {
                    let st = self.io_read(&cmd);
                    let cid = u16::from_le_bytes(
                        cmd[NVME_CMD_CID * 2..NVME_CMD_CID * 2 + 2]
                            .try_into()
                            .unwrap(),
                    );
                    (0, 0, st, cid)
                }
                NVME_IO_WRITE | NVME_IO_FLUSH => {
                    self.census("io-write-or-flush");
                    let cid = u16::from_le_bytes(
                        cmd[NVME_CMD_CID * 2..NVME_CMD_CID * 2 + 2]
                            .try_into()
                            .unwrap(),
                    );
                    (0, 0, 0, cid)
                }
                _ => self.admin_command(&cmd),
            };

            // Write a CQE.
            let cq_off =
                self.admin_cq_base + self.cq_head as u64 * NVME_CQE_SIZE as u64;
            let mut cqe = [0u8; NVME_CQE_SIZE];
            cqe[0..4].copy_from_slice(&d0.to_le_bytes());
            cqe[4..8].copy_from_slice(&d1.to_le_bytes());
            let mut status_dword = (cid as u32) << 16;
            status_dword |= status as u32 & 0xFF;
            if self.cq_phase {
                status_dword |= 1;
            }
            cqe[12..16].copy_from_slice(&status_dword.to_le_bytes());
            self.write_window(cq_off, &cqe);

            self.sq_tail = (self.sq_tail + 1)
                % self.admin_sq_entries.max(1) as u16;
            self.cq_head = (self.cq_head + 1)
                % self.admin_cq_entries.max(1) as u16;
            if self.cq_head == 0 {
                self.cq_phase = !self.cq_phase;
            }
        }
    }

    /// NVMe BAR read (the alias sits at vendor-block offset 0).
    pub fn read(&mut self, off: u64, size: u8) -> u64 {
        let _ = size;
        match off {
            NVME_ASQ | NVME_ACQ => {
                let i = off as usize / 4;
                (self.regs[i + 1] as u64) << 32 | self.regs[i] as u64
            }
            NVME_CSTS => {
                let cc = self.regs[NVME_CC as usize / 4];
                let en = cc & 1 != 0;
                let shst = if cc & 1 == 0 {
                    0u32
                } else {
                    match (cc >> 14) & 3 {
                        0 => 0,         // normal: no shutdown
                        s => s,         // shutdown requested → complete
                    }
                };
                ((shst & 3) << 1) | en as u32
            }
            off if (NVME_SQ0TDBL..NVME_REG_SIZE).contains(&off) => {
                self.regs[off as usize / 4] as u64
            }
            off if off < NVME_REG_SIZE => self.regs[off as usize / 4] as u64,
            _ => 0,
        }
    }

    pub fn write(&mut self, off: u64, size: u8, val: u64) {
        let _ = size;
        match off {
            NVME_INTMS => self.irq_masked = true,
            NVME_INTMC => self.irq_masked = false,
            NVME_CC => {
                let old = self.regs[NVME_CC as usize / 4] as u64;
                self.regs[NVME_CC as usize / 4] = val as u32;
                if val & 1 == 1 && old & 1 == 0 {
                    // enable: latch AQA/ASQ/ACQ already programmed.
                    // AQA: ASQS bits 27:16, ACQS bits 31:24 (NVMe 1.3).
                    let aqa = self.regs[NVME_AQA as usize / 4];
                    self.admin_sq_entries = ((aqa >> 16) & 0xFFF) + 1;
                    self.admin_cq_entries = ((aqa >> 24) & 0xFF) + 1;
                    self.synthesize_identify();
                }
            }
            NVME_NSSR => {
                // subsystem reset: back to disabled
                self.regs[NVME_CC as usize / 4] = 0;
            }
            NVME_ASQ => self.regs[off as usize / 4] = val as u32,
            NVME_ASQ + 4 => self.regs[off as usize / 4] = val as u32,
            NVME_ACQ => self.regs[off as usize / 4] = val as u32,
            NVME_ACQ + 4 => self.regs[off as usize / 4] = val as u32,
            NVME_SQ0TDBL => {
                self.regs[NVME_SQ0TDBL as usize / 4] = val as u32;
                if self.qmem_base != 0 {
                    self.admin_sq_base = self.admin_sq_addr();
                    self.admin_cq_base = self.admin_cq_addr();
                    self.process_admin();
                }
            }
            NVME_CQ0HDBL => {
                self.regs[NVME_CQ0HDBL as usize / 4] = val as u32;
                self.cq_head = val as u16
                    % self.admin_cq_entries.max(1) as u16;
            }
            off if off < NVME_REG_SIZE => {
                self.regs[off as usize / 4] = val as u32;
            }
            _ => {}
        }
    }

    fn admin_sq_addr(&self) -> u64 {
        (self.regs[NVME_ASQ as usize / 4 + 1] as u64) << 32
            | self.regs[NVME_ASQ as usize / 4] as u64
    }

    fn admin_cq_addr(&self) -> u64 {
        (self.regs[NVME_ACQ as usize / 4 + 1] as u64) << 32
            | self.regs[NVME_ACQ as usize / 4] as u64
    }

    pub fn alloc_doorbell_index(&mut self) -> u32 {
        self.next_doorbell += 1;
        self.next_doorbell
    }
}

// ---------------------------------------------------------------------------
// The ANS2 wrapper device
// ---------------------------------------------------------------------------

/// Sub-region layout inside the single attached span. Upstream maps four
/// MMIO regions from the ANS node's `reg` entries (indices 0,2,4,6); when the
/// machine attaches from the ADT it passes the real offsets/sizes, the
/// fallback path uses [`SubLayout::fallback`].
#[derive(Debug, Clone, Copy)]
pub struct SubLayout {
    pub rtkit_off: u64,
    pub rtkit_len: u64,
    pub ascv2_off: u64,
    pub ascv2_len: u64,
    pub autoboot_off: u64,
    pub autoboot_len: u64,
    pub vendor_off: u64,
    pub vendor_len: u64,
}

impl SubLayout {
    /// Layout for the 0x10000 fallback span.
    pub const fn fallback() -> Self {
        SubLayout {
            rtkit_off: 0x0000,
            rtkit_len: 0x2000,
            ascv2_off: 0x2000,
            ascv2_len: 0x2000,
            autoboot_off: 0x4000,
            autoboot_len: 0x2000,
            vendor_off: 0x8000,
            vendor_len: 0x8000,
        }
    }
}

/// Apple ANS2 controller: RTKit mailbox + ascv2/autoboot stubs + vendor regs
/// with the NVMe BAR aliased at vendor-block offset 0 (like upstream).
pub struct Ans2Nvme {
    layout: SubLayout,
    pub rtkit: Rtkit,
    pub nvme: NvmeCore,
    /// Vendor register array (sparse shadow; only in-block offsets).
    vendor: Vec<u32>,
    vendor_len: u64,
    /// `interrupt_pci` GPIO from the APCIE bridge (level).
    pub pci_irq_level: bool,
}

impl Ans2Nvme {
    /// No-arg constructor with the fallback sub-layout (0x10000 span).
    pub fn new() -> Self {
        Ans2Nvme::with_layout(SubLayout::fallback())
    }

    pub fn with_layout(layout: SubLayout) -> Self {
        let vendor_len = layout.vendor_len.min(NVME_APPLE_VENDOR_REG_SIZE);
        Ans2Nvme {
            layout,
            rtkit: Rtkit::new("ANS2", layout.rtkit_len),
            nvme: NvmeCore::new(),
            vendor: vec![0u32; vendor_len as usize / 4],
            vendor_len,
            pci_irq_level: false,
        }
    }

    /// Dispatch a vendor-block read (NVMe alias at 0 + AS-specific regs).
    fn vendor_read(&mut self, off: u64, size: u8) -> u64 {
        if off < NVME_REG_SIZE {
            return self.nvme.read(off, size);
        }
        match off {
            NVME_APPLE_MAX_PEND_CMDS => NVME_APPLE_MAX_PEND_CMDS_VAL as u64,
            NVME_APPLE_BOOT_STATUS => NVME_APPLE_BOOT_STATUS_OK as u64,
            NVME_APPLE_BASE_CMD_ID => 0x6000,
            NVME_APPLE_LINEAR_SQ_CTRL => {
                self.vendor[off as usize / 4] as u64
            }
            off if off < self.vendor_len => {
                self.vendor[off as usize / 4] as u64
            }
            _ => 0,
        }
    }

    fn vendor_write(&mut self, off: u64, size: u8, val: u64) {
        if off < NVME_REG_SIZE {
            self.nvme.write(off, size, val);
            return;
        }
        if off < self.vendor_len {
            self.vendor[off as usize / 4] = val as u32;
        }
    }
}

impl Device for Ans2Nvme {
    fn name(&self) -> &'static str {
        "ans2"
    }

    fn read(&mut self, off: u64, size: u8) -> u64 {
        let l = self.layout;
        if (l.rtkit_off..l.rtkit_off + l.rtkit_len).contains(&off) {
            self.rtkit.read(off - l.rtkit_off, size)
        } else if (l.ascv2_off..l.ascv2_off + l.ascv2_len).contains(&off) {
            // ascv2_core_reg_ops: RAZ
            0
        } else if (l.autoboot_off..l.autoboot_off + l.autoboot_len)
            .contains(&off)
        {
            // iop_autoboot_reg_ops: RAZ
            0
        } else if (l.vendor_off..l.vendor_off + l.vendor_len).contains(&off) {
            self.vendor_read(off - l.vendor_off, size)
        } else {
            0
        }
    }

    fn write(&mut self, off: u64, size: u8, val: u64) {
        let l = self.layout;
        if (l.rtkit_off..l.rtkit_off + l.rtkit_len).contains(&off) {
            self.rtkit.write(off - l.rtkit_off, size, val);
        } else if (l.ascv2_off..l.ascv2_off + l.ascv2_len).contains(&off) {
            // WI
        } else if (l.autoboot_off..l.autoboot_off + l.autoboot_len)
            .contains(&off)
        {
            // WI
        } else if (l.vendor_off..l.vendor_off + l.vendor_len).contains(&off) {
            self.vendor_write(off - l.vendor_off, size, val);
        }
    }

    fn tick(&mut self, now_ns: u64) {
        let _ = now_ns;
        // Drain RTKit user-EP messages (EP 0 = the ANS user EP upstream).
        let msgs = std::mem::take(&mut self.rtkit.user_msgs);
        for (ep, msg) in msgs {
            let _ = (ep, msg); // ANS_LOG_MSG upstream: logged only
        }
    }
}

impl Ans2Nvme {
    pub fn regs_documented() -> &'static [(&'static str, u64)] {
        &[
            ("NVME_CAP", NVME_CAP),
            ("NVME_VS", NVME_VS),
            ("NVME_CC", NVME_CC),
            ("NVME_CSTS", NVME_CSTS),
            ("NVME_AQA", NVME_AQA),
            ("NVME_ASQ", NVME_ASQ),
            ("NVME_ACQ", NVME_ACQ),
            ("NVME_SQ0TDBL", NVME_SQ0TDBL),
            ("NVME_CQ0HDBL", NVME_CQ0HDBL),
            ("NVME_ADMIN_IDENTIFY", NVME_ADMIN_IDENTIFY as u64),
            ("NVME_ADMIN_CREATE_SQ", NVME_ADMIN_CREATE_SQ as u64),
            ("NVME_ADMIN_CREATE_CQ", NVME_ADMIN_CREATE_CQ as u64),
            ("NVME_IO_READ", NVME_IO_READ as u64),
            (
                "NVME_APPLE_MAX_PEND_CMDS",
                NVME_APPLE_MAX_PEND_CMDS,
            ),
            (
                "NVME_APPLE_BOOT_STATUS",
                NVME_APPLE_BOOT_STATUS,
            ),
            ("NVME_APPLE_BOOT_STATUS_OK", NVME_APPLE_BOOT_STATUS_OK as u64),
            ("NVME_APPLE_BASE_CMD_ID", NVME_APPLE_BASE_CMD_ID),
            ("NVME_APPLE_MODESEL", NVME_APPLE_MODESEL),
            ("NVME_APPLE_LINEAR_SQ_CTRL", NVME_APPLE_LINEAR_SQ_CTRL),
        ]
    }
}

impl Default for Ans2Nvme {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an NVMe SQE (CID lives in dw1 = bytes 4..6).
    fn sqe(opcode: u8, cid: u16, prp1: u64, extra: &[u8]) -> [u8; 64] {
        let mut c = [0u8; 64];
        c[0] = opcode;
        c[4..6].copy_from_slice(&cid.to_le_bytes());
        c[8..16].copy_from_slice(&prp1.to_le_bytes());
        c[16..16 + extra.len()].copy_from_slice(extra);
        c
    }

    #[test]
    fn admin_identify_controller() {
        let mut ans = Ans2Nvme::new();
        let base = 0x8000_0000_0000u64;
        ans.nvme.set_dma_window(base);

        // program CC enable path: AQA: ASQS=1 (bits 27:16), ACQS=1 (31:24)
        ans.nvme.write(NVME_AQA, 4, (1 << 24) | (1 << 16));
        let sq = base;
        let cq = base + 0x1000;
        // ASQ / ACQ (64-bit, two 32-bit writes)
        let (lo, hi) = (sq as u32, (sq >> 32) as u32);
        ans.nvme.write(NVME_ASQ, 4, lo as u64);
        ans.nvme.write(NVME_ASQ + 4, 4, hi as u64);
        let (lo, hi) = (cq as u32, (cq >> 32) as u32);
        ans.nvme.write(NVME_ACQ, 4, lo as u64);
        ans.nvme.write(NVME_ACQ + 4, 4, hi as u64);
        ans.nvme.write(NVME_CC, 4, 1); // EN

        // submit IDENTIFY controller (CNS=0) at SQ slot 0
        let prp = base + 0x2000;
        let cmd = sqe(NVME_ADMIN_IDENTIFY, 0x42, prp, &{
            let mut e = [0u8; 8];
            e[0] = 0; // CNS
            e
        });
        let off = (sq - base) as usize;
        ans.nvme.qmem[off..off + 64].copy_from_slice(&cmd);
        ans.nvme.write(NVME_SQ0TDBL, 4, 1); // ring doorbell

        // CQE phase bit must be set (first completion)
        let cq_off = (cq - base) as usize;
        let status =
            u32::from_le_bytes(ans.nvme.qmem[cq_off + 12..cq_off + 16].try_into().unwrap());
        assert_eq!(status >> 16, 0x42, "cid");
        assert_eq!(status & 1, 1, "phase");
        assert_eq!(status & 0xFF, 0, "success");

        // identify data was written into the window
        let p = (prp - base) as usize;
        assert_eq!(&ans.nvme.qmem[p + 24..p + 36], b"ChefKiss-ANS");
        assert_eq!(ans.nvme.qmem[p + 77], 8); // mdts
        assert!(ans.op_census().iter().any(|(n, _)| *n == "identify"));
    }

    #[test]
    fn boot_status_and_max_pend() {
        let mut ans = Ans2Nvme::new();
        let v = ans
            .layout
            .vendor_off;
        assert_eq!(
            ans.read(v + NVME_APPLE_BOOT_STATUS, 4),
            NVME_APPLE_BOOT_STATUS_OK as u64
        );
        assert_eq!(
            ans.read(v + NVME_APPLE_MAX_PEND_CMDS, 4),
            NVME_APPLE_MAX_PEND_CMDS_VAL as u64
        );
        assert_eq!(ans.read(v + NVME_APPLE_BASE_CMD_ID, 4), 0x6000);
    }

    #[test]
    fn io_read_served_from_backend() {
        struct OneBlock;
        impl BlockBackend for OneBlock {
            fn read(&mut self, _lba: u64, bufs: &mut [u8]) -> bool {
                for (i, b) in bufs.iter_mut().enumerate() {
                    *b = (i % 251) as u8;
                }
                true
            }
        }
        let mut ans = Ans2Nvme::new();
        ans.nvme.backend = Box::new(OneBlock);
        let base = 0x8000_0000_0000u64;
        ans.nvme.set_dma_window(base);
        ans.nvme.write(NVME_AQA, 4, (1 << 24) | (1 << 16));
        let sq = base;
        let cq = base + 0x1000;
        let (lo, hi) = (sq as u32, (sq >> 32) as u32);
        ans.nvme.write(NVME_ASQ, 4, lo as u64);
        ans.nvme.write(NVME_ASQ + 4, 4, hi as u64);
        let (lo, hi) = (cq as u32, (cq >> 32) as u32);
        ans.nvme.write(NVME_ACQ, 4, lo as u64);
        ans.nvme.write(NVME_ACQ + 4, 4, hi as u64);
        ans.nvme.write(NVME_CC, 4, 1);

        // I/O READ: SLBA 0x10, NLB 0 → one 4096-byte block at PRP
        let prp = base + 0x4000;
        let mut extra = [0u8; 12];
        extra[0..8].copy_from_slice(&0x10u64.to_le_bytes()); // SLBA
        extra[8] = 0; // NLB low
        let cmd = sqe(NVME_IO_READ, 0x7, prp, &extra);
        let off = (sq - base) as usize;
        ans.nvme.qmem[off..off + 64].copy_from_slice(&cmd);
        ans.nvme.write(NVME_SQ0TDBL, 4, 1);

        let p = (prp - base) as usize;
        assert_eq!(ans.nvme.qmem[p], (0 % 251) as u8);
        assert_eq!(ans.nvme.qmem[p + 4095], (4095 % 251) as u8);
        let cq_off = (cq - base) as usize;
        let status = u32::from_le_bytes(
            ans.nvme.qmem[cq_off + 12..cq_off + 16].try_into().unwrap(),
        );
        assert_eq!(status & 0xFF, 0);
    }
}

impl Ans2Nvme {
    /// Test/parity helper.
    pub fn op_census(&self) -> &[(&'static str, u32)] {
        &self.nvme.op_census
    }
}
