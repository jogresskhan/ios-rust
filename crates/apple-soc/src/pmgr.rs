//! pmgr — T8030 Power Management Unit (register file) and PMGR fuse /
//! "unk" windows.
//!
//! Faithful Rust port of the PMGR regions implemented inside ChefKiss
//! Inferno `hw/arm/apple-silicon/t8030.c` (`pmgr_reg_ops`,
//! `pmgr_unk_reg_ops`, `t8030_pmgr_setup`; AGPL-3.0, © 2024-2026 Visual
//! Ehrmanntraut, Christian Inci).
//!
//! The C keeps the main PMGR as a raw 0x100000 register file with a
//! handful of special offsets and the fuse window as absolute-address
//! switch cases. Both are ported verbatim:
//!
//! * [`Pmgr`] — main `pmgr-reg` window:
//!   - write `0xD4004` → `t8030_start_cpus(data)` (CPU wake mask; *not*
//!     stored, like the C's early `return`)
//!   - write `0x80C00` → SEP_PS (bit31 reset / bit10 off / else on)
//!   - write in `0x80000..=0x8C000` → low nibble replicated to bits 4..8
//!     (and the high word for 8-byte stores), the C's deposit quirk
//!   - read `0xF0010` → `0x5000` (commonSramCheck)
//! * [`PmgrUnk`] — every other PMGR sub-window (fuses, ECID, SEP locks,
//!   temp sensors...). It takes the window's absolute SoC base in the
//!   constructor so the C's absolute switch cases keep working:
//!   fuse rows at 0x3D2BC000.., ECID 0x3D2BC300/304, SEP lock bits
//!   0x3D2E4800, memory-encryption block 0x3D2E4000..0x4180,
//!   0x3D2E8000 (AMK state), PMGR_AON 0x3D280088, MTR temp sensors
//!   0x3B281000/0x3B289000/0x3B299000 (+0x8000), 0x10E7xxxx clock-gate
//!   probe row, 0x3C100C4C.
//!
//! The `voltage-states*` DT properties from `t8030-config.c.inc` are
//! devicetree blobs, not MMIO — out of scope for the device model.

use vm_core::Device;

pub const FUSE_ENABLED: u32 = 0xA55A_C33C;
pub const FUSE_DISABLED: u32 = 0xA050_C030;

pub const PMGR_REG_SIZE: u64 = 0x100_000;

// Main-window special offsets (t8030.c pmgr_reg_write/read).
pub const PMGR_CPU_START: u64 = 0xD4004;
pub const PMGR_SEP_PS: u64 = 0x80C00;
pub const PMGR_SRAM_CHECK: u64 = 0xF0010;
pub const PMGR_CLKGATE_LO: u64 = 0x80000;
pub const PMGR_CLKGATE_HI: u64 = 0x8C000;

// Absolute addresses of the fuse/unk switch cases (t8030.c).
pub const P_AON_3D280088: u64 = 0x3D28_0088;
pub const P_CUR_PROD: u64 = 0x3D2B_C000;
pub const P_CUR_SECURE: u64 = 0x3D2B_C004;
pub const P_CUR_SD_BIT0: u64 = 0x3D2B_C008;
pub const P_RAW_SD_BIT0: u64 = 0x3D2B_C408;
pub const P_CUR_SD_BIT1: u64 = 0x3D2B_C00C;
pub const P_RAW_SD_BIT1: u64 = 0x3D2B_C40C;
pub const P_CUR_BOARD_EPOCH: u64 = 0x3D2B_C010;
pub const P_RAW_BOARD_EPOCH: u64 = 0x3D2B_C410;
pub const P_RAW_PROD: u64 = 0x3D2B_C400;
pub const P_RAW_SECURE: u64 = 0x3D2B_C404;
pub const P_FUSES_SEALED: u64 = 0x3D2B_C020;
pub const P_UNK_2C: u64 = 0x3D2B_C02C;
pub const P_CHIP_REVISION: u64 = 0x3D2B_C030;
pub const P_ECID_LOW: u64 = 0x3D2B_C300;
pub const P_ECID_HIGH: u64 = 0x3D2B_C304;
pub const P_SEP_CHIP_REV: u64 = 0x3D2B_C30C;
pub const P_SEP_LOCKS: u64 = 0x3D2E_4800;
pub const P_SEP_LOCKS_HI: u64 = 0x3D2E_4804;
pub const P_SEP_ENC_BASE: u64 = 0x3D2E_4000;
pub const P_SEP_ENC_END: u64 = 0x3D2E_4180;
pub const P_AMK_STATE: u64 = 0x3D2E_8000;
pub const P_3C100C4C: u64 = 0x3C10_0C4C;
pub const P_MTR_SOC0: u64 = 0x3B28_1000;
pub const P_MTR_SOC3: u64 = 0x3B28_9000;
pub const P_MTR_ANE0: u64 = 0x3B29_9000;
pub const P_MTR_SIZE: u64 = 0x8000;

/// SEP_PS power action decoded from the `0x80C00` write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SepPs {
    On,
    Off,
    Reset,
}

/// T8030 main PMGR register file.
#[derive(Debug)]
pub struct Pmgr {
    reg: Vec<u8>,
    /// CPU wake mask from the `0xD4004` write (`t8030_start_cpus`).
    pub cpu_start_request: u32,
    /// Last SEP_PS action from the `0x80C00` write.
    pub sep_ps: Option<SepPs>,
    pub unknown_reads: u64,
    pub unknown_writes: u64,
}

impl Pmgr {
    pub fn new() -> Self {
        Pmgr {
            reg: vec![0; PMGR_REG_SIZE as usize],
            cpu_start_request: 0,
            sep_ps: None,
            unknown_reads: 0,
            unknown_writes: 0,
        }
    }

    fn load_le(&self, addr: usize, size: u8) -> u64 {
        let mut v: u64 = 0;
        for i in 0..size as usize {
            if addr + i < self.reg.len() {
                v |= (self.reg[addr + i] as u64) << (8 * i);
            }
        }
        v
    }

    fn store_le(&mut self, addr: usize, size: u8, val: u64) {
        for i in 0..size as usize {
            if addr + i < self.reg.len() {
                self.reg[addr + i] = (val >> (8 * i)) as u8;
            }
        }
    }

    /// Deposit `data[0..4)` into `data[4..8)` (and +32 for 8-byte
    /// stores) — the C's clock-gate write quirk.
    fn clkgate_quirk(data: u64, size: u8) -> u64 {
        let mut d = (data & !0xF0) | ((data & 0xF) << 4);
        if size == 8 {
            let hi = d >> 32;
            d = (d & 0xFFFF_FFFF) | (((hi & !0xF0) | ((hi & 0xF) << 4)) << 32);
        }
        d
    }
}

impl Default for Pmgr {
    fn default() -> Self {
        Self::new()
    }
}

impl Device for Pmgr {
    fn name(&self) -> &'static str {
        "pmgr"
    }

    fn read(&mut self, off: u64, size: u8) -> u64 {
        if off >= PMGR_REG_SIZE {
            self.unknown_reads += 1;
            return 0;
        }
        if off == PMGR_SRAM_CHECK {
            // AppleT8030PMGR::commonSramCheck
            return 0x5000;
        }
        self.load_le(off as usize, size.max(1).min(8))
    }

    fn write(&mut self, off: u64, size: u8, val: u64) {
        if off >= PMGR_REG_SIZE {
            self.unknown_writes += 1;
            return;
        }
        if off == PMGR_CPU_START {
            // t8030_start_cpus(t8030, data); return;
            self.cpu_start_request = val as u32;
            return;
        }
        if off == PMGR_SEP_PS {
            if val & (1u64 << 31) != 0 {
                self.sep_ps = Some(SepPs::Reset);
            } else if val & (1u64 << 10) != 0 {
                self.sep_ps = Some(SepPs::Off);
            } else {
                self.sep_ps = Some(SepPs::On);
            }
        }

        let mut data = val;
        if (PMGR_CLKGATE_LO..=PMGR_CLKGATE_HI).contains(&off) {
            data = Self::clkgate_quirk(data, size);
        }
        self.store_le(off as usize, size.max(1).min(8), data);
    }
}

/// One of the secondary PMGR windows that share `pmgr_unk_reg_ops`
/// (fuses, SEP locks, temp sensors...). The C matches on the absolute
/// SoC address, so this struct stores the window's absolute base.
#[derive(Debug)]
pub struct PmgrUnk {
    base: u64,
    /// `pmgr_unk_e4800` (SEP lock bits, 64-bit).
    pub sep_locks: u64,
    /// `pmgr_unk_e4000` array (SEP memory-encryption block).
    pub sep_enc: [u32; 0x180 / 4],
    // Fuse inputs (machine-provided identity values).
    pub board_id: u32,
    pub chip_revision: u32,
    pub ecid: u64,
    pub security_epoch: u32,
    pub current_prod: bool,
    pub raw_prod: bool,
    pub current_secure_mode: bool,
    pub raw_secure_mode: bool,
    pub security_domain: u32,
    pub fuses_locked: bool,
    /// SEP fuse-changer bits (driven by sep-sim in the C).
    pub pmgr_fuse_changer_bit0_was_set: bool,
    pub pmgr_fuse_changer_bit1_was_set: bool,
    pub unknown_reads: u64,
    pub unknown_writes: u64,
}

impl PmgrUnk {
    /// `base` is the window's absolute MMIO base (e.g. 0x3BC00000 for
    /// pmp-reg, or the DT `reg[i]` for `pmgr-unk-reg-i`).
    pub fn new(base: u64) -> Self {
        PmgrUnk {
            base,
            sep_locks: 0,
            sep_enc: [0; 0x180 / 4],
            board_id: 0,
            chip_revision: 0,
            ecid: 0,
            security_epoch: 1, // IMG4: Security Epoch
            current_prod: true,
            raw_prod: true,
            current_secure_mode: true,
            raw_secure_mode: true,
            security_domain: 1,
            fuses_locked: true,
            pmgr_fuse_changer_bit0_was_set: false,
            pmgr_fuse_changer_bit1_was_set: false,
            unknown_reads: 0,
            unknown_writes: 0,
        }
    }

    fn abs(&self, off: u64) -> u64 {
        self.base.wrapping_add(off)
    }
}

impl Device for PmgrUnk {
    fn name(&self) -> &'static str {
        "pmgr-unk"
    }

    fn read(&mut self, off: u64, size: u8) -> u64 {
        let _ = size;
        match self.abs(off) {
            P_AON_3D280088 => 0xFF,
            P_CUR_PROD => {
                if self.current_prod {
                    FUSE_ENABLED as u64
                } else {
                    FUSE_DISABLED as u64
                }
            }
            P_RAW_PROD => {
                if self.raw_prod {
                    FUSE_ENABLED as u64
                } else {
                    FUSE_DISABLED as u64
                }
            }
            P_CUR_SECURE => {
                // SEP DSEC img4 tag demotion can clear this at runtime.
                if self.current_secure_mode {
                    FUSE_ENABLED as u64
                } else {
                    FUSE_DISABLED as u64
                }
            }
            P_RAW_SECURE => {
                if self.raw_secure_mode {
                    FUSE_ENABLED as u64
                } else {
                    FUSE_DISABLED as u64
                }
            }
            P_CUR_SD_BIT0 | P_RAW_SD_BIT0 => {
                if self.security_domain & 1 == 0 {
                    FUSE_DISABLED as u64
                } else {
                    FUSE_ENABLED as u64
                }
            }
            P_CUR_SD_BIT1 | P_RAW_SD_BIT1 => {
                if self.security_domain & 2 == 0 {
                    FUSE_DISABLED as u64
                } else {
                    FUSE_ENABLED as u64
                }
            }
            P_CUR_BOARD_EPOCH => {
                let sep_bit30 = if self.pmgr_fuse_changer_bit0_was_set {
                    1u32 << 30
                } else {
                    0
                };
                (((self.board_id >> 5) & 0x7)
                    | ((self.security_epoch & 0x7f) << 5)
                    | sep_bit30
                    | (if self.fuses_locked { 1u32 << 31 } else { 0 }))
                    as u64
            }
            P_RAW_BOARD_EPOCH => {
                // bit 30 stays unset on the raw view.
                (((self.board_id >> 5) & 0x7)
                    | ((self.security_epoch & 0x7f) << 5)
                    | (if self.fuses_locked { 1u32 << 31 } else { 0 }))
                    as u64
            }
            P_FUSES_SEALED => {
                if self.current_prod {
                    FUSE_ENABLED as u64
                } else {
                    FUSE_DISABLED as u64
                }
            }
            P_UNK_2C => (0u32 << 31 | 1 << 30) as u64, // bit31 causes a panic
            P_CHIP_REVISION => {
                (((self.chip_revision & 0x7) << 6)
                    | (((self.chip_revision & 0x70) >> 4) << 5)
                    | (0 << 1)) as u64
            }
            P_ECID_LOW => self.ecid & 0xFFFF_FFFF,
            P_ECID_HIGH => (self.ecid >> 32) & 0xFFFF_FFFF,
            // T8030 SEP chip revision environment (0x8 == "2", dev value
            // that skips a few checks) — see the C comment.
            P_SEP_CHIP_REV => (0x8u64 << 28),
            P_AMK_STATE => 0xC2E9, // memory-encryption AMK enabled
            P_SEP_LOCKS => self.sep_locks & 0xFFFF_FFFF,
            P_SEP_LOCKS_HI => (self.sep_locks >> 32) & 0xFFFF_FFFF,
            a if (P_SEP_ENC_BASE..=P_SEP_ENC_END).contains(&a) => {
                self.sep_enc[((a - P_SEP_ENC_BASE) / 4) as usize] as u64
            }
            a if (P_MTR_SOC0..P_MTR_SOC0 + P_MTR_SIZE).contains(&a) => 0xAFAF_AFAF,
            a if (P_MTR_SOC3..P_MTR_SOC3 + P_MTR_SIZE).contains(&a) => 0xAFAF_AFAF,
            a if (P_MTR_ANE0..P_MTR_ANE0 + P_MTR_SIZE).contains(&a) => 0xAFAF_AFAF,
            a if a & 0xFFFF_FFFB == 0x10E2_0020 => 0, // (logged-only in C)
            a if a & 0x10E7_0000 == 0x10E7_0000 => (108 << 4) | 0x20_0000,
            P_3C100C4C => 0x1,
            _ => {
                self.unknown_reads += 1;
                0
            }
        }
    }

    fn write(&mut self, off: u64, size: u8, data: u64) {
        match self.abs(off) {
            P_SEP_LOCKS => {
                self.sep_locks = (self.sep_locks & !0xFFFF_FFFF) | (data & 0xFFFF_FFFF);
            }
            P_SEP_LOCKS_HI => {
                self.sep_locks =
                    (self.sep_locks & 0xFFFF_FFFF) | ((data & 0xFFFF_FFFF) << 32);
            }
            a if (P_SEP_ENC_BASE..P_SEP_ENC_END).contains(&a) => {
                let i = ((a - P_SEP_ENC_BASE) / 4) as usize;
                if i < self.sep_enc.len() {
                    self.sep_enc[i] = (data & 0xFFFF_FFFF) as u32;
                    if size == 8 && i + 1 < self.sep_enc.len() {
                        self.sep_enc[i + 1] = ((data >> 32) & 0xFFFF_FFFF) as u32;
                    }
                }
            }
            _ => self.unknown_writes += 1,
        }
    }
}

pub fn regs_documented() -> &'static [(&'static str, u64)] {
    &[
        ("PMGR_CPU_START (t8030_start_cpus)", PMGR_CPU_START),
        ("PMGR_SEP_PS", PMGR_SEP_PS),
        ("PMGR_SRAM_CHECK", PMGR_SRAM_CHECK),
        ("PMGR_CLKGATE range", PMGR_CLKGATE_LO),
        ("PMGR_AON", P_AON_3D280088),
        ("FUSE current production", P_CUR_PROD),
        ("FUSE raw production", P_RAW_PROD),
        ("FUSE current secure", P_CUR_SECURE),
        ("FUSE raw secure", P_RAW_SECURE),
        ("FUSE security domain bit0", P_CUR_SD_BIT0),
        ("FUSE security domain bit1", P_CUR_SD_BIT1),
        ("FUSE board id + epoch (cur)", P_CUR_BOARD_EPOCH),
        ("FUSE board id + epoch (raw)", P_RAW_BOARD_EPOCH),
        ("FUSE sealed", P_FUSES_SEALED),
        ("FUSE unk 0x2C", P_UNK_2C),
        ("FUSE chip revision", P_CHIP_REVISION),
        ("FUSE ECID low", P_ECID_LOW),
        ("FUSE ECID high", P_ECID_HIGH),
        ("FUSE SEP chip revision", P_SEP_CHIP_REV),
        ("SEP lock bits", P_SEP_LOCKS),
        ("SEP mem-encryption block", P_SEP_ENC_BASE),
        ("AMK state", P_AMK_STATE),
        ("MTR temp sensor SOC0", P_MTR_SOC0),
        ("MTR temp sensor SOC3", P_MTR_SOC3),
        ("MTR temp sensor ANE0", P_MTR_ANE0),
        ("pmp 0x3C100C4C", P_3C100C4C),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sram_check_and_cpu_start() {
        let mut p = Pmgr::new();
        assert_eq!(p.read(PMGR_SRAM_CHECK, 4), 0x5000);
        p.write(PMGR_CPU_START, 4, 0b111111);
        assert_eq!(p.cpu_start_request, 0b111111);
        // not stored in the register file
        assert_eq!(p.read(PMGR_CPU_START, 4), 0);
        // SEP_PS decodes
        p.write(PMGR_SEP_PS, 4, 1 << 31);
        assert_eq!(p.sep_ps, Some(SepPs::Reset));
        p.write(PMGR_SEP_PS, 4, 1 << 10);
        assert_eq!(p.sep_ps, Some(SepPs::Off));
        p.write(PMGR_SEP_PS, 4, 1);
        assert_eq!(p.sep_ps, Some(SepPs::On));
    }

    #[test]
    fn clkgate_nibble_replication() {
        let mut p = Pmgr::new();
        p.write(0x80100, 4, 0x0000_00A5);
        // low nibble (5) replicated into bits 4..8: 0xA5 -> 0x55
        assert_eq!(p.read(0x80100, 4), 0x55);
        p.write(0x80100, 4, 0x0000_000A);
        assert_eq!(p.read(0x80100, 4), 0xAA);
        // Outside the range there is no quirk.
        p.write(0x90000, 4, 0x0000_00A5);
        assert_eq!(p.read(0x90000, 4), 0xA5);
    }

    #[test]
    fn fuse_row_values() {
        let mut u = PmgrUnk::new(0);
        u.board_id = 8; // (8>>5)&7 = 0
        u.chip_revision = 0x31; // A13 bionic rev
        u.ecid = 0x1122334455667788;
        assert_eq!(u.read(P_CUR_PROD, 4), FUSE_ENABLED as u64);
        assert_eq!(u.read(P_CUR_SECURE, 4), FUSE_ENABLED as u64);
        assert_eq!(u.read(P_ECID_LOW, 4), 0x5566_7788);
        assert_eq!(u.read(P_ECID_HIGH, 4), 0x1122_3344);
        let epoch = u.read(P_RAW_BOARD_EPOCH, 4) as u32;
        assert_eq!(epoch >> 31, 1, "fuses locked");
        assert_eq!(epoch >> 5 & 0x7f, 1, "security epoch");
        // Chip revision packing: (rev&7)<<6 | ((rev&0x70)>>4)<<5
        let cr = u.read(P_CHIP_REVISION, 4) as u32;
        assert_eq!(cr, (1 << 6) | (3 << 5));
    }

    #[test]
    fn temp_sensors_and_clockgate_probe() {
        let mut u = PmgrUnk::new(0);
        assert_eq!(u.read(P_MTR_SOC0 + 0x100, 4), 0xAFAF_AFAF);
        assert_eq!(u.read(0x10E7_0010, 4), (108 << 4) | 0x20_0000);
        assert_eq!(u.read(P_AON_3D280088, 4), 0xFF);
    }
}
