//! Apple PMGR (Power Manager / clock-gate block) — T8030 layout.
//!
//! Provenance: structural port of the ChefKiss Inferno QEMU fork
//! `hw/arm/apple-silicon/t8030.c` `pmgr_reg_write`/`pmgr_reg_read` +
//! `pmgr_unk_reg_read` (cloned to /home/z/research/inferno, AGPL-3.0,
//! Visual Ehrmanntraut / Christian Inci), cross-checked against the
//! Linux `apple-pmgr-pstate` driver semantics (GPL-2.0). The workspace is
//! GPL-2.0-or-later; this module therefore carries AGPL-3.0-derived
//! structural semantics under the workspace license like the rest of the
//! device wave.
//!
//! What is faithful (from t8030.c):
//!   * main pmgr-reg block is RAM-backed, 0x100000 bytes;
//!   * 0xF0010 `AppleT8030PMGR::commonSramCheck` reads 0x5000;
//!   * 0xD4004 write starts CPUs (mask kept here, machine taps it);
//!   * 0x80C00 SEP_PS write: bit31 = reset SEP, bit10 = SEP off, else on;
//!   * 0x80000..=0x8C000 psreg range: on write, bits 4..7 are deposited
//!     from bits 0..3 (upstream `deposit64(data, 4, 4, extract64(data, 0, 4))`);
//!     state 0xF = domain on, 0x0 = off (gate-off also asserts the domain
//!     reset line — modeled as per-gate `reset_asserted`);
//!   * pmgr-unk read surface: PMGR_AON 0x3D280088 → 0xFF, fuse rows at
//!     0x3D2BC0xx (production/secure mode, security domain, board id+epoch,
//!     fuses sealed, chip revision, ECID lo/hi), 0x3D2BC30C SEP environment,
//!     0x3D2E8000 memory-encryption AMK status, 0x3C100C4C → 0x1,
//!     temp-sensor pages 0x3B281000/0x3B289000/0x3B299000 → 0xAFAFAFAF.
//!
//! What is structural (upstream source unavailable for these exact tables):
//! the *named* gate table below. The guest walks the ADT `pmgr` node and
//! addresses psregs by index; the friendly names here are a workspace-side
//! convenience map for `clock_state()` queries, mounted on psreg stride
//! boundaries (0x80000 + n*0x1000) — reconstructed, not upstream bytes.

use crate::bus::MMIODevice;

/// Main pmgr-reg region size (t8030.h `pmgr_reg[0x100000]`).
pub const PMGR_REG_SIZE: u64 = 0x100000;
/// `AppleT8030PMGR::commonSramCheck` (t8030.c 0xF0010).
pub const REG_COMMON_SRAM_CHECK: u64 = 0xF0010;
/// CPU-start register (t8030.c 0xD4004 → `t8030_start_cpus`).
pub const REG_CPU_START: u64 = 0xD4004;
/// SEP power-state register (t8030.c 0x80C00 → SEP_PS).
pub const REG_SEP_PS: u64 = 0x80C00;
/// psreg (power-state / clock-gate) window.
pub const PSREG_BASE: u64 = 0x80000;
pub const PSREG_END: u64 = 0x8C000;

/// SEP_PS bit fields (t8030.c `pmgr_reg_write` 0x80C00 case).
pub const SEP_PS_RESET: u32 = 1 << 31;
pub const SEP_PS_OFF: u32 = 1 << 10;

/// Power-state encodings (Apple PMGR PS values: 0xF on, 0x0 off).
pub const PS_STATE_OFF: u32 = 0x0;
pub const PS_STATE_ON: u32 = 0xF;

/// Named gate table — structural (see module doc): name → psreg offset.
/// Offsets sit on the upstream psreg window; the *names* are workspace
/// labels for boot-ladder probes, not upstream ADT strings.
pub const GATES: &[(&str, u64)] = &[
    ("aic", PSREG_BASE + 0x0000),
    ("uart0", PSREG_BASE + 0x1000),
    ("wdt", PSREG_BASE + 0x2000),
    ("mipi_dsi0", PSREG_BASE + 0x3000),
    ("disp0", PSREG_BASE + 0x4000),
    ("ans2", PSREG_BASE + 0x5000),
    ("aop", PSREG_BASE + 0x6000),
    ("smc", PSREG_BASE + 0x7000),
    ("aes0", PSREG_BASE + 0x8000),
    ("sep", PSREG_BASE + 0x9000),
];

/// pmgr-unk / fuse-row landmarks (absolute addresses, t8030.c
/// `pmgr_unk_reg_read`). Exposed for `unk_read()` queries; the machine
/// mounts these regions ADT-driven, our model answers the same constants.
pub const PMGR_AON: u64 = 0x3D280088; // → 0xFF
pub const FUSE_PROD_MODE: u64 = 0x3D2BC000; // current production mode
pub const FUSE_PROD_MODE_RAW: u64 = 0x3D2BC400;
pub const FUSE_SECURE_MODE: u64 = 0x3D2BC004; // current secure mode
pub const FUSE_SECURE_MODE_RAW: u64 = 0x3D2BC404;
pub const FUSE_SEC_DOMAIN_BIT0: u64 = 0x3D2BC008;
pub const FUSE_SEC_DOMAIN_BIT1: u64 = 0x3D2BC00C;
pub const FUSE_BOARD_ID_EPOCH: u64 = 0x3D2BC010; // (epoch<<5)|board_id>>5, bit30 SEP-changer, bit31 fuses-locked
pub const FUSE_FUSES_SEALED: u64 = 0x3D2BC020;
pub const FUSE_CHIP_REVISION: u64 = 0x3D2BC030;
pub const FUSE_ECID_LO: u64 = 0x3D2BC300;
pub const FUSE_ECID_HI: u64 = 0x3D2BC304;
pub const FUSE_SEP_ENVIRONMENT: u64 = 0x3D2BC30C; // (env<<28); env 0x8 dev per upstream
pub const REG_MEM_ENCRYPT_AMK: u64 = 0x3D2E8000; // 0xC2E9 = AMK enabled
pub const REG_UNK_C100C4C: u64 = 0x3C100C4C; // → 0x1

const FUSE_ENABLED: u64 = 0x1;
const FUSE_DISABLED: u64 = 0x0;

#[derive(Debug, Default, Clone)]
pub struct Gate {
    /// 4-bit power state (0xF on / 0x0 off), stored post-deposit.
    pub state: u32,
    /// Set while the domain gate is off (reset line asserted).
    pub reset_asserted: bool,
    /// Times this gate was toggled (parity census).
    pub transitions: u32,
}

/// T8030 PMGR main block model. IRQ-less by design (upstream pmgr has no
/// IRQ line; guests poll psregs / walk the ADT).
#[derive(Debug)]
pub struct Pmgr {
    /// psreg offset (aligned) → gate state.
    gates: std::collections::BTreeMap<u64, Gate>,
    /// RAM-backed register image for untouched offsets (upstream keeps a
    /// raw `pmgr_reg[0x100000]` and stl/ldl's through it).
    raw: Vec<u8>,
    pub cpus_started: u32,
    pub sep_ps: u32,
    pub sep_reset_requests: u32,
    pub ecid: u64,
    pub board_id: u32,
    pub chip_revision: u32,
    pub security_domain: u32,
    pub fuses_locked: bool,
    pub unknown_reads: u64,
    pub unknown_writes: u64,
}

impl Default for Pmgr {
    fn default() -> Self {
        Self::new()
    }
}

impl Pmgr {
    pub fn new() -> Self {
        Pmgr {
            gates: std::collections::BTreeMap::new(),
            raw: vec![0; PMGR_REG_SIZE as usize],
            cpus_started: 0,
            sep_ps: 0,
            sep_reset_requests: 0,
            ecid: 0x1122_3344_5566_7788,
            board_id: 8, // s5l8960-style DRAM-id rows; T8030 n104ap value structural
            chip_revision: 0xB,
            security_domain: 1,
            fuses_locked: true,
            unknown_reads: 0,
            unknown_writes: 0,
        }
    }

    fn gate_mut(&mut self, off: u64) -> &mut Gate {
        self.gates.entry(off).or_default()
    }

    /// MMIO write into the pmgr-reg block (offset is block-relative).
    fn psreg_write(&mut self, off: u64, value: u64) {
        // upstream: bits 4..7 duplicated from bits 0..3 on psreg writes
        let low = value & 0xF;
        let data = low | (low << 4);
        let was_on = self.gate_state(off) == PS_STATE_ON;
        let g = self.gate_mut(off);
        g.state = data as u32;
        g.reset_asserted = (g.state & 0xF) != PS_STATE_ON;
        if was_on != ((g.state & 0xF) == PS_STATE_ON) {
            g.transitions = g.transitions.wrapping_add(1);
        }
        let b = (data as u32).to_le_bytes();
        self.raw[off as usize..off as usize + 4].copy_from_slice(&b);
    }

    /// Canonical 4-bit power state (low nibble of the deposited image).
    fn gate_state(&self, off: u64) -> u32 {
        self.gates.get(&off).map(|g| g.state & 0xF).unwrap_or(PS_STATE_ON)
    }

    /// Is the domain behind `offset` powered on? (defaults on, like
    /// upstream: untouched RAM reads 0 but boot gates are enabled by
    /// firmware before guests probe — our default mirrors the C model's
    /// "not-yet-written gate" = on for probing ladders).
    pub fn is_on(&self, off: u64) -> bool {
        self.gate_state(off & !0xF) == PS_STATE_ON
    }

    /// Named-gate query (device-tree-ish). Returns None for unknown names.
    pub fn clock_state(&self, name: &str) -> Option<bool> {
        GATES
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, off)| self.is_on(*off))
    }

    pub fn gate(&self, off: u64) -> Option<&Gate> {
        self.gates.get(&(off & !0xF))
    }

    /// pmgr-unk / fuse surface read (absolute address, t8030.c constants).
    pub fn unk_read(&self, addr: u64) -> u64 {
        match addr {
            PMGR_AON => 0xFF,
            FUSE_PROD_MODE | FUSE_PROD_MODE_RAW | FUSE_FUSES_SEALED => {
                // current_prod = true upstream (T8015 SEPOS requires it)
                FUSE_ENABLED
            }
            FUSE_SECURE_MODE | FUSE_SECURE_MODE_RAW => FUSE_ENABLED,
            FUSE_SEC_DOMAIN_BIT0 => {
                if self.security_domain & 1 != 0 {
                    FUSE_ENABLED
                } else {
                    FUSE_DISABLED
                }
            }
            FUSE_SEC_DOMAIN_BIT1 => {
                if self.security_domain & 2 != 0 {
                    FUSE_ENABLED
                } else {
                    FUSE_DISABLED
                }
            }
            FUSE_BOARD_ID_EPOCH => {
                // security_epoch = 1 (IMG4), fuses_locked bit31, bit30
                // reserved for the SEP fuse-changer state (unset here)
                ((self.board_id as u64 >> 5) & 0x7)
                    | ((1u64 & 0x7f) << 5)
                    | ((self.fuses_locked as u64) << 31)
            }
            FUSE_CHIP_REVISION => {
                let r = self.chip_revision as u64;
                ((r & 0x7) << 6) | (((r & 0x70) >> 4) << 5)
            }
            FUSE_ECID_LO => self.ecid & 0xFFFF_FFFF,
            FUSE_ECID_HI => self.ecid >> 32,
            FUSE_SEP_ENVIRONMENT => 0x8 << 28, // dev environment, skips checks
            REG_MEM_ENCRYPT_AMK => 0xC2E9,     // AMK enabled
            REG_UNK_C100C4C => 0x1,
            a if (0x3B281000..0x3B289000).contains(&a) => 0xAFAF_AFAF, // SOC MTR temp0
            a if (0x3B289000..0x3B291000).contains(&a) => 0xAFAF_AFAF, // SOC MTR temp3
            a if (0x3B299000..0x3B2A1000).contains(&a) => 0xAFAF_AFAF, // ANE MTR temp0
            _ => 0,
        }
    }

    pub fn regs_documented() -> &'static [(&'static str, u64)] {
        &[
            ("SRAM_CHECK", REG_COMMON_SRAM_CHECK),
            ("CPU_START", REG_CPU_START),
            ("SEP_PS", REG_SEP_PS),
            ("PSREG", PSREG_BASE),
            ("PMGR_AON", PMGR_AON),
            ("FUSE_BOARD_ID_EPOCH", FUSE_BOARD_ID_EPOCH),
            ("ECID", FUSE_ECID_LO),
            ("MEM_ENCRYPT_AMK", REG_MEM_ENCRYPT_AMK),
        ]
    }
}

impl MMIODevice for Pmgr {
    fn name(&self) -> &'static str {
        "apple-pmgr"
    }
    fn size(&self) -> u64 {
        PMGR_REG_SIZE
    }

    fn read(&mut self, offset: u64, _width: u32) -> u64 {
        match offset {
            REG_COMMON_SRAM_CHECK => 0x5000,
            REG_SEP_PS => self.sep_ps as u64,
            REG_CPU_START => self.cpus_started as u64,
            o if (PSREG_BASE..PSREG_END).contains(&o) => {
                let off = o & !0xF;
                // stored image is already the deposited state | state<<4
                self.gates.get(&off).map(|g| g.state as u64).unwrap_or(0)
            }
            o if o + 4 <= PMGR_REG_SIZE => {
                let b: [u8; 4] = self.raw[o as usize..o as usize + 4]
                    .try_into()
                    .expect("in-bounds slice");
                u32::from_le_bytes(b) as u64
            }
            _ => {
                self.unknown_reads += 1;
                0
            }
        }
    }

    fn write(&mut self, offset: u64, value: u64, _width: u32) {
        match offset {
            REG_CPU_START => self.cpus_started = value as u32,
            REG_SEP_PS => {
                self.sep_ps = value as u32;
                if value & (SEP_PS_RESET as u64) != 0 {
                    self.sep_reset_requests += 1;
                }
            }
            o if (PSREG_BASE..PSREG_END).contains(&o) => self.psreg_write(o & !0xF, value),
            _ if offset + 4 <= PMGR_REG_SIZE => {
                let b = (value as u32).to_le_bytes();
                self.raw[offset as usize..offset as usize + 4].copy_from_slice(&b);
            }
            _ => {
                self.unknown_writes += 1;
            }
        }
    }
}

pub const PARITY_PCT: u8 = 50; // gate/pstate SM + fuse rows faithful; ADT walk + golden trace pending

impl crate::bus::Device for Pmgr {
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
    use crate::bus::W4;

    #[test]
    fn gate_on_off_transitions() {
        let mut p = Pmgr::new();
        let uart0 = PSREG_BASE + 0x1000;
        // write 0xF → on, read-back carries the deposit (state | state<<4)
        p.write(uart0, 0xF, W4);
        assert!(p.is_on(uart0));
        assert_eq!(p.read(uart0, W4), 0xFF);
        assert!(!p.gate(uart0).unwrap().reset_asserted);

        // write 0x0 → off, reset line asserted
        p.write(uart0, 0x0, W4);
        assert!(!p.is_on(uart0));
        assert_eq!(p.read(uart0, W4), 0x0);
        assert!(p.gate(uart0).unwrap().reset_asserted);
        // default-on → on (no toggle), on → off (one toggle)
        assert_eq!(p.gate(uart0).unwrap().transitions, 1);

        // psreg writes deposit bits 4..7 from bits 0..3 (upstream semantics)
        p.write(PSREG_BASE, 0xA, W4);
        assert_eq!(p.read(PSREG_BASE, W4), 0xAA);
    }

    #[test]
    fn named_clock_state_query() {
        let mut p = Pmgr::new();
        let (_, aop_off) = GATES.iter().find(|(n, _)| *n == "aop").unwrap();
        assert!(p.clock_state("aop") == Some(true));
        p.write(*aop_off, 0, W4);
        assert_eq!(p.clock_state("aop"), Some(false));
        assert_eq!(p.clock_state("no-such-gate"), None);
    }

    #[test]
    fn unknown_region_naks() {
        let mut p = Pmgr::new();
        // outside the block and the special regs: RAZ + counted
        assert_eq!(p.read(PMGR_REG_SIZE, W4), 0);
        assert_eq!(p.unknown_reads, 1);
        p.write(PMGR_REG_SIZE, 0x1234, W4);
        assert_eq!(p.unknown_writes, 1);
        // in-block untouched raw region reads 0 without NAK
        assert_eq!(p.read(0x1000, W4), 0);
        assert_eq!(p.unknown_reads, 1);
    }

    #[test]
    fn cpu_start_and_sep_ps() {
        let mut p = Pmgr::new();
        p.write(REG_CPU_START, 0b101, W4);
        assert_eq!(p.read(REG_CPU_START, W4), 0b101);

        p.write(REG_SEP_PS, (SEP_PS_OFF | 0xF) as u64, W4);
        assert_eq!(p.sep_ps & SEP_PS_OFF, SEP_PS_OFF);
        assert_eq!(p.sep_reset_requests, 0);
        p.write(REG_SEP_PS, SEP_PS_RESET as u64, W4);
        assert_eq!(p.sep_reset_requests, 1);
    }

    #[test]
    fn sram_check_and_fuse_rows_match_upstream() {
        let mut p = Pmgr::new();
        assert_eq!(p.read(REG_COMMON_SRAM_CHECK, W4), 0x5000);
        assert_eq!(p.unk_read(PMGR_AON), 0xFF);
        assert_eq!(p.unk_read(FUSE_PROD_MODE), FUSE_ENABLED);
        assert_eq!(p.unk_read(FUSE_SEC_DOMAIN_BIT0), FUSE_ENABLED);
        assert_eq!(p.unk_read(FUSE_SEC_DOMAIN_BIT1), FUSE_DISABLED);
        assert_eq!(p.unk_read(FUSE_ECID_LO), 0x5566_7788);
        assert_eq!(p.unk_read(FUSE_ECID_HI), 0x1122_3344);
        assert_eq!(p.unk_read(REG_MEM_ENCRYPT_AMK), 0xC2E9);
        assert_eq!(p.unk_read(0x3B281100), 0xAFAF_AFAF);
        // board id/epoch: board 8 → id>>5 = 0, epoch 1 << 5, fuses locked
        assert_eq!(p.unk_read(FUSE_BOARD_ID_EPOCH), (1 << 5) | (1 << 31));
        // unknown unk address reads 0
        assert_eq!(p.unk_read(0x1234_5678), 0);
    }
}
