//! interp — the A13 interpreter backend (always-built CpuBackend).
//!
//! Executes the [`crate::decode`] subset over a [`MemAccess`] (usually the
//! machine Bus). Unknown words STOP with `StopReason::UnknownInsn` — never
//! silently skipped (matches the lib.rs contract and Inferno's honesty
//! rules). SVC stops with `Panic` (kernel-panic hook); HLT halts cleanly;
//! barriers are no-ops.
//!
//! v8.1–v8.5 extension surface (the `soc_t8030::CPU_INSTRUCTIONS` groups):
//! LSE atomics + CAS, scalar/vector RDM, FCMA/FCADD, JSCVT, FP16
//! (scalar + vector), DOTPROD, SHA512/SHA3/SM3/SM4/AES/PMULL, CRC32,
//! PAC (QARMA model), BTI/DGH hints, TLBI range, AMUv1/MPAM/ID system
//! registers — each execution bumps [`Interpreter::group_exec`] so the
//! parity ledger can *measure* coverage per group.

use crate::crypto;
use crate::decode::*;
use crate::mmu::{Mmu, XlateKind};
use crate::simd::{self, Vregs};
use crate::{CpuBackend, InterpBudget, MemAccess, RunResult, StopReason};

use std::collections::HashMap;

#[derive(Debug, Default, Clone, Copy)]
pub struct SystemRegs {
    pub sctlr_el1: u64,
    pub ttbr0_el1: u64,
    pub ttbr1_el1: u64,
    pub tcr_el1: u64,
    pub cpacr_el1: u64,
    pub daif: u64,
    pub vbar_el1: u64,
    pub elr_el1: u64,
    pub spsr_el1: u64,
    // ARMv8.3 PAC keys (modeled; real Apple schedule is not public)
    pub apiakeylo: u64,
    pub apiakeyhi: u64,
    pub apibkeylo: u64,
    pub apibkeyhi: u64,
    pub apdakeylo: u64,
    pub apdakeyhi: u64,
    pub apdbkeylo: u64,
    pub apdbkeyhi: u64,
    pub apgakeylo: u64,
    pub apgakeyhi: u64,
    // AMUv1 (Activity Monitor Unit) — 4 architected + 0 implementable groups
    pub amcr: u64,
    pub amcfgr: u64,
    pub amcgcr: u64,
    pub amuserenr: u64,
    pub amcntenset0: u64,
    pub amcntenclr0: u64,
    pub amcntenset1: u64,
    pub amcntenclr1: u64,
    pub amevcntr0: [u64; 4],
    // MPAM (v8.4) — id registers RES0-modeled, partition knobs RW
    pub mpam0_el1: u64,
    pub mpam1_el1: u64,
    pub mpamidr_el1: u64,
    // Modeled ID registers (ARMv8.4-A feature surface of the A13)
    pub id_aa64isar0: u64,
    pub id_aa64isar1: u64,
    pub id_aa64pfr0: u64,
    pub id_aa64mmfr2: u64,
}

/// Canonical sysreg encodings (op0:1 op1:3 CRn:4 CRm:4 op2:3 → 15 bits).
pub mod sysreg {
    // The 15-bit canonical form: (op0<<14)|(op1<<11)|(CRn<<7)|(CRm<<3)|op2
    pub const fn enc(op0: u16, op1: u16, crn: u16, crm: u16, op2: u16) -> u16 {
        (op0 << 14) | (op1 << 11) | (crn << 7) | (crm << 3) | op2
    }
    pub const SCTLR_EL1: u16 = enc(1, 0, 1, 0, 0); // op0 raw bit (full op0 = 3)
    pub const CPACR_EL1: u16 = enc(1, 0, 1, 0, 2);
    pub const TCR_EL1: u16 = enc(1, 0, 2, 0, 2);
    pub const TTBR0_EL1: u16 = enc(1, 0, 2, 0, 0);
    pub const TTBR1_EL1: u16 = enc(1, 0, 2, 0, 1);
    pub const VBAR_EL1: u16 = enc(1, 0, 12, 0, 0);
    pub const DAIF: u16 = enc(1, 3, 4, 2, 1);
    pub const CNTVCT_EL0: u16 = enc(1, 3, 14, 0, 2);
    pub const ELR_EL1: u16 = enc(1, 0, 4, 0, 1);
    pub const SPSR_EL1: u16 = enc(1, 0, 4, 0, 0);
    // --- early-boot window (verified against the real 18C66 start.s) ---
    pub const MAIR_EL1: u16 = enc(1, 0, 10, 2, 0);
    pub const MIDR_EL1: u16 = enc(1, 0, 0, 0, 0);
    pub const MPIDR_EL1: u16 = enc(1, 0, 0, 0, 5);
    pub const CNTFRQ_EL0: u16 = enc(1, 3, 14, 0, 0);
    pub const CNTPCT_EL0: u16 = enc(1, 3, 14, 0, 1);
    pub const CTR_EL0: u16 = enc(1, 3, 0, 0, 1);
    pub const CURRENT_EL: u16 = enc(1, 0, 4, 2, 2);
    pub const ID_AA64MMFR0_EL1: u16 = enc(1, 0, 0, 7, 0);
    pub const ID_AA64MMFR1_EL1: u16 = enc(1, 0, 0, 7, 1);
    pub const TPIDR_EL1: u16 = enc(1, 0, 13, 0, 2);
    pub const TPIDR_EL0: u16 = enc(1, 3, 13, 0, 2);
    pub const TPIDRRO_EL0: u16 = enc(1, 3, 13, 0, 3);
    /// Apple `s3_4_c15_c0_4` — start.s polls bit 1 before touching the
    /// core (boot-stage handshake). Modeled: reads OR-in bit 1.
    pub const APPLE_BOOT_STAGE: u16 = enc(1, 4, 15, 0, 4);
    /// OSLAR_EL1 — keystone: `msr oslar_el1, xzr` = d510109f →
    /// (op0raw 1, op1 0, CRn 1, CRm 0, op2 4).
    pub const OSLAR_EL1: u16 = enc(1, 0, 1, 0, 4);
    // Apple GXF system regs (a13_gxf.c model)
    pub const GXF_CONFIG_EL1: u16 = enc(1, 0, 15, 1, 1);
    pub const GXF_STATUS_EL1: u16 = enc(1, 0, 15, 1, 2);
    pub const GXF_ENTER_EL1: u16 = enc(1, 0, 15, 1, 3);
    pub const GXF_ABORT_EL1: u16 = enc(1, 0, 15, 1, 4);
    // ARMv8.3 PAC keys
    pub const APIAKEYLO_EL1: u16 = enc(1, 0, 2, 1, 0);
    pub const APIAKEYHI_EL1: u16 = enc(1, 0, 2, 1, 1);
    pub const APIBKEYLO_EL1: u16 = enc(1, 0, 2, 1, 2);
    pub const APIBKEYHI_EL1: u16 = enc(1, 0, 2, 1, 3);
    pub const APDAKEYLO_EL1: u16 = enc(1, 0, 2, 2, 0);
    pub const APDAKEYHI_EL1: u16 = enc(1, 0, 2, 2, 1);
    pub const APDBKEYLO_EL1: u16 = enc(1, 0, 2, 2, 2);
    pub const APDBKEYHI_EL1: u16 = enc(1, 0, 2, 2, 3);
    pub const APGAKEYLO_EL1: u16 = enc(1, 0, 2, 3, 0);
    pub const APGAKEYHI_EL1: u16 = enc(1, 0, 2, 3, 1);
    // AMUv1 (capstone-verified encodings: D53BD2A0 → enc(1,3,13,2,5) etc.)
    pub const AMCR_EL0: u16 = enc(1, 3, 13, 2, 0);
    pub const AMCFGR_EL0: u16 = enc(1, 3, 13, 2, 1);
    pub const AMCGCR_EL0: u16 = enc(1, 3, 13, 2, 2);
    pub const AMUSERENR_EL0: u16 = enc(1, 3, 13, 2, 3);
    pub const AMCNTENCLR0_EL0: u16 = enc(1, 3, 13, 2, 4);
    pub const AMCNTENSET0_EL0: u16 = enc(1, 3, 13, 2, 5);
    pub const AMCNTENCLR1_EL0: u16 = enc(1, 3, 13, 3, 4);
    pub const AMCNTENSET1_EL0: u16 = enc(1, 3, 13, 3, 5);
    // AMEVCNTR00_EL0..03 (group 0 architected counters)
    pub const fn amevcntr0(n: u16) -> u16 {
        enc(1, 3, 13, 4 + n, 0)
    }
    // MPAM (capstone-verified: mpam0_el1 = D538A520 → enc(1,0,10,5,1))
    pub const MPAM0_EL1: u16 = enc(1, 0, 10, 5, 1);
    pub const MPAM1_EL1: u16 = enc(1, 0, 10, 5, 0);
    pub const MPAMIDR_EL1: u16 = enc(1, 0, 10, 4, 5);
    // Modeled ID registers
    pub const ID_AA64ISAR0_EL1: u16 = enc(1, 0, 0, 6, 0);
    pub const ID_AA64ISAR1_EL1: u16 = enc(1, 0, 0, 6, 1);
    pub const ID_AA64PFR0_EL1: u16 = enc(1, 0, 0, 4, 0);
    pub const ID_AA64MMFR2_EL1: u16 = enc(1, 0, 0, 7, 2);
}

/// The 20 CPU instruction groups tracked in `soc_t8030::CPU_INSTRUCTIONS`
/// — the interpreter bumps a counter per group on every executed insn.
pub const N_GROUPS: usize = 20;

pub const GROUP_NAMES: [&str; N_GROUPS] = [
    "LSE",
    "RDM",
    "FCMA",
    "JSCVT",
    "FP16",
    "ASIMDRDM",
    "DOTPROD",
    "SHA512",
    "SHA3",
    "SM3/SM4",
    "AES/PMULL",
    "CRC32",
    "PAC",
    "BTI",
    "CSV2/CSV3",
    "AMUv1",
    "MPAM",
    "TLBI Ranges",
    "DGH/DOT",
    "FCADD",
];

pub struct Interpreter {
    pub x: [u64; 31],
    pub pc: u64,
    pub sp: u64,
    pub nzcv: u32, // N Z C V in bits 3..0
    pub halted: bool,
    pub sys: SystemRegs,
    pub gxf_config: u64,
    pub gxf_status: u64,
    /// AdvSIMD/FP register file (V0–V31) — FP16/DOTPROD/FCMA/crypto groups.
    pub v: Vregs,
    /// Per-group execution counters (parity measurement surface).
    pub group_exec: [u64; N_GROUPS],
    /// Last TLBI range invalidate (base, scale, num) — machine can purge.
    pub last_tlbi_range: Option<(u64, u8, u8)>,
    mem: Box<dyn MemAccess>,
    executed: u64,
    ns_budget_used: u64,
    pub unknown_sysreg_writes: u64,
    pub unknown_sysreg_reads: u64,
    /// Stage-1 MMU (walker + TLB) — armed when the kernel flips SCTLR.M.
    pub mmu: Mmu,
    /// Generic storage for Apple-custom / unarchitected sysreg encodings
    /// (mrs/orr/msr round-trips must preserve values or the kernel hangs).
    sysreg_store: HashMap<u16, u64>,
    /// SPSel flag (single-bank SP model: SP_EL0/SP_EL1 share `sp`).
    pub sp_sel: bool,
    /// First N unknown-sysreg encodings, for the honest report.
    pub unknown_sysreg_seen: Vec<u16>,
    /// Optional instruction trace ring (pc, word, x regs snapshot) — boot
    /// debugging.
    pub trace_enabled: bool,
    pub trace: std::collections::VecDeque<(u64, u32, Vec<u64>, u32)>,
    /// Post-mortem: last (pc, insn, new_sp) that changed SP — finds a lost
    /// stack pointer fast.
    pub last_sp_change: Option<(u64, u32, u64)>,
}

const N: u32 = 1 << 3;
const Z: u32 = 1 << 2;
const C: u32 = 1 << 1;
const V: u32 = 1;

impl Interpreter {
    pub fn new(mem: Box<dyn MemAccess>) -> Self {
        Interpreter {
            x: [0; 31],
            pc: 0,
            sp: 0,
            nzcv: 0,
            halted: false,
            sys: SystemRegs {
                // ARMv8.4-A A13 ID surface (model values — verify against a
                // real device dump; field layout per ARM DDI 0487 G6.1.3):
                // ISAR0: AES=2(PMULL) SHA1=1 SHA2=1 CRC32=1 Atomic(LSE)=2
                //        RDM=1 SHA3=1 SM3=1 SM4=1 DP(DOTPROD)=1 FHM(FP16)=1
                //        TS=1 TLB(RANGE)=1
                id_aa64isar0: (2 << 4)      // AES
                    | (1 << 8)              // SHA1
                    | (1 << 12)             // SHA2
                    | (1 << 16)             // CRC32
                    | (2 << 20)             // Atomic (LSE)
                    | (1 << 24)             // RDM
                    | (1 << 32)             // SHA3
                    | (1 << 36)             // SM3
                    | (1 << 40)             // SM4
                    | (1 << 44)             // DP (dot product)
                    | (1 << 48)             // FHM (FP16 arithmetic)
                    | (1 << 56),            // TLB (RANGE)
                // ISAR1: GPI=0 GPA=0 API=2(APAC) FCMA=1 JSCVT=1 LRCPC=1
                id_aa64isar1: (2 << 4)      // API (PACIA/…)
                    | (1 << 16)             // LRCPC
                    | (1 << 20)             // FCMA
                    | (1 << 24),            // JSCVT
                // PFR0: FP=1 AdvSIMD=1 CSV2=1 CSV3=1 AMU=1 (v8.4)
                id_aa64pfr0: (1 << 0)       // FP
                    | (1 << 4)              // AdvSIMD
                    | (1 << 12)             // GIC?
                    | (1 << 16)             // RAS?
                    | (1 << 52)             // CSV2
                    | (1 << 56)             // CSV3
                    | (1 << 44),            // AMUv1
                id_aa64mmfr2: (1 << 0),     // CnP? (model placeholder)
                ..SystemRegs::default()
            },
            gxf_config: 0,
            gxf_status: 0,
            v: Vregs::new(),
            group_exec: [0; N_GROUPS],
            last_tlbi_range: None,
            mem,
            executed: 0,
            ns_budget_used: 0,
            unknown_sysreg_writes: 0,
            unknown_sysreg_reads: 0,
            mmu: Mmu::new(),
            sysreg_store: HashMap::new(),
            sp_sel: false,
            unknown_sysreg_seen: Vec::new(),
            trace_enabled: false,
            trace: std::collections::VecDeque::new(),
            last_sp_change: None,
        }
    }

    /// Record (pc, word, regs) into the bounded trace ring when enabled.
    #[inline]
    fn trace_tick(&mut self, pc: u64, word: u32) {
        if !self.trace_enabled {
            return;
        }
        if self.trace.len() >= 24 {
            self.trace.pop_front();
        }
        self.trace.push_back((pc, word, self.x.to_vec(), self.nzcv));
    }

    pub fn mem(&mut self) -> &mut dyn MemAccess {
        &mut *self.mem
    }

    /// Register read with the ARM reg-31 rule (ZR for GPR use).
    #[inline]
    fn r(&self, n: u8) -> u64 {
        if n == 31 {
            0
        } else {
            self.x[n as usize]
        }
    }

    /// SP rule: register 31 as stack pointer.
    #[inline]
    fn rsp(&self, n: u8) -> u64 {
        if n == 31 {
            self.sp
        } else {
            self.x[n as usize]
        }
    }

    #[inline]
    fn set_r(&mut self, n: u8, v: u64) {
        if n != 31 {
            self.x[n as usize] = v;
        }
    }

    #[inline]
    fn set_rsp(&mut self, n: u8, v: u64) {
        if n == 31 {
            if v != self.sp {
                self.last_sp_change = Some((self.pc, 0, v));
            }
            self.sp = v;
        } else {
            self.x[n as usize] = v;
        }
    }

    /// Translate a VA through the stage-1 MMU (pass-through while off).
    #[inline]
    fn vaddr(&mut self, va: u64, kind: XlateKind) -> Result<u64, StopReason> {
        if !self.mmu.enabled {
            return Ok(va);
        }
        self.mmu
            .translate(&mut *self.mem, va, kind)
            .map_err(|(v, detail)| StopReason::TranslationFault {
                pc: self.pc,
                va: v,
                kind: kind.as_str(),
                detail,
            })
    }

    /// Translating load (physical pass-through while SCTLR.M is clear).
    /// Masks to the access width so a device that ignores `size` can never
    /// leak neighboring bytes into a narrow register load.
    #[inline]
    fn ld(&mut self, va: u64, size: u8) -> Result<u64, StopReason> {
        let pa = self.vaddr(va, XlateKind::Load)?;
        let v = MemAccess::load(&mut *self.mem, pa, size);
        let bytes = (size as u32).clamp(1, 8);
        Ok(if bytes >= 8 {
            v
        } else {
            v & ((1u64 << (bytes * 8)) - 1)
        })
    }

    /// Translating store.
    #[inline]
    fn st(&mut self, va: u64, size: u8, val: u64) -> Result<(), StopReason> {
        let pa = self.vaddr(va, XlateKind::Store)?;
        MemAccess::store(&mut *self.mem, pa, size, val);
        Ok(())
    }

    /// Translating instruction fetch.
    #[inline]
    fn fetch(&mut self, va: u64) -> Result<u32, StopReason> {
        let pa = self.vaddr(va, XlateKind::Fetch)?;
        Ok(MemAccess::fetch32(&mut *self.mem, pa))
    }

    /// Vector memory read of `bytes` (1/2/4/8/16) as a little-endian u128.
    #[inline]
    fn load_vec(&mut self, addr: u64, bytes: u16) -> Result<u128, StopReason> {
        if bytes <= 8 {
            Ok(self.ld(addr, bytes as u8)? as u128)
        } else {
            let lo = self.ld(addr, 8)?;
            let hi = self.ld(addr + 8, (bytes - 8) as u8)?;
            Ok(((hi as u128) << 64) | lo as u128)
        }
    }

    /// Vector memory write of the low `bytes` of `val`.
    #[inline]
    fn store_vec(&mut self, addr: u64, bytes: u16, val: u128) -> Result<(), StopReason> {
        if bytes <= 8 {
            self.st(addr, bytes as u8, val as u64)
        } else {
            self.st(addr, 8, val as u64)?;
            self.st(addr + 8, (bytes - 8) as u8, (val >> 64) as u64)
        }
    }

    /// Low `bytes` of Vt (partial-register SIMD loads/stores leave the
    /// remaining bits of Vt untouched, per the architecture).
    #[inline]
    fn read_vec_low(&self, vt: u8, bytes: u16) -> u128 {
        if bytes >= 16 {
            self.v.v[vt as usize]
        } else {
            self.v.v[vt as usize] & ((1u128 << (8 * bytes as u32)) - 1)
        }
    }

    #[inline]
    fn write_vec_low(&mut self, vt: u8, bytes: u16, val: u128) {
        if bytes >= 16 {
            self.v.v[vt as usize] = val;
        } else {
            let keep = !((1u128 << (8 * bytes as u32)) - 1);
            self.v.v[vt as usize] = (self.v.v[vt as usize] & keep) | val;
        }
    }

    /// Sign-extend a 32-bit loaded value to 64 bits.
    #[inline]
    fn sext32(v: u64) -> u64 {
        (v as u32 as i32) as i64 as u64
    }

    fn cond(&self, c: Cond) -> bool {
        let (n, z, cc, v) = (
            self.nzcv & N != 0,
            self.nzcv & Z != 0,
            self.nzcv & C != 0,
            self.nzcv & V != 0,
        );
        match c {
            Cond::Eq => z,
            Cond::Ne => !z,
            Cond::Cs => cc,
            Cond::Cc => !cc,
            Cond::Mi => n,
            Cond::Pl => !n,
            Cond::Vs => v,
            Cond::Vc => !v,
            Cond::Hi => cc && !z,
            Cond::Ls => !cc || z,
            Cond::Ge => n == v,
            Cond::Lt => n != v,
            Cond::Gt => !z && n == v,
            Cond::Le => z || n != v,
            Cond::Al => true,
        }
    }

    /// Add/sub with carry+overflow (QEMU: helper for ADDS/SUBS flags).
    fn add_with_flags(&mut self, a: u64, b: u64, carry_in: bool, is64: bool, sub: bool) -> u64 {
        let mask = if is64 { u64::MAX } else { 0xFFFF_FFFF };
        let (a, b) = (a & mask, b & mask);
        let (res, cf, vf) = if sub {
            let res = a.wrapping_sub(b).wrapping_sub(!carry_in as u64);
            let cf = a >= b + (!carry_in as u64);
            let vf = ((a ^ b) & (a ^ res)) >> (if is64 { 63 } else { 31 }) & 1 == 1;
            (res, cf, vf)
        } else {
            let res = a.wrapping_add(b).wrapping_add(carry_in as u64);
            // Carry-out must respect the operation width: for 32-bit ADDS
            // C = (a+b+c) >= 2^32 (the u64 sum never wraps, so `res < a`
            // could never fire — real-data bug #10 follow-up, found on the
            // 18C66 boot path).
            let cf = if is64 { res < a } else { res > 0xFFFF_FFFF };
            let vf = ((a ^ res) & (b ^ res)) >> (if is64 { 63 } else { 31 }) & 1 == 1;
            (res, cf, vf)
        };
        let res = res & mask;
        self.nzcv = if res == 0 { Z } else { 0 }
            | if res >> (if is64 { 63 } else { 31 }) & 1 == 1 { N } else { 0 }
            | if cf { C } else { 0 }
            | if vf { V } else { 0 };
        res
    }

    fn logical_flags(&mut self, res: u64, is64: bool) {
        self.nzcv = if res == 0 { Z } else { 0 }
            | if res >> (if is64 { 63 } else { 31 }) & 1 == 1 { N } else { 0 };
    }

    fn shift(&self, v: u64, kind: ShiftKind, amt: u32, is64: bool) -> u64 {
        let bits = if is64 { 64 } else { 32 };
        let mask = if is64 { u64::MAX } else { 0xFFFF_FFFF };
        let v = v & mask;
        match kind {
            ShiftKind::Lsl => (v.wrapping_shl(amt)) & mask,
            ShiftKind::Lsr => v.wrapping_shr(amt) & mask,
            ShiftKind::Asr => {
                let signed = v as i64;
                let s = if is64 { signed >> amt } else { ((signed as i32) >> amt) as i64 };
                (s as u64) & mask
            }
            ShiftKind::Ror => v.rotate_right(amt % bits),
        }
        .wrapping_shr(0) // pacify
        & mask | (if amt >= bits { 0 } else { 0 })
    }

    fn step(&mut self) -> Result<(), StopReason> {
        let pc = self.pc;
        let word = self.fetch(pc)?;
        self.trace_tick(pc, word);
        let Some(insn) = crate::decode::decode(pc, word) else {
            return Err(StopReason::UnknownInsn { pc, insn: word });
        };
        match insn {
            Insn::Nop => {}
            Insn::Movz { rd, imm16, shift, is64 } => {
                let v = (imm16 as u64) << (shift as u32 * 16);
                self.set_r(rd, if is64 { v } else { v & 0xFFFF_FFFF });
            }
            Insn::Movn { rd, imm16, shift, is64 } => {
                let v = !((imm16 as u64) << (shift as u32 * 16));
                self.set_r(rd, if is64 { v } else { v & 0xFFFF_FFFF });
            }
            Insn::Movk { rd, imm16, shift, is64 } => {
                let sh = shift as u32 * 16;
                let mask = !((0xFFFFu64) << sh)
                    & if is64 { u64::MAX } else { 0xFFFF_FFFF };
                let cur = self.r(rd) & if is64 { u64::MAX } else { 0xFFFF_FFFF };
                self.set_r(rd, (cur & mask) | ((imm16 as u64) << sh));
            }
            Insn::MovReg { rd, rn } => {
                let v = self.r(rn);
                self.set_r(rd, v);
            }
            Insn::AddImm { rd, rn, imm12, shift, setflags, is64 } => {
                let a = self.rsp(rn);
                let b = (imm12 as u64) << if shift { 12 } else { 0 };
                if setflags {
                    let r = self.add_with_flags(a, b, false, is64, false);
                    self.set_rsp(rd, r);
                } else {
                    self.set_rsp(rd, a.wrapping_add(b));
                }
            }
            Insn::SubImm { rd, rn, imm12, shift, setflags, is64 } => {
                let a = self.rsp(rn);
                let b = (imm12 as u64) << if shift { 12 } else { 0 };
                if setflags {
                    let r = self.add_with_flags(a, b, true, is64, true);
                    self.set_rsp(rd, r);
                } else {
                    self.set_rsp(rd, a.wrapping_sub(b));
                }
            }
            Insn::AddSubReg { rd, rn, rm, kind, imm6, subtract, setflags, is64 } => {
                // S=1: Rd=31 is XZR (CMP/CMP-shifted) — the result must be
                // DISCARDED, never written to SP (QEMU op_add_sub_reg: is_cmp
                // path). Real-data bug #10: `cmp x1, x2, lsl #2` clobbered SP
                // with the comparison result and zeroed the kernel stack.
                // Rn=31 reads ZR only on the compare path, SP otherwise.
                let a = if setflags && rd == 31 { self.r(rn) } else { self.rsp(rn) };
                let b = self.shift(self.r(rm), kind, imm6, is64);
                if setflags {
                    // carry-in: ADCS only. ADDS gets 0; SUBS uses it as the
                    // borrow-in (!C → b - 1) — bug #10b: ADDS was computing
                    // a+b+1 on real 18C66 bytes.
                    let r = self.add_with_flags(a, b, subtract, is64, subtract);
                    self.set_r(rd, r);
                } else if subtract {
                    self.set_rsp(rd, a.wrapping_sub(b));
                } else {
                    self.set_rsp(rd, a.wrapping_add(b));
                }
            }
            Insn::AndImm { rd, rn, imm, setflags, is64 } => {
                let r = self.r(rn) & imm;
                if setflags {
                    self.logical_flags(r, is64);
                }
                self.set_r(rd, r);
            }
            Insn::OrrImm { rd, rn, imm, setflags, is64 } => {
                let r = self.r(rn) | imm;
                if setflags {
                    self.logical_flags(r, is64);
                }
                self.set_r(rd, r);
            }
            Insn::EorImm { rd, rn, imm, setflags, is64 } => {
                let r = self.r(rn) ^ imm;
                if setflags {
                    self.logical_flags(r, is64);
                }
                self.set_r(rd, r);
            }
            Insn::CmpImm { rn, imm12, shift, is64 } => {
                let a = self.r(rn);
                let b = (imm12 as u64) << if shift { 12 } else { 0 };
                self.add_with_flags(a, b, true, is64, true);
            }
            Insn::CmnImm { rn, imm12, shift, is64 } => {
                let a = self.r(rn);
                let b = (imm12 as u64) << if shift { 12 } else { 0 };
                self.add_with_flags(a, b, false, is64, false);
            }
            Insn::CmnReg { rn, rm, kind, imm6, is64 } => {
                let a = self.r(rn);
                let b = self.shift(self.r(rm), kind, imm6, is64);
                self.add_with_flags(a, b, false, is64, false);
            }
            Insn::CmpReg { rn, rm, kind, imm6, is64 } => {
                let a = self.r(rn);
                let b = self.shift(self.r(rm), kind, imm6, is64);
                self.add_with_flags(a, b, true, is64, true);
            }
            Insn::B { imm } => {
                self.pc = (pc as i64 + imm) as u64;
                return Ok(());
            }
            Insn::Bl { imm } => {
                self.x[30] = pc + 4;
                self.pc = (pc as i64 + imm) as u64;
                return Ok(());
            }
            Insn::Br { rn } => {
                self.pc = self.r(rn);
                return Ok(());
            }
            Insn::Blr { rn } => {
                let target = self.r(rn);
                self.x[30] = pc + 4;
                self.pc = target;
                return Ok(());
            }
            Insn::Ret { rn } => {
                self.pc = self.rsp(rn);
                return Ok(());
            }
            Insn::BCond { cond, imm } => {
                if self.cond(cond) {
                    self.pc = (pc as i64 + imm) as u64;
                    return Ok(());
                }
            }
            Insn::Cbz { rn, imm, is64 } => {
                let v = self.r(rn) & if is64 { u64::MAX } else { 0xFFFF_FFFF };
                if v == 0 {
                    self.pc = (pc as i64 + imm) as u64;
                    return Ok(());
                }
            }
            Insn::Cbnz { rn, imm, is64 } => {
                let v = self.r(rn) & if is64 { u64::MAX } else { 0xFFFF_FFFF };
                if v != 0 {
                    self.pc = (pc as i64 + imm) as u64;
                    return Ok(());
                }
            }
            Insn::Tbz { rn, bit, imm } => {
                if self.r(rn) >> bit & 1 == 0 {
                    self.pc = (pc as i64 + imm) as u64;
                    return Ok(());
                }
            }
            Insn::Tbnz { rn, bit, imm } => {
                if self.r(rn) >> bit & 1 == 1 {
                    self.pc = (pc as i64 + imm) as u64;
                    return Ok(());
                }
            }
            Insn::Adr { rd, imm } => self.set_r(rd, (pc as i64 + imm) as u64),
            Insn::Adrp { rd, imm } => {
                let page = pc & !0xFFF;
                self.set_r(rd, (page as i64 + imm) as u64);
            }
            Insn::LdrImmU { rt, rn, imm12, size_log2 } => {
                let addr = self.rsp(rn) + ((imm12 as u64) << size_log2);
                let sz = 1u8 << size_log2;
                let v = self.ld(addr, sz)?;
                self.set_r(rt, v);
            }
            Insn::StrImmU { rt, rn, imm12, size_log2 } => {
                let addr = self.rsp(rn) + ((imm12 as u64) << size_log2);
                let sz = 1u8 << size_log2;
                self.st(addr, sz, self.r(rt))?;
            }
            Insn::LdrLit { rt, imm, is64 } => {
                let addr = (pc as i64 + imm) as u64;
                let v = self.ld(addr, if is64 { 8 } else { 4 })?;
                self.set_r(rt, v);
            }
            Insn::Ldp { rt, rt2, rn, imm, mode, is64 } => {
                let base = self.rsp(rn);
                let addr = match mode {
                    PairMode::Offset | PairMode::NonTemporal => (base as i64 + imm) as u64,
                    PairMode::Pre => (base as i64 + imm) as u64,
                    PairMode::Post => base,
                };
                let sz = if is64 { 8 } else { 4 };
                let a = self.ld(addr, sz)?;
                let b = self.ld(addr + sz as u64, sz)?;
                self.set_r(rt, a);
                self.set_r(rt2, b);
                if mode == PairMode::Pre || mode == PairMode::Post {
                    self.set_rsp(rn, (base as i64 + imm) as u64);
                }
            }
            Insn::Stp { rt, rt2, rn, imm, mode, is64 } => {
                let base = self.rsp(rn);
                let addr = match mode {
                    PairMode::Offset | PairMode::NonTemporal => (base as i64 + imm) as u64,
                    PairMode::Pre => (base as i64 + imm) as u64,
                    PairMode::Post => base,
                };
                let sz = if is64 { 8 } else { 4 };
                self.st(addr, sz, self.r(rt))?;
                self.st(addr + sz as u64, sz, self.r(rt2))?;
                if mode == PairMode::Pre || mode == PairMode::Post {
                    self.set_rsp(rn, (base as i64 + imm) as u64);
                }
            }
            Insn::Ldpsw { rt, rt2, rn, imm, mode } => {
                let base = self.rsp(rn);
                let addr = match mode {
                    PairMode::Offset | PairMode::NonTemporal | PairMode::Pre => {
                        (base as i64 + imm) as u64
                    }
                    PairMode::Post => base,
                };
                let a = Self::sext32(self.ld(addr, 4)?);
                let b = Self::sext32(self.ld(addr + 4, 4)?);
                self.set_r(rt, a);
                self.set_r(rt2, b);
                if mode == PairMode::Pre || mode == PairMode::Post {
                    self.set_rsp(rn, (base as i64 + imm) as u64);
                }
            }
            Insn::LdpSimd { vt, vt2, rn, imm, mode, log2_width } => {
                let base = self.rsp(rn);
                let addr = match mode {
                    PairMode::Offset | PairMode::NonTemporal | PairMode::Pre => {
                        (base as i64 + imm) as u64
                    }
                    PairMode::Post => base,
                };
                let sz = 1u16 << log2_width;
                self.v.v[vt as usize] = self.load_vec(addr, sz)?;
                self.v.v[vt2 as usize] = self.load_vec(addr + sz as u64, sz)?;
                if mode == PairMode::Pre || mode == PairMode::Post {
                    self.set_rsp(rn, (base as i64 + imm) as u64);
                }
            }
            Insn::StpSimd { vt, vt2, rn, imm, mode, log2_width } => {
                let base = self.rsp(rn);
                let addr = match mode {
                    PairMode::Offset | PairMode::NonTemporal | PairMode::Pre => {
                        (base as i64 + imm) as u64
                    }
                    PairMode::Post => base,
                };
                let sz = 1u16 << log2_width;
                self.store_vec(addr, sz, self.v.v[vt as usize])?;
                self.store_vec(addr + sz as u64, sz, self.v.v[vt2 as usize])?;
                if mode == PairMode::Pre || mode == PairMode::Post {
                    self.set_rsp(rn, (base as i64 + imm) as u64);
                }
            }
            Insn::LdSt9 { rt, rn, imm9, size_log2, load, mode } => {
                let base = self.rsp(rn);
                let addr = match mode {
                    LsMode::Unscaled | LsMode::Unpriv | LsMode::Pre => {
                        (base as i64 + imm9) as u64
                    }
                    LsMode::Post => base,
                };
                let sz = 1u8 << size_log2;
                if load {
                    let v = self.ld(addr, sz)?;
                    self.set_r(rt, v);
                } else {
                    self.st(addr, sz, self.r(rt))?;
                }
                if matches!(mode, LsMode::Pre | LsMode::Post) {
                    self.set_rsp(rn, (base as i64 + imm9) as u64);
                }
            }
            Insn::Ldrs9 { rt, rn, imm9, size_log2, mode, dest64 } => {
                let base = self.rsp(rn);
                let addr = match mode {
                    LsMode::Unscaled | LsMode::Unpriv | LsMode::Pre => {
                        (base as i64 + imm9) as u64
                    }
                    LsMode::Post => base,
                };
                let sz = 1u8 << size_log2;
                let raw = self.ld(addr, sz)?;
                let sh = 64 - 8 * sz;
                let v = ((raw << sh) as i64 >> sh) as u64;
                self.set_r(rt, if dest64 { v } else { v & 0xFFFF_FFFF });
                if matches!(mode, LsMode::Pre | LsMode::Post) {
                    self.set_rsp(rn, (base as i64 + imm9) as u64);
                }
            }
            Insn::LdStRegOff { rt, rn, rm, option, scaled, size_log2, load, sign_ext, dest64 } => {
                let base = self.rsp(rn);
                let idx = option.apply(self.r(rm)) << if scaled { size_log2 as u64 } else { 0 };
                let addr = base.wrapping_add(idx);
                let sz = 1u8 << size_log2;
                if load && sign_ext {
                    let raw = self.ld(addr, sz)?;
                    let sh = 64 - 8 * sz;
                    let v = ((raw << sh) as i64 >> sh) as u64;
                    self.set_r(rt, if dest64 { v } else { v & 0xFFFF_FFFF });
                } else if load {
                    let v = self.ld(addr, sz)?;
                    self.set_r(rt, v);
                } else {
                    self.st(addr, sz, self.r(rt))?;
                }
            }
            Insn::VLogic3 { rd, rn, rm, size, u, q } => {
                // Element-wise bitwise, lane width 1 byte, lanes = 16 (Q=1)
                // or 8 (Q=0); the upper half of Vd is UNCHANGED for Q=0.
                let lanes = if q { 16 } else { 8 };
                let a = self.v.v[rn as usize];
                let b = self.v.v[rm as usize];
                let r: u128 = match (size, u) {
                    (0, false) => a & b, // AND
                    (1, false) => a & !b, // BIC
                    (2, false) => a | b, // ORR
                    (3, false) => a | !b, // ORN
                    (0, true) => a ^ b, // EOR
                    (1, true) => (a & b) | (!a & b), // BSL (dst is the mask)
                    (2, true) => (a & !b) | (!a & b), // BIT
                    (3, true) => a ^ !b, // EON
                    _ => 0,
                };
                let keep = if lanes * 8 >= 128 {
                    0 // .16b writes the whole 128-bit register
                } else {
                    !((1u128 << (lanes * 8)) - 1)
                };
                self.v.v[rd as usize] = (self.v.v[rd as usize] & keep)
                    | (r & !keep);
            }
            Insn::VReduce { rd, rn, size, op, q } => {
                // Across-lane reduce: element width = 1 << size bytes
                // (size 00 → bytes), lane count = (16 if Q else 8) >> size.
                // Result (element-width) written to the low bytes of Vd;
                // remaining Vd bits UNCHANGED per the architecture.
                let eb = 1u64 << size;
                let lanes = ((if q { 16 } else { 8 }) as u64) >> size;
                let full = self.v.v[rn as usize];
                let mut acc: i128 = match op {
                    VReduceOp::Addv => 0,
                    VReduceOp::Sminv => i128::from(i64::from_ne_bytes(
                        (full as u64).to_ne_bytes())),
                    VReduceOp::Uminv => u128::from(full) as i128,
                    VReduceOp::Smaxv => i128::MIN,
                    VReduceOp::Umaxv => 0,
                };
                let mut uacc: u128 = match op {
                    VReduceOp::Uminv => u128::MAX,
                    VReduceOp::Umaxv => 0,
                    _ => 0,
                };
                let mut signed_acc: i128 = match op {
                    VReduceOp::Sminv => i128::MAX,
                    VReduceOp::Smaxv => i128::MIN,
                    _ => 0,
                };
                let mut first = true;
                for l in 0..lanes {
                    let shift = l * eb * 8;
                    let mask = (1u128 << (eb * 8)) - 1;
                    let raw = ((full >> shift) & mask) as u64;
                    let signed = ((raw << (64 - eb * 8)) as i64) >> (64 - eb * 8);
                    match op {
                        VReduceOp::Addv => acc += raw as i128,
                        VReduceOp::Uminv => uacc = uacc.min(raw as u128),
                        VReduceOp::Umaxv => uacc = uacc.max(raw as u128),
                        VReduceOp::Sminv => {
                            signed_acc = if first { signed as i128 } else { signed_acc.min(signed as i128) }
                        }
                        VReduceOp::Smaxv => {
                            signed_acc = if first { signed as i128 } else { signed_acc.max(signed as i128) }
                        }
                    }
                    first = false;
                }
                let out: u128 = match op {
                    VReduceOp::Addv => acc as u128,
                    VReduceOp::Uminv | VReduceOp::Umaxv => uacc,
                    VReduceOp::Sminv | VReduceOp::Smaxv => signed_acc as u128,
                };
                // DDI 0487 leaves the rest of Vd UNDEFINED for across-lane
                // reduces; Apple cores ZERO-extend and the real kernel's
                // idiom `uminv b1, v0.16b; fmov w2, s1; cbnz w2` (memscan at
                // 0x…8169df4, 18C66) only works when the full low element —
                // and everything above it — reads as zero. Zero the register.
                self.v.v[rd as usize] = out;
            }
            Insn::FmovGprVec { rt, rn, is64, to_vec } => {
                // Bit-exact move between GPR and scalar FP register (the low
                // Vn element). 32-bit: w/s; 64-bit: x/d.
                if to_vec {
                    let v = self.r(rt);
                    let bytes = if is64 { 8 } else { 4 };
                    let keep = !((1u128 << (bytes * 8)) - 1);
                    self.v.v[rn as usize] =
                        (self.v.v[rn as usize] & keep) | ((v as u128) & !keep);
                } else {
                    let bytes = if is64 { 8 } else { 4 };
                    let mask = (1u128 << (bytes * 8)) - 1;
                    self.set_r(rt, (self.v.v[rn as usize] & mask) as u64);
                }
            }
            Insn::V3SameInt { rd, rn, rm, size, u, q, op } => {
                use crate::decode::V3Op;
                let eb = 1u64 << size; // element bytes (1/2/4/8)
                let total = if q { 16u64 } else { 8 };
                let lanes = total / eb;
                let a = self.v.v[rn as usize];
                let b = self.v.v[rm as usize];
                let mask = (1u128 << (eb * 8)) - 1;
                let mut r: u128 = 0;
                let mut pair: Vec<(u128, u128)> = Vec::new();
                for l in 0..lanes {
                    let sh = l * eb * 8;
                    let av = (a >> sh) & mask;
                    let bv = (b >> sh) & mask;
                    pair.push((av, bv));
                }
                let lanes_h = (lanes / 2).max(1);
                for l in 0..lanes {
                    let sh = l * eb * 8;
                    // signed views (element width)
                    let bits = eb * 8;
                    let sext = |v: u128| -> i128 {
                        let m = 1i128 << (bits - 1);
                        ((v as i128) & ((m << 1) - 1)) - (((v as i128) & m) << 1)
                    };
                    let out: u128 = match op {
                        V3Op::Add => pair[l as usize].0.wrapping_add(pair[l as usize].1) & mask,
                        V3Op::Sub => pair[l as usize].0.wrapping_sub(pair[l as usize].1) & mask,
                        V3Op::Cmgt => {
                            if sext(pair[l as usize].0) > sext(pair[l as usize].1) { mask } else { 0 }
                        }
                        V3Op::Cmhi => {
                            if pair[l as usize].0 > pair[l as usize].1 { mask } else { 0 }
                        }
                        V3Op::Cmge => {
                            if sext(pair[l as usize].0) >= sext(pair[l as usize].1) { mask } else { 0 }
                        }
                        V3Op::Cmhs => {
                            if pair[l as usize].0 >= pair[l as usize].1 { mask } else { 0 }
                        }
                        V3Op::Cmeq => {
                            if pair[l as usize].0 == pair[l as usize].1 { mask } else { 0 }
                        }
                        V3Op::Cmtst => {
                            if (pair[l as usize].0 & pair[l as usize].1) != 0 { mask } else { 0 }
                        }
                        V3Op::Smin => {
                            (sext(pair[l as usize].0).min(sext(pair[l as usize].1)) as u128) & mask
                        }
                        V3Op::Umin => pair[l as usize].0.min(pair[l as usize].1) & mask,
                        V3Op::Smax => {
                            (sext(pair[l as usize].0).max(sext(pair[l as usize].1)) as u128) & mask
                        }
                        V3Op::Umax => pair[l as usize].0.max(pair[l as usize].1) & mask,
                        V3Op::Mul => pair[l as usize].0.wrapping_mul(pair[l as usize].1) & mask,
                        // session C: MLA/MLS — lane = a*b (+/- lane of Vd)
                        V3Op::Mla => {
                            let sh = l * eb * 8;
                            let acc = (self.v.v[rd as usize] >> sh) & mask;
                            pair[l as usize]
                                .0
                                .wrapping_mul(pair[l as usize].1)
                                .wrapping_add(acc)
                                & mask
                        }
                        V3Op::Mls => {
                            let sh = l * eb * 8;
                            let acc = (self.v.v[rd as usize] >> sh) & mask;
                            acc.wrapping_sub(
                                pair[l as usize].0.wrapping_mul(pair[l as usize].1),
                            ) & mask
                        }
                        // pairwise: lane l of the result folds elements
                        // 2l, 2l+1 of the SOURCE (per-lane pairing)
                        V3Op::Smaxp | V3Op::Umaxp | V3Op::Sminp | V3Op::Uminp => {
                            let i0 = (l * 2) as usize;
                            let i1 = (l * 2 + 1) as usize;
                            if i1 as u64 >= lanes {
                                0
                            } else {
                                let (x, y) = (pair[i0].0, pair[i1].0);
                                match op {
                                    V3Op::Smaxp => (sext(x).max(sext(y)) as u128) & mask,
                                    V3Op::Umaxp => x.max(y) & mask,
                                    V3Op::Sminp => (sext(x).min(sext(y)) as u128) & mask,
                                    V3Op::Uminp => x.min(y) & mask,
                                    _ => 0,
                                }
                            }
                        }
                    };
                    r |= out << sh;
                    let _ = lanes_h;
                }
                self.v.v[rd as usize] = r;
            }
            Insn::V3SameFp { rd, rn, rm, d, u, q, op } => {
                self.group_exec[1] += 1;
                // Three-same FP: per-lane f32 (d=false) or f64 (d=true).
                // Pairwise ops (ADDP/MAXP/MINP/MAXNMP/MINNMP): result lanes
                // = pair(vn) followed by pair(vm); .1d = the vn pair only.
                use crate::decode::V3FpOp;
                let pairwise = matches!(
                    op,
                    V3FpOp::Addp | V3FpOp::Maxp | V3FpOp::Minp | V3FpOp::Maxnmp | V3FpOp::Minnmp
                );
                let a = self.v.v[rn as usize];
                let b = self.v.v[rm as usize];
                let mut r: u128 = 0;
                if d {
                    if pairwise {
                        let mut lane = |x: u64, y: u64, sh: u32, acc: f64, r: &mut u128| {
                            let out = fp3_f64(op, f64::from_bits(x), f64::from_bits(y), acc);
                            *r |= (out.to_bits() as u128) << sh;
                        };
                        // .2d: pair0 = vn[0] op vn[1]; pair1 = vm[0] op vm[1]
                        let v0 = (a & u128::from(u64::MAX)) as u64;
                        let v1 = ((a >> 64) & u128::from(u64::MAX)) as u64;
                        let m0 = (b & u128::from(u64::MAX)) as u64;
                        let m1 = ((b >> 64) & u128::from(u64::MAX)) as u64;
                        lane(v0, v1, 0, 0.0, &mut r);
                        if q {
                            lane(m0, m1, 64, 0.0, &mut r);
                        }
                    } else {
                        let n = if q { 2 } else { 1 };
                        for i in 0..n {
                            let x = ((a >> (64 * i)) & u128::from(u64::MAX)) as u64;
                            let y = ((b >> (64 * i)) & u128::from(u64::MAX)) as u64;
                            let out = fp3_f64(op, f64::from_bits(x), f64::from_bits(y), 0.0);
                            r |= (out.to_bits() as u128) << (64 * i);
                        }
                    }
                } else {
                    let lanes = if q { 4 } else { 2 };
                    for i in 0..lanes {
                        let (x, y) = if pairwise {
                            let half = i / (lanes / 2).max(1);
                            let src = if half == 0 { a } else { b };
                            let off = ((i % (lanes / 2).max(1)) * 2) as u32;
                            (
                                ((src >> (32 * off)) & u128::from(u32::MAX as u64)) as u32,
                                ((src >> (32 * (off + 1))) & u128::from(u32::MAX as u64)) as u32,
                            )
                        } else {
                            (
                                ((a >> (32 * i)) & u128::from(u32::MAX as u64)) as u32,
                                ((b >> (32 * i)) & u128::from(u32::MAX as u64)) as u32,
                            )
                        };
                        let out = fp3_f32(op, f32::from_bits(x), f32::from_bits(y), 0.0);
                        r |= (out.to_bits() as u128) << (32 * i);
                    }
                }
                self.v.v[rd as usize] = r;
            }
            Insn::MoviVec64 { rd, q, imm8 } => {
                // cmode 111x: each imm8 bit expands to a byte of the 64-bit
                // immediate (measured vs capstone); replicated per D lane.
                let mut imm64: u64 = 0;
                for i in 0..8 {
                    if (imm8 >> i) & 1 == 1 {
                        imm64 |= 0xFFu64 << (8 * i);
                    }
                }
                self.v.v[rd as usize] = if q {
                    (imm64 as u128) | ((imm64 as u128) << 64)
                } else {
                    // Q=0 writes D[0]; upper half UNDEF per DDI → zero.
                    imm64 as u128
                };
            }
            Insn::MoviVec { rd, op, value, width_log2, q } => {
                self.group_exec[1] += 1;
                // Modified immediate: value = precomputed 64-bit lane-unit
                // pattern (decode). MOVI/MVNI write; ORR |=; BIC &= !.
                match op {
                    VecImmOp::Movi | VecImmOp::Mvni => {
                        let imm128 = if q {
                            (value as u128) | ((value as u128) << 64)
                        } else {
                            value as u128 // upper half UNDEF → zero
                        };
                        self.v.v[rd as usize] = imm128;
                    }
                    VecImmOp::Orr => {
                        let pat = if q {
                            (value as u128) | ((value as u128) << 64)
                        } else {
                            value as u128
                        };
                        self.v.v[rd as usize] |= pat;
                    }
                    VecImmOp::Bic => {
                        let pat = if q {
                            (value as u128) | ((value as u128) << 64)
                        } else {
                            value as u128
                        };
                        self.v.v[rd as usize] &= !pat;
                    }
                }
            }
            Insn::FmovVecImm { rd, q, imm8 } => {
                self.group_exec[1] += 1;
                // FMOV (vector, immediate): VFP-ExpandImm, single-precision
                // form (.2s/.4s). imm8 = a:B:cdef:  exp = NOT(b6)b6b5b4<<4
                // | 0xF (low 4 bits forced — the VFP imm exponent rule,
                // verified against the real kernel's fmov d8,#1.0 imm8=0x70);
                // frac[22:19] = b3..b0.
                let b = imm8;
                let exp = (((((!b >> 6) & 1) << 3) | ((b >> 6) & 1) << 2)
                    | ((b >> 5) & 1) << 1)
                    | ((b >> 4) & 1);
                let exp8 = (exp << 4) | 0xF;
                let frac = (b & 0xF) as u32;
                let bits = (((b >> 7) as u32) << 31) | ((exp8 as u32) << 23) | (frac << 19);
                let lane = bits as u64;
                let imm128 = if q {
                    (lane | (lane << 32)) as u128
                        | (((lane | (lane << 32)) as u128) << 64)
                } else {
                    (lane | (lane << 32)) as u128
                };
                self.v.v[rd as usize] = imm128;
            }
            Insn::VShiftImm { rd, rn, op, immh_immb, size, u, q } => {
                self.group_exec[1] += 1;
                // Shift amount (keystone sweep rules, session C):
                //   LEFT forms (shl/sli, sqshl/uqshl/sqshlu, sshll/ushll):
                //       shift = X − (8<<size)
                //   RIGHT forms (sshr/ushr, *sra, r*shr, sri, narrowing,
                //   scvtf/ucvtf): shift = (16<<size) − X.
                let left_style = matches!(op, VShiftOp::Shl | VShiftOp::Sqshl | VShiftOp::Shll);
                let shift = if left_style {
                    (immh_immb as u32) - (8u32 << size)
                } else {
                    ((16u32 << size) - immh_immb as u32) as u32
                };
                let lane_bits = 8u32 << size;
                let mask = (1u128 << lane_bits) - 1;
                let sext = |v: u128| -> i128 {
                    if v & (1 << (lane_bits - 1)) != 0 {
                        (v as i128) - (1i128 << lane_bits)
                    } else {
                        v as i128
                    }
                };
                let sat_signed = |v: i128| -> u128 {
                    let lo = -(1i128 << (lane_bits - 1));
                    let hi = (1i128 << (lane_bits - 1)) - 1;
                    v.clamp(lo, hi) as u128 & mask
                };
                let sat_unsigned = |v: i128| -> u128 {
                    v.clamp(0, (mask) as i128) as u128
                };
                match op {
                    // ---- full-width shifts ----
                    VShiftOp::Shr | VShiftOp::Shra | VShiftOp::Rshr | VShiftOp::Rsra
                    | VShiftOp::Shl | VShiftOp::Sri | VShiftOp::Sqshl | VShiftOp::Sqshlu => {
                        let eb = 1u64 << size;
                        let total = if q { 16u64 } else { 8 };
                        let lanes = (total / eb) as u8;
                        let a = self.v.v[rn as usize];
                        let d = self.v.v[rd as usize];
                        let mut r: u128 = 0;
                        for l in 0..lanes {
                            let sh = (l as u32) * lane_bits;
                            let av = (a >> sh) & mask;
                            let dv = (d >> sh) & mask;
                            let out = match op {
                                VShiftOp::Shr => {
                                    if u {
                                        (av >> shift) & mask
                                    } else {
                                        (sext(av) >> shift) as u128 & mask
                                    }
                                }
                                VShiftOp::Shra => {
                                    let sv = if u {
                                        (av >> shift) & mask
                                    } else {
                                        (sext(av) >> shift) as u128 & mask
                                    };
                                    (dv.wrapping_add(sv) as u128) & mask
                                }
                                VShiftOp::Rshr => {
                                    let round = 1u128 << (shift - 1);
                                    if u {
                                        ((av + round) >> shift) & mask
                                    } else {
                                        ((sext(av) + round as i128) >> shift) as u128 & mask
                                    }
                                }
                                VShiftOp::Rsra => {
                                    let round = 1u128 << (shift - 1);
                                    let sv = if u {
                                        ((av + round) >> shift) & mask
                                    } else {
                                        ((sext(av) + round as i128) >> shift) as u128 & mask
                                    };
                                    (dv.wrapping_add(sv) as u128) & mask
                                }
                                VShiftOp::Shl => {
                                    if u {
                                        // SLI: insert — low `shift` bits of Vd kept
                                        ((av << shift) & mask)
                                            | (dv & ((1u128 << shift) - 1))
                                    } else {
                                        (av << shift) & mask
                                    }
                                }
                                VShiftOp::Sri => {
                                    // SRI: shift right, keep low `shift` bits of Vd
                                    ((av >> shift) & mask)
                                        | (dv & if shift >= lane_bits {
                                            mask
                                        } else {
                                            (1u128 << shift) - 1
                                        })
                                }
                                VShiftOp::Sqshl => {
                                    if u {
                                        sat_unsigned((av << shift) as i128)
                                    } else {
                                        sat_signed(sext(av) << shift)
                                    }
                                }
                                VShiftOp::Sqshlu => {
                                    // signed input, UNSIGNED saturating result
                                    sat_unsigned(sext(av) << shift)
                                }
                                _ => unreachable!(),
                            };
                            r |= (out & mask) << sh;
                        }
                        self.v.v[rd as usize] = if q { r } else { r & 0xFFFF_FFFF_FFFF_FFFF };
                    }
                    // ---- narrowing: src elem = 2× dest; src lanes = 8>>size
                    //      (FULL 128-bit source); Q picks the dest half. ----
                    VShiftOp::Shrn | VShiftOp::Rshrn | VShiftOp::Sqshrn | VShiftOp::Sqrshrn => {
                        // `size` came from X = the DEST width: dest element
                        // bits = 8<<size; src element bits = 16<<size.
                        let src_bits = lane_bits * 2;
                        let src_mask = (1u128 << src_bits) - 1;
                        let lanes = (16u32 / src_bits) as u8; // 8>>size
                        let a = self.v.v[rn as usize];
                        let mut out: u64 = 0;
                        let sext_s = |v: u128| -> i128 {
                            if v & (1 << (src_bits - 1)) != 0 {
                                (v as i128) - (1i128 << src_bits)
                            } else {
                                v as i128
                            }
                        };
                        let rounding = matches!(op, VShiftOp::Rshrn | VShiftOp::Sqrshrn);
                        let round = if rounding { 1i128 << (shift - 1) } else { 0 };
                        for l in 0..lanes {
                            let sh = (l as u32) * src_bits;
                            let av = (a >> sh) & src_mask;
                            let dest_val: u64 = match (op, u) {
                                (VShiftOp::Shrn, _) => ((av >> shift) & mask) as u64,
                                (VShiftOp::Rshrn, _) => ((av >> shift) & mask) as u64,
                                (VShiftOp::Sqshrn, false) => {
                                    sat_signed((sext_s(av) >> shift)) as u64
                                }
                                (VShiftOp::Sqshrn, true) => {
                                    // UQSHRN: unsigned source, unsigned sat
                                    ((av >> shift) & mask).min(mask) as u64
                                }
                                (VShiftOp::Sqrshrn, false) => {
                                    sat_signed(sext_s(av) + round >> shift) as u64
                                }
                                (VShiftOp::Sqrshrn, true) => {
                                    // UQRSHRN: unsigned source + round, unsigned sat
                                    (((av as i128) + round) >> shift).clamp(0, mask as i128)
                                        as u64
                                }
                                _ => 0,
                            };
                            out |= (dest_val & mask as u64) << ((l as u32) * lane_bits);
                        }
                        // Q=0: write low half, zero upper; Q=1: write UPPER
                        // half (the "2" variant), preserve low.
                        self.v.v[rd as usize] = if q {
                            (self.v.v[rd as usize] & 0xFFFF_FFFF_FFFF_FFFF)
                                | ((out as u128) << 64)
                        } else {
                            out as u128
                        };
                    }
                    // ---- widening: src elem = half dest; Q picks the SRC
                    //      half; dest = FULL 128-bit register. ----
                    VShiftOp::Shll => {
                        let src_bits = lane_bits; // src element = 8<<size bits
                        let src_mask = (1u128 << src_bits) - 1;
                        let lanes = (64u32 / src_bits) as u8; // 8>>size
                        let a = self.v.v[rn as usize];
                        let src = if q { a >> 64 } else { a & 0xFFFF_FFFF_FFFF_FFFF };
                        let mut r: u128 = 0;
                        for l in 0..lanes {
                            let sh = (l as u32) * src_bits;
                            let av = (src >> sh) & src_mask;
                            let widened: i128 = if u {
                                av as i128
                            } else {
                                // sign-extend then widen
                                if av & (1 << (src_bits - 1)) != 0 {
                                    (av as i128) | -(1i128 << src_bits)
                                } else {
                                    av as i128
                                }
                            };
                            let out = ((widened << shift) as u128)
                                & ((1u128 << (src_bits * 2)) - 1);
                            r |= out << ((l as u32) * src_bits * 2);
                        }
                        self.v.v[rd as usize] = r;
                    }
                    // ---- fixed-point int → FP ----
                    VShiftOp::Cvtf => {
                        let eb = 1u64 << size;
                        let total = if q { 16u64 } else { 8 };
                        let lanes = (total / eb) as u8;
                        let a = self.v.v[rn as usize];
                        let mut r: u128 = 0;
                        for l in 0..lanes {
                            let sh = (l as u32) * lane_bits;
                            let av = (a >> sh) & mask;
                            let int_val = if u { av as i128 } else { sext(av) };
                            let f = int_val as f64 / (1u64 << shift) as f64;
                            let bits: u64 = match size {
                                3 => f.to_bits(),
                                2 => (f as f32).to_bits() as u64,
                                _ => (simd::f64_to_h(f) as u64),
                            };
                            let wbits: u32 = match size {
                                3 => 64,
                                2 => 32,
                                _ => 16,
                            };
                            r |= ((bits as u128) & ((1u128 << wbits) - 1)) << sh;
                        }
                        self.v.v[rd as usize] = if q { r } else { r & 0xFFFF_FFFF_FFFF_FFFF };
                    }
                    // ---- fixed-point FP → int (FCVTZS/FCVTZU) ----
                    VShiftOp::Fcvtz => {
                        let eb = 1u64 << size;
                        let total = if q { 16u64 } else { 8 };
                        let lanes = (total / eb) as u8;
                        let a = self.v.v[rn as usize];
                        let mut r: u128 = 0;
                        for l in 0..lanes {
                            let sh = (l as u32) * lane_bits;
                            let av = (a >> sh) & mask;
                            // element FP width == lane width (S/D forms)
                            let f = if size == 3 {
                                f64::from_bits(av as u64)
                            } else {
                                f32::from_bits(av as u32) as f64
                            };
                            let scaled = f * (1u64 << shift) as f64;
                            let int_val: i128 = if u {
                                scaled.clamp(0.0, 9.223372036854776e18) as u64 as i128
                            } else {
                                scaled.clamp(-9.223372036854776e18, 9.223372036854776e18) as i64
                                    as i128
                            };
                            r |= ((int_val as u128) & mask) << sh;
                        }
                        self.v.v[rd as usize] = if q { r } else { r & 0xFFFF_FFFF_FFFF_FFFF };
                    }
                }
            }
            Insn::LdStSimd9 { vt, rn, imm9, width_log2, load, mode } => {
                let base = self.rsp(rn);
                let addr = match mode {
                    LsMode::Unscaled | LsMode::Unpriv | LsMode::Pre => {
                        (base as i64 + imm9) as u64
                    }
                    LsMode::Post => base,
                };
                let sz = 1u16 << width_log2;
                if load {
                    let val = self.load_vec(addr, sz)?;
                    self.write_vec_low(vt, sz, val);
                } else {
                    let val = self.read_vec_low(vt, sz);
                    self.store_vec(addr, sz, val)?;
                }
                if matches!(mode, LsMode::Pre | LsMode::Post) {
                    self.set_rsp(rn, (base as i64 + imm9) as u64);
                }
            }
            Insn::LdStSimdU { vt, rn, imm12, width_log2, load } => {
                let addr = self.rsp(rn) + ((imm12 as u64) << width_log2);
                let sz = 1u16 << width_log2;
                if load {
                    let val = self.load_vec(addr, sz)?;
                    self.write_vec_low(vt, sz, val);
                } else {
                    let val = self.read_vec_low(vt, sz);
                    self.store_vec(addr, sz, val)?;
                }
            }
            Insn::RetA { .. } => {
                // QARMA-model auth: our interpreter runs with its own key
                // schedule, so the authenticated strip is identity here.
                self.pc = self.r(30);
                return Ok(());
            }
            Insn::BrAuth { rn, link, .. } => {
                let target = self.r(rn);
                if link {
                    self.x[30] = pc + 4;
                }
                self.pc = target;
                return Ok(());
            }
            Insn::Brk { .. } | Insn::Dcps { .. } | Insn::Drps => {
                // Software breakpoint / debug-state exception: the guest
                // halts here (xnu release kernels hit BRK only on panic
                // paths, so reaching one is a genuine boot finding).
                return Err(StopReason::Panic);
            }
            Insn::AddSubExt { rd, rn, rm, option, imm3, subtract, setflags, is64 } => {
                // S=1: Rd=31 is XZR — discard (CMP-extended). Real-data bug
                // #10 (THE boot stopper): `cmp x17, w16, uxtw` wrote its
                // comparison result into SP via set_rsp(31, …), zeroing the
                // kernel stack mid-boot → `str xzr, [sp, #8]` faulted at
                // 0xfffffff007ff97ac. Rn=31 → ZR on the compare path.
                let a = if setflags && rd == 31 { self.r(rn) } else { self.rsp(rn) };
                let b = option.apply(self.r(rm)) << imm3 as u64;
                if setflags {
                    // carry-in: ADCS only (see AddSubReg — bug #10b).
                    let r = self.add_with_flags(a, b, subtract, is64, subtract);
                    self.set_r(rd, r);
                } else if subtract {
                    let r = a.wrapping_sub(b);
                    self.set_rsp(rd, if is64 { r } else { r & 0xFFFF_FFFF });
                } else {
                    let r = a.wrapping_add(b);
                    self.set_rsp(rd, if is64 { r } else { r & 0xFFFF_FFFF });
                }
            }
            Insn::ShiftReg { rd, rn, rm, op, is64 } => {
                // Data-processing (2 source): register 31 is ZR for BOTH
                // operands — SP is never addressable here.
                let bits: u64 = if is64 { 64 } else { 32 };
                let a = self.r(rn);
                let s = self.r(rm) % bits;
                let r = match op {
                    ShiftOp::Lsl => a << s,
                    ShiftOp::Lsr => a >> s,
                    ShiftOp::Asr => ((a as i64) >> s) as u64,
                    ShiftOp::Ror => a.rotate_right(s as u32),
                };
                self.set_r(rd, if is64 { r } else { r & 0xFFFF_FFFF });
            }
            Insn::Mrs { rt, sysreg } => {
                let v = self.read_sysreg(sysreg);
                self.set_r(rt, v);
            }
            Insn::Msr { sysreg, rt } => {
                self.write_sysreg(sysreg, self.r(rt));
            }
            Insn::Svc { .. } => return Err(StopReason::Panic),
            Insn::Hvc { .. } | Insn::Smc { .. } => return Err(StopReason::Panic),
            Insn::Isb | Insn::Dsb | Insn::Dmb => {}
            Insn::Eret => {
                self.pc = self.sys.elr_el1;
                return Ok(());
            }
            Insn::Genter { .. } => {
                // GXF guarded entry: model as state flip (a13_gxf.c semantics
                // reduced: GENTER → GXF_STATUS becomes 'in guard')
                self.gxf_status = 1;
            }
            Insn::Gexit { .. } => {
                self.gxf_status = 0;
            }
            Insn::Hlt { .. } => {
                self.halted = true;
                return Err(StopReason::Halted);
            }
            // ==================== LSE atomics (group 0) ====================
            Insn::Atomic { op, rt, rs, rn, size_log2, .. } => {
                self.group_exec[0] += 1;
                let size = 1u8 << size_log2;
                let addr = self.r(rn);
                let src = self.r(rs) & self.size_mask(size_log2);
                let old = self.ld(addr, size)?;
                let new = match op {
                    AtomicOp::Add => old.wrapping_add(src),
                    AtomicOp::Clr => old & !src,
                    AtomicOp::Eor => old ^ src,
                    AtomicOp::Set => old | src,
                    AtomicOp::Swp => src,
                    AtomicOp::SMax => {
                        let (a, b) = (old as i64, src as i64);
                        (if a > b { a } else { b }) as u64
                    }
                    AtomicOp::SMin => {
                        let (a, b) = (old as i64, src as i64);
                        (if a < b { a } else { b }) as u64
                    }
                    AtomicOp::UMax => if old > src { old } else { src },
                    AtomicOp::UMin => if old < src { old } else { src },
                };
                self.st(addr, size, new)?;
                self.set_r(rt, old); // return the OLD value
            }
            Insn::Cas { rt, rs, rn, size_log2, .. } => {
                self.group_exec[0] += 1;
                let size = 1u8 << size_log2;
                let addr = self.r(rn);
                let cmp = self.r(rt) & self.size_mask(size_log2);
                let new = self.r(rs) & self.size_mask(size_log2);
                let old = self.ld(addr, size)?;
                if old == cmp {
                    self.st(addr, size, new)?;
                } else {
                    self.set_r(rt, old);
                }
            }
            Insn::Ldxr { rt, rt2, rn, size_log2, pair, .. } => {
                self.group_exec[0] += 1;
                let size = 1u8 << size_log2;
                let addr = self.rsp(rn);
                let a = self.ld(addr, size)?;
                self.set_r(rt, a);
                if pair {
                    let b = self.ld(addr + size as u64, size)?;
                    self.set_r(rt2, b);
                }
            }
            Insn::Stxr { rs, rt, rt2, rn, size_log2, pair, .. } => {
                self.group_exec[0] += 1;
                let size = 1u8 << size_log2;
                let addr = self.rsp(rn);
                self.st(addr, size, self.r(rt))?;
                if pair {
                    self.st(addr + size as u64, size, self.r(rt2))?;
                }
                self.set_r(rs, 0); // exclusive success (single core)
            }
            Insn::Ldar { rt, rn, size_log2 } => {
                self.group_exec[0] += 1;
                let val = self.ld(self.rsp(rn), 1u8 << size_log2)?;
                self.set_r(rt, val);
            }
            Insn::Stlr { rt, rn, size_log2 } => {
                self.group_exec[0] += 1;
                self.st(self.rsp(rn), 1u8 << size_log2, self.r(rt))?;
            }
            Insn::Ldapr { rt, rn, size_log2 } => {
                self.group_exec[0] += 1;
                let val = self.ld(self.rsp(rn), 1u8 << size_log2)?;
                self.set_r(rt, val);
            }
            // ==================== CRC32 (group 11) ====================
            Insn::Crc32 { rd, rn, rm, size_log2, castagnoli } => {
                self.group_exec[11] += 1;
                let size = 1u32 << size_log2;
                let acc = self.r(rn) as u32;
                let val = self.r(rm);
                let out = if castagnoli { crypto::crc32c(size, acc, val) } else { crypto::crc32(size, acc, val) };
                self.set_r(rd, out as u64);
            }
            // ==================== 2-source ====================
            Insn::Udiv { rd, rn, rm } => {
                let a = self.r(rn);
                let b = self.r(rm);
                let q = if b == 0 { 0 } else { a / b };
                self.set_r(rd, q);
            }
            Insn::Sdiv { rd, rn, rm } => {
                let a = self.r(rn) as i64;
                let b = self.r(rm) as i64;
                let q = if b == 0 { 0 } else { a.wrapping_div(b) };
                self.set_r(rd, q as u64);
            }
            Insn::Smulh { rd, rn, rm } => {
                let p = (self.r(rn) as i128) * (self.r(rm) as i128);
                self.set_r(rd, ((p >> 64) & u64::MAX as i128) as u64);
            }
            Insn::Umulh { rd, rn, rm } => {
                let p = (self.r(rn) as u128) * (self.r(rm) as u128);
                self.set_r(rd, (p >> 64) as u64);
            }
            // ============ data-processing (1 source) ============
            Insn::Dp1 { rd, rn, op, is64 } => {
                let mask = if is64 { u64::MAX } else { 0xFFFF_FFFF };
                let v = self.r(rn) & mask;
                let out: u64 = match op {
                    Dp1Op::Rbit => v.reverse_bits(),
                    Dp1Op::Rev16 => {
                        let s = ((v & 0x00FF_00FF_00FF_00FF) << 8)
                            | ((v >> 8) & 0x00FF_00FF_00FF_00FF);
                        s & mask
                    }
                    Dp1Op::Rev32 => {
                        let s = ((v & 0x0000_FFFF_0000_FFFF) << 16)
                            | ((v >> 16) & 0x0000_FFFF_0000_FFFF);
                        s & mask
                    }
                    Dp1Op::Rev => {
                        if is64 {
                            v.swap_bytes()
                        } else {
                            (v as u32).swap_bytes() as u64
                        }
                    }
                    Dp1Op::Clz => {
                        if is64 {
                            v.leading_zeros() as u64
                        } else {
                            (v as u32).leading_zeros() as u64
                        }
                    }
                    Dp1Op::Cls => {
                        // count leading bits equal to the sign bit
                        let x = if is64 {
                            v ^ (v >> 63)
                        } else {
                            let sign = ((v >> 31) & 1) * 0xFFFF_FFFF;
                            v ^ sign
                        };
                        let lz = if is64 {
                            x.leading_zeros()
                        } else {
                            (x as u32).leading_zeros()
                        };
                        lz.saturating_sub(1) as u64
                    }
                };
                self.set_r(rd, out & mask);
            }
            // ==================== PAC (group 12) ====================
            Insn::Pacga { rd, rn, rm } => {
                self.group_exec[12] += 1;
                let tag = crypto::pac(self.r(rn), self.r(rm), self.sys.apgakeylo, self.sys.apgakeyhi);
                self.set_r(rd, tag);
            }
            Insn::Sqrdmlah { rd, rn, rm, is64, subtract } => {
                self.group_exec[1] += 1;
                let (a, b, c) = (self.r(rn), self.r(rm), self.r(rd));
                let out: i64 = if is64 {
                    if subtract {
                        simd::sqrdmlsh_i64(a as i64, b as i64, c as i64) as i64
                    } else {
                        simd::sqrdmlah_i64(a as i64, b as i64, c as i64) as i64
                    }
                } else {
                    let (a, b, c) = (a as u32 as i32, b as u32 as i32, c as u32 as i32);
                    if subtract {
                        simd::sqrdmlsh_i32(a, b, c) as i64
                    } else {
                        simd::sqrdmlah_i32(a, b, c) as i64
                    }
                };
                self.set_r(rd, out as u64);
            }
            // ==================== 3-source / data-proc ====================
            Insn::Madd { rd, rn, rm, ra, subtract, is64 } => {
                let a = self.r(rn);
                let b = self.r(rm);
                let c = self.rsp(ra);
                let (a, b) = if is64 { (a, b) } else { (a & 0xFFFF_FFFF, b & 0xFFFF_FFFF) };
                let r = if subtract { a.wrapping_mul(b).wrapping_sub(c) } else { a.wrapping_mul(b).wrapping_add(c) };
                self.set_rsp(rd, r);
            }
            Insn::MaddW { rd, rn, rm, ra, subtract, unsigned } => {
                let a = self.r(rn) as u32;
                let b = self.r(rm) as u32;
                let prod: i64 = if unsigned {
                    (a as u64 as i64).wrapping_mul(b as u64 as i64)
                } else {
                    (a as i32 as i64).wrapping_mul(b as i32 as i64)
                };
                let c = self.rsp(ra) as i64;
                let r = if subtract { prod.wrapping_sub(c) } else { prod.wrapping_add(c) };
                self.set_rsp(rd, r as u64);
            }
            Insn::LogicReg { rd, rn, rm, kind, imm6, op, setflags, invert, is64 } => {
                let mut b = self.shift(self.r(rm), kind, imm6, is64);
                if invert {
                    b = !b;
                }
                let a = self.r(rn);
                let r = match op {
                    LogicOp::And => a & b,
                    LogicOp::Orr => a | b,
                    LogicOp::Eor => a ^ b,
                };
                if setflags {
                    self.logical_flags(r, is64);
                }
                self.set_r(rd, r);
            }
            Insn::Bfm { rd, rn, immr, imms, kind, is64 } => {
                let bits: u32 = if is64 { 64 } else { 32 };
                let mask = if is64 { u64::MAX } else { 0xFFFF_FFFF };
                let (immr, imms) = if is64 { (immr, imms) } else { (immr & 31, imms & 31) };
                let src = self.r(rn) & mask;
                let dst = self.r(rd);
                match kind {
                    BfmKind::Bfm => {
                        // Insert: dst[immr+width-1 : immr] = src[width-1:0]
                        // (wrapping rotate), all other dst bits preserved.
                        // `imms` encodes ~width: width = bits - imms - 1.
                        let width: u32 = bits - (imms & (bits - 1)) - 1;
                        if width == 0 {
                            self.set_r(rd, dst);
                        } else {
                            let ones = if width >= 64 { u64::MAX } else { (1u64 << width) - 1 };
                            let sh = immr % bits;
                            let field = src & ones;
                            let (placed, wm) = if is64 {
                                (field.rotate_right(sh), ones.rotate_right(sh))
                            } else {
                                (
                                    ((field as u32).rotate_right(sh)) as u64,
                                    ((ones as u32).rotate_right(sh)) as u64,
                                )
                            };
                            self.set_r(rd, ((dst & !wm) | (placed & wm)) & mask);
                        }
                    }
                    BfmKind::Sbfm => {
                        // Signed: extract width = imms-immr+1 bits from immr
                        // and sign-extend. W-form extracting through bit 31
                        // sign-extends into the upper word.
                        if (imms as u32) < immr.min(bits - 1) {
                            // s < r: rotate-model fallback (LSL/ASR alias
                            // territory — rare on the boot path)
                            let rot = src.rotate_right(immr % bits);
                            let sign_bit = (rot >> imms) & 1;
                            let mut v = rot & ((1u64 << (imms + 1)) - 1);
                            if sign_bit == 1 {
                                v |= (!0u64) << (imms + 1);
                            }
                            self.set_r(rd, v & mask);
                        } else {
                            let width = imms - immr + 1;
                            let ones = if width >= 64 { u64::MAX } else { (1u64 << width) - 1 };
                            let field = (src >> immr) & ones;
                            let sign = (field >> (width - 1)) & 1;
                            let mut v = field;
                            if sign == 1 {
                                v |= !ones;
                            }
                            if !is64 && width == 32 && sign == 1 {
                                v |= 0xFFFF_FFFF_0000_0000;
                            }
                            self.set_r(rd, v);
                        }
                    }
                    BfmKind::Ubfm => {
                        // Unsigned: LSR alias (imms == bits-1), LSL alias
                        // (s < r → dst = src << (bits-immr)), else UBFX:
                        // dst = (src >> immr) & ones(imms-immr+1).
                        if imms == bits - 1 {
                            self.set_r(rd, (src >> (immr.min(bits - 1))) & mask);
                        } else if (imms as u32) < immr.min(bits - 1) {
                            let sh = (bits as u64) - (immr.min(bits - 1) as u64);
                            self.set_r(rd, src.wrapping_shl(sh as u32) & mask);
                        } else {
                            let width = imms - immr + 1;
                            let ones = if width >= 64 { u64::MAX } else { (1u64 << width) - 1 };
                            self.set_r(rd, ((src >> immr) & ones) & mask);
                        }
                    }
                }
            }
            Insn::Extr { rd, rn, rm, lsb, is64 } => {
                let mask = if is64 { u64::MAX } else { 0xFFFF_FFFF };
                let hi = self.r(rn) & mask;
                let lo = self.r(rm) & mask;
                let combined: u128 = if is64 {
                    ((hi as u128) << 64) | lo as u128
                } else {
                    ((hi as u128) << 32) | lo as u128
                };
                let r = (combined >> lsb) as u64;
                self.set_r(rd, r & mask);
            }
            Insn::Csel { rd, rn, rm, cond, op, is64 } => {
                let taken = self.cond(cond);
                let mask = if is64 { u64::MAX } else { 0xFFFF_FFFF };
                let n = self.r(rn) & mask;
                let mut m = self.r(rm) & mask;
                if !taken {
                    m = match op {
                        CselOp::Sel => m,
                        CselOp::Inc => m.wrapping_add(1),
                        CselOp::Inv => !m,
                        CselOp::Neg => m.wrapping_neg(),
                    };
                }
                self.set_rsp(rd, if taken { n } else { m });
            }
            Insn::Ccmp { rn, rm_imm, nzcv, cond, ccmn, is64 } => {
                if self.cond(cond) {
                    let mask = if is64 { u64::MAX } else { 0xFFFF_FFFF };
                    let a = self.r(rn) & mask;
                    let b = rm_imm as u64 & mask;
                    self.add_with_flags(a, b, true, is64, !ccmn);
                } else {
                    self.nzcv = (nzcv as u32) << 0; // direct NZCV copy (bits 3..0)
                }
            }
            Insn::MsrSpsel { use_sp } => {
                // single-bank SP model: the flag is tracked for honesty but
                // SP_EL0/SP_EL1 share `self.sp` (matches the boot window —
                // start.s switches banks right before loading the stack it
                // then uses through the same `sp`).
                self.sp_sel = use_sp;
            }
            Insn::MsrImm { daifclr, imm4 } => {
                let bits = (imm4 as u64) << 6; // DAIF bits D[9] A[8] I[7] F[6]
                if daifclr {
                    self.sys.daif &= !bits;
                } else {
                    self.sys.daif |= bits;
                }
            }
            // ==================== PAC (group 12) ====================
            Insn::Pac { op, rd, rn } => {
                self.group_exec[12] += 1;
                let ptr = self.r(rd);
                let modifier = self.rsp(rn);
                let r = match op {
                    PacOp::Xpaci | PacOp::Xpacd => {
                        let p = crypto::xpac(ptr);
                        self.set_r(rd, p);
                        return self.advance(pc);
                    }
                    _ => ptr,
                };
                // Map op → (key pair, sign/verify, invert modifier for AUT)
                let (k0, k1, verify) = match op {
                    PacOp::Pacia | PacOp::Paciza | PacOp::Paciaz | PacOp::Paciasp | PacOp::Autia | PacOp::Autiza | PacOp::Autiaz | PacOp::Autiasp => {
                        (self.sys.apiakeylo, self.sys.apiakeyhi, matches!(op, PacOp::Autia | PacOp::Autiza | PacOp::Autiaz | PacOp::Autiasp))
                    }
                    PacOp::Pacib | PacOp::Pacizb | PacOp::Pacibz | PacOp::Pacibsp | PacOp::Autib | PacOp::Autizb | PacOp::Autibz | PacOp::Autibsp => {
                        (self.sys.apibkeylo, self.sys.apibkeyhi, matches!(op, PacOp::Autib | PacOp::Autizb | PacOp::Autibz | PacOp::Autibsp))
                    }
                    PacOp::Pacda | PacOp::Autda => (self.sys.apdakeylo, self.sys.apdakeyhi, matches!(op, PacOp::Autda)),
                    PacOp::Pacdb | PacOp::Autdb => (self.sys.apdbkeylo, self.sys.apdbkeyhi, matches!(op, PacOp::Autdb)),
                    PacOp::Xpaci | PacOp::Xpacd => unreachable!(),
                };
                if verify {
                    if let Some(p) = crypto::aut(r, modifier, k0, k1) {
                        self.set_r(rd, p);
                    } else {
                        // AUTH failure: bits 54..53 set (ARM behavior model)
                        self.set_r(rd, (r & !0x00C0_0000_0000_0000) | 0x0080_0000_0000_0000);
                    }
                } else {
                    // Sign: the model PAC places the 16-bit tag in bits 48..63
                    self.set_r(rd, crypto::pac(r, modifier, k0, k1));
                }
            }
            // ==================== BTI / hints (groups 13/18) ====================
            Insn::Bti { kind } => {
                self.group_exec[13] += 1;
                let _ = kind; // fault-on-land modeling lands with the exec-loop change
            }
            Insn::Hint { op } => {
                self.group_exec[18] += 1; // DGH bucket (other named hints tracked here)
                let _ = op;
            }
            Insn::TlbiRange { op, rt } => {
                self.group_exec[17] += 1;
                // Rt = base:Scale:Num (v8.4 range format); decode base=bits, etc.
                let v = self.r(rt);
                let num = ((v >> 36) & 0x1F) as u8;
                let scale = ((v >> 46) & 0xF) as u8;
                let base = v & 0xF_FFFF_FFFF;
                let _ = op;
                self.last_tlbi_range = Some((base, scale, num));
                self.mmu.flush();
            }
            // ==================== SIMD / FP16 / crypto (groups 2,3,4,5,6,7,8,9,10,19) ====================
            Insn::Vdot { vd, vn, vm, unsigned, q, two_s } => {
                self.group_exec[6] += 1;
                let acc_size_log2 = 2u8; // S lanes
                let lanes = if q && !two_s { 4 } else { if two_s { 2 } else { 2 } };
                // .2s (non-Q) or .4s (Q): element bytes = 1 (B)
                for i in 0..lanes {
                    let mut acc = self.v.lane(vd, i, acc_size_log2) as u32;
                    // each S accumulator consumes 4 B lanes from Vn/Vm
                    for j in 0..4u8 {
                        let idx = i * 4 + j;
                        let a = self.v.lane(vn, idx, 0) as u32;
                        let b = self.v.lane(vm, idx, 0) as u32;
                        acc = if unsigned { simd::udot_u8(acc, a, b) } else { simd::sdot_u8(acc, a, b) };
                    }
                    self.v.set_lane(vd, i, acc_size_log2, acc as u64);
                }
            }
            Insn::Vsqrdmlah { vd, vn, vm, subtract, size_log2, q } => {
                self.group_exec[5] += 1;
                let lanes = Vregs::lanes(size_log2);
                for i in 0..lanes {
                    let a = self.v.lane(vn, i, size_log2) as u16 as i16;
                    let b = self.v.lane(vm, i, size_log2) as u16 as i16;
                    let c = self.v.lane(vd, i, size_log2) as u16 as i16;
                    let r: i16 = if size_log2 == 1 {
                        if subtract { simd::sqrdmlsh_i16(a, b, c) } else { simd::sqrdmlah_i16(a, b, c) }
                    } else {
                        let (a, b, c) = (a as i32, b as i32, c as i32);
                        (if subtract { simd::sqrdmlsh_i32(a, b, c) } else { simd::sqrdmlah_i32(a, b, c) }) as i16
                    };
                    self.v.set_lane(vd, i, size_log2, r as u64);
                }
                let _ = q;
            }
            Insn::Vfcmla { vd, vn, vm, rot, size_log2, q } => {
                self.group_exec[2] += 1;
                let lanes = Vregs::lanes(size_log2) / 2; // complex pairs
                let lanes = if q { lanes } else { lanes / 2 };
                for i in 0..lanes {
                    let re_i = i * 2;
                    let im_i = i * 2 + 1;
                    if size_log2 == 2 {
                        let acc_re = f32::from_bits(self.v.lane(vd, re_i, 2) as u32);
                        let acc_im = f32::from_bits(self.v.lane(vd, im_i, 2) as u32);
                        let n_re = f32::from_bits(self.v.lane(vn, re_i, 2) as u32);
                        let n_im = f32::from_bits(self.v.lane(vn, im_i, 2) as u32);
                        let m_re = f32::from_bits(self.v.lane(vm, re_i, 2) as u32);
                        let m_im = f32::from_bits(self.v.lane(vm, im_i, 2) as u32);
                        let (re, im) = simd::fcmla_f32(acc_re, acc_im, n_re, n_im, m_re, m_im, rot);
                        self.v.set_lane(vd, re_i, 2, re.to_bits() as u64);
                        self.v.set_lane(vd, im_i, 2, im.to_bits() as u64);
                    } else {
                        let acc_re = simd::h_to_f32(self.v.lane(vd, re_i, 1) as u16);
                        let acc_im = simd::h_to_f32(self.v.lane(vd, im_i, 1) as u16);
                        let n_re = simd::h_to_f32(self.v.lane(vn, re_i, 1) as u16);
                        let n_im = simd::h_to_f32(self.v.lane(vn, im_i, 1) as u16);
                        let m_re = simd::h_to_f32(self.v.lane(vm, re_i, 1) as u16);
                        let m_im = simd::h_to_f32(self.v.lane(vm, im_i, 1) as u16);
                        let (re, im) = simd::fcmla_f32(acc_re, acc_im, n_re, n_im, m_re, m_im, rot);
                        self.v.set_lane(vd, re_i, 1, simd::f32_to_h(re) as u64);
                        self.v.set_lane(vd, im_i, 1, simd::f32_to_h(im) as u64);
                    }
                }
            }
            Insn::Vfcadd { vd, vn, vm, rot270, size_log2, q } => {
                self.group_exec[19] += 1;
                let lanes = Vregs::lanes(size_log2) / 2;
                let lanes = if q { lanes } else { lanes / 2 };
                for i in 0..lanes {
                    let re_i = i * 2;
                    let im_i = i * 2 + 1;
                    // FCADD: acc += (n rot±90) * 1 + m — complex add with rotate:
                    // FCADD #90:  acc_re += -n_im; acc_im += n_re (per-lane pairs)
                    let (n_re, n_im) = if size_log2 == 2 {
                        (
                            f32::from_bits(self.v.lane(vn, re_i, 2) as u32),
                            f32::from_bits(self.v.lane(vn, im_i, 2) as u32),
                        )
                    } else {
                        (
                            simd::h_to_f32(self.v.lane(vn, re_i, 1) as u16),
                            simd::h_to_f32(self.v.lane(vn, im_i, 1) as u16),
                        )
                    };
                    let (rot_re, rot_im) = if rot270 {
                        (n_im, -n_re)
                    } else {
                        (-n_im, n_re)
                    };
                    if size_log2 == 2 {
                        let acc_re = f32::from_bits(self.v.lane(vd, re_i, 2) as u32) + rot_re;
                        let acc_im = f32::from_bits(self.v.lane(vd, im_i, 2) as u32) + rot_im;
                        self.v.set_lane(vd, re_i, 2, acc_re.to_bits() as u64);
                        self.v.set_lane(vd, im_i, 2, acc_im.to_bits() as u64);
                    } else {
                        let acc_re = simd::h_to_f32(self.v.lane(vd, re_i, 1) as u16) + rot_re;
                        let acc_im = simd::h_to_f32(self.v.lane(vd, im_i, 1) as u16) + rot_im;
                        self.v.set_lane(vd, re_i, 1, simd::f32_to_h(acc_re) as u64);
                        self.v.set_lane(vd, im_i, 1, simd::f32_to_h(acc_im) as u64);
                    }
                }
            }
            Insn::Vfp16 { vd, vn, vm, op, q } => {
                self.group_exec[4] += 1;
                let lanes = if q { 8 } else { 4 };
                for i in 0..lanes {
                    let a = simd::h_to_f32(self.v.lane(vn, i, 1) as u16);
                    let b = simd::h_to_f32(self.v.lane(vm, i, 1) as u16);
                    let r = match op {
                        VfpOp::Add => a + b,
                        VfpOp::Sub => a - b,
                        VfpOp::Mul => a * b,
                        VfpOp::Div => a / b,
                        VfpOp::Max => if a > b { a } else { b },
                        VfpOp::Min => if a < b { a } else { b },
                    };
                    self.v.set_lane(vd, i, 1, simd::f32_to_h(r) as u64);
                }
            }
            Insn::Vsha512h { vd, vn, vm, .. } => {
                self.group_exec[7] += 1;
                let d = [self.v.lane(vd, 0, 3), self.v.lane(vd, 1, 3)];
                let n = [self.v.lane(vn, 0, 3), self.v.lane(vn, 1, 3)];
                let m = [self.v.lane(vm, 0, 3), self.v.lane(vm, 1, 3)];
                let out = crypto::sha512h(d, n, m);
                self.v.set_lane(vd, 0, 3, out[0]);
                self.v.set_lane(vd, 1, 3, out[1]);
            }
            Insn::Vsha512su1 { vd, vn, vm } => {
                self.group_exec[7] += 1;
                let d = [self.v.lane(vd, 0, 3), self.v.lane(vd, 1, 3)];
                let n = [self.v.lane(vn, 0, 3), self.v.lane(vn, 1, 3)];
                let m = [self.v.lane(vm, 0, 3), self.v.lane(vm, 1, 3)];
                let out = crypto::sha512su1(d, n, m);
                self.v.set_lane(vd, 0, 3, out[0]);
                self.v.set_lane(vd, 1, 3, out[1]);
            }
            Insn::Vsha512su0 { vd, vn } => {
                self.group_exec[7] += 1;
                let d = [self.v.lane(vd, 0, 3), self.v.lane(vd, 1, 3)];
                let n = [self.v.lane(vn, 0, 3), self.v.lane(vn, 1, 3)];
                let out = crypto::sha512su0(d, n);
                self.v.set_lane(vd, 0, 3, out[0]);
                self.v.set_lane(vd, 1, 3, out[1]);
            }
            Insn::Vsha3 { vd, vn, vm, ra, op } => {
                self.group_exec[8] += 1;
                let a = self.v.v[vn as usize];
                let b = self.v.v[vm as usize];
                let c = self.v.v[ra as usize];
                let r = match op {
                    Sha3Op::Eor3 => crypto::eor3(a, b, c),
                    Sha3Op::Bcax => crypto::bcax(a, b, c),
                    Sha3Op::Rax1 => crypto::rax1(a, b),
                };
                self.v.v[vd as usize] = r;
            }
            Insn::Vxar { vd, vn, vm, imm6 } => {
                self.group_exec[8] += 1;
                let a = self.v.v[vn as usize];
                let b = self.v.v[vm as usize];
                self.v.v[vd as usize] = crypto::xar(a, b, imm6 as u32);
            }
            Insn::Vsm3ss1 { vd, vn, vm, ra } => {
                self.group_exec[9] += 1;
                let t = self.v.lane(ra, 0, 2) as u32; // T from Vra
                let a = self.v.lane(vn, 0, 2) as u32;
                let b = self.v.lane(vm, 0, 2) as u32;
                let c = self.v.lane(ra, 1, 2) as u32;
                let ss1 = crypto::sm3ss1(a, b, c, t);
                self.v.set_lane(vd, 0, 2, ss1 as u64);
            }
            Insn::Vsm3part { vd, vn, vm, w2 } => {
                self.group_exec[9] += 1;
                let a = self.v.lane(vn, 0, 2) as u32;
                let b = self.v.lane(vn, 1, 2) as u32;
                let c = self.v.lane(vm, 0, 2) as u32;
                let r = if w2 { crypto::sm3partw2(a, b, c) } else { crypto::sm3partw1(a, b, c) };
                self.v.set_lane(vd, 0, 2, r as u64);
            }
            Insn::Vsm4ekey { vd, vn, vm } => {
                self.group_exec[9] += 1;
                let rd = [
                    self.v.lane(vd, 0, 2) as u32,
                    self.v.lane(vd, 1, 2) as u32,
                    self.v.lane(vd, 2, 2) as u32,
                    self.v.lane(vd, 3, 2) as u32,
                ];
                let rn4 = [
                    self.v.lane(vn, 0, 2) as u32,
                    self.v.lane(vn, 1, 2) as u32,
                    self.v.lane(vn, 2, 2) as u32,
                    self.v.lane(vn, 3, 2) as u32,
                ];
                let rm4 = [
                    self.v.lane(vm, 0, 2) as u32,
                    self.v.lane(vm, 1, 2) as u32,
                    self.v.lane(vm, 2, 2) as u32,
                    self.v.lane(vm, 3, 2) as u32,
                ];
                let out = crypto::sm4ekey(rd, rn4, rm4);
                for i in 0..4usize {
                    self.v.set_lane(vd, i as u8, 2, out[i] as u64);
                }
            }
            Insn::Vsm4e { vd, vn } => {
                self.group_exec[9] += 1;
                let s = [
                    self.v.lane(vn, 0, 2) as u32,
                    self.v.lane(vn, 1, 2) as u32,
                    self.v.lane(vn, 2, 2) as u32,
                    self.v.lane(vn, 3, 2) as u32,
                ];
                // The guest supplies round keys via the register quad rolling
                // (ARM SM4E uses Vn as both state and key lanes).
                let rks = [s[3], s[3], s[3], s[3]];
                let out = crypto::sm4e(s, &rks);
                for i in 0..4usize {
                    self.v.set_lane(vd, i as u8, 2, out[i] as u64);
                }
            }
            Insn::Vsm3tt { vd, vn, vm, index, two, b } => {
                self.group_exec[9] += 1;
                let ss1 = self.v.lane(vd, 0, 2) as u32;
                let a = self.v.lane(vn, 0, 2) as u32;
                let e = self.v.lane(vn, 1, 2) as u32;
                let c = self.v.lane(vm, index, 2) as u32;
                let (d, ss2) = (self.v.lane(vn, 2, 2) as u32, self.v.lane(vn, 3, 2) as u32);
                let r = match (two, b) {
                    (false, false) => crypto::sm3tt1a(a, self.v.lane(vm, index, 2) as u32, c, ss1),
                    (false, true) => crypto::sm3tt1b(a, c, self.v.lane(vm, index, 2) as u32, ss1),
                    (true, false) => crypto::sm3tt2a(d, e, ss1, ss2),
                    (true, true) => crypto::sm3tt2b(d, e, ss1, ss2),
                };
                self.v.set_lane(vd, 0, 2, r as u64);
            }
            Insn::Vaes { vd, vn, op } => {
                self.group_exec[10] += 1;
                // The crypto helpers use the BE byte convention (state
                // byte 0 = bits 120:127, matching the FIPS vectors); the
                // register file is LE (lane 0 = LSB) — convert both ways.
                let s = u128::from_be_bytes(self.v.v[vn as usize].to_le_bytes());
                let r = match op {
                    AesOp::Ese => crypto::aese(s, 0),
                    AesOp::Esd => crypto::aesd(s, 0),
                    AesOp::Emc => crypto::aesmc(s),
                    AesOp::Eimc => crypto::aesimc(s),
                };
                self.v.v[vd as usize] = u128::from_le_bytes(r.to_be_bytes());
            }
            Insn::Vpmull { vd, vn, vm, q, d64 } => {
                self.group_exec[10] += 1;
                let r = if d64 {
                    let a = self.v.lane(vn, 0, 3);
                    let b = self.v.lane(vm, 0, 3);
                    crypto::pmull64(a, b)
                } else {
                    let a = self.v.lane(vn, 0, 0) | (self.v.lane(vn, 1, 0) << 8)
                        | (self.v.lane(vn, 2, 0) << 16) | (self.v.lane(vn, 3, 0) << 24)
                        | (self.v.lane(vn, 4, 0) << 32) | (self.v.lane(vn, 5, 0) << 40)
                        | (self.v.lane(vn, 6, 0) << 48) | (self.v.lane(vn, 7, 0) << 56);
                    let b = self.v.lane(vm, 0, 0) | (self.v.lane(vm, 1, 0) << 8)
                        | (self.v.lane(vm, 2, 0) << 16) | (self.v.lane(vm, 3, 0) << 24)
                        | (self.v.lane(vm, 4, 0) << 32) | (self.v.lane(vm, 5, 0) << 40)
                        | (self.v.lane(vm, 6, 0) << 48) | (self.v.lane(vm, 7, 0) << 56);
                    crypto::pmull8(a, b)
                };
                let _ = q;
                self.v.v[vd as usize] = r;
            }
            Insn::Vindexed { vd, vn, vm, op, index, size_log2, q } => {
                match op {
                    VIndexedOp::Sdot | VIndexedOp::Udot => {
                        self.group_exec[6] += 1;
                        let lanes = if q { 4 } else { 2 };
                        let unsigned = matches!(op, VIndexedOp::Udot);
                        for i in 0..lanes {
                            let mut acc = self.v.lane(vd, i, 2) as u32;
                            for j in 0..4u8 {
                                let idx = i * 4 + j;
                                let a = self.v.lane(vn, idx, 0) as u32;
                                let b = self.v.lane(vm, index * 4 + j, 0) as u32;
                                acc = if unsigned { simd::udot_u8(acc, a, b) } else { simd::sdot_u8(acc, a, b) };
                            }
                            self.v.set_lane(vd, i, 2, acc as u64);
                        }
                    }
                    VIndexedOp::Sqrdmlah | VIndexedOp::Sqrdmlsh => {
                        self.group_exec[5] += 1;
                        let lanes = Vregs::lanes(size_log2);
                        let subtract = matches!(op, VIndexedOp::Sqrdmlsh);
                        let e = self.v.lane(vm, index, size_log2) as u16 as i16;
                        for i in 0..lanes {
                            let a = self.v.lane(vn, i, size_log2) as u16 as i16;
                            let c = self.v.lane(vd, i, size_log2) as u16 as i16;
                            let r: i16 = if size_log2 == 1 {
                                if subtract { simd::sqrdmlsh_i16(a, e, c) } else { simd::sqrdmlah_i16(a, e, c) }
                            } else {
                                let (a, e, c) = (a as i32, e as i32, c as i32);
                                (if subtract { simd::sqrdmlsh_i32(a, e, c) } else { simd::sqrdmlah_i32(a, e, c) }) as i16
                            };
                            self.v.set_lane(vd, i, size_log2, (r as i16) as u64);
                        }
                    }
                    VIndexedOp::Fcmla(rot) => {
                        self.group_exec[2] += 1;
                        self.exec_indexed_fcmla(vd, vn, vm, rot, index, size_log2, q);
                    }
                    VIndexedOp::Fcadd(is270) => {
                        self.group_exec[19] += 1;
                        self.exec_indexed_fcmla(vd, vn, vm, if is270 { 3 } else { 1 }, index, size_log2, q);
                    }
                }
            }
            Insn::Vldr { rt, rn, imm12 } => {
                let addr = self.rsp(rn) + ((imm12 as u64) << 4);
                let mut v = 0u128;
                for i in 0..16 {
                    let b = self.ld(addr + i, 1)?;
                    v |= (b as u128) << (i * 8);
                }
                self.v.v[rt as usize] = v;
            }
            Insn::Vstr { rt, rn, imm12 } => {
                let addr = self.rsp(rn) + ((imm12 as u64) << 4);
                let v = self.v.v[rt as usize];
                for i in 0..16 {
                    let b = ((v >> (i * 8)) & 0xFF) as u64;
                    self.st(addr + i, 1, b)?;
                }
            }
            Insn::VldrD { rt, rn, imm12 } => {
                let addr = self.rsp(rn) + ((imm12 as u64) << 3);
                let lo = self.ld(addr, 8)?;
                self.v.v[rt as usize] = lo as u128;
            }
            Insn::VstrD { rt, rn, imm12 } => {
                let addr = self.rsp(rn) + ((imm12 as u64) << 3);
                let lo = self.v.v[rt as usize] as u64;
                self.st(addr, 8, lo)?;
            }
            // ==================== FP16 scalar (groups 3/4) ====================
            Insn::Fjcvtzs { rd, rn } => {
                self.group_exec[3] += 1;
                // JavaScript ToInt32 conversion (FJCVTZS semantics): NaN → 0,
                // otherwise the exact-mod-2^32 wrap of the rounded value.
                let d = f64::from_bits(self.v.lane(rn, 0, 3));
                let r: i32 = if d.is_nan() {
                    0
                } else if d >= 2147483648.0 || d < -2147483648.0 {
                    // wrap mod 2^32 (the FJCVTZS "mod" semantics)
                    (d as i64).wrapping_mul(-1) as i32
                } else {
                    d as i32
                };
                self.set_r(rd, (r as u32) as u64);
            }
            Insn::Fcvt { rd, rn, from, to } => {
                self.group_exec[4] += 1;
                let raw = self.v.lane(rn, 0, match from { FpType::S => 2, FpType::D => 3, FpType::H => 1 });
                let val = match from {
                    FpType::S => f32::from_bits(raw as u32) as f64,
                    FpType::D => f64::from_bits(raw),
                    FpType::H => simd::h_to_f64(raw as u16),
                };
                match to {
                    FpType::S => self.v.set_lane(rd, 0, 2, (val as f32).to_bits() as u64),
                    FpType::D => self.v.set_lane(rd, 0, 3, val.to_bits()),
                    FpType::H => self.v.set_lane(rd, 0, 1, simd::f64_to_h(val) as u64),
                }
            }
            Insn::Fp2 { rd, rn, rm, op } => {
                self.group_exec[4] += 1;
                let a = simd::h_to_f32(self.v.lane(rn, 0, 1) as u16);
                let b = simd::h_to_f32(self.v.lane(rm, 0, 1) as u16);
                let r = match op {
                    VfpOp::Add => a + b,
                    VfpOp::Sub => a - b,
                    VfpOp::Mul => a * b,
                    VfpOp::Div => a / b,
                    VfpOp::Max => if a > b { a } else { b },
                    VfpOp::Min => if a < b { a } else { b },
                };
                self.v.set_lane(rd, 0, 1, simd::f32_to_h(r) as u64);
            }
            Insn::Fp1 { rd, rn, op } => {
                self.group_exec[4] += 1;
                let a = simd::h_to_f32(self.v.lane(rn, 0, 1) as u16);
                let r = match op {
                    Vfp1Op::Abs => a.abs(),
                    Vfp1Op::Neg => -a,
                    Vfp1Op::Sqrt => a.sqrt(),
                };
                self.v.set_lane(rd, 0, 1, simd::f32_to_h(r) as u64);
            }
            Insn::FpCvtInt { rd, rn, to_half, unsigned, src64 } => {
                self.group_exec[4] += 1;
                if to_half {
                    // SCVTF/UCVTF H <- W/X
                    let v = self.r(rn);
                    let val = if unsigned {
                        if src64 { v as f64 } else { (v as u32) as f64 }
                    } else if src64 {
                        (v as i64) as f64
                    } else {
                        (v as i32) as f64
                    };
                    self.v.set_lane(rd, 0, 1, simd::f64_to_h(val) as u64);
                } else {
                    // SCVTF/UCVTF S/D <- H
                    let h = simd::h_to_f64(self.v.lane(rn, 0, 1) as u16);
                    if unsigned {
                        let u = h as u64;
                        self.v.set_lane(rd, 0, if src64 { 3 } else { 2 }, u);
                    } else {
                        let s = (h as i64) as u64;
                        self.v.set_lane(rd, 0, if src64 { 3 } else { 2 }, s);
                    }
                }
            }
            Insn::FpCvtFixed { rd, rn, unsigned, src64 } => {
                self.group_exec[4] += 1;
                let h = simd::h_to_f32(self.v.lane(rn, 0, 1) as u16);
                // FCVTZS/FCVTZU (fbits fixed-point; model uses fbits=0 scalar)
                let r = if unsigned {
                    (h.max(0.0) as u64) & if src64 { u64::MAX } else { 0xFFFF_FFFF }
                } else {
                    ((h as i64) & if src64 { -1 } else { 0xFFFF_FFFF }) as u64
                };
                self.set_r(rd, r);
            }
        }
        self.pc = pc + 4;
        Ok(())
    }

    #[inline]
    fn size_mask(&self, size_log2: u8) -> u64 {
        match size_log2 {
            0 => 0xFF,
            1 => 0xFFFF,
            2 => 0xFFFF_FFFF,
            _ => u64::MAX,
        }
    }

    /// Indexed FCMLA/FCADD: per-lane complex multiply-add against the
    /// broadcast element Vm[index] (FCADD maps onto FCMLA with m = 1+0i —
    /// rot 1/3 reproduce the 90°/270° rotate-and-add).
    fn exec_indexed_fcmla(
        &mut self,
        vd: u8,
        vn: u8,
        vm: u8,
        rot: u8,
        index: u8,
        size_log2: u8,
        q: bool,
    ) {
        let lanes = Vregs::lanes(size_log2) / 2;
        let lanes = if q { lanes } else { lanes / 2 };
        for i in 0..lanes {
            let re_i = i * 2;
            let im_i = i * 2 + 1;
            if size_log2 == 2 {
                let m_re = f32::from_bits(self.v.lane(vm, index, 2) as u32);
                let m_im = 0.0;
                let acc_re = f32::from_bits(self.v.lane(vd, re_i, 2) as u32);
                let acc_im = f32::from_bits(self.v.lane(vd, im_i, 2) as u32);
                let n_re = f32::from_bits(self.v.lane(vn, re_i, 2) as u32);
                let n_im = f32::from_bits(self.v.lane(vn, im_i, 2) as u32);
                let (re, im) = simd::fcmla_f32(acc_re, acc_im, n_re, n_im, m_re, m_im, rot);
                self.v.set_lane(vd, re_i, 2, re.to_bits() as u64);
                self.v.set_lane(vd, im_i, 2, im.to_bits() as u64);
            } else {
                let m_re = simd::h_to_f32(self.v.lane(vm, index, 1) as u16);
                let m_im = 0.0;
                let acc_re = simd::h_to_f32(self.v.lane(vd, re_i, 1) as u16);
                let acc_im = simd::h_to_f32(self.v.lane(vd, im_i, 1) as u16);
                let n_re = simd::h_to_f32(self.v.lane(vn, re_i, 1) as u16);
                let n_im = simd::h_to_f32(self.v.lane(vn, im_i, 1) as u16);
                let (re, im) = simd::fcmla_f32(acc_re, acc_im, n_re, n_im, m_re, m_im, rot);
                self.v.set_lane(vd, re_i, 1, simd::f32_to_h(re) as u64);
                self.v.set_lane(vd, im_i, 1, simd::f32_to_h(im) as u64);
            }
        }
    }

    #[inline]
    fn advance(&mut self, pc: u64) -> Result<(), StopReason> {
        self.pc = pc + 4;
        Ok(())
    }

    fn read_sysreg(&mut self, enc: u16) -> u64 {
        // AMUv1 group access bumps the AMU group counter
        if enc == sysreg::AMCR_EL0
            || enc == sysreg::AMCFGR_EL0
            || enc == sysreg::AMCGCR_EL0
            || enc == sysreg::AMUSERENR_EL0
            || enc == sysreg::AMCNTENCLR0_EL0
            || enc == sysreg::AMCNTENSET0_EL0
            || enc == sysreg::AMCNTENCLR1_EL0
            || enc == sysreg::AMCNTENSET1_EL0
            || (enc & 0x7FC0) == (sysreg::amevcntr0(0) & 0x7FC0)
        {
            self.group_exec[15] += 1;
        }
        if enc == sysreg::MPAM0_EL1 || enc == sysreg::MPAM1_EL1 || enc == sysreg::MPAMIDR_EL1 {
            self.group_exec[16] += 1;
        }
        match enc {
            sysreg::SCTLR_EL1 => self.sys.sctlr_el1,
            sysreg::TTBR0_EL1 => self.sys.ttbr0_el1,
            sysreg::TTBR1_EL1 => self.sys.ttbr1_el1,
            sysreg::TCR_EL1 => self.sys.tcr_el1,
            sysreg::CPACR_EL1 => self.sys.cpacr_el1,
            sysreg::DAIF => self.sys.daif,
            sysreg::VBAR_EL1 => self.sys.vbar_el1,
            sysreg::ELR_EL1 => self.sys.elr_el1,
            sysreg::SPSR_EL1 => self.sys.spsr_el1,
            sysreg::GXF_CONFIG_EL1 => self.gxf_config,
            sysreg::GXF_STATUS_EL1 => self.gxf_status,
            sysreg::CNTVCT_EL0 => self.ns_budget_used / 40, // 40ns tick model
            // PAC keys
            sysreg::APIAKEYLO_EL1 => self.sys.apiakeylo,
            sysreg::APIAKEYHI_EL1 => self.sys.apiakeyhi,
            sysreg::APIBKEYLO_EL1 => self.sys.apibkeylo,
            sysreg::APIBKEYHI_EL1 => self.sys.apibkeyhi,
            sysreg::APDAKEYLO_EL1 => self.sys.apdakeylo,
            sysreg::APDAKEYHI_EL1 => self.sys.apdakeyhi,
            sysreg::APDBKEYLO_EL1 => self.sys.apdbkeylo,
            sysreg::APDBKEYHI_EL1 => self.sys.apdbkeyhi,
            sysreg::APGAKEYLO_EL1 => self.sys.apgakeylo,
            sysreg::APGAKEYHI_EL1 => self.sys.apgakeyhi,
            // AMUv1
            sysreg::AMCR_EL0 => self.sys.amcr,
            sysreg::AMCFGR_EL0 => self.sys.amcfgr,
            sysreg::AMCGCR_EL0 => self.sys.amcgcr, // N: 4 architected counters
            sysreg::AMUSERENR_EL0 => self.sys.amuserenr,
            sysreg::AMCNTENCLR0_EL0 => self.sys.amcntenclr0,
            sysreg::AMCNTENSET0_EL0 => self.sys.amcntenset0,
            sysreg::AMCNTENCLR1_EL0 => self.sys.amcntenclr1,
            sysreg::AMCNTENSET1_EL0 => self.sys.amcntenset1,
            _ => {
                // AMEVCNTR00..03_EL0
                for n in 0..4u16 {
                    if enc == sysreg::amevcntr0(n) {
                        return self.sys.amevcntr0[n as usize];
                    }
                }
                // Early-boot named surface (verified vs the real start.s)
                match enc {
                    // T8030 (A13): implementer 0x61, variant 1, arch 0xF,
                    // part 0x120, rev 0 — variant≠0 skips the stepping-halt
                    sysreg::MIDR_EL1 => return 0x611F_0120,
                    sysreg::MPIDR_EL1 => return 0x8000_0000, // core 0, MT=0
                    sysreg::CNTFRQ_EL0 => return 24_000_000, // Apple 24 MHz
                    sysreg::CNTPCT_EL0 => return self.ns_budget_used / 40,
                    sysreg::CTR_EL0 => return 0x8444_C004,
                    sysreg::CURRENT_EL => return 0x4, // EL1
                    // 40-bit PA, 4K+16K granules, 48-bit VA
                    sysreg::ID_AA64MMFR0_EL1 => {
                        return (2 << 0) // PARange = 40-bit
                            | (1 << 20)  // TGran16 supported
                            | (0xF << 24) // TGran64 unsupported
                            | (5 << 32) // TSH = 48-bit
                    }
                    sysreg::ID_AA64MMFR1_EL1 => return 0,
                    // start.s boot-stage poll: bit 1 must read as set
                    sysreg::APPLE_BOOT_STAGE => {
                        return *self.sysreg_store.get(&enc).unwrap_or(&0) | 0b10
                    }
                    sysreg::MAIR_EL1 => return *self.sysreg_store.get(&enc).unwrap_or(&0),
                    sysreg::OSLAR_EL1 => return 0,
                    _ => {}
                }
                self.unknown_sysreg_reads += 1;
                if self.unknown_sysreg_seen.len() < 64 && !self.unknown_sysreg_seen.contains(&enc) {
                    self.unknown_sysreg_seen.push(enc);
                }
                // generic round-trip storage (Apple-custom regs)
                *self.sysreg_store.get(&enc).unwrap_or(&0)
            }
        }
    }

    fn write_sysreg(&mut self, enc: u16, v: u64) {
        if enc == sysreg::MPAM0_EL1 || enc == sysreg::MPAM1_EL1 {
            self.group_exec[16] += 1;
        }
        if enc == sysreg::AMCNTENSET0_EL0
            || enc == sysreg::AMCNTENCLR0_EL0
            || enc == sysreg::AMCNTENSET1_EL0
            || enc == sysreg::AMCNTENCLR1_EL0
            || enc == sysreg::AMUSERENR_EL0
        {
            self.group_exec[15] += 1;
        }
        match enc {
            sysreg::SCTLR_EL1 => {
                self.sys.sctlr_el1 = v;
                self.mmu.set_enabled(v & 1 == 1);
            }
            sysreg::TTBR0_EL1 => {
                self.sys.ttbr0_el1 = v;
                self.mmu.set_ttbr0(v);
            }
            sysreg::TTBR1_EL1 => {
                self.sys.ttbr1_el1 = v;
                self.mmu.set_ttbr1(v);
            }
            sysreg::TCR_EL1 => {
                self.sys.tcr_el1 = v;
                self.mmu.set_tcr(v);
            }
            sysreg::CPACR_EL1 => self.sys.cpacr_el1 = v,
            sysreg::DAIF => self.sys.daif = v,
            sysreg::VBAR_EL1 => self.sys.vbar_el1 = v,
            sysreg::ELR_EL1 => self.sys.elr_el1 = v,
            sysreg::SPSR_EL1 => self.sys.spsr_el1 = v,
            sysreg::GXF_CONFIG_EL1 => self.gxf_config = v,
            sysreg::GXF_STATUS_EL1 => {}
            // PAC keys
            sysreg::APIAKEYLO_EL1 => self.sys.apiakeylo = v,
            sysreg::APIAKEYHI_EL1 => self.sys.apiakeyhi = v,
            sysreg::APIBKEYLO_EL1 => self.sys.apibkeylo = v,
            sysreg::APIBKEYHI_EL1 => self.sys.apibkeyhi = v,
            sysreg::APDAKEYLO_EL1 => self.sys.apdakeylo = v,
            sysreg::APDAKEYHI_EL1 => self.sys.apdakeyhi = v,
            sysreg::APDBKEYLO_EL1 => self.sys.apdbkeylo = v,
            sysreg::APDBKEYHI_EL1 => self.sys.apdbkeyhi = v,
            sysreg::APGAKEYLO_EL1 => self.sys.apgakeylo = v,
            sysreg::APGAKEYHI_EL1 => self.sys.apgakeyhi = v,
            // AMUv1 (SET=write-1-to-set, CLR=write-1-to-clear)
            sysreg::AMCNTENSET0_EL0 => self.sys.amcntenset0 |= v,
            sysreg::AMCNTENCLR0_EL0 => self.sys.amcntenclr0 &= !v,
            sysreg::AMCNTENSET1_EL0 => self.sys.amcntenset1 |= v,
            sysreg::AMCNTENCLR1_EL0 => self.sys.amcntenclr1 &= !v,
            sysreg::AMUSERENR_EL0 => self.sys.amuserenr = v,
            // MPAM
            sysreg::MPAM0_EL1 => self.sys.mpam0_el1 = v,
            sysreg::MPAM1_EL1 => self.sys.mpam1_el1 = v,
            // MAIR: stored, attributes not enforced (honest gap)
            sysreg::MAIR_EL1 => {}
            // OSLAR (debug OS lock): unlock write, no effect
            sysreg::OSLAR_EL1 => {}
            // TLBI (op0=1, CRn=8): full software-TLB invalidate. The
            // Apple range variant (Insn::TlbiRange) flushes separately.
            _ if (enc >> 14) & 1 == 0 && (enc >> 7) & 0xF == 8 => {
                self.mmu.flush();
                self.group_exec[17] += 1;
            }
            // Cache maintenance (op0=1, CRn=7): no cache model — except
            // DC ZVA, which really zeroes the 64-byte aligned line.
            _ if (enc >> 14) & 1 == 0 && (enc >> 7) & 0xF == 7 => {
                let crm = (enc >> 3) & 0xF;
                let op2 = enc & 7;
                if crm == 4 && op2 == 1 {
                    let va = v & !63;
                    for off in (0..64).step_by(8) {
                        if self.st(va + off, 8, 0).is_err() {
                            break;
                        }
                    }
                }
            }
            // ID registers + MPAMIDR are read-only
            sysreg::MPAMIDR_EL1
            | sysreg::ID_AA64ISAR0_EL1
            | sysreg::ID_AA64ISAR1_EL1
            | sysreg::ID_AA64PFR0_EL1
            | sysreg::ID_AA64MMFR2_EL1 => {}
            _ => {
                self.unknown_sysreg_writes += 1;
                if self.unknown_sysreg_seen.len() < 64
                    && !self.unknown_sysreg_seen.contains(&enc)
                {
                    self.unknown_sysreg_seen.push(enc);
                }
                // generic Apple-custom storage: mrs/orr/msr round-trips
                // must preserve values (start.s spins on some of them)
                self.sysreg_store.insert(enc, v);
            }
        }
    }

    pub fn dump_state(&self) -> String {
        let mut s = String::from("A13 interpreter state:\n");
        for i in 0..31 {
            if i % 4 == 0 {
                s.push('\n');
            }
            s.push_str(&format!("  x{:<2} = 0x{:016X}", i, self.x[i]));
        }
        s.push_str(&format!("\n  pc  = 0x{:016X}\n  sp  = 0x{:016X}\n", self.pc, self.sp));
        s
    }
}

impl CpuBackend for Interpreter {
    fn run(&mut self, budget: InterpBudget) -> RunResult {
        self.executed = 0;
        self.ns_budget_used = 0;
        loop {
            if self.executed >= budget.max_insn {
                return RunResult { stop: StopReason::Budget, executed: self.executed };
            }
            if self.ns_budget_used >= budget.max_ns {
                return RunResult { stop: StopReason::Budget, executed: self.executed };
            }
            match self.step() {
                Ok(()) => {
                    self.executed += 1;
                    self.ns_budget_used += 40; // ~25 MIPS model
                }
                Err(StopReason::Halted) => {
                    self.executed += 1;
                    return RunResult { stop: StopReason::Halted, executed: self.executed };
                }
                Err(other) => {
                    return RunResult { stop: other, executed: self.executed };
                }
            }
        }
    }

    fn set_reset_vector(&mut self, pc: u64) {
        self.pc = pc;
    }

    fn regs(&self) -> Vec<u64> {
        self.x.to_vec()
    }

    fn pc(&self) -> u64 {
        self.pc
    }

    fn set_irq(&mut self, _level: bool) {
        // IRQ delivery via AIC IACK; level latched by machine loop.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct FakeRam(Arc<Mutex<Vec<u8>>>);
    impl FakeRam {
        fn new(n: usize) -> Self {
            FakeRam(Arc::new(Mutex::new(vec![0u8; n])))
        }
        fn load_code(&self, base: usize, code: &[u8]) {
            let mut m = self.0.lock().unwrap();
            m[base..base + code.len()].copy_from_slice(code);
        }
    }
    impl MemAccess for FakeRam {
        fn load(&mut self, addr: u64, size: u8) -> u64 {
            let m = self.0.lock().unwrap();
            let off = addr as usize;
            let mut v = 0u64;
            for i in 0..size as usize {
                v |= (*m.get(off + i).unwrap_or(&0) as u64) << (i * 8);
            }
            v
        }
        fn store(&mut self, addr: u64, size: u8, val: u64) {
            let mut m = self.0.lock().unwrap();
            let off = addr as usize;
            for i in 0..size as usize {
                if off + i < m.len() {
                    m[off + i] = ((val >> (i * 8)) & 0xFF) as u8;
                }
            }
        }
        fn fetch32(&mut self, addr: u64) -> u32 {
            self.load(addr, 4) as u32
        }
    }

    // Hand-assembled program:
    //   movz x0, #6
    //   movz x1, #7
    //   mul not in subset → loop add:
    //   movz x2, #0        ; acc
    //   movz x3, #7        ; counter
    // loop:
    //   add x2, x2, x0
    //   sub x3, x3, #1
    //   cbnz x3, loop
    //   str x2, [sp]
    //   hlt #0
    fn mul_program() -> Vec<u8> {
        let mut code = Vec::new();
        let put = |code: &mut Vec<u8>, w: u32| code.extend_from_slice(&w.to_le_bytes());
        // movz x0, #6 : sf=1 opc=10 100101 hw=00 imm16=6 rd=0
        put(&mut code, 0xD28000C0);
        // movz x1, #7
        put(&mut code, 0xD28000E1);
        // movz x2, #0
        put(&mut code, 0xD2800002);
        // movz x3, #7
        put(&mut code, 0xD28000E3);
        // loop (offset 16): add x2,x2,x0 : sf=1 op=0 S=0 01011 shift=00 0 rm=0 imm6=0 rn=2 rd=2
        put(&mut code, 0x8B000042);
        // sub x3,x3,#1 : sf=1 op=1 S=0 100010 sh=0 imm12=1 rn=3 rd=3
        put(&mut code, 0xD1000463);
        // cbnz x3, loop : CBNZ 64, imm19 = -2 (0x7FFFE), rt=3 → 0xB5FFFFC3
        put(&mut code, 0xB5FFFFC3);
        // str x2,[sp] : 11111001 00 imm12=0 rn=31 rt=2 → 0xF90003E2
        put(&mut code, 0xF90003E2);
        // hlt #0 : 11010100 100 imm16=0 → 0xD4400000
        put(&mut code, 0xD4400000);
        code
    }

    #[test]
    fn computes_6x7_via_loop() {
        let ram = FakeRam::new(0x10000);
        ram.load_code(0x1000, &mul_program());
        let mut cpu = Interpreter::new(Box::new(ram));
        cpu.sp = 0x8000;
        cpu.set_reset_vector(0x1000);
        let res = cpu.run(InterpBudget { max_insn: 1000, max_ns: 1_000_000_000 });
        assert!(res.stop == StopReason::Halted, "stop={res:?}");
        // 6*7 = 42 stored at sp
        assert_eq!(cpu.regs()[2], 42);
    }

    #[test]
    fn unknown_insn_stops() {
        let ram = FakeRam::new(0x1000);
        ram.load_code(0x100, &[0x00, 0x00, 0x00, 0x00]); // UDF
        let mut cpu = Interpreter::new(Box::new(ram));
        cpu.set_reset_vector(0x100);
        let res = cpu.run(InterpBudget { max_insn: 10, max_ns: 1_000_000 });
        assert!(matches!(res.stop, StopReason::UnknownInsn { .. }));
    }
}

/// Per-lane FP arithmetic for the three-same FP family (session C). The
/// model targets xnu's FP usage: normal arithmetic, compares and pairwise
/// reduce. FMAXNM/FMINNM implement the IEEE-754 maxNum/minNum NaN rule
/// (a NaN operand yields the OTHER operand); FMAX/FMIN propagate NaN.
/// FMULX: zero × inf yields +2.0 per the ARM pseudo-code special case.
fn fp3_f32(op: crate::decode::V3FpOp, a: f32, b: f32, acc: f32) -> f32 {
    use crate::decode::V3FpOp::*;
    match op {
        Add => a + b,
        Sub => a - b,
        Addp => a + b,
        Abd => (a - b).abs(),
        Mul => a * b,
        Mulx => {
            if (a == 0.0 && b.is_infinite()) || (b == 0.0 && a.is_infinite()) {
                2.0
            } else {
                a * b
            }
        }
        Div => a / b,
        Cmeq => if a == b { f32::from_bits(u32::MAX) } else { 0.0 },
        Cmge => if a >= b { f32::from_bits(u32::MAX) } else { 0.0 },
        Cmgt => if a > b { f32::from_bits(u32::MAX) } else { 0.0 },
        Acge => if a.abs() >= b.abs() { f32::from_bits(u32::MAX) } else { 0.0 },
        Acgt => if a.abs() > b.abs() { f32::from_bits(u32::MAX) } else { 0.0 },
        Max => {
            if a.is_nan() || b.is_nan() {
                f32::NAN
            } else {
                a.max(b)
            }
        }
        Min => {
            if a.is_nan() || b.is_nan() {
                f32::NAN
            } else {
                a.min(b)
            }
        }
        Maxp | Maxnmp => {
            if a.is_nan() {
                b
            } else if b.is_nan() {
                a
            } else {
                a.max(b)
            }
        }
        Minp | Minnmp => {
            if a.is_nan() {
                b
            } else if b.is_nan() {
                a
            } else {
                a.min(b)
            }
        }
        Maxnm => {
            if a.is_nan() {
                b
            } else if b.is_nan() {
                a
            } else {
                a.max(b)
            }
        }
        Minnm => {
            if a.is_nan() {
                b
            } else if b.is_nan() {
                a
            } else {
                a.min(b)
            }
        }
        Mla => a * b + acc,
        Mls => acc - a * b,
        Recps => 2.0 - a * b,
        Rsqrts => (3.0 - a * b) / 2.0,
    }
}

fn fp3_f64(op: crate::decode::V3FpOp, a: f64, b: f64, acc: f64) -> f64 {
    use crate::decode::V3FpOp::*;
    match op {
        Add => a + b,
        Sub => a - b,
        Addp => a + b,
        Abd => (a - b).abs(),
        Mul => a * b,
        Mulx => {
            if (a == 0.0 && b.is_infinite()) || (b == 0.0 && a.is_infinite()) {
                2.0
            } else {
                a * b
            }
        }
        Div => a / b,
        Cmeq => if a == b { f64::from_bits(u64::MAX) } else { 0.0 },
        Cmge => if a >= b { f64::from_bits(u64::MAX) } else { 0.0 },
        Cmgt => if a > b { f64::from_bits(u64::MAX) } else { 0.0 },
        Acge => if a.abs() >= b.abs() { f64::from_bits(u64::MAX) } else { 0.0 },
        Acgt => if a.abs() > b.abs() { f64::from_bits(u64::MAX) } else { 0.0 },
        Max => {
            if a.is_nan() || b.is_nan() {
                f64::NAN
            } else {
                a.max(b)
            }
        }
        Min => {
            if a.is_nan() || b.is_nan() {
                f64::NAN
            } else {
                a.min(b)
            }
        }
        Maxp | Maxnmp => {
            if a.is_nan() {
                b
            } else if b.is_nan() {
                a
            } else {
                a.max(b)
            }
        }
        Minp | Minnmp => {
            if a.is_nan() {
                b
            } else if b.is_nan() {
                a
            } else {
                a.min(b)
            }
        }
        Maxnm => {
            if a.is_nan() {
                b
            } else if b.is_nan() {
                a
            } else {
                a.max(b)
            }
        }
        Minnm => {
            if a.is_nan() {
                b
            } else if b.is_nan() {
                a
            } else {
                a.min(b)
            }
        }
        Mla => a * b + acc,
        Mls => acc - a * b,
        Recps => 2.0 - a * b,
        Rsqrts => (3.0 - a * b) / 2.0,
    }
}
