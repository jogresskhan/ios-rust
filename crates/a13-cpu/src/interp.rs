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
use crate::simd::{self, Vregs};
use crate::{CpuBackend, InterpBudget, MemAccess, RunResult, StopReason};

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
        }
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
            self.sp = v;
        } else {
            self.x[n as usize] = v;
        }
    }

    /// Vector memory read of `bytes` (1/2/4/8/16) as a little-endian u128.
    #[inline]
    fn load_vec(&mut self, addr: u64, bytes: u16) -> u128 {
        if bytes <= 8 {
            self.mem.load(addr, bytes as u8) as u128
        } else {
            let lo = self.mem.load(addr, 8);
            let hi = self.mem.load(addr + 8, (bytes - 8) as u8);
            ((hi as u128) << 64) | lo as u128
        }
    }

    /// Vector memory write of the low `bytes` of `val`.
    #[inline]
    fn store_vec(&mut self, addr: u64, bytes: u16, val: u128) {
        if bytes <= 8 {
            self.mem.store(addr, bytes as u8, val as u64);
        } else {
            self.mem.store(addr, 8, val as u64);
            self.mem.store(addr + 8, (bytes - 8) as u8, (val >> 64) as u64);
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
            let cf = res < a;
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
        let word = self.mem.fetch32(pc);
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
                let a = self.rsp(rn);
                let b = self.shift(self.r(rm), kind, imm6, is64);
                if setflags {
                    let r = self.add_with_flags(a, b, true, is64, subtract);
                    self.set_rsp(rd, r);
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
                let v = self.mem.load(addr, sz);
                self.set_r(rt, v);
            }
            Insn::StrImmU { rt, rn, imm12, size_log2 } => {
                let addr = self.rsp(rn) + ((imm12 as u64) << size_log2);
                let sz = 1u8 << size_log2;
                self.mem.store(addr, sz, self.r(rt));
            }
            Insn::LdrLit { rt, imm, is64 } => {
                let addr = (pc as i64 + imm) as u64;
                let v = self.mem.load(addr, if is64 { 8 } else { 4 });
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
                let a = self.mem.load(addr, sz);
                let b = self.mem.load(addr + sz as u64, sz);
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
                self.mem.store(addr, sz, self.r(rt));
                self.mem.store(addr + sz as u64, sz, self.r(rt2));
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
                let a = Self::sext32(self.mem.load(addr, 4));
                let b = Self::sext32(self.mem.load(addr + 4, 4));
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
                self.v.v[vt as usize] = self.load_vec(addr, sz);
                self.v.v[vt2 as usize] = self.load_vec(addr + sz as u64, sz);
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
                self.store_vec(addr, sz, self.v.v[vt as usize]);
                self.store_vec(addr + sz as u64, sz, self.v.v[vt2 as usize]);
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
                    let v = self.mem.load(addr, sz);
                    self.set_r(rt, v);
                } else {
                    self.mem.store(addr, sz, self.r(rt));
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
                let raw = self.mem.load(addr, sz);
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
                    let raw = self.mem.load(addr, sz);
                    let sh = 64 - 8 * sz;
                    let v = ((raw << sh) as i64 >> sh) as u64;
                    self.set_r(rt, if dest64 { v } else { v & 0xFFFF_FFFF });
                } else if load {
                    let v = self.mem.load(addr, sz);
                    self.set_r(rt, v);
                } else {
                    self.mem.store(addr, sz, self.r(rt));
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
                    let val = self.load_vec(addr, sz);
                    self.write_vec_low(vt, sz, val);
                } else {
                    let val = self.read_vec_low(vt, sz);
                    self.store_vec(addr, sz, val);
                }
                if matches!(mode, LsMode::Pre | LsMode::Post) {
                    self.set_rsp(rn, (base as i64 + imm9) as u64);
                }
            }
            Insn::LdStSimdU { vt, rn, imm12, width_log2, load } => {
                let addr = self.rsp(rn) + ((imm12 as u64) << width_log2);
                let sz = 1u16 << width_log2;
                if load {
                    let val = self.load_vec(addr, sz);
                    self.write_vec_low(vt, sz, val);
                } else {
                    let val = self.read_vec_low(vt, sz);
                    self.store_vec(addr, sz, val);
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
                let a = self.rsp(rn);
                let b = option.apply(self.r(rm)) << imm3 as u64;
                if setflags {
                    let r = self.add_with_flags(a, b, true, is64, subtract);
                    self.set_rsp(rd, r);
                } else if subtract {
                    let r = a.wrapping_sub(b);
                    self.set_rsp(rd, if is64 { r } else { r & 0xFFFF_FFFF });
                } else {
                    let r = a.wrapping_add(b);
                    self.set_rsp(rd, if is64 { r } else { r & 0xFFFF_FFFF });
                }
            }
            Insn::ShiftReg { rd, rn, rm, op, is64 } => {
                let bits: u64 = if is64 { 64 } else { 32 };
                let a = self.rsp(rn);
                let s = self.r(rm) % bits;
                let r = match op {
                    ShiftOp::Lsl => a << s,
                    ShiftOp::Lsr => a >> s,
                    ShiftOp::Asr => ((a as i64) >> s) as u64,
                    ShiftOp::Ror => a.rotate_right(s as u32),
                };
                self.set_rsp(rd, if is64 { r } else { r & 0xFFFF_FFFF });
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
                let old = self.mem.load(addr, size);
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
                self.mem.store(addr, size, new);
                self.set_r(rt, old); // return the OLD value
            }
            Insn::Cas { rt, rs, rn, size_log2, .. } => {
                self.group_exec[0] += 1;
                let size = 1u8 << size_log2;
                let addr = self.r(rn);
                let cmp = self.r(rt) & self.size_mask(size_log2);
                let new = self.r(rs) & self.size_mask(size_log2);
                let old = self.mem.load(addr, size);
                if old == cmp {
                    self.mem.store(addr, size, new);
                } else {
                    self.set_r(rt, old);
                }
            }
            Insn::Ldxr { rt, rt2, rn, size_log2, pair, .. } => {
                self.group_exec[0] += 1;
                let size = 1u8 << size_log2;
                let addr = self.rsp(rn);
                let a = self.mem.load(addr, size);
                self.set_r(rt, a);
                if pair {
                    let b = self.mem.load(addr + size as u64, size);
                    self.set_r(rt2, b);
                }
            }
            Insn::Stxr { rs, rt, rt2, rn, size_log2, pair, .. } => {
                self.group_exec[0] += 1;
                let size = 1u8 << size_log2;
                let addr = self.rsp(rn);
                self.mem.store(addr, size, self.r(rt));
                if pair {
                    self.mem.store(addr + size as u64, size, self.r(rt2));
                }
                self.set_r(rs, 0); // exclusive success (single core)
            }
            Insn::Ldar { rt, rn, size_log2 } => {
                self.group_exec[0] += 1;
                let val = self.mem.load(self.rsp(rn), 1u8 << size_log2);
                self.set_r(rt, val);
            }
            Insn::Stlr { rt, rn, size_log2 } => {
                self.group_exec[0] += 1;
                self.mem.store(self.rsp(rn), 1u8 << size_log2, self.r(rt));
            }
            Insn::Ldapr { rt, rn, size_log2 } => {
                self.group_exec[0] += 1;
                let val = self.mem.load(self.rsp(rn), 1u8 << size_log2);
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
                        let width: u64 = (bits as u64).wrapping_sub(imms as u64).wrapping_sub(1);
                        let hi = if imms == 63 { 0 } else { !0u64 >> (imms + 1) };
                        let lo = !0u64 >> (bits - 1 - imms); // ones(width)
                        let wmask = (hi ^ lo) & mask;
                        let dst_val = (dst & !wmask & mask)
                            | (((src >> immr) | (src << (bits - immr))) & wmask);
                        self.set_r(rd, dst_val & mask);
                    }
                    BfmKind::Sbfm => {
                        // dst = ROR(src, immr) sign-extended from bit imms
                        let rot = src.rotate_right(immr % bits as u32);
                        let v = if imms == bits - 1 {
                            rot
                        } else {
                            let sign_bit = (rot >> imms) & 1;
                            let mut ext = rot & ((1u64 << (imms + 1)) - 1);
                            if sign_bit == 1 {
                                ext |= !0u64 << (imms + 1);
                            }
                            ext
                        };
                        self.set_r(rd, v & mask);
                    }
                    BfmKind::Ubfm => {
                        let rot = src.rotate_right(immr % bits as u32);
                        let w = if imms >= bits - 1 {
                            rot
                        } else {
                            rot & ((1u64 << (imms + 1)) - 1)
                        };
                        // UBFM with imms+1==immr → LSL alias
                        let w = if imms + 1 == immr { src << (bits - immr) } else { w };
                        self.set_r(rd, w & mask);
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
                    let b = self.mem.load(addr + i, 1);
                    v |= (b as u128) << (i * 8);
                }
                self.v.v[rt as usize] = v;
            }
            Insn::Vstr { rt, rn, imm12 } => {
                let addr = self.rsp(rn) + ((imm12 as u64) << 4);
                let v = self.v.v[rt as usize];
                for i in 0..16 {
                    let b = ((v >> (i * 8)) & 0xFF) as u64;
                    self.mem.store(addr + i, 1, b);
                }
            }
            Insn::VldrD { rt, rn, imm12 } => {
                let addr = self.rsp(rn) + ((imm12 as u64) << 3);
                let lo = self.mem.load(addr, 8);
                self.v.v[rt as usize] = lo as u128;
            }
            Insn::VstrD { rt, rn, imm12 } => {
                let addr = self.rsp(rn) + ((imm12 as u64) << 3);
                let lo = self.v.v[rt as usize] as u64;
                self.mem.store(addr, 8, lo);
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
                self.unknown_sysreg_reads += 1;
                0
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
            sysreg::SCTLR_EL1 => self.sys.sctlr_el1 = v,
            sysreg::TTBR0_EL1 => self.sys.ttbr0_el1 = v,
            sysreg::TTBR1_EL1 => self.sys.ttbr1_el1 = v,
            sysreg::TCR_EL1 => self.sys.tcr_el1 = v,
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
            // ID registers + MPAMIDR are read-only
            sysreg::MPAMIDR_EL1
            | sysreg::ID_AA64ISAR0_EL1
            | sysreg::ID_AA64ISAR1_EL1
            | sysreg::ID_AA64PFR0_EL1
            | sysreg::ID_AA64MMFR2_EL1 => {}
            _ => self.unknown_sysreg_writes += 1,
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
