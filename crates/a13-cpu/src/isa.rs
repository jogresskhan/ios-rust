//! ISA summary, constants and the modeled AArch64 system-register table
//! for the Apple A13 (T8030) CPU crate.
//!
//! # Provenance
//!
//! * Topology / extension notes — Apple A13 Bionic (T8030) as modelled by
//!   ChefKiss Inferno (`hw/arm/apple-silicon/a13.c`, `a13_gxf.c`,
//!   `target/arm/cpu.h`): 2× Vortex performance cores + 4× Tempest
//!   efficiency cores, all ARMv8.4-A with Apple extensions.
//! * System-register encodings — ARM Architecture Reference Manual
//!   (ARM DDI 0487), ARMv8.4-A baseline.
//! * Apple GXF / SPRR / VMSA_LOCK encodings — ported from ChefKiss
//!   Inferno `hw/arm/apple-silicon/a13_gxf.c` and `target/arm/cpu.h`
//!   (AGPL-3.0, Visual Ehrmanntraut / Christian Inci).
//!
//! # Apple A13 CPU complex
//!
//! | Cluster        | Cores | Micro-arch | Role                  |
//! |----------------|-------|------------|-----------------------|
//! | Performance    | 2     | Vortex     | big cores (P-cluster) |
//! | Efficiency     | 4     | Tempest    | little cores (E-cluster) |
//!
//! All six cores present the same ISA surface:
//!
//! * **ARMv8.4-A baseline** — A64/A32/T32, VFP/NEON, the v8.4 additions
//!   (dot product, FJCVTZS, …). This crate's interpreter models the A64
//!   integer subset only (see the subset table below).
//! * **GXF** (Guarded Execution Facility) — Apple's guard-page based
//!   kernel-boundary mechanism. A guarded "GL1" execution context is
//!   entered via the Apple `GENTER` instruction (or a GXF abort) and left
//!   via `GEXIT`; while guarded, EL1 system registers read from a banked
//!   `*_GL1` register file. Register set ported in [`crate::gxf`].
//!   (Inferno: `hw/arm/apple-silicon/a13_gxf.c`,
//!   `target/arm/helper.c:arm_cpu_do_interrupt_aarch64`.)
//! * **PAC / pointer authentication** — ARMv8.3 PAC with Apple keys
//!   (APGA + Apple-extended key set). *Not* modeled here; boot code paths
//!   we target run with PAC disabled or patched out.
//! * **AMXv1** — userspace matrix co-processor. *Not* modeled; EL0-only
//!   on the A13 and irrelevant to early boot.
//! * **Apple MMU** — TTE in 16 KiB pages, WXN enforced, SPRR/MPRR page
//!   permission remapping (registers ported in [`crate::gxf`], walker not
//!   yet implemented — the interpreter drives physical memory directly
//!   through [`crate::MemAccess`]).
//! * **VMSA_LOCK_EL1** — Apple register that locks down VBAR/SCTLR/TCR/
//!   TTBR against non-guarded writes (bit constants below, ported from
//!   Inferno `target/arm/cpu.h`).
//!
//! # Implemented A64 instruction subset (this crate)
//!
//! `decode::decode(pc, word) -> Option<Insn>`; `None` means "not in the
//! subset" and the interpreter *reports* the unknown word
//! (`StopReason::UnknownInsn`) — it never silently skips it.
//!
//! | Class                              | Forms                          | Status |
//! |------------------------------------|--------------------------------|--------|
//! | Move wide imm                      | MOVZ / MOVN / MOVK (32/64)     | ✔ exec |
//! | MOV (register)                     | ORR alias `MOV Xd, Xn`         | ✔ exec¹ |
//! | Add/sub imm                        | ADD/SUB/ADDS/SUBS (32/64)      | ✔ exec |
//! | Add/sub shifted reg                | ADD/SUB/ADDS/SUBS (LSL/LSR/ASR)| ✔ exec |
//! | CMP/CMN                            | SUBS/ADDS with Rd=ZR           | ✔ exec |
//! | Logical imm                        | AND/ANDS/ORR/EOR (bitmask imm) | ✔ exec |
//! | Branches imm                       | B, BL, B.cond (14 conds)       | ✔ exec |
//! | Branches reg                       | BR, BLR, RET                   | ✔ exec |
//! | Compare & branch                   | CBZ/CBNZ (32/64)               | ✔ exec |
//! | Test & branch                      | TBZ/TBNZ                       | ✔ exec |
//! | PC-rel address                     | ADR, ADRP                      | ✔ exec |
//! | Load/store uimm                    | LDR/STR 8/16/32/64             | ✔ exec |
//! | Load literal                       | LDR (literal) 32/64            | ✔ exec |
//! | Load/store pair                    | LDP/STP offset/pre/post/NP     | ✔ exec |
//! | System                             | MRS/MSR (register form)        | ✔ exec² |
//! | Barriers                           | ISB/DSB/DMB (→ no-ops)         | ✔ exec |
//! | Exceptions                         | SVC (→ Panic), HVC, SMC        | ✔ exec³ |
//! | Apple GXF                          | GENTER/GEXIT                   | ✔ exec⁴ |
//! | Hints                              | NOP (+YIELD/WFE/WFI → no-op)   | ✔ exec |
//! | Halt                               | HLT (→ clean `Halted` stop)    | ✔ exec⁴ |
//! | ERET                               | ERET (→ pc = ELR_EL1)          | ✔ exec |
//! | Logical shifted reg                | AND/ORR/EOR/BIC/ORN/EON        | ✘ (decode→None) |
//! | Mov wide 32-bit hw>1               | invalid encodings              | ✘ |
//! | AdvSIMD / FP / SVE                 | all                            | ✘ |
//! | Loads/stores: reg offset, pre/post uimm, LDAR*/STXR* (atomics/LSE) | ✘ |
//! | MUL/MADD/SDIV/UDIV/CLZ/CSEL/CCMP…  | data-processing misc           | ✘ |
//! | EXTR/BFM/UBFM/SBFM (bitfield)      | incl. MOVK-adjacent aliases    | ✘ |
//! | CRC32/PMULL/CRYPTO                 | ✘ |
//! | MSR (immediate) DAIFSet/DAIFClr    | system                         | ✘ (reported) |
//!
//! ¹ Pragmatic addition: every real boot path emits `MOV Xd, Xn` (ORR
//!   alias); without it the interpreter reports unknowns immediately.
//! ² System registers routed through [`SystemRegTable`] and the GXF
//!   register file ([`crate::gxf`]); unknown encodings are counted, never
//!   silently ignored.
//! ³ `SVC` stops with [`crate::StopReason::Panic`] (kernel-panic hook);
//!   HVC/SMC likewise (no EL2/EL3 exception model yet).
//! ⁴ Pragmatic additions so tests and the machine crate get clean
//!   stop/resume semantics.
//!
//! Honest coverage estimate vs. full ARMv8.4-A A64: **roughly 5–10 % of
//! instruction classes** (enough for flat early boot / low-level bring-up
//! where code is deliberately simple and AArch64-clean). Everything else
//! stops loudly with the offending word instead of mis-executing.

use core::fmt;

// ---------------------------------------------------------------------------
// System register encoding helpers (ARM DDI 0487 "MRS/MSR system register
// encoding"): enc = op0<<14 | op1<<12 | CRn<<8 | CRm<<4 | op2.
// ---------------------------------------------------------------------------

/// Encode an AArch64 system register into the canonical 15-bit value used
/// by this crate (the instruction's bits 20..5 with Rt removed).
pub const fn sysreg_enc(op0: u16, op1: u16, crn: u16, crm: u16, op2: u16) -> u16 {
    (op0 << 14) | (op1 << 12) | (crn << 8) | (crm << 4) | op2
}

/// Split a canonical encoding back into its fields.
pub const fn sysreg_fields(enc: u16) -> (u16, u16, u16, u16, u16) {
    (
        (enc >> 14) & 0b11,
        (enc >> 12) & 0b111,
        (enc >> 8) & 0xF,
        (enc >> 4) & 0xF,
        enc & 0b111,
    )
}

// ARMv8 system registers modeled by SystemRegTable (op0, op1, CRn, CRm, op2).
/// SCTLR_EL1 — system control (op0=3 op1=0 CRn=1 CRm=0 op2=0).
pub const SCTLR_EL1: u16 = sysreg_enc(3, 0, 1, 0, 0);
/// TTBR0_EL1 — translation table base 0 (op0=3 op1=0 CRn=2 CRm=0 op2=0).
pub const TTBR0_EL1: u16 = sysreg_enc(3, 0, 2, 0, 0);
/// TTBR1_EL1 — translation table base 1 (op0=3 op1=0 CRn=2 CRm=0 op2=1).
pub const TTBR1_EL1: u16 = sysreg_enc(3, 0, 2, 0, 1);
/// TCR_EL1 — translation control (op0=3 op1=0 CRn=2 CRm=0 op2=2).
pub const TCR_EL1: u16 = sysreg_enc(3, 0, 2, 0, 2);
/// CPACR_EL1 — coprocessor access control (op0=3 op1=0 CRn=1 CRm=0 op2=2).
pub const CPACR_EL1: u16 = sysreg_enc(3, 0, 1, 0, 2);
/// DAIF — interrupt mask bits (op0=3 op1=3 CRn=4 CRm=2 op2=1).
pub const DAIF: u16 = sysreg_enc(3, 3, 4, 2, 1);
/// CNTVCT_EL0 — virtual counter read (op0=3 op1=3 CRn=14 CRm=0 op2=2).
pub const CNTVCT_EL0: u16 = sysreg_enc(3, 3, 14, 0, 2);
/// CNTFRQ_EL0 — counter frequency read (op0=3 op1=3 CRn=14 CRm=0 op2=0).
pub const CNTFRQ_EL0: u16 = sysreg_enc(3, 3, 14, 0, 0);
/// MPIDR_EL1 — multiprocessor affinity (op0=3 op1=0 CRn=0 CRm=0 op2=5).
pub const MPIDR_EL1: u16 = sysreg_enc(3, 0, 0, 0, 5);
/// CurrentEL — current exception level (op0=3 op1=0 CRn=4 CRm=2 op2=2).
pub const CURRENT_EL: u16 = sysreg_enc(3, 0, 4, 2, 2);

/// Modeled SCTLR_EL1 reset value: RES1 bits 11/20/22/23 per the ARMv8 ARM
/// (DDI 0487 SCTLR_EL1.RES1) — the value quoted for this port is
/// `0x00C5_0800`. The MMU is off (M=0): the interpreter drives physical
/// memory directly.
pub const SCTLR_EL1_RESET: u64 = 0x00C5_0800;

/// Modeled counter frequency: 25 MHz ⇒ CNTVCT advances one tick per 40 ns
/// (per the port spec; real A13 hardware runs its generic counter at
/// 24 MHz — 41.67 ns/tick — a difference irrelevant to boot code).
pub const CNTFRQ_HZ: u64 = 25_000_000;
/// Nanoseconds per CNTVCT tick (1e9 / CNTFRQ_HZ).
pub const NS_PER_TICK: u64 = 40;

// ---------------------------------------------------------------------------
// SystemRegTable
// ---------------------------------------------------------------------------

/// The small ARMv8 system-register table the interpreter models.
///
/// Plain RW storage for the EL1 MMU/control registers boot code touches
/// first, plus read-only clock registers. Registers not present here are
/// reported by the interpreter (`unknown_sysreg_reads` /
/// `unknown_sysreg_writes`) — never silently dropped.
///
/// CNTVCT_EL0 is derived, not stored: it returns `now_ns / 40` where
/// `now_ns` is the interpreter's monotonic instruction-cost counter.
#[derive(Clone, Debug)]
pub struct SystemRegTable {
    pub sctlr_el1: u64,
    pub ttbr0_el1: u64,
    pub ttbr1_el1: u64,
    pub tcr_el1: u64,
    pub cpacr_el1: u64,
    pub daif: u64,
    /// Core index reported by MPIDR_EL1 (aff0); machine crate sets this.
    pub mpidr_aff0: u64,
}

impl SystemRegTable {
    pub fn new() -> Self {
        SystemRegTable {
            sctlr_el1: SCTLR_EL1_RESET,
            ttbr0_el1: 0,
            ttbr1_el1: 0,
            tcr_el1: 0,
            cpacr_el1: 0,
            daif: 0b1111, // all masked at reset
            mpidr_aff0: 0,
        }
    }

    /// `true` if the encoding is one we model (readable and/or writable).
    pub fn known(&self, sysreg: u16) -> bool {
        matches!(
            sysreg,
            SCTLR_EL1
                | TTBR0_EL1
                | TTBR1_EL1
                | TCR_EL1
                | CPACR_EL1
                | DAIF
                | CNTVCT_EL0
                | CNTFRQ_EL0
                | MPIDR_EL1
                | CURRENT_EL
        )
    }

    /// System-register read; `None` = not modeled. `now_ns` feeds CNTVCT.
    pub fn read(&self, sysreg: u16, now_ns: u64) -> Option<u64> {
        match sysreg {
            SCTLR_EL1 => Some(self.sctlr_el1),
            TTBR0_EL1 => Some(self.ttbr0_el1),
            TTBR1_EL1 => Some(self.ttbr1_el1),
            TCR_EL1 => Some(self.tcr_el1),
            CPACR_EL1 => Some(self.cpacr_el1),
            DAIF => Some(self.daif),
            CNTVCT_EL0 => Some(now_ns / NS_PER_TICK),
            CNTFRQ_EL0 => Some(CNTFRQ_HZ),
            MPIDR_EL1 => Some(self.mpidr_aff0 & 0xFF), // Bit31=0 (UP), others 0
            CURRENT_EL => Some(1 << 2),                // EL1
            _ => None,
        }
    }

    /// System-register write; `false` = not modeled (caller counts it).
    /// CNTVCT/CNTFRQ/MPIDR/CurrentEL are read-only per the ARM (writes
    /// report as unmodeled).
    pub fn write(&mut self, sysreg: u16, val: u64) -> bool {
        match sysreg {
            SCTLR_EL1 => self.sctlr_el1 = val,
            TTBR0_EL1 => self.ttbr0_el1 = val,
            TTBR1_EL1 => self.ttbr1_el1 = val,
            TCR_EL1 => self.tcr_el1 = val,
            CPACR_EL1 => self.cpacr_el1 = val,
            DAIF => self.daif = val & 0x3C0,
            _ => return false,
        }
        true
    }
}

impl Default for SystemRegTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// VMSA_LOCK_EL1 bits (ported from Inferno target/arm/cpu.h) — used by the
// GXF register file to gate non-guarded VBAR_EL1 writes.
// ---------------------------------------------------------------------------

/// VMSA_LOCK_EL1 bit 0: VBAR_EL1 locked against non-guarded writes.
pub const VMSA_LOCK_VBAR_EL1: u64 = 1 << 0;
/// VMSA_LOCK_EL1 bit 1: SCTLR_EL1 locked.
pub const VMSA_LOCK_SCTLR_EL1: u64 = 1 << 1;
/// VMSA_LOCK_EL1 bit 2: TCR_EL1 locked.
pub const VMSA_LOCK_TCR_EL1: u64 = 1 << 2;
/// VMSA_LOCK_EL1 bit 3: TTBR0_EL1 locked.
pub const VMSA_LOCK_TTBR0_EL1: u64 = 1 << 3;
/// VMSA_LOCK_EL1 bit 4: TTBR1_EL1 locked.
pub const VMSA_LOCK_TTBR1_EL1: u64 = 1 << 4;
/// VMSA_LOCK_EL1 bit 63: SCTLR_EL1.M bit locked.
pub const VMSA_LOCK_SCTLR_M_BIT: u64 = 1 << 63;

/// Human-readable decode of a system-register encoding (for logs).
pub fn sysreg_name(enc: u16) -> String {
    match enc {
        SCTLR_EL1 => "SCTLR_EL1".into(),
        TTBR0_EL1 => "TTBR0_EL1".into(),
        TTBR1_EL1 => "TTBR1_EL1".into(),
        TCR_EL1 => "TCR_EL1".into(),
        CPACR_EL1 => "CPACR_EL1".into(),
        DAIF => "DAIF".into(),
        CNTVCT_EL0 => "CNTVCT_EL0".into(),
        CNTFRQ_EL0 => "CNTFRQ_EL0".into(),
        MPIDR_EL1 => "MPIDR_EL1".into(),
        CURRENT_EL => "CurrentEL".into(),
        _ => {
            let (op0, op1, crn, crm, op2) = sysreg_fields(enc);
            format!("S{}_{:#x}_c{:#x}_c{:#x}_{:#x}", op0, op1, crn, crm, op2)
        }
    }
}

impl fmt::Display for SystemRegTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sctlr_el1={:#x} ttbr0={:#x} ttbr1={:#x} tcr={:#x} cpacr={:#x} daif={:#x}",
            self.sctlr_el1, self.ttbr0_el1, self.ttbr1_el1, self.tcr_el1, self.cpacr_el1,
            self.daif
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodings_match_arm_arm() {
        assert_eq!(SCTLR_EL1, 0x3100);
        assert_eq!(TTBR0_EL1, 0x3200);
        assert_eq!(TTBR1_EL1, 0x3201);
        assert_eq!(TCR_EL1, 0x3202);
        assert_eq!(CPACR_EL1, 0x3102);
        assert_eq!(DAIF, 0xF421);
        assert_eq!(CNTVCT_EL0, 0xFE02);
        // round-trip
        for (op0, op1, crn, crm, op2) in
            [(3u16, 0u16, 1u16, 0u16, 0u16), (3, 3, 14, 0, 2), (3, 6, 15, 1, 2)]
        {
            let e = sysreg_enc(op0, op1, crn, crm, op2);
            assert_eq!(sysreg_fields(e), (op0, op1, crn, crm, op2));
        }
    }

    #[test]
    fn table_rw_and_clock() {
        let mut t = SystemRegTable::new();
        assert_eq!(t.sctlr_el1, SCTLR_EL1_RESET);
        assert!(t.write(TTBR0_EL1, 0xdead));
        assert_eq!(t.read(TTBR0_EL1, 0), Some(0xdead));
        // CNTVCT = now_ns / 40
        assert_eq!(t.read(CNTVCT_EL0, 4000), Some(100));
        assert_eq!(t.read(CNTFRQ_EL0, 0), Some(CNTFRQ_HZ));
        // read-only regs report unmodeled writes
        assert!(!t.write(CNTVCT_EL0, 5));
        assert!(!t.known(0));
    }
}
