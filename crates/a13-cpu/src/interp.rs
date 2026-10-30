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
    /// Synthesized on stage-1 translation faults (EC/WnR/DFSC per
    /// `mmu::synth_esr`); guest-writable for M4 vectoring tests.
    pub esr_el1: u64,
    /// Faulting virtual address of the most recent translation fault.
    pub far_el1: u64,
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
    // --- M4: generic timer (xnu arms the VIRTUAL timer; CNTP disabled+IMASK) ---
    /// CTL: bit0 ENABLE, bit1 IMASK, bit2 ISTATUS (RO, synthesized on read).
    pub cntv_ctl: u64,
    pub cntv_cval: u64,
    pub cntp_ctl: u64,
    pub cntp_cval: u64,
    pub cntkctl_el1: u64,
    // --- M4: Apple GXF context registers (T8030 exception plumbing) ---
    /// S3_6_C15_C9_1 — kernel percpu/thread pointer mirror. On hardware the
    /// GXF machinery keeps this live; PPL entry saves TPIDR→here, exception
    /// vectors restore here→TPIDR (both sites byte-verified in the kernel).
    pub gxf_ctx: u64,
    /// S3_6_C15_C8_3 — GXF dispatch flag (the vector spins while bit0 set).
    pub gxf_c8_3: u64,
    /// S3_6_C15_C9_5 — guarded-world ESR mirror.
    pub gxf_esr_m: u64,
    /// S3_6_C15_C9_7 — guarded-world FAR mirror.
    pub gxf_far_m: u64,
    /// TPIDR_EL1 (s3_0_c13_c0_4) — percpu/thread pointer.
    pub tpidr_el1: u64,
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
    /// Exception syndrome register (op0=3 op1=0 CRn=5 CRm=0 op2=0).
    pub const ESR_EL1: u16 = enc(1, 0, 5, 0, 0);
    /// Fault address register (op0=3 op1=0 CRn=6 CRm=0 op2=0).
    pub const FAR_EL1: u16 = enc(1, 0, 6, 0, 0);
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
    /// REAL-DATA BUG #21 fix: TPIDR_EL1 is s3_0_c13_c0_**4** (hand-checked
    /// against the kernel's MRS x8, tpidr_el1 = 0xD538D088 → op2=4), not op2=2.
    pub const TPIDR_EL1: u16 = enc(1, 0, 13, 0, 4);
    pub const TPIDR_EL0: u16 = enc(1, 3, 13, 0, 2);
    pub const TPIDRRO_EL0: u16 = enc(1, 3, 13, 0, 3);
    /// Apple `s3_4_c15_c0_4` — start.s polls bit 1 before touching the
    /// core (boot-stage handshake). Modeled: reads OR-in bit 1.
    pub const APPLE_BOOT_STAGE: u16 = enc(1, 4, 15, 0, 4);
    // --- M4: generic timer (measured usage: MSR CNTV_CTL=1, CNTP_CTL=2,
    // CNTV_TVAL deadlines, MRS CNTV_CTL ISTATUS; census in
    // tools/re/notes/m4-aic-timer-re.md) ---
    pub const CNTV_CTL_EL0: u16 = enc(1, 3, 14, 3, 1);
    pub const CNTV_CVAL_EL0: u16 = enc(1, 3, 14, 3, 2);
    pub const CNTV_TVAL_EL0: u16 = enc(1, 3, 14, 3, 0);
    pub const CNTP_CTL_EL0: u16 = enc(1, 3, 14, 2, 1);
    pub const CNTP_CVAL_EL0: u16 = enc(1, 3, 14, 2, 2);
    pub const CNTP_TVAL_EL0: u16 = enc(1, 3, 14, 2, 0);
    pub const CNTKCTL_EL1: u16 = enc(1, 0, 14, 1, 0);
    // --- M4: Apple GXF + fast-IPI (byte-verified MSR/MRS sites) ---
    pub const GXF_C8_3: u16 = enc(1, 6, 15, 8, 3);
    pub const GXF_CTX: u16 = enc(1, 6, 15, 9, 1);
    pub const GXF_ESR_M: u16 = enc(1, 6, 15, 9, 5);
    pub const GXF_FAR_M: u16 = enc(1, 6, 15, 9, 7);
    pub const IPI_SR_EL1: u16 = enc(1, 5, 15, 1, 1); // fast-IPI status, W1C
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
    /// Insn index at the SCTLR.M 0→1 edge — THE M3 gate metric source:
    /// `mmu_live_insns = executed − mmu_live_from` (RunResult carries it).
    pub mmu_live_from: Option<u64>,
    /// M4: WFI fast-forwarded idle time (ns) — added to the exec time for
    /// CNTVCT/CNTPCT/timer deadlines but NOT counted against the ns budget
    /// (virtual idle must not starve the instruction budget).
    pub ns_ffwd: u64,
    /// M4: AIC IRQ line (the machine's interrupt controller raises it).
    pub irq_line: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    /// M4 counters — the honest report surface.
    pub exc_taken: u64,
    pub fiq_taken: u64,
    pub irq_taken: u64,
    pub sync_aborts: u64,
    /// M4-b: undefined-instruction exceptions vectored to the guest
    /// (ESR EC=UNCATEGORIZED — the kernel's own 0xE7FFDEFF GDB-trap
    /// markers in the panic path, measured at 2 file sites).
    pub undefined_taken: u64,
    pub wfi_count: u64,
    pub wfi_wakeups: u64,
    /// M4: synchronous-abort vectoring budget (0 disables vectoring).
    pub vector_budget: u64,
    /// M4: last exception (kind, esr, far, elr) for the boot report.
    pub last_exception: Option<(&'static str, u64, u64, u64)>,
    /// M4: GXF context seed provenance flag (seeded once, then reported).
    pub gxf_ctx_seeded: bool,
    /// M4: PA window of the kernel's __DATA segment — where the
    /// cpu_data[0] discovery scan runs (the machine fills this from the
    /// parsed segments).
    pub cpu_data_scan: Option<(u64, u64)>,
    /// M4: discovered cpu_data[0] address (report surface).
    pub cpu_data0_addr: Option<u64>,
    /// M4: KVA = PA + kva_base (the kernel's bootstrap identity
    /// virtBase − physBase, set by the machine at handoff).
    pub kva_base: u64,
    /// M4 debug: capture stores of boot-stack-range kernel VAs (finds the
    /// cpu_data_init int-stack field writes without any heuristic scan).
    pub stack_write_watch: bool,
    pub stack_writes: std::collections::VecDeque<(u64, u64, u64)>, // (pc, addr, val)
    /// M4: earliest insn index the failed discovery scan may retry at.
    cpu_data_scan_retry_at: u64,
    /// M4-b (session I): consecutive IDENTICAL exceptions (kind, esr, far,
    /// elr all equal) — the recursion detector. Real handlers make
    /// progress; 96 identical re-entries with zero retired insns between
    /// is a closed report loop (measured: 21,270 cycles of (elr,far)
    /// constant, 0x4F0 stack descent each — the session-H text zeroing).
    exc_repeat_key: Option<(&'static str, u64, u64, u64)>,
    exc_repeat_count: u32,
    /// M4-b: named-stop latch set by the recursion/stack guardrails —
    /// (detail, elr, far, cycles). The run loop converts it to
    /// StopReason::ExceptionRecursion before any further guest insn runs.
    pub recursion_stop: Option<(&'static str, u64, u64, u64)>,
    /// M4-b: kernel __TEXT_EXEC base KVA (set by the machine from the real
    /// segments). An exception taken with SP below this floor means the
    /// exception stack has descended into text — named stop instead of a
    /// silent text zeroing.
    pub text_floor_kva: Option<u64>,
    /// M4-b diagnostics (env IOS_RUST_WATCH_VA, default empty): log every
    /// store whose VA matches (pc+value) — RE aid for global corruption,
    /// first 64 hits per address, zero behavior drift.
    pub watch_store_vas: Vec<u64>,
    watch_store_hits: std::collections::HashMap<u64, u32>,
    /// M4-K diagnostic: stop when pc enters [lo, hi) (env
    /// IOS_RUST_STOP_PC_RANGE="0xlo,0xhi"). The trace ring then holds the
    /// entry path instead of a self-spin filling it.
    pub stop_pc_range: Option<(u64, u64)>,
    /// Diagnostic watchpoints (env IOS_RUST_WATCH="0xaddr,…" — default
    /// empty, zero behavior drift): on pc match, log pc/lr/x0..x3 to
    /// stderr. Kernel-RE breakpoint aid, not emulation semantics.
    pub watch_addrs: Vec<u64>,
    /// Watchpoint dedup: last executed index reported per address.
    watch_last_hit: std::collections::HashMap<u64, u64>,
    // --- M4-b percpu-blocker diagnostics (measured, bounded, report-only) ---
    /// Every vectored synchronous abort: (insn, elr, far, esr) — bounded
    /// ring of the LAST 512 plus the FIRST 8 verbatim (the storm origin).
    pub abort_log: std::collections::VecDeque<(u64, u64, u64, u64)>,
    pub first_aborts: Vec<(u64, u64, u64, u64)>,
    /// Stores into the kernel __DATA window whose VALUE is a stack-range
    /// kernel VA — the cpu_stack_alloc(&BootCpuData) fingerprint
    /// (target+value filtered; no heuristic struct scan).
    pub data_stores: std::collections::VecDeque<(u64, u64, u64)>, // (pc, va, val)
    pub data_store_count: u64,
    /// Stores of 48-bit-truncated kernel VAs (bits 63:48 zero while
    /// 47:32 == 0xFFF0 — observed 0x0000FFF008137198 on the boot path).
    /// REAL-DATA BUG probe; capture-only, zero behavior drift.
    pub poison_stores: std::collections::VecDeque<(u64, u64, u64)>,
    pub poison_count: u64,
    /// xnu panic() entry probe (pc set by boot_real from the measured
    /// wrapper at 0x…987b99c): captures (insn, x0 fmt, x1, x2, x3) per
    /// call — names the ORIGINAL panic that feeds the exception storm.
    pub panic_watch_pc: Option<u64>,
    pub panic_calls: std::collections::VecDeque<(u64, u64, u64, u64, u64, u64)>, // (insn, x0, x1, x2, x3, lr)
    pub panic_call_count: u64,
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
            mmu_live_from: None,
            ns_ffwd: 0,
            irq_line: None,
            exc_taken: 0,
            fiq_taken: 0,
            irq_taken: 0,
            sync_aborts: 0,
            wfi_count: 0,
            wfi_wakeups: 0,
            vector_budget: 100_000,
            last_exception: None,
            gxf_ctx_seeded: false,
            undefined_taken: 0,
            cpu_data_scan: None,
            cpu_data0_addr: None,
            kva_base: 0,
            stack_write_watch: false,
            stack_writes: std::collections::VecDeque::new(),
            cpu_data_scan_retry_at: 0,
            exc_repeat_key: None,
            exc_repeat_count: 0,
            recursion_stop: None,
            text_floor_kva: None,
            watch_store_vas: std::env::var("IOS_RUST_WATCH_VA")
                .unwrap_or_default()
                .split(',')
                .filter_map(|s| u64::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok())
                .collect(),
            watch_store_hits: std::collections::HashMap::new(),
            stop_pc_range: std::env::var("IOS_RUST_STOP_PC_RANGE").ok().and_then(|s| {
                let mut it = s.split(',');
                let lo = u64::from_str_radix(it.next()?.trim_start_matches("0x"), 16).ok()?;
                let hi = u64::from_str_radix(it.next()?.trim_start_matches("0x"), 16).ok()?;
                Some((lo, hi))
            }),
            watch_addrs: std::env::var("IOS_RUST_WATCH")
                .unwrap_or_default()
                .split(',')
                .filter_map(|s| u64::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok())
                .collect(),
            watch_last_hit: std::collections::HashMap::new(),
            abort_log: std::collections::VecDeque::new(),
            first_aborts: Vec::new(),
            data_stores: std::collections::VecDeque::new(),
            data_store_count: 0,
            poison_stores: std::collections::VecDeque::new(),
            poison_count: 0,
            panic_watch_pc: None,
            panic_calls: std::collections::VecDeque::new(),
            panic_call_count: 0,
        }
    }

    /// M4: discover cpu_data[0]'s address by scanning the kernel's __DATA
    /// for the struct the kernel's own bootstrap filled in: a live kernel
    /// VA at +0x4f8 (intstack_top, written by cpu_data_init) with the
    /// exception-depth counter at +0x500 still small. Returns the struct
    /// base. Every seeded byte is guest-written — nothing invented.
    fn discover_cpu_data0(&mut self) -> Option<u64> {
        let (start, end) = self.cpu_data_scan?;
        // rescan cooldown: a failed scan is retried at most once per 1M
        // retired insns (cpu_data_init may simply not have run yet).
        if self.executed < self.cpu_data_scan_retry_at {
            return None;
        }
        let mut addr = (start + 0xF) & !0xF;
        while addr + 0x520 <= end {
            let istack = MemAccess::load(&mut *self.mem, addr + 0x4f8, 8);
            // intstack_top KVA: a canonical kernel VA in the boot-stack
            // neighborhood (observed SP = 0xFFFFFFF0_09B0FD30 — __BOOTDATA
            // stacks). Anything else is a false positive.
            if (0xFFFF_FFF0_0980_0000..0xFFFF_FFF0_0A40_0000).contains(&istack)
                && istack & 7 == 0
            {
                let depth = MemAccess::load(&mut *self.mem, addr + 0x500, 8);
                if depth <= 0x1000 {
                    self.cpu_data0_addr = Some(addr);
                    return Some(addr);
                }
            }
            addr += 8;
        }
        self.cpu_data_scan_retry_at = self.executed + 1_000_000;
        None
    }

    /// Record (pc, word, regs) into the bounded trace ring when enabled.
    #[inline]
    fn trace_tick(&mut self, pc: u64, word: u32) {
        if !self.trace_enabled {
            return;
        }
        let cap = if std::env::var("IOS_RUST_TRACE_DEEP").is_ok() { 2048 } else { 24 };
        if self.trace.len() >= cap {
            self.trace.pop_front();
        }
        self.trace.push_back((pc, word, self.x.to_vec(), self.nzcv));
    }

    pub fn mem(&mut self) -> &mut dyn MemAccess {
        &mut *self.mem
    }

    /// Post-mortem diagnostic: re-walk a VA under the CURRENT table state
    /// (no side effects on counters) — boot reports use it to separate
    /// "the kernel remapped this page" from "our walker misread it".
    pub fn debug_walk(&mut self, va: u64, kind: crate::mmu::XlateKind) -> Result<u64, String> {
        let chain_before = self.mmu.last_fault_chain.len();
        let r = self
            .mmu
            .translate(self.mem.as_mut(), va, kind)
            .map_err(|(v, d)| format!("walk fault va={v:#x} {d}"));
        if self.mmu.last_fault_chain.len() > chain_before {
            self.mmu.last_fault_chain.truncate(chain_before);
        }
        r
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

    /// Sign-extend a 32-bit loaded value to 64 bits.
    #[inline]
    fn sext32(v: u64) -> u64 {
        (v as u32 as i32) as i64 as u64
    }

    /// Translate a VA through the stage-1 MMU (pass-through while off).
    /// M4: on a walk fault, if the guest's VBAR_EL1 is live and vectoring
    /// budget remains, deliver a SYNCHRONOUS ABORT to the vector table
    /// (ELR=faulting insn, FAR=va, ESR per `mmu::synth_esr`, DAIF masked)
    /// and return `ExceptionTaken` — the run loop continues at the vector.
    /// Without a live VBAR (pre-vector boot) the fault stays terminal.
    #[inline]
    fn vaddr(&mut self, va: u64, kind: XlateKind) -> Result<u64, StopReason> {
        if !self.mmu.enabled {
            return Ok(va);
        }
        self.mmu
            .translate(&mut *self.mem, va, kind)
            .map_err(|(v, detail)| {
                let level = self.mmu.last_fault_chain.last().map(|c| c.0).unwrap_or(0);
                let esr = crate::mmu::synth_esr(kind, detail, level);
                if self.sys.vbar_el1 != 0 && self.vector_budget > 0 {
                    self.vector_budget -= 1;
                    self.sync_aborts += 1;
                    // M4-b: bounded abort journal — names the storm origin
                    // (first 8) and the steady-state loop (last 512).
                    self.abort_log.push_back((self.executed, self.pc, v, esr));
                    if self.abort_log.len() > 512 {
                        self.abort_log.pop_front();
                    }
                    if self.first_aborts.len() < 8 {
                        self.first_aborts.push((self.executed, self.pc, v, esr));
                    }
                    // current-EL SPx sync entry (instr + data aborts both
                    // enter at VBAR+0x200; EC in the ESR distinguishes them)
                    self.take_exception(0x200, esr, Some(v), kind.as_str());
                    StopReason::ExceptionTaken
                } else {
                    self.sys.far_el1 = v;
                    self.sys.esr_el1 = esr;
                    StopReason::TranslationFault {
                        pc: self.pc,
                        va: v,
                        kind: kind.as_str(),
                        detail,
                    }
                }
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
        if !self.watch_store_vas.is_empty() && self.watch_store_vas.contains(&va) {
            let c = self.watch_store_hits.entry(va).or_insert(0);
            if *c < 64 {
                *c += 1;
                eprintln!(
                    "[watch-st] insn={} pc={:#x} va={va:#x} val={val:#x} size={size} sp={:#x}",
                    self.executed, self.pc, self.sp
                );
            }
        }
        let pa = self.vaddr(va, XlateKind::Store)?;
        if size == 8 {
            // M4-b: cpu_stack_alloc fingerprint — a stack-range kernel VA
            // stored into the kernel __DATA window (BootCpuData fields live
            // there; the boot stack in __BOOTDATA is excluded by design).
            if (0xFFFF_FFF0_098A_C000..0xFFFF_FFF0_09B0_0000).contains(&va)
                && (0xFFFF_FFF0_0900_0000..0xFFFF_FFF0_8000_0000).contains(&val)
            {
                self.data_store_count += 1;
                if self.data_stores.len() < 256 {
                    self.data_stores.push_back((self.pc, va, val));
                }
                // M4-c Fix #1 (tools/re/notes/m4-text-zeroing-re.md): the
                // first cpu_stack_alloc fingerprint IS cpu_data_init's own
                // intstack_top write (measured pc=0x7b80844 → [0x9a4afc0]=
                // 0x98e4658) — at that moment the RE-validated discovery
                // scan can find cpu_data[0] from the guest's own bytes.
                // Seed TPIDR_EL1 with the discovered KVA ONLY while the
                // kernel has not written TPIDR itself (never overwrite a
                // guest-written value). xnu leaves TPIDR=0 between
                // cpu_data_init and its percpu switch, and the panic path
                // derefs [tpidr+0x4f0] in that window — the exact 21,270-
                // cycle storm origin.
                if self.sys.tpidr_el1 == 0 && self.cpu_data0_addr.is_none() {
                    if let Some(base_pa) = self.discover_cpu_data0() {
                        self.sys.tpidr_el1 = base_pa.wrapping_add(self.kva_base);
                    }
                }
            }
            // M4-b: 48-bit-truncated kernel-VA poison probe (bits 63:48
            // zeroed, 47:32 == 0xFFF0 — impossible as a canonical VA).
            if val & 0xFFFF_0000_0000_0000 == 0 && (val >> 32) & 0xFFFF == 0xFFF0 {
                self.poison_count += 1;
                if self.poison_stores.len() < 32 {
                    self.poison_stores.push_back((self.pc, va, val));
                }
            }
        }
        if self.stack_write_watch
            && size == 8
            && (0xFFFF_FFF0_0980_0000..0xFFFF_FFF0_0A40_0000).contains(&val)
        {
            if self.stack_writes.len() < 128 {
                self.stack_writes.push_back((self.pc, va, val));
            }
        }
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

    /// 24 MHz model counter (measured: gPEClockFrequencyInfo.timebase =
    /// 24,000,000 on T8030; the kernel never reads CNTFRQ but CNTVCT drives
    /// mach_absolute_time). Ticks advance with executed insns (40 ns model)
    /// PLUS WFI fast-forwarded idle time.
    #[inline]
    pub fn ticks(&self) -> u64 {
        (self.ns_budget_used + self.ns_ffwd) * 24 / 1000
    }

    #[inline]
    fn ctl_istatus(&self, ctl: u64, cval: u64) -> bool {
        (ctl & 1) == 1 && (ctl & 2) == 0 && self.ticks() >= cval
    }

    /// Virtual-timer FIQ pending (xnu's ml_get_timer_pending = CNTV_CTL
    /// ISTATUS; sleh_fiq path bypasses the AIC — measured).
    #[inline]
    fn timer_fiq_pending(&self) -> bool {
        self.ctl_istatus(self.sys.cntv_ctl, self.sys.cntv_cval)
    }

    /// Next armed timer deadline in model ns (None = nothing armed).
    fn next_timer_deadline_ns(&self) -> Option<u64> {
        let mut dl = u64::MAX;
        if self.sys.cntv_ctl & 1 == 1 {
            dl = dl.min(self.sys.cntv_cval);
        }
        if self.sys.cntp_ctl & 1 == 1 {
            dl = dl.min(self.sys.cntp_cval);
        }
        if dl == u64::MAX {
            None
        } else {
            Some(dl.saturating_mul(1000) / 24)
        }
    }

    /// M4 exception delivery to the EL1 vector table. `off` = VBAR offset
    /// (current-EL SPx: sync 0x200, IRQ 0x280, FIQ 0x300), `esr` = 0 for
    /// IRQ/FIQ, `far` set for synchronous aborts.
    fn take_exception(&mut self, off: u64, esr: u64, far: Option<u64>, kind: &'static str) {
        // M4-b guardrail 1 — exception recursion: the same (kind, esr, far,
        // elr) re-entered 96 times with no retired insn between means a
        // closed report loop (measured session-H storm: 21,270 identical
        // cycles, each descending the exception stack 0x4F0 bytes until it
        // zeroed 24 MB of __DATA/__TEXT_EXEC). Named stop beats a silent
        // text zeroing; the latch is converted by the run loop.
        let key = (kind, esr, far.unwrap_or(0), self.pc);
        if self.exc_repeat_key == Some(key) {
            self.exc_repeat_count += 1;
        } else {
            self.exc_repeat_key = Some(key);
            self.exc_repeat_count = 1;
        }
        if self.exc_repeat_count >= 96 && self.recursion_stop.is_none() {
            self.recursion_stop = Some((
                "identical-exception-loop",
                self.sys.elr_el1,
                far.unwrap_or(0),
                self.exc_repeat_count as u64,
            ));
        }
        // M4-b guardrail 2 — stack descended into text: an exception entry
        // with SP below __TEXT_EXEC means the exception stack walked into
        // the kernel image (the session-H zeroing's terminal state).
        if let Some(floor) = self.text_floor_kva {
            if self.sp != 0 && self.sp < floor && self.recursion_stop.is_none() {
                self.recursion_stop = Some((
                    "stack-descended-into-text",
                    self.sys.elr_el1,
                    self.sp,
                    self.exc_taken,
                ));
            }
        }
        // SPSR_EL1 = NZCV | DAIF | M[3:0]=EL1h (0b0101)
        self.sys.spsr_el1 = ((self.nzcv as u64) << 28) | self.sys.daif | 0x5;
        self.sys.elr_el1 = self.pc;
        self.sys.esr_el1 = esr;
        if let Some(f) = far {
            self.sys.far_el1 = f;
        }
        // entry masks async exceptions (DAIF.I/F set)
        self.sys.daif |= 0x3C0;
        self.sp_sel = true; // SPx
        self.pc = self.sys.vbar_el1.wrapping_add(off);
        self.exc_taken += 1;
        self.last_exception = Some((kind, esr, far.unwrap_or(0), self.sys.elr_el1));
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
        if let Some((lo, hi)) = self.stop_pc_range {
            if pc >= lo && pc < hi {
                self.pc = pc;
                return Err(StopReason::Budget);
            }
        }
        let Some(insn) = crate::decode::decode(pc, word) else {
            // M4-b (session I): an undecodable word is NOT a model stop
            // once the guest has exception vectoring — real hardware raises
            // a SYNCHRONOUS UNDEFINED-INSTRUCTION exception (ESR
            // EC=ESR_EC_UNCATEGORIZED=0, IL=1, ISS=0 — the ISS=0 the real
            // kernel asserts on, tools/re/refs/xnu/sleh.c:694; delivered
            // via handle_uncategorized → EXC_BAD_INSTRUCTION). The kernel's
            // own text contains deliberate markers (0xE7FFDEFF, the ARM
            // GDB trap, 2 file sites in the panic path — measured) that
            // MUST vector, not halt. Pre-VBAR boot keeps the terminal
            // stop (the boot stub region genuinely has no handler).
            if self.sys.vbar_el1 != 0 && self.vector_budget > 0 {
                self.vector_budget -= 1;
                self.undefined_taken += 1;
                self.abort_log.push_back((self.executed, self.pc, self.pc, 0x0200_0000));
                if self.abort_log.len() > 512 {
                    self.abort_log.pop_front();
                }
                if self.first_aborts.len() < 8 {
                    self.first_aborts.push((self.executed, self.pc, self.pc, 0x0200_0000));
                }
                self.take_exception(0x200, 0x0200_0000, Some(pc), "undefined");
                return Err(StopReason::ExceptionTaken);
            }
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
                    // S=1 with Rd=31 is the CMP/CMN alias — discard (bug #31
                    // family: the old set_rsp(31) wrote the compare result
                    // into SP). S=0 with Rd=31 is `add sp, …` — SP write.
                    let r = self.add_with_flags(a, b, false, is64, false);
                    self.set_r(rd, r);
                } else {
                    self.set_rsp(rd, a.wrapping_add(b));
                }
            }
            Insn::SubImm { rd, rn, imm12, shift, setflags, is64 } => {
                let a = self.rsp(rn);
                let b = (imm12 as u64) << if shift { 12 } else { 0 };
                if setflags {
                    // S=1: Rd=31 = ZR discard (cmp sp, #imm) — see AddImm.
                    let r = self.add_with_flags(a, b, true, is64, true);
                    self.set_r(rd, r);
                } else {
                    self.set_rsp(rd, a.wrapping_sub(b));
                }
            }
            Insn::AddSubReg { rd, rn, rm, kind, imm6, subtract, setflags, is64 } => {
                // S=1: Rd=31 is XZR (CMP/CMP-shifted) — the result must be
                // DISCARDED, never written to SP (QEMU op_add_sub_reg: is_cmp
                // path). Real-data bug #10: `cmp x1, x2, lsl #2` clobbered SP
                // with the comparison result and zeroed the kernel stack.
                // REAL-DATA BUG #31: Rn=31 reads SP in the add/sub register
                // forms ALWAYS (S=0 and S=1 — `cmp sp, x18` is
                // `subs xzr, sp, x18`); the old "ZR on the compare path"
                // special-case compared 0 against the bound and the kernel's
                // exception-stack guard at 0x…8160400 spun on stale flags.
                let a = self.rsp(rn);
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
                // REAL-DATA BUG #31: rn=31 = SP (`cmp sp, #imm`).
                let a = self.rsp(rn);
                let b = (imm12 as u64) << if shift { 12 } else { 0 };
                self.add_with_flags(a, b, true, is64, true);
            }
            Insn::CmnImm { rn, imm12, shift, is64 } => {
                // REAL-DATA BUG #31: rn=31 = SP (`cmn sp, #imm`).
                let a = self.rsp(rn);
                let b = (imm12 as u64) << if shift { 12 } else { 0 };
                self.add_with_flags(a, b, false, is64, false);
            }
            Insn::CmnReg { rn, rm, kind, imm6, is64 } => {
                // REAL-DATA BUG #31: rn=31 = SP (`cmn sp, x18`).
                let a = self.rsp(rn);
                let b = self.shift(self.r(rm), kind, imm6, is64);
                self.add_with_flags(a, b, false, is64, false);
            }
            Insn::CmpReg { rn, rm, kind, imm6, is64 } => {
                // REAL-DATA BUG #31: rn=31 = SP (`cmp sp, x18`).
                let a = self.rsp(rn);
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
            Insn::LdrLitSw { rt, imm } => {
                // LDRSW Xt, label — sign-extended 32-bit literal load
                let addr = (pc as i64 + imm) as u64;
                let v = self.ld(addr, 4)?;
                self.set_r(rt, (v as u32 as i32) as i64 as u64);
            }
            Insn::LdrLitVec { rt, imm, width_log2 } => {
                // SIMD LDR (literal): S/D/Q from a PC-relative address
                let addr = (pc as i64 + imm) as u64;
                let sz = 1u16 << width_log2;
                let val = self.load_vec(addr, sz)?;
                self.write_vec_low(rt, sz, val);
            }
            Insn::Adc { rd, rn, rm, setflags, subtract, is64 } => {
                // ADC/ADCS/SBC/SBCS (session D): carry-in via NZCV.C.
                let c_in = self.nzcv & C != 0;
                let mask = if is64 { u64::MAX } else { 0xFFFF_FFFF };
                let (a, b) = (self.r(rn) & mask, self.r(rm) & mask);
                if setflags {
                    let res = self.add_with_flags(self.r(rn), self.r(rm), c_in, is64, subtract);
                    self.set_r(rd, res);
                } else {
                    // plain ADC/SBC: no flag writes
                    let res = if subtract {
                        a.wrapping_sub(b).wrapping_sub(!c_in as u64)
                    } else {
                        a.wrapping_add(b).wrapping_add(c_in as u64)
                    } & mask;
                    self.set_r(rd, res);
                }
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
                        // Session D: shift-by-register three-same. Amount =
                        // signed element of Vm; positive → left, negative →
                        // right (arithmetic for U=0 SSHL/SQSHL-family, logical
                        // for U=1 USHL/UQSHL-family). SRSHL/URSHL (Rshl) and
                        // SQRSHL/UQRSHL (Rsqshl) negate the amount.
                        V3Op::Shl | V3Op::Sqshl | V3Op::Rshl | V3Op::Rsqshl => {
                            let negate = matches!(op, V3Op::Rshl | V3Op::Rsqshl);
                            let sat = matches!(op, V3Op::Sqshl | V3Op::Rsqshl);
                            let amt_raw = sext(pair[l as usize].1) as i64;
                            let mut amt = if negate { -amt_raw } else { amt_raw };
                            // saturating ops clamp the shift amount to width
                            if sat {
                                amt = amt.clamp(-(bits as i64), bits as i64);
                            }
                            let x = pair[l as usize].0;
                            if amt >= 0 {
                                if sat {
                                    // saturating left shift
                                    if amt >= bits as i64 {
                                        if sext(x) == 0 {
                                            0
                                        } else if sext(x) < 0 && !u {
                                            (1i128 << (bits - 1)) as u128 & mask
                                        } else {
                                            mask
                                        }
                                    } else {
                                        let wide = (x as i128) << amt;
                                        let lim = (1i128 << (bits - 1)) - 1;
                                        if !u && wide > lim {
                                            lim as u128 & mask
                                        } else if !u && wide < -lim - 1 {
                                            ((-lim - 1) as u128) & mask
                                        } else if u && wide > (lim << 1 | 1) {
                                            mask
                                        } else {
                                            (wide as u128) & mask
                                        }
                                    }
                                } else if u {
                                    // USHL: logical left
                                    if amt >= bits as i64 {
                                        0
                                    } else {
                                        (x << amt) & mask
                                    }
                                } else {
                                    // SSHL: arithmetic left (same as logical)
                                    if amt >= bits as i64 {
                                        0
                                    } else {
                                        (x << amt) & mask
                                    }
                                }
                            } else {
                                let amt = (-amt) as u32;
                                if amt >= bits as u32 {
                                    if !u && sext(x) < 0 {
                                        mask
                                    } else {
                                        0
                                    }
                                } else if u {
                                    (x >> amt) & mask
                                } else {
                                    ((sext(x) >> amt) as u128) & mask
                                }
                            }
                        }
                        // Session D: ADDP three-register (pairwise add).
                        // First half of the lanes fold Vn pairs, second half
                        // fold Vm pairs (mirrors the FP Addp layout).
                        V3Op::Addp3 => {
                            let half = (lanes / 2).max(1);
                            let (src, idx) = if (l as u64) < half {
                                (a, (l as u64) * 2)
                            } else {
                                (b, ((l as u64) - half) * 2)
                            };
                            let sh0 = idx * eb * 8;
                            let sh1 = sh0 + eb * 8;
                            let x = (src >> sh0) & mask;
                            let y = (src >> sh1) & mask;
                            x.wrapping_add(y) & mask
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
            Insn::FmovVecImm { rd, q, imm8, double } => {
                self.group_exec[1] += 1;
                // FMOV (vector, immediate): VFP-ExpandImm. U=0: FP32 lanes
                // (.4s/.2s); U=1: FP64 lanes (.2d — 6F00F400 fmov v0.2d,#2.0).
                let s = (imm8 >> 7) & 1;
                let n = (imm8 >> 6) & 1;
                let e2 = ((imm8 >> 4) & 3) as u64;
                let frac = (imm8 & 0xF) as u64;
                if double {
                    let mut exp: u64 = if n == 0 { 1 << 10 } else { 0 };
                    if n == 1 {
                        exp |= ((1u64 << 8) - 1) << 2;
                    }
                    exp |= e2 << 2;
                    let bits = ((s as u64) << 63) | (exp << 52) | (frac << 48);
                    let imm128 = (bits as u128) | ((bits as u128) << 64);
                    self.v.v[rd as usize] = if q { imm128 } else { bits as u128 };
                } else {
                    let mut exp: u32 = if n == 0 { 1 << 7 } else { 0 };
                    if n == 1 {
                        exp |= ((1u32 << 5) - 1) << 2;
                    }
                    exp |= (e2 as u32) << 2;
                    let bits = ((s as u32) << 31) | (exp << 23) | ((frac as u32) << 19);
                    let lane = bits as u64;
                    let imm128 = if q {
                        (lane | (lane << 32)) as u128
                            | (((lane | (lane << 32)) as u128) << 64)
                    } else {
                        (lane | (lane << 32)) as u128
                    };
                    self.v.v[rd as usize] = imm128;
                }
            }
            Insn::LdStSimdRegOff { vt, rn, rm, option, scaled, width_log2, load } => {
                self.group_exec[0] += 1;
                let bytes = 1u16 << width_log2;
                let shift = if scaled { width_log2 as u64 } else { 0 };
                let addr = self.rsp(rn).wrapping_add(option.apply(self.r(rm)) << shift);
                if load {
                    let val = self.load_vec(addr, bytes)?;
                    self.write_vec_low(vt, bytes, val);
                } else {
                    let val = self.read_vec_low(vt, bytes);
                    self.store_vec(addr, bytes, val)?;
                }
            }
            Insn::LdStMult { q, load, op4, type2, post, rm, rn, rt } => {
                self.group_exec[0] += 1;
                // regs from op4 {0:4, 2:4, 4:3, 6:3, 7:1, 8:2, 0xA:2};
                // lanes per reg = 8>>type2 (Q=0) or 16>>type2 (Q=1);
                // element bytes = 1<<type2.
                let regs: u8 = match op4 {
                    0x0 | 0x2 => 4,
                    0x4 | 0x6 => 3,
                    0x7 => 1,
                    0x8 => 2,
                    0xA => 2,
                    _ => 1,
                };
                let ebytes = 1u16 << type2;
                let lanes: u16 = (if q { 16 } else { 8 }) / ebytes;
                let per_reg = (lanes * ebytes) as u64; // 8 or 16
                let base = self.rsp(rn);
                if load {
                    for l in 0..lanes {
                        for r in 0..regs {
                            let addr = base + (l as u64) * (regs as u64) * (ebytes as u64)
                                + (r as u64) * (ebytes as u64);
                            let val = self.load_vec(addr, ebytes)?;
                            let sh = (l as u32) * (ebytes as u32) * 8;
                            let keep = !((0xFu128 << ((r as u32) * 64)) << (sh / 8) * 8
                                >> (sh / 8) * 8);
                            let _ = keep;
                            // write into v[rt+r] lane l
                            let lane_bytes = ebytes as u32;
                            let mask = (1u128 << (lane_bytes * 8)) - 1;
                            let reg_i = (rt + r) as usize;
                            self.v.v[reg_i] = (self.v.v[reg_i] & !(mask << sh))
                                | ((val & mask) << sh);
                        }
                    }
                } else {
                    for l in 0..lanes {
                        for r in 0..regs {
                            let addr = base + (l as u64) * (regs as u64) * (ebytes as u64)
                                + (r as u64) * (ebytes as u64);
                            let lane_bytes = ebytes as u32;
                            let mask = (1u128 << (lane_bytes * 8)) - 1;
                            let sh = (l as u32) * lane_bytes * 8;
                            let val = (self.v.v[(rt + r) as usize] >> sh) & mask;
                            self.store_vec(addr, ebytes, val)?;
                        }
                    }
                }
                if post {
                    let nb = if rm == 31 {
                        (regs as u64) * per_reg
                    } else {
                        self.r(rm)
                    };
                    self.set_rsp(rn, base.wrapping_add(nb));
                }
            }
            Insn::LdStSingle { q, load, op4, s, h, r, size2, post, rm, rn, rt } => {
                self.group_exec[0] += 1;
                if op4 >= 0xC {
                    // LD1R/LD2R/LD3R/LD4R: op4 0xC+r → 1/2 regs, 0xE+r → 3/4
                    let reps: u8 = match op4 {
                        0xC => if r { 2 } else { 1 },
                        0xE => if r { 4 } else { 3 },
                        _ => 1,
                    };
                    let ebytes = 1u16 << size2;
                    let base = self.rsp(rn);
                    let val = self.load_vec(base, ebytes)?;
                    let mask = (1u128 << (ebytes as u32 * 8)) - 1;
                    let mut rep: u128 = 0;
                    for j in 0..(16 / ebytes as u32) {
                        rep |= (val & mask) << (j * ebytes as u32 * 8);
                    }
                    for k in 0..reps {
                        self.v.v[(rt + k) as usize] = rep;
                    }
                    if post {
                        let nb = if rm == 31 { (reps as u64) * (ebytes as u64) } else { self.r(rm) };
                        self.set_rsp(rn, base.wrapping_add(nb));
                    }
                } else {
                    // one-lane load/store: index + esize from op4/size2/s/h/q
                    let (esize_log2, index) = match op4 & 0b1110 {
                        0b0000 => {
                            // B: index = Q:S:size2
                            (0u8, ((q as u8) << 3) | ((s as u8) << 2) | size2)
                        }
                        0b0100 => {
                            // H: index = Q:S:h
                            (1u8, ((q as u8) << 2) | ((s as u8) << 1) | h as u8)
                        }
                        _ => {
                            if size2 == 0b01 {
                                // D: index = Q
                                (3u8, q as u8)
                            } else {
                                // S: index = Q:S
                                (2u8, ((q as u8) << 1) | s as u8)
                            }
                        }
                    };
                    let ebytes = 1u16 << esize_log2;
                    let base = self.rsp(rn);
                    if load {
                        let val = self.load_vec(base, ebytes)?;
                        self.v.set_lane(rt, index, esize_log2, val as u64);
                    } else {
                        let val = self.v.lane(rt, index, esize_log2) as u128;
                        self.store_vec(base, ebytes, val)?;
                    }
                    if post {
                        let nb = if rm == 31 { ebytes as u64 } else { self.r(rm) };
                        self.set_rsp(rn, base.wrapping_add(nb));
                    }
                }
            }
            Insn::VindexStd { vd, vn, vm, op, index, size_log2, q } => {
                self.group_exec[1] += 1;
                use crate::decode::VindexStdOp as VO;
                let lanes: u8 = if q { 16 >> size_log2 } else { 8 >> size_log2 };
                let lanes = lanes.max(1);
                let eb = 1u64 << size_log2;
                let bits = eb * 8;
                let mask = (1u128 << bits) - 1;
                let a = self.v.v[vn as usize];
                let m = self.v.v[vm as usize];
                let sh_m = (index as u32) * (eb as u32) * 8;
                let mv = (m >> sh_m) & (mask as u128);
                let mut r: u128 = 0;
                for l in 0..lanes {
                    let sh = (l as u32) * (eb as u32) * 8;
                    let av = (a >> sh) & (mask as u128);
                    // destination accumulate (MLA family reads Vd)
                    let acc = (self.v.v[vd as usize] >> sh) & (mask as u128);
                    let out: u128 = match op {
                        VO::Fp16Fml { sub, two } => {
                            // FMLAL/FMLSL by element (pin_m1d3.py): dest
                            // S-lane j = f32(Vn.H[src_j]) * f32(Vm.H[index])
                            // +/- acc (fused). "two" reads the source HIGH
                            // half. size_log2==2 keeps the generic loop's
                            // lane count == dest S-lanes (4/2).
                            let dlanes: u32 = if q { 4 } else { 2 };
                            let src_j = if two { l as u32 + dlanes } else { l as u32 };
                            let a = simd::h_to_f32(self.v.lane(vn, src_j as u8, 1) as u16);
                            let mel = simd::h_to_f32(self.v.lane(vm, index, 1) as u16);
                            let c = f32::from_bits(acc as u32);
                            let r = if sub { (-a).mul_add(mel, c) } else { a.mul_add(mel, c) };
                            r.to_bits() as u128
                        }
                        VO::Fmul | VO::Fmulx => vindex_fp(op, av, mv, 0, size_log2),
                        VO::Fmla | VO::Fmls => vindex_fp(op, av, mv, acc, size_log2),
                        VO::Mul => av.wrapping_mul(mv),
                        VO::Mla => av.wrapping_mul(mv).wrapping_add(acc),
                        VO::Mls => acc.wrapping_sub(av.wrapping_mul(mv)),
                        VO::Smull | VO::Umlal | VO::Smlsl | VO::Umull | VO::Smlal
                        | VO::Umlsl | VO::Sqdmull | VO::Sqdmlal | VO::Sqdmlsl => {
                            // widening: dest element is 2× src; handled
                            // separately below — placeholder (never reached)
                            0
                        }
                        VO::Sqdmulh | VO::Sqrdmulh => {
                            // signed saturating doubling multiply high
                            let sx = sext_u128(av, bits as u32);
                            let sm = sext_u128(mv, bits as u32);
                            let prod = (sx as i128) * (sm as i128) * 2;
                            let hi = if bits >= 64 {
                                // 64-bit: product may exceed i128? sx,sm < 2^63
                                // product < 2^127 fits
                                (prod >> bits) as i128
                            } else {
                                prod >> bits
                            };
                            let sat_lim = (1i128 << (bits - 1)) - 1;
                            let v = if matches!(op, VO::Sqrdmulh) {
                                // rounding variant: add 2^(bits-1) before shift
                                let prod = (sx as i128) * (sm as i128) * 2
                                    + (1i128 << bits);
                                (prod >> (bits + 1)) as i128
                            } else {
                                hi
                            };
                            v.clamp(-sat_lim - 1, sat_lim) as u128 & mask
                        }
                    };
                    if matches!(op, VO::Smull | VO::Umull | VO::Smlal | VO::Umlal
                        | VO::Smlsl | VO::Umlsl | VO::Sqdmull | VO::Sqdmlal | VO::Sqdmlsl)
                    {
                        // widening indexed: dest lanes = 2× count, element 2×
                        let dbits = bits * 2;
                        let dmask = ((1u128 << dbits) - 1) as u128;
                        if dbits >= 128 {
                            // 64→128 not expressible in u128 lanes; saturate
                            // to the i128/u128 domain (not used by kernel)
                            continue;
                        }
                        let sx = sext_u128(av, bits as u32);
                        let sm = sext_u128(mv, bits as u32);
                        let prod: i128 = match op {
                            VO::Sqdmull | VO::Sqdmlal | VO::Sqdmlsl => {
                                // saturating doubling
                                let p = (sx as i128) * (sm as i128) * 2;
                                let lim = (1i128 << (dbits - 1)) - 1;
                                p.clamp(-lim - 1, lim)
                            }
                            _ => match op {
                                VO::Umull | VO::Umlal | VO::Umlsl => {
                                    (av as i128) * (mv as i128)
                                }
                                _ => (sx as i128) * (sm as i128),
                            },
                        };
                        let base_acc = if matches!(op, VO::Umlal | VO::Smlal | VO::Sqdmlal) {
                            let ash = (l as u32) * (dbits as u32);
                            let lim = (1i128 << (dbits - 1)) - 1;
                            if matches!(op, VO::Umlal) {
                                ((self.v.v[vd as usize] >> ash) & dmask) as i128
                            } else {
                                let cur = (self.v.v[vd as usize] >> ash) & dmask;
                                let m2 = (1i128 << (dbits - 1));
                                ((cur as i128 & ((m2 << 1) - 1))
                                    - ((cur as i128 & m2 as u128 as i128) << 1))
                            }
                        } else {
                            0
                        };
                        let val: i128 = match op {
                            VO::Smlsl | VO::Umlsl | VO::Sqdmlsl => base_acc.wrapping_sub(prod),
                            _ => base_acc.wrapping_add(prod),
                        };
                        let ash = (l as u32) * (dbits as u32);
                        self.v.v[vd as usize] = (self.v.v[vd as usize]
                            & !(dmask << ash))
                            | (((val as u128) & dmask) << ash);
                        continue;
                    }
                    r |= (out & (mask as u128)) << sh;
                }
                if !matches!(op, VO::Smull | VO::Umull | VO::Smlal | VO::Umlal
                    | VO::Smlsl | VO::Umlsl | VO::Sqdmull | VO::Sqdmlal | VO::Sqdmlsl)
                {
                    self.v.v[vd as usize] = r;
                }
            }
            Insn::V2Misc { rd, rn, q, size, op } => {
                self.group_exec[1] += 1;
                use crate::decode::V2MiscOp as VM;
                let eb = 1u64 << size;
                let total = if q { 16u64 } else { 8 };
                let lanes = (total / eb).max(1);
                let bits = eb * 8;
                let mask = (1u128 << bits) - 1;
                let a = self.v.v[rn as usize];
                let mut r: u128 = 0;
                let sextl = |v: u128| -> i128 { sext_u128(v, bits as u32) };
                match op {
                    VM::Rev64 | VM::Rev32 | VM::Rev16 => {
                        // REV64: reverse element order within 64-bit containers;
                        // REV32: within 32-bit; REV16: byte-swap within 16-bit
                        // elements. Element bytes = 1<<size.
                        let cont: u64 = match op {
                            VM::Rev64 => 8,
                            VM::Rev32 => 4,
                            _ => 2,
                        };
                        let ebytes = eb as usize;
                        let mut out = [0u8; 16];
                        let src = a.to_le_bytes();
                        let mut c = 0usize;
                        while c < 16 {
                            let cw = cont as usize;
                            for e in 0..(cw / ebytes) {
                                // element e in container c (reverse order)
                                let se = cw / ebytes - 1 - e;
                                for b in 0..ebytes {
                                    out[c + e * ebytes + b] =
                                        src[c + se * ebytes + b];
                                }
                            }
                            c += cw;
                        }
                        // REV16 semantics: reverse BYTES within each element
                        if matches!(op, VM::Rev16) {
                            let mut o2 = [0u8; 16];
                            for e in 0..(16 / ebytes) {
                                for b in 0..ebytes {
                                    o2[e * ebytes + b] = src[e * ebytes + (ebytes - 1 - b)];
                                }
                            }
                            r = u128::from_le_bytes(o2);
                        } else {
                            r = u128::from_le_bytes(out);
                        }
                    }
                    VM::Saddlp | VM::Uaddlp => {
                        // pairwise add long: dest element 2× src
                        let dbits = bits * 2;
                        let dmask = ((1u128 << dbits) - 1) as u128;
                        let dlanes = (total * 8 / dbits as u64).max(1);
                        for l in 0..dlanes {
                            let sh0 = (l * 2) as u32 * (bits as u32);
                            let sh1 = sh0 + bits as u32;
                            let x = (a >> sh0) & mask;
                            let y = (a >> sh1) & mask;
                            let v: i128 = if matches!(op, VM::Saddlp) {
                                sextl(x).wrapping_add(sextl(y))
                            } else {
                                (x as i128).wrapping_add(y as i128)
                            };
                            let sh = (l as u32) * dbits as u32;
                            r |= ((v as u128) & dmask) << sh;
                        }
                    }
                    VM::Suqadd | VM::Usqadd => {
                        // saturating accumulate: dest element = sat(vd + vn)
                        // SUQADD: signed dest + unsigned src; USQADD: unsigned
                        // dest + signed src
                        let d = self.v.v[rd as usize];
                        for l in 0..lanes {
                            let sh = (l as u32) * bits as u32;
                            let x = (d >> sh) & mask;
                            let y = (a >> sh) & mask;
                            let lim = (1i128 << (bits - 1)) - 1;
                            let v: i128 = match op {
                                VM::Suqadd => sextl(x).wrapping_add(y as i128),
                                _ => (x as i128).wrapping_add(sextl(y)),
                            };
                            let sv = if matches!(op, VM::Suqadd) {
                                v.clamp(-lim - 1, lim)
                            } else {
                                v.clamp(0, (lim << 1) | 1)
                            };
                            r |= ((sv as u128) & mask) << sh;
                        }
                    }
                    VM::Cls | VM::Clz | VM::Cnt => {
                        for l in 0..lanes {
                            let sh = (l as u32) * bits as u32;
                            let x = (a >> sh) & mask;
                            let v: u64 = match op {
                                VM::Cls => {
                                    let sv = sextl(x);
                                    if sv == 0 || sv == -1 {
                                        bits - 1
                                    } else if sv > 0 {
                                        (sv.leading_zeros() as u64) - (64 - bits)
                                    } else {
                                        (sv.leading_ones() as u64) - (64 - bits)
                                    }
                                }
                                VM::Clz => {
                                    if x == 0 {
                                        bits
                                    } else {
                                        (x.leading_zeros() as u64) - (64 - bits)
                                    }
                                }
                                _ => x.count_ones() as u64,
                            };
                            r |= ((v as u128) & mask) << sh;
                        }
                    }
                    VM::Cmgt0 | VM::Cmge0 | VM::Cmeq0 | VM::Cmle0 | VM::Cmlt0 => {
                        for l in 0..lanes {
                            let sh = (l as u32) * bits as u32;
                            let x = sextl((a >> sh) & mask);
                            let hit = match op {
                                VM::Cmgt0 => x > 0,
                                VM::Cmge0 => x >= 0,
                                VM::Cmeq0 => x == 0,
                                VM::Cmle0 => x <= 0,
                                _ => x < 0,
                            };
                            r |= if hit { mask } else { 0 } << sh;
                        }
                    }
                    VM::Abs | VM::Neg => {
                        for l in 0..lanes {
                            let sh = (l as u32) * bits as u32;
                            let x = (a >> sh) & mask;
                            let v: u128 = match op {
                                VM::Abs => {
                                    if sextl(x) < 0 {
                                        ((sextl(x).wrapping_neg()) as u128) & mask
                                    } else {
                                        x
                                    }
                                }
                                _ => ((sextl(x).wrapping_neg()) as u128) & mask,
                            };
                            r |= v << sh;
                        }
                    }
                    VM::Fabs | VM::Fneg | VM::Fsqrt => {
                        for l in 0..lanes {
                            let sh = (l as u32) * bits as u32;
                            let x = (a >> sh) & mask;
                            let v: u128 = if bits == 64 {
                                let f = f64::from_bits(x as u64);
                                let o = match op {
                                    VM::Fabs => f.abs(),
                                    VM::Fneg => -f,
                                    _ => f.sqrt(),
                                };
                                (o.to_bits() as u128) & mask
                            } else {
                                let f = f32::from_bits(x as u32);
                                let o = match op {
                                    VM::Fabs => f.abs(),
                                    VM::Fneg => -f,
                                    _ => f.sqrt(),
                                };
                                (o.to_bits() as u128) & mask
                            };
                            r |= v << sh;
                        }
                    }
                    VM::Xtn | VM::Sqxtn | VM::Uqxtn | VM::Sqxtun => {
                        // narrowing: dest element = size, src = size+1; dest
                        // lane count = 2× (Q=0 → low half only, Q=1 → high)
                        let dbits = bits / 2;
                        let dmask = (1u128 << dbits) - 1;
                        let dlanes = lanes * 2;
                        let lim = (1i128 << (dbits - 1)) - 1;
                        for l in 0..dlanes {
                            let sh = (l as u32) * bits as u32;
                            if sh >= 128 {
                                break;
                            }
                            let x = (a >> sh) & mask;
                            let v: i128 = match op {
                                VM::Xtn => sextl(x),
                                VM::Sqxtn => sextl(x).clamp(-lim - 1, lim),
                                // UQXTN/SQXTUN: saturate to unsigned range
                                _ => sextl(x).clamp(0, (lim << 1) | 1),
                            };
                            let dsh = (l as u32) * dbits as u32 + if q { 64 } else { 0 };
                            if dsh + dbits as u32 > 128 {
                                break;
                            }
                            r |= ((v as u128) & dmask) << dsh;
                        }
                    }
                    VM::Fcvtn | VM::Fcvtxn => {
                        // FP narrowing: D→S (size==1) with round-to-nearest
                        // (fcvtn) or round-to-odd (fcvtxn); Q=1 = high half
                        let dsh0 = if q { 64u32 } else { 0 };
                        for l in 0..(lanes * 2) {
                            let sh = (l as u32) * bits as u32;
                            if sh >= 128 {
                                break;
                            }
                            let x = (a >> sh) & mask;
                            let d = f64::from_bits(x as u64);
                            let o: u128 = if matches!(op, VM::Fcvtn) {
                                (d as f32).to_bits() as u128
                            } else {
                                // round-to-odd: round to f32; if lost bits,
                                // OR the LSB
                                let f = d as f32;
                                let mut bitsv = f.to_bits();
                                if d != f64::from(f) && (bitsv & 1) == 0 {
                                    // approx RTO: nudge toward odd on ties
                                    bitsv |= 1;
                                }
                                bitsv as u128
                            };
                            let dsh = dsh0 + (l as u32) * 32;
                            if dsh >= 128 {
                                break;
                            }
                            r |= (o & 0xFFFF_FFFF) << dsh;
                        }
                    }
                    VM::Fcvtl => {
                        // widening: S→D (size 1) or H→S (size 0); Q=1 = src
                        // high half
                        let ssh0 = if q { 64u32 } else { 0 };
                        for l in 0..(lanes / 2).max(1) {
                            let sh = ssh0 + (l as u32) * bits as u32;
                            if sh >= 128 {
                                break;
                            }
                            let x = (a >> sh) & mask;
                            let o: u128 = if size == 1 {
                                (f32::from_bits(x as u32) as f64).to_bits() as u128
                            } else {
                                (simd::h_to_f32(x as u16) as f32).to_bits() as u128
                            };
                            let dsh = (l as u32) * (bits as u32) * 2;
                            r |= o << dsh;
                        }
                    }
                    VM::Fcvtzs | VM::Fcvtzu => {
                        for l in 0..lanes {
                            let sh = (l as u32) * bits as u32;
                            let x = (a >> sh) & mask;
                            let v: u128 = if bits == 64 {
                                let f = f64::from_bits(x as u64);
                                match op {
                                    VM::Fcvtzs => (f as i64) as u128,
                                    _ => (f as u64) as u128,
                                }
                            } else {
                                let f = f32::from_bits(x as u32);
                                match op {
                                    VM::Fcvtzs => (f as i32 as i64) as u128 & mask,
                                    _ => (f.max(0.0) as u64 as u128) & mask,
                                }
                            };
                            r |= v << sh;
                        }
                    }
                    VM::Scvtf | VM::Ucvtf => {
                        for l in 0..lanes {
                            let sh = (l as u32) * bits as u32;
                            let x = (a >> sh) & mask;
                            let v: u128 = if bits == 64 {
                                let f = match op {
                                    VM::Scvtf => (sextl(x) as i64) as f64,
                                    _ => (x as u64) as f64,
                                };
                                f.to_bits() as u128
                            } else {
                                let f = match op {
                                    VM::Scvtf => sextl(x) as f32,
                                    _ => x as u32 as f32,
                                };
                                (f.to_bits() as u128) & mask
                            };
                            r |= v << sh;
                        }
                    }
                    VM::Sadalp | VM::Uadalp => {
                        // pairwise add + accumulate: vd[i] += widen(vn[2i] +
                        // vn[2i+1]) (SADALP signed / UADALP unsigned)
                        let d = self.v.v[rd as usize];
                        let dbits = (bits * 2).min(128);
                        let dmask = if dbits >= 128 { u128::MAX } else { (1u128 << dbits) - 1 };
                        let dlanes = (total * 8 / dbits as u64).max(1);
                        for l in 0..dlanes {
                            let sh0 = (l * 2) as u32 * bits as u32;
                            let sh1 = sh0 + bits as u32;
                            let x = (a >> sh0) & mask;
                            let y = (a >> sh1) & mask;
                            let pair = if matches!(op, VM::Sadalp) {
                                sextl(x).wrapping_add(sextl(y))
                            } else {
                                (x as i128).wrapping_add(y as i128)
                            };
                            let dsh = (l as u32) * dbits as u32;
                            let cur = (d >> dsh) & dmask;
                            let cur_s = sext_u128(cur, dbits as u32);
                            let v = cur_s.wrapping_add(pair);
                            r |= ((v as u128) & dmask) << dsh;
                        }
                    }
                    VM::Saddlv | VM::Uaddlv => {
                        // across-lane widening add; dest scalar lane 0
                        let dbits = (bits * 2).min(64);
                        let dmask = (1u128 << dbits) - 1;
                        let mut acc: i128 = 0;
                        for l in 0..lanes {
                            let sh = (l as u32) * bits as u32;
                            let x = (a >> sh) & mask;
                            acc = if matches!(op, VM::Saddlv) {
                                acc.wrapping_add(sextl(x))
                            } else {
                                acc.wrapping_add(x as i128)
                            };
                        }
                        r = (acc as u128) & dmask;
                    }
                    VM::Addv => {
                        // across-lane add, non-widening: dest scalar lane 0
                        let mut acc: u128 = 0;
                        let mut sacc: i128 = 0;
                        for l in 0..lanes {
                            let sh = (l as u32) * bits as u32;
                            let x = (a >> sh) & mask;
                            acc = acc.wrapping_add(x);
                            sacc = sacc.wrapping_add(sextl(x));
                        }
                        r = acc & mask;
                        let _ = sacc;
                    }

                    VM::Sadalp | VM::Uadalp => {
                        // pairwise add + accumulate: vd[i] += widen(vn[2i] +
                        // vn[2i+1]) (SADALP signed / UADALP unsigned)
                        let d = self.v.v[rd as usize];
                        let dbits = (bits * 2).min(128);
                        let dmask = if dbits >= 128 { u128::MAX } else { (1u128 << dbits) - 1 };
                        let dlanes = (total * 8 / dbits as u64).max(1);
                        for l in 0..dlanes {
                            let sh0 = (l * 2) as u32 * bits as u32;
                            let sh1 = sh0 + bits as u32;
                            let x = (a >> sh0) & mask;
                            let y = (a >> sh1) & mask;
                            let pair = if matches!(op, VM::Sadalp) {
                                sextl(x).wrapping_add(sextl(y))
                            } else {
                                (x as i128).wrapping_add(y as i128)
                            };
                            let dsh = (l as u32) * dbits as u32;
                            let cur = (d >> dsh) & dmask;
                            let cur_s = sext_u128(cur, dbits as u32);
                            let v = cur_s.wrapping_add(pair);
                            r |= ((v as u128) & dmask) << dsh;
                        }
                    }
                }
                self.v.v[rd as usize] = r;
            }
            Insn::VPerm { rd, rn, rm, size, op } => {
                self.group_exec[1] += 1;
                use crate::decode::PermOp as PO;
                let eb = 1u64 << size;
                let total = 16u64; // permute ops are always full vectors
                let lanes = (total / eb).max(1);
                let bits = eb * 8;
                let mask = (1u128 << bits) - 1;
                let a = self.v.v[rn as usize];
                let b = self.v.v[rm as usize];
                let get = |v: u128, i: u64| -> u128 { (v >> (i * bits)) & mask };
                let mut r: u128 = 0;
                for l in 0..lanes {
                    let idx = match op {
                        // even/odd interleaves across the concat(a,b)
                        PO::Zip1 => {
                            let h = l / ((lanes + 1) / 2);
                            let i = l % ((lanes + 1) / 2);
                            if h == 0 {
                                i * 2
                            } else {
                                lanes + i * 2
                            }
                        }
                        PO::Zip2 => {
                            let h = l / ((lanes + 1) / 2);
                            let i = l % ((lanes + 1) / 2);
                            if h == 0 {
                                i * 2 + 1
                            } else {
                                lanes + i * 2 + 1
                            }
                        }
                        PO::Uzp1 => {
                            let h = l / ((lanes + 1) / 2);
                            let i = l % ((lanes + 1) / 2);
                            if h == 0 {
                                i * 2
                            } else {
                                lanes + i * 2
                            }
                        }
                        PO::Uzp2 => {
                            let h = l / ((lanes + 1) / 2);
                            let i = l % ((lanes + 1) / 2);
                            if h == 0 {
                                i * 2 + 1
                            } else {
                                lanes + i * 2 + 1
                            }
                        }
                        PO::Trn1 => {
                            let h = l / ((lanes + 1) / 2);
                            let i = l % ((lanes + 1) / 2);
                            if h == 0 {
                                i * 2
                            } else {
                                lanes + i * 2
                            }
                        }
                        PO::Trn2 => {
                            let h = l / ((lanes + 1) / 2);
                            let i = l % ((lanes + 1) / 2);
                            if h == 0 {
                                i * 2 + 1
                            } else {
                                lanes + i * 2 + 1
                            }
                        }
                    };
                    let v = if idx < lanes { get(a, idx) } else { get(b, idx - lanes) };
                    r |= v << (l * bits);
                }
                self.v.v[rd as usize] = r;
            }
            Insn::VExt { rd, rn, rm, imm4, q } => {
                self.group_exec[1] += 1;
                // concat(rn, rm) >> (imm4 * 8) bytes; .16b always (Q=1) —
                // .8b form writes the low 8 bytes and zeroes the rest.
                let concat = (self.v.v[rn as usize] << 64)
                    | (self.v.v[rm as usize] >> 64)
                    | (self.v.v[rn as usize] & u128::from(u64::MAX) << 0);
                // proper concat: low half = rm, high half = rn
                let cat = ((self.v.v[rn as usize] as u128) << 64)
                    | (self.v.v[rm as usize] & u128::from(u64::MAX));
                let _ = concat;
                let sh = (imm4 as u32) * 8;
                let out = cat >> sh;
                self.v.v[rd as usize] = if q { out } else { out & u128::from(u64::MAX) };
            }
            Insn::VTbl { rd, rn, rm, len, tbx, q } => {
                self.group_exec[1] += 1;
                // table registers rn..rn+len-1 form a 16*len byte table;
                // index bytes come from rm; out-of-range → 0 (TBL) or keep
                // rd's original byte (TBX).
                let mut table = [0u8; 64];
                for k in 0..len as usize {
                    let bytes = self.v.v[(rn + k as u8) as usize].to_le_bytes();
                    table[k * 16..k * 16 + 16].copy_from_slice(&bytes);
                }
                let idx = self.v.v[rm as usize].to_le_bytes();
                let orig = self.v.v[rd as usize].to_le_bytes();
                let n = if q { 16 } else { 8 };
                let mut out = [0u8; 16];
                for i in 0..n {
                    let j = idx[i] as usize;
                    out[i] = if j < len as usize * 16 {
                        table[j]
                    } else if tbx {
                        orig[i]
                    } else {
                        0
                    };
                }
                let mut val = u128::from_le_bytes(out);
                if !q {
                    val &= u128::from(u64::MAX);
                }
                self.v.v[rd as usize] = val;
            }
            Insn::VDupElem { rd, rn, index, size_log2, q } => {
                self.group_exec[1] += 1;
                let lane = self.v.lane(rn, index, size_log2);
                let eb = 1u64 << size_log2;
                let mut rep: u128 = 0;
                let count = if q { 16 / eb } else { 8 / eb };
                for j in 0..count {
                    rep |= (lane as u128) << (j * eb * 8);
                }
                self.v.v[rd as usize] = rep;
            }
            Insn::VDupGpr { rd, rn, size_log2, q } => {
                self.group_exec[1] += 1;
                let v = self.r(rn) & match size_log2 {
                    0 => 0xFF,
                    1 => 0xFFFF,
                    2 => 0xFFFF_FFFF,
                    _ => u64::MAX,
                };
                let eb = 1u64 << size_log2;
                let mut rep: u128 = 0;
                let count = if q { 16 / eb } else { 8 / eb };
                for j in 0..count {
                    rep |= (v as u128) << (j * eb * 8);
                }
                self.v.v[rd as usize] = rep;
            }
            Insn::VInsGpr { rd, rn, index, size_log2, src64 } => {
                self.group_exec[1] += 1;
                let v = if src64 { self.r(rn) } else { self.r(rn) & 0xFFFF_FFFF };
                self.v.set_lane(rd, index, size_log2, v);
            }
            Insn::VInsLane { rd, rn, dst_index, src_index, size_log2, q: _ } => {
                self.group_exec[1] += 1;
                let v = self.v.lane(rn, src_index, size_log2);
                self.v.set_lane(rd, dst_index, size_log2, v);
            }
            Insn::VVecToGpr { rd, rn, index, size_log2, signed, dest64 } => {
                self.group_exec[1] += 1;
                let lane = self.v.lane(rn, index, size_log2);
                let bits = 1u32 << (size_log2 + 3);
                let val = if signed {
                    let m = 1i64 << (bits - 1);
                    (((lane as i64) & ((m << 1) - 1)) - (((lane as i64) & m) << 1)) as u64
                } else {
                    lane
                };
                self.set_r(rd, if dest64 { val } else { val & 0xFFFF_FFFF });
            }
            Insn::VLong { vd, vn, vm, size, u, q, op } => {
                self.group_exec[1] += 1;
                use crate::decode::VLongOp as VL;
                let eb = 1u64 << size;
                let bits = eb * 8;
                let dbits = bits * 2;
                let mask = (1u128 << bits) - 1;
                let dmask = ((1u128 << dbits) - 1) as u128;
                let lanes = 8 >> size; // source lanes per half
                let sh0 = if q { (8 >> size) as u32 * bits as u32 } else { 0 };
                let a = self.v.v[vn as usize];
                let b = self.v.v[vm as usize];
                let dsh = if q { 0u32 } else { 0 }; // dest offset: Q=1 → full 128, Q=0 → low half
                let dsh = if q { 0u32 } else { 0 };
                for l in 0..lanes {
                    let sh = sh0 + (l as u32) * bits as u32;
                    let av = (a >> sh) & mask;
                    let bv = (b >> sh) & mask;
                    let sx = sext_u128(av, bits as u32);
                    let sx2 = sext_u128(bv, bits as u32);
                    let (prod, add): (i128, i128) = match op {
                        VL::Addl => (0, if u { av as i128 } else { sx }.wrapping_add(if u { bv as i128 } else { sx2 })),
                        VL::Addw => (0, 0), // handled below
                        VL::Subl => (0, if u { av as i128 } else { sx }.wrapping_sub(if u { bv as i128 } else { sx2 })),
                        VL::Subw => (0, 0),
                        VL::Mlal | VL::Mlsl => {
                            let p = if u { (av as i128) * (bv as i128) } else { sx * sx2 };
                            (p, 0)
                        }
                        VL::Mull => {
                            let p = if u { (av as i128) * (bv as i128) } else { sx * sx2 };
                            (p, 0)
                        }
                    };
                    let dsh = dsh + (l as u32) * dbits as u32;
                    if dsh + dbits as u32 > 128 {
                        break;
                    }
                    let cur = (self.v.v[vd as usize] >> dsh) & dmask;
                    let cur_s = sext_u128(cur, dbits as u32);
                    let out: i128 = match op {
                        VL::Addl | VL::Subl => add,
                        VL::Addw => {
                            // vn is the WIDE operand (size+1), vm narrow
                            let wsh = sh0 + (l as u32) * dbits as u32;
                            let wmask = dmask;
                            let wv = (a >> wsh) & wmask;
                            let wsext = sext_u128(wv, dbits as u32);
                            let nv = if u { wv as i128 } else { wsext };
                            nv.wrapping_add(if u { bv as i128 } else { sx2 })
                        }
                        VL::Subw => {
                            let wsh = sh0 + (l as u32) * dbits as u32;
                            let wmask = dmask;
                            let wv = (a >> wsh) & wmask;
                            let wsext = sext_u128(wv, dbits as u32);
                            let nv = if u { wv as i128 } else { wsext };
                            nv.wrapping_sub(if u { bv as i128 } else { sx2 })
                        }
                        VL::Mlal | VL::Mull => cur_s.wrapping_add(prod),
                        VL::Mlsl => cur_s.wrapping_sub(prod),
                    };
                    self.v.v[vd as usize] = (self.v.v[vd as usize] & !(dmask << dsh))
                        | (((out as u128) & dmask) << dsh);
                }
            }
            Insn::VSha1H { rd, rn } => {
                self.group_exec[2] += 1;
                let v = self.v.lane(rn, 0, 2) as u32;
                self.v.set_lane(rd, 0, 2, v.rotate_left(30) as u64);
            }
            Insn::VSha1Su1 { vd, vn } => {
                self.group_exec[2] += 1;
                let d = self.v.v[vd as usize];
                let n = self.v.v[vn as usize];
                let lane = |v: u128, i: u32| -> u32 { ((v >> (i * 32)) & 0xFFFF_FFFF) as u32 };
                let mut r: u128 = 0;
                for i in 0..4u32 {
                    let t = lane(d, i) ^ lane(n, (i + 1) % 4) ^ lane(n, i).rotate_right(2);
                    r |= (t as u128) << (i * 32);
                }
                self.v.v[vd as usize] = r;
            }
            Insn::VSha256Su0 { vd, vn } => {
                self.group_exec[2] += 1;
                let d = self.v.v[vd as usize];
                let lane = |v: u128, i: u32| -> u32 { ((v >> (i * 32)) & 0xFFFF_FFFF) as u32 };
                let sig0 = |x: u32| x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3);
                let mut r: u128 = 0;
                for i in 0..4u32 {
                    let t = sig0(lane(d, i)).wrapping_add(lane(d, (i + 3) % 4));
                    r |= (t as u128) << (i * 32);
                }
                self.v.v[vd as usize] = r;
            }
            Insn::VSha1Cpm { vd, vn, vm, op } => {
                self.group_exec[2] += 1;
                use crate::decode::Sha1CpmOp as SO;
                let d = self.v.v[vd as usize];
                let lane = |v: u128, i: u32| -> u32 { ((v >> (i * 32)) & 0xFFFF_FFFF) as u32 };
                let (a, b, c, d4) = (lane(d, 0), lane(d, 1), lane(d, 2), lane(d, 3));
                let e = self.v.lane(vn, 0, 2) as u32;
                let w = self.v.lane(vm, 0, 2) as u32;
                let f = match op {
                    SO::Ch => (b & c) | (!b & d4),
                    SO::Parity => b ^ c ^ d4,
                    SO::Maj => (b & c) | (b & d4) | (c & d4),
                };
                // ARM round: t = e + f + w + ror(a, 2); state shifts
                let t = e.wrapping_add(f).wrapping_add(w).wrapping_add(a.rotate_right(2));
                let mut r: u128 = t as u128;
                r |= (a as u128) << 32;
                r |= (b as u128) << 64;
                r |= (c as u128) << 96;
                self.v.v[vd as usize] = r;
            }
            Insn::VSha1Su0 { vd, vn, vm } => {
                self.group_exec[2] += 1;
                let d = self.v.v[vd as usize];
                let n = self.v.v[vn as usize];
                let m = self.v.v[vm as usize];
                let lane = |v: u128, i: u32| -> u32 { ((v >> (i * 32)) & 0xFFFF_FFFF) as u32 };
                let mut r: u128 = 0;
                for i in 0..4u32 {
                    let t = lane(m, i) ^ lane(d, (i + 2) % 4) ^ lane(n, i).rotate_right(2);
                    r |= (t as u128) << (i * 32);
                }
                self.v.v[vd as usize] = r;
            }
            Insn::VSha256H { vd, vn, vm, h2 } => {
                self.group_exec[2] += 1;
                // 2 rounds of SHA256 compression; H uses Vm lanes 0-1, H2
                // lanes 2-3. Both Qd (a..d) and Qn (e..h) are written back.
                let lane = |v: u128, i: u32| -> u32 { ((v >> (i * 32)) & 0xFFFF_FFFF) as u32 };
                let put = |i: u32, t: u32| (t as u128) << (i * 32);
                let sig0 = |x: u32| x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22);
                let sig1 = |x: u32| x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25);
                let sml0 = |x: u32| x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3);
                let sml1 = |x: u32| x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10);
                let (mut a, mut b, mut c, mut d) = (
                    lane(self.v.v[vd as usize], 0),
                    lane(self.v.v[vd as usize], 1),
                    lane(self.v.v[vd as usize], 2),
                    lane(self.v.v[vd as usize], 3),
                );
                let (mut e, mut f, mut g, mut h) = (
                    lane(self.v.v[vn as usize], 0),
                    lane(self.v.v[vn as usize], 1),
                    lane(self.v.v[vn as usize], 2),
                    lane(self.v.v[vn as usize], 3),
                );
                let base = if h2 { 2u32 } else { 0 };
                for i in 0..2u32 {
                    let w = lane(self.v.v[vm as usize], base + i);
                    let t1 = h
                        .wrapping_add(sig1(e))
                        .wrapping_add((e & f) ^ (!e & g))
                        .wrapping_add(w);
                    let t2 = sig0(a).wrapping_add((a & b) ^ (a & c) ^ (b & c));
                    h = g;
                    g = f;
                    f = e;
                    e = d.wrapping_add(t1);
                    d = c;
                    c = b;
                    b = a;
                    a = t1.wrapping_add(t2);
                }
                self.v.v[vd as usize] =
                    put(0, a) | put(1, b) | put(2, c) | put(3, d);
                self.v.v[vn as usize] =
                    put(0, e) | put(1, f) | put(2, g) | put(3, h);
            }
            Insn::VSha256Su1 { vd, vn, vm } => {
                self.group_exec[2] += 1;
                let d = self.v.v[vd as usize];
                let n = self.v.v[vn as usize];
                let m = self.v.v[vm as usize];
                let lane = |v: u128, i: u32| -> u32 { ((v >> (i * 32)) & 0xFFFF_FFFF) as u32 };
                let sml1 = |x: u32| x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10);
                let mut r: u128 = 0;
                for i in 0..4u32 {
                    let t = lane(d, i)
                        .wrapping_add(sml1(lane(n, (i + 1) % 4)))
                        .wrapping_add(lane(m, i));
                    r |= (t as u128) << (i * 32);
                }
                self.v.v[vd as usize] = r;
            }
            Insn::FpCmp { rn, rm, zero, e: _, double } => {
                self.group_exec[4] += 1;
                let (ord, lt, eq) = if double {
                    let a = f64::from_bits(self.v.lane(rn, 0, 3));
                    let b = if zero {
                        0.0
                    } else {
                        f64::from_bits(self.v.lane(rm, 0, 3))
                    };
                    (a.partial_cmp(&b), a < b, a == b)
                } else {
                    let a = f32::from_bits(self.v.lane(rn, 0, 2) as u32);
                    let b = if zero {
                        0.0f32
                    } else {
                        f32::from_bits(self.v.lane(rm, 0, 2) as u32)
                    };
                    (a.partial_cmp(&b), a < b, a == b)
                };
                self.nzcv = match ord {
                    None => C | V,               // unordered
                    Some(std::cmp::Ordering::Less) => N,
                    Some(std::cmp::Ordering::Equal) => Z | C,
                    Some(std::cmp::Ordering::Greater) => C,
                };
                let _ = (lt, eq);
            }
            Insn::Fccmp { rn, rm, nzcv, cond, e: _, double } => {
                self.group_exec[4] += 1;
                let c = crate::decode::Cond::from_bits(cond as u32);
                match c {
                    Some(c) if self.cond(c) => {
                        let (ord, _lt, _eq) = if double {
                            let a = f64::from_bits(self.v.lane(rn, 0, 3));
                            let b = f64::from_bits(self.v.lane(rm, 0, 3));
                            (a.partial_cmp(&b), a < b, a == b)
                        } else {
                            let a = f32::from_bits(self.v.lane(rn, 0, 2) as u32);
                            let b = f32::from_bits(self.v.lane(rm, 0, 2) as u32);
                            (a.partial_cmp(&b), a < b, a == b)
                        };
                        self.nzcv = match ord {
                            None => C | V,
                            Some(std::cmp::Ordering::Less) => N,
                            Some(std::cmp::Ordering::Equal) => Z | C,
                            Some(std::cmp::Ordering::Greater) => C,
                        };
                    }
                    _ => self.nzcv = nzcv as u32,
                }
            }
            Insn::Fcsel { rd, rn, rm, cond, double } => {
                self.group_exec[4] += 1;
                let pick = crate::decode::Cond::from_bits(cond as u32)
                    .map(|c| self.cond(c))
                    .unwrap_or(false);
                let src = if pick { rn } else { rm };
                let sl = if double { 3 } else { 2 };
                let v = self.v.lane(src, 0, sl);
                self.v.set_lane(rd, 0, sl, v);
            }
            Insn::FmovReg { rd, rn, double } => {
                self.group_exec[4] += 1;
                let sl = if double { 3 } else { 2 };
                let v = self.v.lane(rn, 0, sl);
                self.v.set_lane(rd, 0, sl, v);
            }
            Insn::FmovImm { rd, imm8, double } => {
                self.group_exec[4] += 1;
                // VFP-ExpandImm: exp = NOT(imm8<6>) : Replicate(imm8<6>, E-3)
                // : imm8<5:4>; frac = imm8<3:0> (keystone grid-verified:
                // 1.0→0x70, 0.5→0x60, 2.0→0x00, 31.0(D)→0x3F, -1.0→0xF0).
                let s = (imm8 >> 7) & 1;
                let n = (imm8 >> 6) & 1;
                let e2 = ((imm8 >> 4) & 3) as u64;
                let frac = (imm8 & 0xF) as u64;
                if double {
                    let mut exp: u64 = if n == 0 { 1 << 10 } else { 0 };
                    if n == 1 {
                        exp |= ((1u64 << 8) - 1) << 2;
                    }
                    exp |= e2 << 2;
                    let bits = ((s as u64) << 63) | (exp << 52) | (frac << 48);
                    self.v.set_lane(rd, 0, 3, bits);
                } else {
                    let mut exp: u32 = if n == 0 { 1 << 7 } else { 0 };
                    if n == 1 {
                        exp |= ((1u32 << 5) - 1) << 2;
                    }
                    exp |= (e2 as u32) << 2;
                    let bits = ((s as u32) << 31) | (exp << 23) | ((frac as u32) << 19);
                    self.v.set_lane(rd, 0, 2, bits as u64);
                }
            }
            Insn::FpIntCvt { rd, rn, kind, double, gpr64, fbits } => {
                self.group_exec[4] += 1;
                use crate::decode::FpIntCvtKind as FK;
                match kind {
                    FK::MovToFp => {
                        // FMOV Sd,Wn / Dd,Xn — bit pattern copy
                        let v = if gpr64 { self.r(rn) } else { self.r(rn) & 0xFFFF_FFFF };
                        let sl = if double { 3 } else { 2 };
                        self.v.set_lane(rd, 0, sl, v);
                    }
                    FK::MovFromFp => {
                        let sl = if double { 3 } else { 2 };
                        let mask = if gpr64 { u64::MAX } else { 0xFFFF_FFFF };
                        self.set_r(rd, self.v.lane(rn, 0, sl) & mask);
                    }
                    FK::Cvtf { unsigned } => {
                        // SCVTF/UCVTF: int -> fp (fbits = fixed-point scale)
                        let v = if gpr64 { self.r(rn) } else { self.r(rn) & 0xFFFF_FFFF };
                        let scale = 2f64.powi(-(fbits as i32));
                        let val: f64 = if unsigned {
                            (v as f64) * scale
                        } else {
                            let sv = if gpr64 { v as i64 } else { v as i32 as i64 };
                            (sv as f64) * scale
                        };
                        if double {
                            self.v.set_lane(rd, 0, 3, val.to_bits());
                        } else {
                            self.v.set_lane(rd, 0, 2, (val as f32).to_bits() as u64);
                        }
                    }
                    FK::FcvtGpr { round } => {
                        // FCVT{N,A,P,M,Z}{S,U}: fp -> int with rounding mode;
                        // round encoding: 0=N(even) 1=U?? — layout from the
                        // decode table: 0b00=NS/NU pair is rmode 00 op 0/1…
                        // here round: 0=NS 1=NU 2=AS 3=AU 4=ZS 5=ZU (PS/PU
                        // unused by kernel but encoded 2b10/2b11 at decode…)
                        let sl = if double { 3 } else { 2 };
                        let val: f64 = if double {
                            f64::from_bits(self.v.lane(rn, 0, 3))
                        } else {
                            f32::from_bits(self.v.lane(rn, 0, 2) as u32) as f64
                        };
                        let scaled = val * 2f64.powi(fbits as i32);
                        let unsigned = round & 1 == 1;
                        // mode = round>>1: 0=N, 1=A, 2=Z (rounds 4/5), 3=P
                        let rm_kind = match round {
                            0 | 1 => 0u8,
                            2 | 3 => 1,
                            4 | 5 => 2,
                            6 | 7 => 3, // P (toward +inf)
                            _ => 4,     // M (toward -inf)
                        };
                        let iv: i128 = match rm_kind {
                            0 => scaled as i128, // nearest-even (Rust cast)
                            1 => {
                                // round ties away from zero
                                let t = scaled.trunc();
                                let frac = (scaled - t).abs();
                                let r = if frac >= 0.5 {
                                    t + (if scaled < 0.0 { -1.0 } else { 1.0 })
                                } else {
                                    t
                                };
                                r as i128
                            }
                            2 => scaled.trunc() as i128, // Z (toward zero)
                            3 => scaled.ceil() as i128,  // P (toward +inf)
                            _ => scaled.floor() as i128, // M (toward -inf)
                        };
                        if !unsigned {
                            let v = if gpr64 {
                                (iv.clamp(i64::MIN as i128, i64::MAX as i128)) as i64 as u64
                            } else {
                                (iv.clamp(i32::MIN as i128, i32::MAX as i128)) as i32 as u64
                            };
                            self.set_r(rd, v);
                        } else {
                            let v = if gpr64 {
                                (iv.clamp(0, u64::MAX as i128)) as u64
                            } else {
                                (iv.clamp(0, u32::MAX as i128)) as u32 as u64
                            };
                            self.set_r(rd, v);
                        }
                    }
                }
            }
            Insn::AddpScalar { rd, rn, double } => {
                self.group_exec[4] += 1;
                if double {
                    let lo = self.v.lane(rn, 0, 3);
                    let hi = self.v.lane(rn, 1, 3);
                    self.v.set_lane(rd, 0, 3, lo.wrapping_add(hi));
                } else {
                    let lo = self.v.lane(rn, 0, 2) as u32;
                    let hi = self.v.lane(rn, 1, 2) as u32;
                    self.v.set_lane(rd, 0, 2, lo.wrapping_add(hi) as u64);
                }
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
                // REAL-DATA BUG #30: the model pac() tags bits 63:48, so the
                // authenticated return must STRIP AND RESTORE the canonical
                // pointer (sign-extend bit 47) — the raw `self.pc = self.r(30)`
                // fetched the TAGGED return address (e.g. 0x402fff007a8d060).
                self.pc = crypto::canonical(self.r(30));
                return Ok(());
            }
            Insn::BrAuth { rn, link, .. } => {
                // REAL-DATA BUG #30: same canonical strip as RetA — the real
                // boot's `blraa x27, x26` (0xD73F0B7A @0x…7f2f658) jumped to
                // the tagged pointer before this fix.
                let target = crypto::canonical(self.r(rn));
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
                // 0xfffffff007ff97ac. REAL-DATA BUG #31: Rn=31 reads SP in
                // both the S=0 and S=1 forms (`cmp sp, w16, uxtw` is a real
                // kernel sequence).
                let a = self.rsp(rn);
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
                // M4: ERET restores PSTATE from SPSR (NZCV + DAIF + SP bit).
                // xnu's exception RETURN path depends on the DAIF restore:
                // handlers ERET with SPSR.I=0 to re-enable interrupts.
                let spsr = self.sys.spsr_el1;
                self.nzcv = ((spsr >> 28) & 0xF) as u32;
                self.sys.daif = (self.sys.daif & !0x3C0) | (spsr & 0x3C0);
                self.sp_sel = spsr & 1 == 1;
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
                // REAL-DATA BUG #28 (engine half): the subtract form is
                // MSUB Xd, Xn, Xm, Xa → Xd = Xa − Xn·Xm (ARM ARM C6.2.349),
                // NOT Xn·Xm − Xa. MADD hides the flip (addition commutes);
                // the kernel's Euclid remainder step `udiv q,a,b;
                // msub r,q,b,a` (0x9B0BA98C @0x…7b92d70, keystone-pinned)
                // requires r = a − q·b ∈ [0,b) — the flipped form returned
                // 2⁶⁴−(a mod b) and the gcd loop at 0x…7b92d68 diverged
                // forever (bug #28 stop after 2G clean insns).
                // REAL-DATA BUG #29: MUL is the MADD alias with Ra=31 = XZR
                // (keystone: `mul x9,x8,x9` ≡ `madd x9,x8,x9,xzr` =
                // 0x9B097D09; `madd x0,x1,x2,sp` DOES NOT ASSEMBLE — dp3 has
                // no SP forms for Rd/Ra). The addend MUST read the ZR rule;
                // reading rsp(31) added SP to EVERY mul the kernel executes
                // — the div-by-6 size check `mul x9,x8,x9; ror #3; cmp;
                // b.hs` at 0x…7a8ce6c turned rot(0xcc0+SP) huge and panicked
                // "Section __BOOTDATA,__init_entry_set has invalid size"
                // (vm_mem_bootstrap, insn 8,255,200). Rd=31 likewise
                // discards (XZR), never SP.
                // W-form (sf=0): all operands are W regs — the addend reads
                // Wc (bits 31:0 only) and the result is (… ) mod 2³²
                // zero-extended into Xd.
                let a = self.r(rn);
                let b = self.r(rm);
                let (a, b) = if is64 { (a, b) } else { (a & 0xFFFF_FFFF, b & 0xFFFF_FFFF) };
                let c = if is64 { self.r(ra) } else { self.r(ra) & 0xFFFF_FFFF };
                let prod = a.wrapping_mul(b);
                let r = if subtract { c.wrapping_sub(prod) } else { prod.wrapping_add(c) };
                let r = if is64 { r } else { r & 0xFFFF_FFFF };
                self.set_r(rd, r);
            }
            Insn::MaddW { rd, rn, rm, ra, subtract, unsigned } => {
                // umaddl/umsubl/smaddl/smsubl: Xd = Xa −/+ ZExt/SExt(Wn)·…
                // — same operand-order fix as Insn::Madd's subtract form
                // (real kernel umsubl sites share the Euclid pattern) and
                // the same dp3 reg-31 rule as bug #29: Ra=31 reads XZR
                // (keystone: `umaddl xzr,w1,w2,xzr` = 0x9BA27C3F; the sp
                // spelling does not assemble), Rd=31 discards.
                let a = self.r(rn) as u32;
                let b = self.r(rm) as u32;
                let prod: i64 = if unsigned {
                    (a as u64 as i64).wrapping_mul(b as u64 as i64)
                } else {
                    (a as i32 as i64).wrapping_mul(b as i32 as i64)
                };
                let c = self.r(ra) as i64;
                let r = if subtract { c.wrapping_sub(prod) } else { prod.wrapping_add(c) };
                self.set_r(rd, r as u64);
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
                        // Canonical BFM (REAL-DATA BUG #27, keystone/capstone-
                        // pinned). The old `width = bits - imms - 1` formula
                        // was simply wrong: it turned `bfxil x14,x15,#0,#56`
                        // — the arm_vm_init packed-pointer decoder — into an
                        // 8-bit insert, storing 0xfffe00ee488b0058 instead of
                        // 0xfffffff007724458 (the array base the DT walk
                        // later dereferences — the bug #27 stop).
                        // Aliases (capstone ground truth):
                        //   bfxil #lsb,#w  = BFM immr=lsb, imms=lsb+w-1
                        //     → dst[w-1:0] = src[lsb+w-1:lsb], rest preserved
                        //   bfi  #lsb,#w   = BFM immr=(bits-lsb)&63, imms=w-1
                        //     → dst[lsb+w-1:lsb] = src[w-1:0], rest preserved
                        //   raw BFM s>=r  → dst[s-r:0] = src[s:r] (capstone
                        //     renders `bfm #4,#10` as `bfxil #4,#7`)
                        //   raw BFM s<r   → bfi lsb=bits-r, w=s+1
                        if imms >= immr {
                            // bfxil family: extract src[imms:immr], insert low.
                            let w = imms - immr + 1;
                            let ones = if w >= 64 { u64::MAX } else { (1u64 << w) - 1 };
                            let field = (src >> immr) & ones;
                            self.set_r(rd, ((dst & !ones) | field) & mask);
                        } else {
                            // bfi family (wrap): insert src[imms:0] at
                            // lsb = bits - immr.
                            let lsb = ((bits as u64) - immr as u64) % bits as u64;
                            let w = imms + 1;
                            let ones = if w >= 64 { u64::MAX } else { (1u64 << w) - 1 };
                            let field = (src & ones).wrapping_shl(lsb as u32);
                            let wm = ones.wrapping_shl(lsb as u32) & mask;
                            self.set_r(rd, ((dst & !wm) | (field & wm)) & mask);
                        }
                    }
                    BfmKind::Sbfm => {
                        // Signed: extract width = imms-immr+1 bits from immr
                        // and sign-extend. W-form extracting through bit 31
                        // sign-extends into the upper word.
                        if (imms as u32) < immr.min(bits - 1) {
                            // sbfiz family (bug #27 follow-up): dst =
                            // SX(src[imms:0]) << (bits - immr). The old
                            // rotate-model fallback picked up the WRAPPED
                            // high bits (src[63:62]-class) that the alias
                            // discards — sx-first, shift, zero the LSB gap.
                            let w = imms + 1;
                            let ones = if w >= 64 { u64::MAX } else { (1u64 << w) - 1 };
                            let field = src & ones;
                            let sign = (field >> (w - 1)) & 1;
                            let mut v = if sign == 1 { field | !ones } else { field };
                            let sh = (bits as u64) - immr as u64;
                            v = v.wrapping_shl(sh as u32);
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
                            // ubfiz family (bug #27 follow-up): dst =
                            // (src & ones(imms+1)) << (bits - immr) — the
                            // mask matters: the plain `src << sh` leaked
                            // src's high bits into the field (ubfiz must
                            // zero everything outside [lsb, lsb+w)). For the
                            // LSL alias (imms = bits-1-immr) the mask is
                            // exactly the bits the shift discards, so it is
                            // a no-op there — one path serves both.
                            let sh = (bits as u64) - (immr.min(bits - 1) as u64);
                            let ones = (1u64 << (imms + 1)) - 1;
                            self.set_r(rd, ((src & ones).wrapping_shl(sh as u32)) & mask);
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
            Insn::Ccmp { rn, rm_imm, reg_form, nzcv, cond, ccmn, is64 } => {
                if self.cond(cond) {
                    let mask = if is64 { u64::MAX } else { 0xFFFF_FFFF };
                    let a = self.r(rn) & mask;
                    // REAL-DATA BUG #24 companion: register form compares
                    // against the REGISTER VALUE — the first cut used the
                    // reg NUMBER as an immediate.
                    let b = if reg_form { self.r(rm_imm) & mask } else { rm_imm as u64 & mask };
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
                if op == HintOp::Wfi {
                    // M4 WFI semantics: park until the next armed timer
                    // deadline (the xnu idle loop is `wfi; b .-4`), then let
                    // the loop check deliver the timer FIQ. With nothing
                    // armed the park is an honest named stop.
                    self.wfi_count += 1;
                    if self.timer_fiq_pending() {
                        // deadline already passed: FIQ taken at the loop check
                    } else if let Some(target_ns) = self.next_timer_deadline_ns() {
                        let cur = self.ns_budget_used + self.ns_ffwd;
                        if target_ns > cur {
                            self.ns_ffwd += target_ns - cur;
                        }
                        self.wfi_wakeups += 1;
                    } else {
                        return Err(StopReason::Wfi);
                    }
                }
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
                        VfpOp::Maxnm => {
                            if a.is_nan() { b } else if b.is_nan() { a } else { a.max(b) }
                        }
                        VfpOp::Minnm => {
                            if a.is_nan() { b } else if b.is_nan() { a } else { a.min(b) }
                        }
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
            Insn::Fp2 { rd, rn, rm, op, ty } => {
                self.group_exec[4] += 1;
                use crate::decode::FpType;
                match ty {
                    FpType::D => {
                        let a = f64::from_bits(self.v.lane(rn, 0, 3));
                        let b = f64::from_bits(self.v.lane(rm, 0, 3));
                        self.v.set_lane(rd, 0, 3, fp2_f64(op, a, b).to_bits());
                    }
                    FpType::S => {
                        let a = f32::from_bits(self.v.lane(rn, 0, 2) as u32);
                        let b = f32::from_bits(self.v.lane(rm, 0, 2) as u32);
                        self.v.set_lane(rd, 0, 2, fp2_f32(op, a, b).to_bits() as u64);
                    }
                    FpType::H => {
                        let a = simd::h_to_f32(self.v.lane(rn, 0, 1) as u16);
                        let b = simd::h_to_f32(self.v.lane(rm, 0, 1) as u16);
                        let r = fp2_f32(op, a, b);
                        self.v.set_lane(rd, 0, 1, simd::f32_to_h(r) as u64);
                    }
                }
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
            sysreg::ESR_EL1 => self.sys.esr_el1,
            sysreg::FAR_EL1 => self.sys.far_el1,
            sysreg::GXF_CONFIG_EL1 => self.gxf_config,
            sysreg::GXF_STATUS_EL1 => self.gxf_status,
            // M4 timer + GXF surface
            sysreg::CNTV_CTL_EL0 => {
                self.sys.cntv_ctl | if self.ctl_istatus(self.sys.cntv_ctl, self.sys.cntv_cval) { 4 } else { 0 }
            }
            sysreg::CNTV_CVAL_EL0 => self.sys.cntv_cval,
            sysreg::CNTV_TVAL_EL0 => self.sys.cntv_cval.wrapping_sub(self.ticks()) as u32 as u64,
            sysreg::CNTP_CTL_EL0 => {
                self.sys.cntp_ctl | if self.ctl_istatus(self.sys.cntp_ctl, self.sys.cntp_cval) { 4 } else { 0 }
            }
            sysreg::CNTP_CVAL_EL0 => self.sys.cntp_cval,
            sysreg::CNTP_TVAL_EL0 => self.sys.cntp_cval.wrapping_sub(self.ticks()) as u32 as u64,
            sysreg::CNTKCTL_EL1 => self.sys.cntkctl_el1,
            sysreg::GXF_C8_3 => self.sys.gxf_c8_3,
            sysreg::GXF_ESR_M => self.sys.gxf_esr_m,
            sysreg::GXF_FAR_M => self.sys.gxf_far_m,
            sysreg::IPI_SR_EL1 => 0, // no IPI source modeled yet; W1C on write
            sysreg::TPIDR_EL1 => {
                // T8030 hardware contract: ordinary kernel code NEVER writes
                // TPIDR_EL1 — on real hardware the confidential GXF boot
                // programs the guard context with &cpu_data[cpu] before the
                // first consumer runs. Measured emulator findings (both
                // recorded in tools/re/notes/m4-aic-timer-re.md):
                //  * the kernel's exception prologue (0x…81603ec) HANDLES
                //    tpidr==0 (skips the percpu stack switch);
                //  * ANY non-zero tpidr whose [0x4f8] isn't a live
                //    stack-info struct self-spins the prologue (0x…81603f8)
                //    — a poisoned seed is worse than the honest reset state;
                //  * the kernel's own bootstrap (cpu_bootstrap, stripped in
                //    the public tree) sets the real value only mid-boot.
                // Session I (M4-b RE, tools/re/notes/m4-text-zeroing-re.md):
                // cpu_data_init STORES intstack_top at cpu_data[0]+0x4f8
                // (measured 0x98e4658 @0x9a4afc0 ⇒ base 0x9a4aac8). The
                // honest seed is that guest-written fingerprint:
                // discover_cpu_data0() only returns a struct whose +0x4f8
                // the kernel itself filled with a live boot-stack KVA, so
                // the prologue's [tpidr+0x4f8] check passes on real data.
                // Discovered lazily at first MRS after cpu_data_init ran;
                // the scan's 1M-insn retry cooldown covers "not yet written".
                if self.sys.tpidr_el1 == 0 && self.cpu_data0_addr.is_none() {
                    if let Some(pa) = self.discover_cpu_data0() {
                        self.sys.tpidr_el1 = pa.wrapping_add(self.kva_base);
                    }
                }
                self.sys.tpidr_el1
            }
            sysreg::GXF_CTX => self.sys.gxf_ctx,
            sysreg::CNTVCT_EL0 => self.ticks(),
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
                    sysreg::CNTPCT_EL0 => return self.ticks(),
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
                // M3 gate metric: record the insn index at the 0→1 arming
                // edge (before `set_enabled`, which flushes the TLB).
                let arming = (v & 1 == 1) && !self.mmu.enabled;
                if arming {
                    self.mmu_live_from = Some(self.executed);
                }
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
            sysreg::ESR_EL1 => self.sys.esr_el1 = v,
            sysreg::FAR_EL1 => self.sys.far_el1 = v,
            sysreg::GXF_CONFIG_EL1 => self.gxf_config = v,
            sysreg::GXF_STATUS_EL1 => {}
            // M4 timer + GXF writes
            sysreg::CNTV_CTL_EL0 => self.sys.cntv_ctl = v & 0x3, // ISTATUS is RO
            sysreg::CNTV_CVAL_EL0 => self.sys.cntv_cval = v,
            sysreg::CNTV_TVAL_EL0 => self.sys.cntv_cval = self.ticks() + (v as u32 as u64),
            sysreg::CNTP_CTL_EL0 => self.sys.cntp_ctl = v & 0x3,
            sysreg::CNTP_CVAL_EL0 => self.sys.cntp_cval = v,
            sysreg::CNTP_TVAL_EL0 => self.sys.cntp_cval = self.ticks() + (v as u32 as u64),
            sysreg::CNTKCTL_EL1 => self.sys.cntkctl_el1 = v,
            sysreg::GXF_CTX => self.sys.gxf_ctx = v,
            sysreg::GXF_C8_3 => self.sys.gxf_c8_3 = v,
            sysreg::GXF_ESR_M => self.sys.gxf_esr_m = v,
            sysreg::GXF_FAR_M => self.sys.gxf_far_m = v,
            sysreg::IPI_SR_EL1 => {} // W1C, nothing pending to clear
            sysreg::TPIDR_EL1 => self.sys.tpidr_el1 = v,
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
            // MAIR: round-trips through sysreg_store (MRS must read back
            // what MSR wrote — the old arm dropped it, a real round-trip
            // bug) AND feeds the MMU as the attr-indirection source.
            sysreg::MAIR_EL1 => {
                self.sysreg_store.insert(enc, v);
                self.mmu.set_mair(v);
            }
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
        self.mmu_live_from = None;
        loop {
            if self.executed >= budget.max_insn {
                return RunResult {
                    stop: StopReason::Budget,
                    executed: self.executed,
                    mmu_live_from: self.mmu_live_from,
                };
            }
            if self.ns_budget_used >= budget.max_ns {
                return RunResult {
                    stop: StopReason::Budget,
                    executed: self.executed,
                    mmu_live_from: self.mmu_live_from,
                };
            }
            // M4-b guardrail: recursion/stack latch → named stop BEFORE any
            // further guest insn executes (covers both the sync-abort path
            // and async FIQ/IRQ delivery from the Ok arm below).
            if let Some((detail, elr, far, cycles)) = self.recursion_stop {
                return RunResult {
                    stop: StopReason::ExceptionRecursion { detail, elr, far, cycles },
                    executed: self.executed,
                    mmu_live_from: self.mmu_live_from,
                };
            }
            // M4-b: xnu panic() entry probe (pc supplied by boot_real).
            if self.panic_watch_pc == Some(self.pc) {
                self.panic_call_count += 1;
                if self.panic_calls.len() < 64 {
                    self.panic_calls
                        .push_back((self.executed, self.x[0], self.x[1], self.x[2], self.x[3], self.x[30]));
                }
            }
            // Diagnostic watchpoints (env-gated, default off): log the
            // register window each time pc matches a watched address.
            if !self.watch_addrs.is_empty() {
                if self.watch_addrs.contains(&self.pc) {
                    let hit = self.watch_last_hit.entry(self.pc).or_insert(0);
                    if self.executed >= *hit + 1 {
                        *hit = self.executed;
                        eprintln!(
                            "[watch] insn={} pc={:#x} lr={:x} x0={:x} x1={:x} x2={:x} x3={:x} x4={:x} x5={:x} x8={:x} x9={:x} x10={:x} x11={:x} x12={:x} x13={:x} x19={:x} x20={:x} x21={:x} x22={:x} x23={:x} x24={:x} x25={:x} x26={:x} x27={:x} x28={:x} sp={:x}",
                            self.executed, self.pc, self.x[30],
                            self.x[0], self.x[1], self.x[2], self.x[3], self.x[4], self.x[5],
                            self.x[8], self.x[9], self.x[10], self.x[11],
                            self.x[12], self.x[13],
                            self.x[19], self.x[20], self.x[21], self.x[22],
                            self.x[23], self.x[24], self.x[25], self.x[26],
                            self.x[27], self.x[28], self.sp
                        );
                    }
                }
            }
            match self.step() {
                Ok(()) => {
                    self.executed += 1;
                    self.ns_budget_used += 40; // ~25 MIPS model
                    // M4: async exception delivery — check after each retired
                    // insn. FIQ (timer) first: xnu's critical path; then IRQ
                    // (AIC line). DAIF gates: F=bit6, I=bit7.
                    if self.timer_fiq_pending() && self.sys.daif & 0x40 == 0 {
                        self.fiq_taken += 1;
                        self.take_exception(0x300, 0, None, "fiq");
                    } else if let Some(line) = &self.irq_line {
                        if line.load(std::sync::atomic::Ordering::Relaxed)
                            && self.sys.daif & 0x80 == 0
                        {
                            self.irq_taken += 1;
                            self.take_exception(0x280, 0, None, "irq");
                        }
                    }
                }
                Err(StopReason::ExceptionTaken) => {
                    // M4: a synchronous abort vectored to the guest — the
                    // faulting insn did NOT retire; execution resumes at the
                    // vector (pc already updated by take_exception). The
                    // M4-b recursion latch (if latched) is checked at the
                    // top of the loop before the next guest insn.
                }
                Err(StopReason::Halted) => {
                    self.executed += 1;
                    return RunResult {
                        stop: StopReason::Halted,
                        executed: self.executed,
                        mmu_live_from: self.mmu_live_from,
                    };
                }
                Err(other) => {
                    return RunResult {
                        stop: other,
                        executed: self.executed,
                        mmu_live_from: self.mmu_live_from,
                    };
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

    fn set_irq(&mut self, level: bool) {
        // M4: the machine's AIC raises the shared IRQ line; the run loop
        // polls it after every retired insn (DAIF.I gates delivery).
        if let Some(line) = &self.irq_line {
            line.store(level, std::sync::atomic::Ordering::Relaxed);
        }
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
        fn poke64(&self, addr: u64, val: u64) {
            let mut m = self.0.lock().unwrap();
            let off = addr as usize;
            for i in 0..8 {
                m[off + i] = ((val >> (i * 8)) & 0xFF) as u8;
            }
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

    /// M4-c Fix #1 golden: the cpu_stack_alloc fingerprint store — the
    /// guest's OWN intstack_top write (measured pc=0x7b80844 →
    /// [0x9a4afc0]=0x98e4658) — triggers the RE-validated cpu_data[0]
    /// discovery and seeds TPIDR_EL1 with the guest-built KVA, so the panic
    /// path's `ldr [tpidr,#0x4f0]` deref resolves instead of opening the
    /// 21,270-cycle exception storm (text-zeroing RE §fix-1).
    #[test]
    fn cpu_data0_fingerprint_seeds_tpidr() {
        let ram = FakeRam::new(0x4000);
        // cpu_data[0] candidate at PA 0x1000: intstack_top @+0x4f8 holds a
        // stack-range kernel VA (the discovery filter), depth @+0x500 small.
        ram.poke64(0x1000 + 0x4f8, 0xFFFF_FFF0_098E_4658);
        ram.poke64(0x1000 + 0x500, 0);
        let mut cpu = Interpreter::new(Box::new(ram));
        cpu.cpu_data_scan = Some((0x1000, 0x2000));
        cpu.kva_base = 0x1000; // test identity: KVA = PA + 0x1000
        assert_eq!(cpu.sys.tpidr_el1, 0, "pre-seed: kernel has not set TPIDR");
        // The fingerprint store: va = base+0x4f8 KVA inside the __DATA
        // window, val = the stack VA. (MMU off → PA passthrough; the store
        // itself lands out of FakeRam range and is dropped — the trigger is
        // what matters.)
        let va = 0xFFFF_FFF0_09A4_AFC0;
        cpu.st(va, 8, 0xFFFF_FFF0_098E_4658).expect("store ok");
        assert_eq!(cpu.data_store_count, 1, "fingerprint captured");
        assert_eq!(
            cpu.cpu_data0_addr,
            Some(0x1000),
            "scan found the guest-written struct"
        );
        assert_eq!(
            cpu.sys.tpidr_el1,
            0x2000,
            "TPIDR_EL1 seeded with discovered KVA (PA + kva_base)"
        );
        // A second fingerprint store must NOT re-scan or re-seed: the
        // kernel's own percpu switch stays the only later writer.
        cpu.st(va, 8, 0xFFFF_FFF0_098E_4658).expect("store ok 2");
        assert_eq!(cpu.sys.tpidr_el1, 0x2000, "seed is one-shot");
        assert_eq!(cpu.cpu_data0_addr, Some(0x1000));
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

/// Sign-extend the low `bits` of a u128 lane value to i128.
pub(crate) fn sext_u128(v: u128, bits: u32) -> i128 {
    if bits >= 128 {
        v as i128
    } else {
        let m = 1i128 << (bits - 1);
        ((v as i128) & ((m << 1) - 1)) - (((v as i128) & m) << 1)
    }
}

/// Scalar/indexed 2-source FP for the VfpOp set (S width).
fn fp2_f32(op: crate::decode::VfpOp, a: f32, b: f32) -> f32 {
    use crate::decode::VfpOp::*;
    match op {
        Add => a + b,
        Sub => a - b,
        Mul => a * b,
        Div => a / b,
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
    }
}

/// Scalar/indexed 2-source FP (D width).
fn fp2_f64(op: crate::decode::VfpOp, a: f64, b: f64) -> f64 {
    use crate::decode::VfpOp::*;
    match op {
        Add => a + b,
        Sub => a - b,
        Mul => a * b,
        Div => a / b,
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
    }
}

/// Indexed (by-element) FP op: a OP b (+/- acc for FMLA/FMLS). S or D width
/// from size_log2 (2 = S, 3 = D). Returns raw bits in the low lane.
fn vindex_fp(
    op: crate::decode::VindexStdOp,
    a: u128,
    b: u128,
    acc: u128,
    size_log2: u8,
) -> u128 {
    use crate::decode::VindexStdOp as VO;
    if size_log2 >= 3 {
        let x = f64::from_bits(a as u64);
        let y = f64::from_bits(b as u64);
        let c = f64::from_bits(acc as u64);
        let o = match op {
            VO::Fmul => x * y,
            VO::Fmulx => {
                if (x == 0.0 && y.is_infinite()) || (y == 0.0 && x.is_infinite()) {
                    2.0
                } else {
                    x * y
                }
            }
            VO::Fmla => x * y + c,
            _ => c - x * y,
        };
        o.to_bits() as u128
    } else {
        let x = f32::from_bits(a as u32);
        let y = f32::from_bits(b as u32);
        let c = f32::from_bits(acc as u32);
        let o = match op {
            VO::Fmul => x * y,
            VO::Fmulx => {
                if (x == 0.0 && y.is_infinite()) || (y == 0.0 && x.is_infinite()) {
                    2.0
                } else {
                    x * y
                }
            }
            VO::Fmla => x * y + c,
            _ => c - x * y,
        };
        o.to_bits() as u128
    }
}

// ---------------------------------------------------------------------------
// gap_mair_* goldens — REAL-DATA BUG #18: the MAIR_EL1 write arm dropped the
// value (`=> {}`), so any `msr mair_el1` + later `mrs mair_el1` read 0.
// Found by the M3 groundwork inventory (tools/re/notes, 2026-10-29 session);
// the kernel programs MAIR before the SCTLR_EL1.M flip, so every later
// attribute read came back zero. Fixed: write arm round-trips through
// sysreg_store AND feeds Mmu::set_mair (attr-indirection source).
// ---------------------------------------------------------------------------
#[cfg(test)]
mod gap_mair_tests {
    use super::*;

    struct NullMem;
    impl MemAccess for NullMem {
        fn load(&mut self, _addr: u64, _size: u8) -> u64 {
            0
        }
        fn store(&mut self, _addr: u64, _size: u8, _val: u64) {}
        fn fetch32(&mut self, _addr: u64) -> u32 {
            0
        }
    }

    /// Byte-backed RAM for the M4-b exception/percpu tests.
    struct FakeRam(Vec<u8>);
    impl FakeRam {
        fn new(n: usize) -> Self {
            FakeRam(vec![0u8; n])
        }
        fn load_code(&mut self, base: usize, code: &[u8]) {
            self.0[base..base + code.len()].copy_from_slice(code);
        }
    }
    impl MemAccess for FakeRam {
        fn load(&mut self, addr: u64, size: u8) -> u64 {
            let off = addr as usize;
            let mut v = 0u64;
            for i in 0..size as usize {
                v |= (*self.0.get(off + i).unwrap_or(&0) as u64) << (i * 8);
            }
            v
        }
        fn store(&mut self, addr: u64, size: u8, val: u64) {
            let off = addr as usize;
            for i in 0..size as usize {
                if off + i < self.0.len() {
                    self.0[off + i] = ((val >> (i * 8)) & 0xFF) as u8;
                }
            }
        }
        fn fetch32(&mut self, addr: u64) -> u32 {
            self.load(addr, 4) as u32
        }
    }

    fn cpu() -> Interpreter {
        Interpreter::new(Box::new(NullMem))
    }

    /// MRS must read back exactly what MSR wrote (the bug: always 0).
    #[test]
    fn gap_mair_roundtrip() {
        let mut c = cpu();
        // synthesized MAIR (the kernel's real value is not yet captured —
        // honest limit): n=0 normal wb, n=1 device-nGnRE, n=2 normal nc
        let v: u64 = 0x0000_0000_4400_04FF;
        c.write_sysreg(sysreg::MAIR_EL1, v);
        assert_eq!(c.read_sysreg(sysreg::MAIR_EL1), v, "MAIR_EL1 MRS round-trip");
        // a second write replaces (not ORs) — PMA semantics
        c.write_sysreg(sysreg::MAIR_EL1, 0x0100_0000_0000_00FF);
        assert_eq!(c.read_sysreg(sysreg::MAIR_EL1), 0x0100_0000_0000_00FF);
    }

    /// The MMU mirror receives the write: AttrIndx → MAIR byte decode.
    #[test]
    fn gap_mair_mmu_attr_byte() {
        let mut c = cpu();
        let v: u64 = 0x0000_0000_4400_04FF;
        c.write_sysreg(sysreg::MAIR_EL1, v);
        assert_eq!(c.mmu.mair, v, "Mmu must see the MAIR write");
        assert_eq!(c.mmu.attr_byte(0), 0xFF, "attr[0] = normal write-back");
        assert_eq!(c.mmu.attr_byte(1), 0x04, "attr[1] = device-nGnRE");
        assert_eq!(c.mmu.attr_byte(2), 0x00, "attr[2] unset");
        assert_eq!(c.mmu.attr_byte(3), 0x44, "attr[3]");
        assert_eq!(c.mmu.attr_byte(7), 0x00, "attr[7] unset");
        // direct mmu path too (no interp involved)
        let mut m = crate::mmu::Mmu::new();
        m.set_mair(v);
        assert_eq!(m.attr_byte(1), 0x04);
        assert_eq!(m.attr_byte(3), 0x44);
        assert_eq!(m.attr_byte(7), 0x00);
    }

    /// M4-b: an undecodable word VECTORS to the guest once VBAR is live —
    /// real hardware raises EC=UNCATEGORIZED (ESR 0x0200_0000: EC=0, IL=1,
    /// ISS=0 — the ISS==0 the real kernel asserts, tools/re/refs/xnu/
    /// sleh.c:694). The kernel's own 0xE7FFDEFF GDB-trap markers (2 file
    /// sites in the panic path) depend on this. Words: keystone-verified
    /// (`b .` = 0x14000000).
    #[test]
    fn undefined_insn_vectors_with_live_vbar() {
        let mut ram = FakeRam::new(0x8000);
        // the marker the real kernel ships in its panic path
        ram.load_code(0x1000, &0xE7FF_DEFFu32.to_le_bytes());
        // handler at vbar+0x200: `b .` — spins; budget stop proves the
        // exception was TAKEN (not a terminal UnknownInsn stop)
        ram.load_code(0x2200, &0x1400_0000u32.to_le_bytes());
        let mut cpu = Interpreter::new(Box::new(ram));
        cpu.set_reset_vector(0x1000);
        cpu.sys.vbar_el1 = 0x2000;
        let res = cpu.run(InterpBudget { max_insn: 64, max_ns: u64::MAX });
        assert!(matches!(res.stop, StopReason::Budget), "stop={res:?}");
        assert_eq!(cpu.undefined_taken, 1);
        assert_eq!(cpu.exc_taken, 1);
        assert_eq!(
            cpu.sys.esr_el1, 0x0200_0000,
            "EC=UNCATEGORIZED(0), IL=1, ISS=0"
        );
        assert_eq!(cpu.sys.elr_el1, 0x1000);
        assert_eq!(cpu.sys.far_el1, 0x1000);
        assert_eq!(cpu.pc, 0x2200, "resumed at vbar+0x200");
    }

    /// M4-b: BEFORE the guest installs VBAR the undefined word stays a
    /// terminal stop (the boot-stub region has no handler) — unchanged.
    #[test]
    fn undefined_insn_stops_before_vbar() {
        let mut ram = FakeRam::new(0x8000);
        ram.load_code(0x1000, &0xE7FF_DEFFu32.to_le_bytes());
        let mut cpu = Interpreter::new(Box::new(ram));
        cpu.set_reset_vector(0x1000);
        let res = cpu.run(InterpBudget { max_insn: 16, max_ns: u64::MAX });
        assert!(
            matches!(res.stop, StopReason::UnknownInsn { insn: 0xE7FF_DEFF, .. }),
            "stop={res:?}"
        );
        assert_eq!(cpu.undefined_taken, 0);
    }

    /// REAL-DATA BUG #27: the BFM family executed `width = bits-imms-1` —
    /// the arm_vm_init packed-pointer decoder's `bfxil x14,x15,#0,#56`
    /// became an 8-bit insert, storing 0xfffe00ee488b0058 instead of
    /// 0xfffffff007724458 into the DT-registry array base (the
    /// far=0xfffe00ee488b0058 stop @0x…7b8cd70, 8.18M insns). Encodings
    /// keystone-verified; expected values per ARM DDI 0487 (bfxil/bfi/bfm/
    /// ubfiz/sbfiz), cross-checked against the rebase decode arithmetic.
    #[test]
    fn bfm_bfxil_family_value_goldens() {
        let exec = |words: &[u32], preset: &[(usize, u64)]| {
            let mut ram = FakeRam::new(0x8000);
            for (i, w) in words.iter().enumerate() {
                ram.load_code(0x1000 + i * 4, &w.to_le_bytes());
            }
            ram.load_code(0x1000 + words.len() * 4, &0xD440_0000u32.to_le_bytes());
            let mut cpu = Interpreter::new(Box::new(ram));
            cpu.set_reset_vector(0x1000);
            for &(r, v) in preset {
                cpu.x[r] = v;
            }
            let res = cpu.run(InterpBudget { max_insn: 64, max_ns: u64::MAX });
            assert_eq!(res.stop, StopReason::Halted, "program must halt");
            cpu
        };

        // 1) THE rebase-decode pipeline (arm_vm_init, verbatim):
        //    lsl x14,x13,#13 ; sbfx x15,x13,#0,#43 ; bfxil x14,x15,#0,#56 ;
        //    add x14,x22,x14 ; add x14,x14,x11
        //    with x13 = the shipped packed entry, x22 = link base, x11 =
        //    0x0FF8FFC000 (the walker's constant) → x14 MUST be the clean
        //    array-base VA. x14 pre-filled with garbage: bfxil must replace
        //    the low 56 bits and preserve the top byte.
        let cpu = exec(
            &[0xD373_C9AE, 0x9340_A9AF, 0xB340_DDEE, 0x8B0E_02CE, 0x8B0B_01CE],
            &[
                (13, 0x0017_FFF0_0772_4458),
                (22, 0xFFFF_FFF0_0700_4000),
                (11, 0x0000_000F_F8FF_C000), // the walker's x11 constant (watch-measured)
                (14, 0x1234_5678_9ABC_DEF0), // garbage: bfxil must replace low 56
            ],
        );
        assert_eq!(
            cpu.x[14], 0xFFFF_FFF0_0772_4458,
            "packed-pointer decode pipeline must yield the clean VA (bug #27)"
        );

        // 2) bfi x0,x1,#3,#9 (wrap family): x0[11:3] = x1[8:0], rest kept.
        let cpu = exec(
            &[0xB37D_2020],
            &[(0, 0xDEAD_BEEF_DEAD_BEEF), (1, 0x1234_5678_9ABC_DEF1)],
        );
        assert_eq!(cpu.x[0], 0xDEAD_BEEF_DEAD_B78F, "bfi wrap insert");

        // 3) raw bfm x4,x5,#4,#10 (capstone: bfxil #4,#7): x4[6:0]=x5[10:4].
        let cpu = exec(
            &[0xB344_28A4],
            &[(4, 0xCAFE_F00D_BEEF_F00D), (5, 0x0123_4567_89AB_CDEF)],
        );
        assert_eq!(cpu.x[4], 0xCAFE_F00D_BEEF_F05E, "raw bfm = bfxil s>=r");

        // 4) ubfiz x0,x1,#2,#12: (x1 & 0xFFF) << 2 — high garbage must go.
        let cpu = exec(&[0xD37E_2C20], &[(1, 0xFEED_FACE_FEED_FACE)]);
        assert_eq!(cpu.x[0], 0x2B38, "ubfiz must mask the field");

        // 5) sbfiz x2,x3,#2,#12: SX12(x3[11:0]) << 2 — negative + positive.
        let cpu = exec(&[0x937E_2C62], &[(3, 0x1234_5678_9ABC_DEF1)]);
        assert_eq!(cpu.x[2], 0xFFFF_FFFF_FFFF_FBC4, "sbfiz negative sx");
        let cpu = exec(&[0x937E_2C62], &[(3, 0xFFFF_FFFF_FFFF_F801)]);
        assert_eq!(cpu.x[2], 0xFFFF_FFFF_FFFF_E004, "sbfiz negative 2");

        // 6) 32-bit bfxil w0,w1,#8,#12: w0[11:0]=w1[19:8], upper word zero.
        let cpu = exec(&[0x3308_4C20], &[(0, 0xDEAD_BEEF), (1, 0x1ABC_DEF1)]);
        assert_eq!(cpu.x[0], 0xDEAD_BCDE, "W-form bfxil zero-extends");
    }

    /// M4-b: TPIDR_EL1 seeds itself from the GUEST's own cpu_data[0]
    /// fingerprint (intstack_top written by cpu_data_init at +0x4f8,
    /// measured 0x98e4658 @0x9a4afc0 ⇒ base 0x9a4aac8). The MRS at
    /// 0xD538D080 is keystone-verified (`mrs x0, tpidr_el1`).
    #[test]
    fn tpidr_discovers_guest_written_cpu_data() {
        let mut ram = FakeRam::new(0x8000);
        // the guest-written fingerprint at struct base 0x3000
        ram.load_code(0x34f8, &0xFFFF_FFF0_098E_4658u64.to_le_bytes());
        ram.load_code(0x3500, &1u64.to_le_bytes());
        // mrs x0, tpidr_el1 ; hlt #0
        ram.load_code(0x1000, &0xD538_D080u32.to_le_bytes());
        ram.load_code(0x1004, &0xD440_0000u32.to_le_bytes());
        let mut cpu = Interpreter::new(Box::new(ram));
        cpu.set_reset_vector(0x1000);
        cpu.cpu_data_scan = Some((0x3000, 0x4000));
        cpu.kva_base = 0x1000;
        let res = cpu.run(InterpBudget { max_insn: 8, max_ns: u64::MAX });
        assert_eq!(res.stop, StopReason::Halted);
        assert_eq!(cpu.cpu_data0_addr, Some(0x3000));
        assert_eq!(cpu.sys.tpidr_el1, 0x4000, "discovered PA + kva_base");
        assert_eq!(cpu.x[0], 0x4000, "the MRS must observe the seed");
    }

    /// M4-b guardrail: ≥96 identical re-entries of the SAME exception
    /// (kind/esr/far/pc) latch the named ExceptionRecursion stop — the
    /// measured session-H storm cycled (elr,far) 21,270 times and zeroed
    /// 24 MB of the kernel image before any stop fired.
    #[test]
    fn identical_exception_loop_latches_named_stop() {
        let mut ram = FakeRam::new(0x8000);
        let mut cpu = Interpreter::new(Box::new(ram));
        cpu.sys.vbar_el1 = 0x2000;
        for _ in 0..200 {
            cpu.take_exception(0x200, 0x9600_0006, Some(0x4f0), "sync");
        }
        let (detail, _elr, far, cycles) = cpu
            .recursion_stop
            .expect("the latch must fire at 96 identical re-entries");
        assert_eq!(detail, "identical-exception-loop");
        assert_eq!(far, 0x4f0);
        assert!(cycles >= 96);
    }
}
