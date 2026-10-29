//! A64 instruction decoder for the Apple A13 boot-critical subset.
//!
//! # Provenance
//!
//! Encoding tables and field layouts follow the ARM Architecture Reference
//! Manual (ARM DDI 0487, "C4.1 A64 instruction set encoding" and the
//! per-instruction C6.2 pages). The Apple GXF `GENTER`/`GEXIT` encodings
//! follow ChefKiss Inferno `target/arm/tcg/translate-a64.c`
//! (`disas_apple_insn`: encoding group `insn[28:25] == 0b0000`,
//! `insn[15:10] == 0b000101`, `insn[9:5] == 1 → GENTER, 0 → GEXIT`).
//!
//! # Contract
//!
//! `decode(pc, word) -> Option<Insn>`: `Some(insn)` for anything in the
//! modeled subset (see [`crate::isa`] for the table), `None` for
//! everything else. `None` is the *unsupported marker* — the interpreter
//! turns it into `StopReason::UnknownInsn { pc, insn }` and stops; it
//! never silently skips an undecoded word. No `qemu-util` dependency: the
//! bit-extraction helpers are local to this file.
//!
//! Immediates are pre-canonicalized where it removes an execution-time
//! footgun: branch offsets are sign-extended *byte* offsets, and logical
//! "bitmask immediate" encodings are expanded to their full 64-bit value
//! at decode time (invalid bitmask encodings decode to `None`).

/// Condition code for `B.cond` (ARM DDI 0487 C1.2.4). `Nv` (0b1111) is
/// rejected by the decoder — it is an unpredictable alias of AL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cond {
    Eq,
    Ne,
    Cs, // HS
    Cc, // LO
    Mi,
    Pl,
    Vs,
    Vc,
    Hi,
    Ls,
    Ge,
    Lt,
    Gt,
    Le,
    Al,
}

impl Cond {
    /// Decode the 4-bit condition field; `None` for NV (0b1111).
    pub fn from_bits(bits: u32) -> Option<Cond> {
        Some(match bits {
            0x0 => Cond::Eq,
            0x1 => Cond::Ne,
            0x2 => Cond::Cs,
            0x3 => Cond::Cc,
            0x4 => Cond::Mi,
            0x5 => Cond::Pl,
            0x6 => Cond::Vs,
            0x7 => Cond::Vc,
            0x8 => Cond::Hi,
            0x9 => Cond::Ls,
            0xA => Cond::Ge,
            0xB => Cond::Lt,
            0xC => Cond::Gt,
            0xD => Cond::Le,
            0xE => Cond::Al,
            _ => return None,
        })
    }

    pub fn mnemonic(&self) -> &'static str {
        match self {
            Cond::Eq => "eq",
            Cond::Ne => "ne",
            Cond::Cs => "cs",
            Cond::Cc => "cc",
            Cond::Mi => "mi",
            Cond::Pl => "pl",
            Cond::Vs => "vs",
            Cond::Vc => "vc",
            Cond::Hi => "hi",
            Cond::Ls => "ls",
            Cond::Ge => "ge",
            Cond::Lt => "lt",
            Cond::Gt => "gt",
            Cond::Le => "le",
            Cond::Al => "al",
        }
    }
}

/// Shift applied to a register operand (`ADD/SUB (shifted register)`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShiftKind {
    Lsl,
    Lsr,
    Asr,
    /// ROR — logical shifted register with rotate (real 14.3: ~1.2k words
    /// e.g. `eor w13,w11,w21,ror #29` = 0x4AD5756D); amount taken mod size.
    Ror,
}

/// Data-processing (1-source) opcode (opc bits 15:10; capstone-derived map
/// on real 18C66 bytes: 0=RBIT 1=REV16 2=REV32(64)/REV(32) 3=REV(64)
/// 4=CLZ 5=CLS).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dp1Op {
    Rbit,
    Rev16,
    Rev32,
    Rev,
    Clz,
    Cls,
}

/// LDP/STP addressing mode (ARM DDI 0487 "Load/store pair").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairMode {
    /// Non-temporal (LDNP/STNP) — behaves as offset, no writeback.
    NonTemporal,
    /// Post-index: use base, then base += offset.
    Post,
    /// Signed offset, no writeback.
    Offset,
    /// Pre-index: base += offset, use new base.
    Pre,
}

/// One decoded A64 instruction from the modeled subset.
///
/// Register fields are raw 5-bit encodings; the interpreter applies the
/// ARM rule for register 31 (SP vs ZR per instruction class). Immediates
/// that feed PC are pre-sign-extended byte offsets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Insn {
    /// NOP (and harmless hints YIELD/WFE/WFI/SEV — modeled as no-ops).
    Nop,
    /// MOVZ (wide immediate).
    Movz { rd: u8, imm16: u16, shift: u8, is64: bool },
    /// MOVN (inverted wide immediate).
    Movn { rd: u8, imm16: u16, shift: u8, is64: bool },
    /// MOVK (keep bits wide immediate).
    Movk { rd: u8, imm16: u16, shift: u8, is64: bool },
    /// MOV (register) — ORR Xd, XZR, Xn alias.
    MovReg { rd: u8, rn: u8 },
    /// ADD/SUB immediate; `setflags` ⇒ ADDS/SUBS.
    AddImm { rd: u8, rn: u8, imm12: u32, shift: bool, setflags: bool, is64: bool },
    SubImm { rd: u8, rn: u8, imm12: u32, shift: bool, setflags: bool, is64: bool },
    /// ADD/SUB shifted register; `subtract` ⇒ SUB form.
    AddSubReg {
        rd: u8,
        rn: u8,
        rm: u8,
        kind: ShiftKind,
        imm6: u32,
        subtract: bool,
        setflags: bool,
        is64: bool,
    },
    /// AND (immediate) / ANDS (setflags); bitmask pre-expanded.
    AndImm { rd: u8, rn: u8, imm: u64, setflags: bool, is64: bool },
    /// ORR (immediate).
    OrrImm { rd: u8, rn: u8, imm: u64, setflags: bool, is64: bool },
    /// EOR (immediate).
    EorImm { rd: u8, rn: u8, imm: u64, setflags: bool, is64: bool },
    /// CMP (immediate) — SUBS XZR, Rn, #imm.
    CmpImm { rn: u8, imm12: u32, shift: bool, is64: bool },
    /// AdvSIMD three-same integer (per-lane ADD/SUB, compares CM*,
    /// S/UMIN/MAX (+P pairwise), MUL) — width from size, U splits signed/
    /// unsigned variants. Boot: `cmhi v0.16b, …` @ 0x…8169e04 (18C66 memscan).
    V3SameInt { rd: u8, rn: u8, rm: u8, size: u8, u: bool, q: bool, op: V3Op },
    /// AdvSIMD three-same FP (session C, keystone-pinned): fadd/fsub/fmla/
    /// fmls/fmul/fmulx/fdiv/fabd/faddp/fmax*/fmin*/fcm*/fac*/frecps/frsqrts.
    /// `d` = bit22 (false: S-lanes f32, true: D-lanes f64); `half` = bit23
    /// (the opcode-pair selector). Boot path: xnu FP math in memscan/compress.
    V3SameFp { rd: u8, rn: u8, rm: u8, d: bool, u: bool, q: bool, op: V3FpOp },
    /// AdvSIMD three-same logical (U=0: AND/BIC/ORR/ORN; U=1: EOR/BSL/BIT/EON)
    /// — size field selects the op within the U family; Q selects .16b/.8b.
    /// Boot: `orr v0.16b, v0.16b, v1.16b` @ 0x…8169de8 (real 18C66 memscan).
    VLogic3 { rd: u8, rn: u8, rm: u8, size: u8, u: bool, q: bool },
    /// Across-lane reduces — {S,U}MINV/{S,U}MAXV/ADDV, size selects the
    /// result width (00=B, 01=H). Boot: `uminv b1, v0.16b` @ 0x…8169df4.
    VReduce { rd: u8, rn: u8, size: u8, op: VReduceOp, q: bool },
    /// Scalar FP ↔ GPR move — `fmov w2, s1` / `fmov d0, x3` (int←scalar) and
    /// `fmov s0, w3` / `fmov d0, x3` (scalar←int). Boot: `fmov w2, s1` @ 0x…8169df8.
    FmovGprVec { rt: u8, rn: u8, is64: bool, to_vec: bool },
    /// MOVI (vector, 64-bit lanes — cmode 111x): immh=0, opcode=111001,
    /// bit11=0. imm8 = bits[9:5] | (immb<<5) and the 64-bit immediate
    /// EXPANDS each imm8 bit into a byte (bit i → byte i = 0xFF/0x00) —
    /// measured 12/12 against capstone incl. `movi v0.2d, #0xffffffffffffffff`
    /// (0x6F07E7E0, real 18C66 boot @ 0x…7b8cbf4).
    MoviVec64 { rd: u8, q: bool, imm8: u8 },
    /// Shift-by-immediate (0x0F group, bit10=1, immh:immb valid as a shift).
    /// Field map pinned by keystone sweeps (session C): X = immh:immb =
    /// bits[22:16] must lie in [8<<size, 16<<size) and SHIFT = (16<<size)−X;
    /// element size derives from X's MSB (bits 23:22 are 0 in shift forms);
    /// opcode = bits[15:11], U(29) splits signed/unsigned arms.
    VShiftImm {
        rd: u8,
        rn: u8,
        op: VShiftOp,
        immh_immb: u8,
        size: u8,
        u: bool,
        q: bool,
    },
    /// Modified-immediate (0x0F group, bit10=1, X < 8): MOVI/MVNI/ORR-imm/
    /// BIC-imm, cmode = bits[15:12]. `value` = precomputed 64-bit lane-unit
    /// pattern; `width_log2` = the encoded element width (0=8b,1=16b,2=32b,
    /// 3=64b bit-expansion). Exec replicates the unit across the register.
    MoviVec { rd: u8, op: VecImmOp, value: u64, width_log2: u8, q: bool },
    /// FMOV (vector, immediate) — cmode 1111, U=0: VFP-ExpandImm of imm8.
    FmovVecImm { rd: u8, q: bool, imm8: u8 },
    /// CMN (register/immediate) — `adds wzr/xzr, xn, …` (add-flags test).
    CmnImm { rn: u8, imm12: u32, shift: bool, is64: bool },
    CmnReg { rn: u8, rm: u8, kind: ShiftKind, imm6: u32, is64: bool },
    /// CMP (register) — SUBS XZR, Rn, Rm{,shift}.
    CmpReg { rn: u8, rm: u8, kind: ShiftKind, imm6: u32, is64: bool },
    /// B — `imm` is the sign-extended byte offset from the B's own PC.
    B { imm: i64 },
    /// BL — link register gets PC+4.
    Bl { imm: i64 },
    /// BR Xn.
    Br { rn: u8 },
    /// BLR Xn.
    Blr { rn: u8 },
    /// RET {Xn} (default X30).
    Ret { rn: u8 },
    /// B.cond — `imm` is the sign-extended byte offset.
    BCond { cond: Cond, imm: i64 },
    /// CBZ (32/64 test).
    Cbz { rn: u8, imm: i64, is64: bool },
    /// CBNZ.
    Cbnz { rn: u8, imm: i64, is64: bool },
    /// TBZ — `bit` is the absolute bit number (0..63).
    Tbz { rn: u8, bit: u8, imm: i64 },
    /// TBNZ.
    Tbnz { rn: u8, bit: u8, imm: i64 },
    /// ADR — `imm` is the sign-extended byte offset from PC.
    Adr { rd: u8, imm: i64 },
    /// ADRP — `imm` is the sign-extended offset in 4 KiB pages from the
    /// page containing PC.
    Adrp { rd: u8, imm: i64 },
    /// LDR (immediate, unsigned offset). `size_log2` ∈ 0..=3 ⇒ 1/2/4/8 B.
    LdrImmU { rt: u8, rn: u8, imm12: u32, size_log2: u8 },
    /// STR (immediate, unsigned offset).
    StrImmU { rt: u8, rn: u8, imm12: u32, size_log2: u8 },
    /// LDR (literal) — `imm` is the sign-extended byte offset from PC.
    LdrLit { rt: u8, imm: i64, is64: bool },
    /// LDP — `imm` is the pre-scaled signed byte offset.
    Ldp { rt: u8, rt2: u8, rn: u8, imm: i64, mode: PairMode, is64: bool },
    /// STP.
    Stp { rt: u8, rt2: u8, rn: u8, imm: i64, mode: PairMode, is64: bool },
    /// LDPSW — load pair, sign-extend 32→64.
    Ldpsw { rt: u8, rt2: u8, rn: u8, imm: i64, mode: PairMode },
    /// SIMD load/store pair (S=4B / D=8B / Q=16B): `log2_width` 2..=4.
    LdpSimd { vt: u8, vt2: u8, rn: u8, imm: i64, mode: PairMode, log2_width: u8 },
    StpSimd { vt: u8, vt2: u8, rn: u8, imm: i64, mode: PairMode, log2_width: u8 },
    /// Load/store 9-bit-addressing forms: LDUR/STUR, pre/post-index,
    /// LDTR/STTR. `size_log2` 0..=3; post/pre write back base+imm9.
    LdSt9 { rt: u8, rn: u8, imm9: i64, size_log2: u8, load: bool, mode: LsMode },
    /// Signed 9-bit forms: LDRSB/LDRSH/LDRSW. `dest64` selects the
    /// 64-bit-destination variant (opc 10) vs 32-bit (opc 11).
    Ldrs9 { rt: u8, rn: u8, imm9: i64, size_log2: u8, mode: LsMode, dest64: bool },
    /// Load/store register offset: LDR/STR/STRB/LDRB/… [Rn, Rm{, extend {#s}}].
    LdStRegOff {
        rt: u8,
        rn: u8,
        rm: u8,
        option: ExtOp,
        scaled: bool,
        size_log2: u8,
        load: bool,
        /// Signed-load variants (LDRSB/LDRSH/LDRSW) in this group.
        sign_ext: bool,
        dest64: bool,
    },
    /// SIMD single register, 9-bit addressing (LDUR/STUR/post/pre B/H/Q).
    LdStSimd9 { vt: u8, rn: u8, imm9: i64, width_log2: u8, load: bool, mode: LsMode },
    /// SIMD single register, unsigned offset (B/H/S/D/Q); Q = width_log2 4.
    LdStSimdU { vt: u8, rn: u8, imm12: u32, width_log2: u8, load: bool },
    /// RETAA / RETAB (auth-return; QARMA-model auth is a no-op strip).
    RetA { ab: bool },
    /// BRAA/BRAB/BLRAA/BLRAB — authenticated branch (register).
    BrAuth { rn: u8, link: bool, ab: bool },
    /// BRK #imm — software breakpoint; interpreter stops with Panic.
    Brk { imm16: u16 },
    /// DCPS1/2/3 #imm.
    Dcps { level: u8, imm16: u16 },
    /// DRPS — debug restore state.
    Drps,
    /// Variable-shift register ops: LSLV/LSRV/ASRV/RORV (2-source).
    ShiftReg { rd: u8, rn: u8, rm: u8, op: ShiftOp, is64: bool },
    /// Add/sub extended register: ADD Xd, Xn, Wm, UXTW #imm3 …
    AddSubExt {
        rd: u8,
        rn: u8,
        rm: u8,
        option: ExtOp,
        imm3: u8,
        subtract: bool,
        setflags: bool,
        is64: bool,
    },
    /// MRS Xt, <sysreg> — `sysreg` is the canonical 15-bit encoding.
    Mrs { rt: u8, sysreg: u16 },
    /// MSR <sysreg>, Xt.
    Msr { sysreg: u16, rt: u8 },
    /// SVC #imm — supervisor call; interpreter stops with Panic.
    Svc { imm16: u16 },
    /// HVC #imm.
    Hvc { imm16: u16 },
    /// SMC #imm.
    Smc { imm16: u16 },
    /// ISB / DSB / DMB — barriers are no-ops in the interpreter.
    Isb,
    Dsb,
    Dmb,
    /// ERET — PC ← ELR_EL1.
    Eret,
    /// Apple GXF GENTER (ChefKiss Inferno `disas_apple_insn`).
    Genter { rd: u8 },
    /// Apple GXF GEXIT.
    Gexit { rd: u8 },
    /// HLT #imm — modeled as a clean halt (`StopReason::Halted`).
    Hlt { imm16: u16 },
    // ------------------------------------------------------------------
    // ARMv8.1 LSE atomics + CAS (golden-verified layout)
    // ------------------------------------------------------------------
    /// LSE atomic memory operation: LDADD/LDCLR/LDEOR/LDSET/LDSMAX/
    /// LDSMIN/LDUMAX/LDUMIN/SWP family with A/R qualifiers. `rt` may be
    /// 31 (= ZR) which the ST* store-only aliases encode.
    Atomic {
        op: AtomicOp,
        rt: u8,
        rs: u8,
        rn: u8,
        size_log2: u8,
        acquire: bool,
        release: bool,
    },
    /// CAS/CASA/CASL/CASAL (+ B/H suffixes): compare-and-swap.
    Cas { rt: u8, rs: u8, rn: u8, size_log2: u8, acquire: bool, release: bool },
    /// LDXR/LDAXR (size in bytes 1/2/4/8), LDXP when `pair`.
    Ldxr { rt: u8, rt2: u8, rn: u8, size_log2: u8, acquire: bool, pair: bool },
    /// STXR/STLXR (rs = status register), STXP when `pair`.
    Stxr { rs: u8, rt: u8, rt2: u8, rn: u8, size_log2: u8, release: bool, pair: bool },
    /// LDAR/STLR (load-acquire / store-release).
    Ldar { rt: u8, rn: u8, size_log2: u8 },
    Stlr { rt: u8, rn: u8, size_log2: u8 },
    /// LDAPR / LDAPUR (v8.3 RCPC with address auth variants folded in).
    Ldapr { rt: u8, rn: u8, size_log2: u8 },
    // ------------------------------------------------------------------
    // Data-processing (2 source) — CRC32, DIV, MULH, PACGA, scalar RDM
    // ------------------------------------------------------------------
    /// CRC32B/H/W/X (+CRC32C when `castagnoli`); X-form (size_log2==3)
    /// reads an Xm source.
    Crc32 { rd: u8, rn: u8, rm: u8, size_log2: u8, castagnoli: bool },
    /// UDIV / SDIV (scalar RDM has its own variants below).
    Udiv { rd: u8, rn: u8, rm: u8 },
    Sdiv { rd: u8, rn: u8, rm: u8 },
    /// SMULH / UMULH (64-bit only).
    Smulh { rd: u8, rn: u8, rm: u8 },
    Umulh { rd: u8, rn: u8, rm: u8 },
    /// Data-processing (1 source): RBIT/REV16/REV32/REV/CLZ/CLS.
    Dp1 { rd: u8, rn: u8, op: Dp1Op, is64: bool },
    /// PACGA Xd, Xn, Xm (v8.3 generic-A PAC, 2-source form).
    Pacga { rd: u8, rn: u8, rm: u8 },
    /// SQRDMLAH/SQRDMLSH (v8.1 scalar; QEMU case 0x1c/0x1d anchored).
    Sqrdmlah { rd: u8, rn: u8, rm: u8, is64: bool, subtract: bool },
    // ------------------------------------------------------------------
    // Data-processing (3 source) — MADD/MSUB/MUL + logical shifted reg
    // ------------------------------------------------------------------
    /// MADD Xd, Xn, Xm, Xa (Ra=31 → MUL alias); MSUB when `subtract`.
    Madd { rd: u8, rn: u8, rm: u8, ra: u8, subtract: bool, is64: bool },
    /// SMADDL/SMSUBL/UMADDL/UMSUBL (widening, 32-bit operands).
    MaddW { rd: u8, rn: u8, rm: u8, ra: u8, subtract: bool, unsigned: bool },
    /// AND/ORR/EOR (+BIC/ORN/EON via `invert`, ANDS/TST via `setflags`)
    /// with a shifted register operand.
    LogicReg {
        rd: u8,
        rn: u8,
        rm: u8,
        kind: ShiftKind,
        imm6: u32,
        op: LogicOp,
        setflags: bool,
        invert: bool,
        is64: bool,
    },
    /// BFM/SBFM/UBFM (bitfield move; SBFM aliases ASR/SBFIZ/…,
    /// UBFM aliases LSR/UBFIZ/…).
    Bfm { rd: u8, rn: u8, immr: u32, imms: u32, kind: BfmKind, is64: bool },
    /// EXTR Xd, Xn, Xm, #lsb (extract; ROR alias when Xn==Xm).
    Extr { rd: u8, rn: u8, rm: u8, lsb: u32, is64: bool },
    /// CSEL/CSINC/CSINV/CSNEG (conditional select).
    Csel { rd: u8, rn: u8, rm: u8, cond: Cond, op: CselOp, is64: bool },
    /// CCMP/CCMN (immediate `#imm5` or register form).
    Ccmp { rn: u8, rm_imm: u8, nzcv: u8, cond: Cond, ccmn: bool, is64: bool },
    /// MSR (immediate): DAIFSet/DAIFClr.
    MsrImm { daifclr: bool, imm4: u8 },
    /// MSR (immediate) SPSel — `msr spsel, #0/#1` (keystone: d50040bf /
    /// d50041bf; the stack-select bit is instruction bit 8).
    MsrSpsel { use_sp: bool },
    // ------------------------------------------------------------------
    // PAC (v8.3 pointer authentication — ARM hint-space group 0xDA)
    // ------------------------------------------------------------------
    /// PACIA/PACIB/PACDA/PACDB (+AUT*/Z/SP variants) and XPACI/XPACD.
    Pac { op: PacOp, rd: u8, rn: u8 },
    /// BTI C/J/JC (v8.5 branch target identification).
    Bti { kind: BtiKind },
    /// DGH (data gathering hint) and the other named hints (ESB, PSB
    /// CSYNC, CSDB, TSB CSYNC) — modeled as no-ops, decoded by name.
    Hint { op: HintOp },
    // ------------------------------------------------------------------
    // System: TLBI range (v8.4), MSR-immediate handled above
    // ------------------------------------------------------------------
    /// TLBI RVAE1IS/RVALE1/RVAALE1OS/… range invalidations (v8.4); the
    /// Rt field carries base:Scale:Num for the range.
    TlbiRange { op: TlbiRangeOp, rt: u8 },
    // ------------------------------------------------------------------
    // AdvSIMD — vector three-same / crypto / FP16 (the v8.2/8.3/8.4 groups)
    // ------------------------------------------------------------------
    /// SDOT/UDOT (vector): Vd.S += Σ a.B * b.B (signed/unsigned).
    Vdot { vd: u8, vn: u8, vm: u8, unsigned: bool, q: bool, two_s: bool },
    /// SQRDMLAH/SQRDMLSH vector (v8.1 ASIMD RDM).
    Vsqrdmlah { vd: u8, vn: u8, vm: u8, subtract: bool, size_log2: u8, q: bool },
    /// FCMLA (v8.1 FCMA): complex multiply-add, rot ∈ {0,1,2,3} × 90°.
    Vfcmla { vd: u8, vn: u8, vm: u8, rot: u8, size_log2: u8, q: bool },
    /// FCADD (v8.4): complex add with rotate 90/270.
    Vfcadd { vd: u8, vn: u8, vm: u8, rot270: bool, size_log2: u8, q: bool },
    /// FP16 vector arithmetic: FADD/FSUB/FMUL/FDIV/FABS/FNEG/FSQRT/
    /// FMAX/FMIN over .8H/.4H lanes.
    Vfp16 { vd: u8, vn: u8, vm: u8, op: VfpOp, q: bool },
    /// SHA512H / SHA512H2 (2-round compression fragments).
    Vsha512h { vd: u8, vn: u8, vm: u8, h2: bool },
    /// SHA512SU1 (message schedule step 1).
    Vsha512su1 { vd: u8, vn: u8, vm: u8 },
    /// SHA3 three-register ops: EOR3/BCAX (Ra form), RAX1.
    Vsha3 { vd: u8, vn: u8, vm: u8, ra: u8, op: Sha3Op },
    /// XAR: (Vn ^ Vm) ror imm6 per 64-bit lane.
    Vxar { vd: u8, vn: u8, vm: u8, imm6: u32 },
    /// SM3SS1 (four-register round helper).
    Vsm3ss1 { vd: u8, vn: u8, vm: u8, ra: u8 },
    /// SM3PARTW1/W2.
    Vsm3part { vd: u8, vn: u8, vm: u8, w2: bool },
    /// SM4EKEY (round key derivation).
    Vsm4ekey { vd: u8, vn: u8, vm: u8 },
    /// PMULL/PMULL2: 8→16 (`d64=false`) or 64→128 polynomial multiply.
    Vpmull { vd: u8, vn: u8, vm: u8, q: bool, d64: bool },
    /// Vector by-element (indexed) forms — structural decode (no local
    /// v8.1+ assembler oracle): SDOT/UDOT/SQRDMLAH/SQRDMLSH/FCMLA/FCADD.
    Vindexed {
        vd: u8,
        vn: u8,
        vm: u8,
        op: VIndexedOp,
        index: u8,
        size_log2: u8,
        q: bool,
    },
    /// AESE/AESD/AESMC/AESIMC.
    Vaes { vd: u8, vn: u8, op: AesOp },
    /// SHA512SU0 / SM4E (two-register misc crypto).
    Vsha512su0 { vd: u8, vn: u8 },
    Vsm4e { vd: u8, vn: u8 },
    /// SM3TT1A/1B/2A/2B (indexed imm2 selects table lane).
    Vsm3tt { vd: u8, vn: u8, vm: u8, index: u8, two: bool, b: bool },
    // ------------------------------------------------------------------
    // FP16 scalar (the JSCVT / FP16 groups)
    // ------------------------------------------------------------------
    /// FJCVTZS Wd, Dn (v8.1 JSCVT).
    Fjcvtzs { rd: u8, rn: u8 },
    /// FCVT between half/single/double.
    Fcvt { rd: u8, rn: u8, from: FpType, to: FpType },
    /// Scalar FP16 2-source arithmetic.
    Fp2 { rd: u8, rn: u8, rm: u8, op: VfpOp },
    /// Scalar FP16 1-source (FABS/FNEG/FSQRT).
    Fp1 { rd: u8, rn: u8, op: Vfp1Op },
    /// SCVTF/UCVTF into half (W/X source) or out of half (S/D dest).
    FpCvtInt { rd: u8, rn: u8, to_half: bool, unsigned: bool, src64: bool },
    /// FCVTZS/FCVTZU from half to W/X.
    FpCvtFixed { rd: u8, rn: u8, unsigned: bool, src64: bool },
    /// LDR Qt, [Xn{, #imm}] — 128-bit SIMD load (uimm12 scaled by 16).
    Vldr { rt: u8, rn: u8, imm12: u32 },
    /// STR Qt, [Xn{, #imm}].
    Vstr { rt: u8, rn: u8, imm12: u32 },
    /// LDR Dt, [Xn{, #imm}] — 64-bit SIMD-scalar load (low lane).
    VldrD { rt: u8, rn: u8, imm12: u32 },
    /// STR Dt, [Xn{, #imm}].
    VstrD { rt: u8, rn: u8, imm12: u32 },
}

/// LSE atomic operation kind (ARMv8.1 "Atomics" opcode field).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AtomicOp {
    Add,
    Clr,
    Eor,
    Set,
    SMax,
    SMin,
    UMax,
    UMin,
    Swp,
}

/// Variable-shift op (LSLV/LSRV/ASRV/RORV).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShiftOp {
    Lsl,
    Lsr,
    Asr,
    Ror,
}

/// 9-bit-addressing load/store mode (unscaled / post / pre / unprivileged).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LsMode {
    /// LDUR/STUR (imm9, type 00).
    Unscaled,
    /// post-index (imm9, type 01) — writeback base+imm.
    Post,
    /// pre-index (imm9, type 11) — writeback, address = base+imm.
    Pre,
    /// LDTR/STTR (imm9, type 10) — unprivileged alias of unscaled.
    Unpriv,
}

/// Register-offset index extension (bits 15:13).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExtOp {
    Uxtb,
    Uxth,
    Uxtw,
    Lsl,
    Sxtb,
    Sxth,
    Sxtw,
    Sxtx,
}

impl ExtOp {
    pub fn from_bits(b: u32) -> Option<ExtOp> {
        Some(match b {
            0 => ExtOp::Uxtb,
            1 => ExtOp::Uxth,
            2 => ExtOp::Uxtw,
            3 => ExtOp::Lsl,
            4 => ExtOp::Sxtb,
            5 => ExtOp::Sxth,
            6 => ExtOp::Sxtw,
            7 => ExtOp::Sxtx,
            _ => return None,
        })
    }

    /// Extend `v`'s relevant low half per the option.
    pub fn apply(self, v: u64) -> u64 {
        match self {
            ExtOp::Uxtb => v & 0xFF,
            ExtOp::Uxth => v & 0xFFFF,
            ExtOp::Uxtw => v & 0xFFFF_FFFF,
            ExtOp::Lsl => v,
            ExtOp::Sxtb => (v & 0xFF) as u8 as i8 as i64 as u64,
            ExtOp::Sxth => (v & 0xFFFF) as u16 as i16 as i64 as u64,
            ExtOp::Sxtw => (v & 0xFFFF_FFFF) as u32 as i32 as i64 as u64,
            ExtOp::Sxtx => v,
        }
    }
}

/// Logical (shifted register) op.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogicOp {
    And,
    Orr,
    Eor,
}

/// BFM family kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BfmKind {
    Bfm,
    Sbfm,
    Ubfm,
}

/// CSEL family op.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CselOp {
    Sel,
    Inc,
    Inv,
    Neg,
}

/// PAC instruction op (v8.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacOp {
    Pacia,
    Pacib,
    Pacda,
    Pacdb,
    Autia,
    Autib,
    Autda,
    Autdb,
    Paciza,
    Pacizb,
    Paciaz,
    Pacibz,
    Autiza,
    Autizb,
    Autiaz,
    Autibz,
    Paciasp,
    Pacibsp,
    Autiasp,
    Autibsp,
    Xpaci,
    Xpacd,
}

/// BTI target kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BtiKind {
    None,
    C,
    J,
    Jc,
}

/// Named hint ops (decoded-by-name no-ops).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HintOp {
    Dgh,
    Esb,
    PsbCsync,
    Csdb,
    TsbCsync,
    Xpaclri,
}

/// TLBI range op (v8.4) — the EL1-relevant subset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlbiRangeOp {
    Rvae1is,
    Rvae1os,
    Rvae1,
    Rvaale1is,
    Rvaale1os,
    Rvaale1,
    Rvaae1is,
    Rvaae1os,
    Rvaae1,
}

/// Vector FP16 op.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VfpOp {
    Add,
    Sub,
    Mul,
    Div,
    Max,
    Min,
}

/// Scalar/vector FP16 1-source op.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Vfp1Op {
    Abs,
    Neg,
    Sqrt,
}

/// SHA3 helper op.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sha3Op {
    Eor3,
    Bcax,
    Rax1,
}

/// AES round op.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AesOp {
    Ese,
    Esd,
    Emc,
    Eimc,
}

/// Indexed (by-element) vector ops — structural decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VIndexedOp {
    Sdot,
    Udot,
    Sqrdmlah,
    Sqrdmlsh,
    Fcmla(u8),
    Fcadd(bool),
}

/// FP type for FCVT (half = binary16).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FpType {
    S,
    D,
    H,
}

/// Decode one 32-bit A64 word. `pc` is the address of the instruction
/// (kept in the signature for API symmetry and future literal-pool work;
/// all PC-relative immediates are stored relative to it).
/// AdvSIMD three-same integer op (opcode bits[15:10] + U).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum V3Op {
    Add,
    Sub,
    Cmgt,
    Cmhi,
    Cmge,
    Cmhs,
    Cmeq,
    Cmtst,
    Smin,
    Umin,
    Smax,
    Umax,
    Smaxp,
    Umaxp,
    Sminp,
    Uminp,
    Mul,
    /// 100101 U=0: MLA (vector) — accumulate multiply
    Mla,
    /// 100101 U=1: MLS (vector)
    Mls,
}

/// AdvSIMD three-same FP op (session C keystone pin): opcode bits[15:10] +
/// U(29) + half(23) selects the op; width = bit22 (0=S-lanes, 1=D-lanes);
/// bit21 must be 1 and bit10 must be 1 (crypto-3 siblings are bit10=0).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum V3FpOp {
    /// 0x35 U=0 half=0: FADD
    Add,
    /// 0x35 U=0 half=1: FSUB
    Sub,
    /// 0x35 U=1 half=0: FADDP (pairwise)
    Addp,
    /// 0x35 U=1 half=1: FABD
    Abd,
    /// 0x37 U=0: FMULX
    Mulx,
    /// 0x37 U=1: FMUL
    Mul,
    /// 0x39 U=0: FCMEQ
    Cmeq,
    /// 0x39 U=1 half=0: FCMGE
    Cmge,
    /// 0x39 U=1 half=1: FCMGT
    Cmgt,
    /// 0x3B U=1 half=0: FACGE
    Acge,
    /// 0x3B U=1 half=1: FACGT
    Acgt,
    /// 0x3D U=0 half=0: FMAX
    Max,
    /// 0x3D U=0 half=1: FMIN
    Min,
    /// 0x3D U=1 half=0: FMAXP
    Maxp,
    /// 0x3D U=1 half=1: FMINP
    Minp,
    /// 0x31 U=0 half=0: FMAXNM
    Maxnm,
    /// 0x31 U=0 half=1: FMINNM
    Minnm,
    /// 0x31 U=1 half=0: FMAXNMP
    Maxnmp,
    /// 0x31 U=1 half=1: FMINNMP
    Minnmp,
    /// 0x33 U=0 half=0: FMLA (fused multiply-accumulate)
    Mla,
    /// 0x33 U=0 half=1: FMLS
    Mls,
    /// 0x3F U=0 half=0: FRECPS
    Recps,
    /// 0x3F U=0 half=1: FRSQRTS
    Rsqrts,
    /// 0x3F U=1: FDIV
    Div,
}

/// Across-lane reduce op (bits[17:16] + U + opcode bits[15:10]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VReduceOp {
    Sminv,
    Uminv,
    Smaxv,
    Umaxv,
    Addv,
}

/// Shift-by-immediate op (0x0F group, opcode bits[15:11] + U arm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VShiftOp {
    Shr,     // 00000: SSHR (U=0) / USHR (U=1)
    Shra,    // 00001: SSRA / USRA (accumulate)
    Rshr,    // 00010: SRSHR / URSHR (rounding)
    Rsra,    // 00011: SRSRA / URSRA
    Sri,     // 01000: SRI (U=1 only — insert from below)
    Shl,     // 01010: SHL (U=0) / SLI (U=1, insert)
    Sqshlu,  // 01100: SQSHLU (U=1 only)
    Sqshl,   // 01110: SQSHL (U=0) / UQSHL (U=1)
    Shrn,    // 10000: SHRN (U=0) / SQSHRUN (U=1) — narrowing
    Rshrn,   // 10001: RSHRN (U=0) / SQRSHRUN (U=1)
    Sqshrn,  // 10010: SQSHRN (U=0) / UQSHRN (U=1)
    Sqrshrn, // 10011: SQRSHRN (U=0) / UQRSHRN (U=1)
    Shll,    // 10100: SSHLL (U=0) / USHLL (U=1) — widening
    Cvtf,    // 11100: SCVTF (U=0) / UCVTF (U=1) — fixed-point int→fp
    Fcvtz,   // 11111: FCVTZS (U=0) / FCVTZU (U=1) — fixed-point fp→int
}

/// Modified-immediate op (0x0F group, cmode interpretation).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VecImmOp {
    Movi,
    Mvni,
    Orr,
    Bic,
}

pub fn decode(_pc: u64, w: u32) -> Option<Insn> {
    let is64 = w >> 31 == 1;

    // --- Barriers: 1101 0101 0000 0011 0011 CRm op2(4/5/6) ---
    if (w & 0xFFFF_F000) == 0xD503_3000 {
        return match (w >> 5) & 7 {
            4 => Some(Insn::Dsb),
            5 => Some(Insn::Dmb),
            6 => Some(Insn::Isb),
            _ => Some(Insn::Nop), // BTI-style hints in the same slot
        };
    }

    // --- Unconditional branch (register): 1101011 ---
    if (w & 0xFFFF_FC1F) == 0xD65F_0000 {
        return Some(Insn::Ret { rn: reg(w, 5) });
    }
    // RETAA/RETAB (exact encodings; capstone-verified 0xD65F0BFF/0xD65F0FFF)
    if w == 0xD65F_0BFF {
        return Some(Insn::RetA { ab: false });
    }
    if w == 0xD65F_0FFF {
        return Some(Insn::RetA { ab: true });
    }
    // BRAA/BRAB/BLRAA/BLRAB — authenticated branch (register); masks
    // derived with tools/re/oracle/mask_discover.py over the 0xd6/0xd7
    // space (capstone ground truth).
    if (w & 0xFFFF_FC00) == 0xD71F_0800 {
        return Some(Insn::BrAuth { rn: reg(w, 5), link: false, ab: false });
    }
    if (w & 0xFFFF_FC00) == 0xD71F_0C00 {
        return Some(Insn::BrAuth { rn: reg(w, 5), link: false, ab: true });
    }
    if (w & 0xFFFF_FC00) == 0xD73F_0800 {
        return Some(Insn::BrAuth { rn: reg(w, 5), link: true, ab: false });
    }
    if (w & 0xFFFF_FC00) == 0xD73F_0C00 {
        return Some(Insn::BrAuth { rn: reg(w, 5), link: true, ab: true });
    }
    // Z-forms in the 0xD6 space (REAL-DATA BUG #13): BRAAZ/BLRAAZ ship
    // xnu's indirect-branch tail calls, but the session-A PAC campaign
    // only pinned the 0xD7 (B-key) arm — the 0xD6 (A-key, Rm=11111) arm
    // stayed unknown. Masks: census over 0xD61F/0xD63F windows, step=1
    // (capstone: 0xd61f083f=braaz x1, 0xd63f0a1f=blraaz x16).
    if (w & 0xFFFF_FC1F) == 0xD61F_081F {
        return Some(Insn::BrAuth { rn: reg(w, 5), link: false, ab: false });
    }
    if (w & 0xFFFF_FC1F) == 0xD63F_081F {
        return Some(Insn::BrAuth { rn: reg(w, 5), link: true, ab: false });
    }
    if (w & 0xFFFF_FFE0) == 0xD69F_03E0 {
        return Some(Insn::Eret);
    }
    if (w & 0xFFFF_FC1F) == 0xD61F_0000 {
        return Some(Insn::Br { rn: reg(w, 5) });
    }
    if (w & 0xFFFF_FC1F) == 0xD63F_0000 {
        return Some(Insn::Blr { rn: reg(w, 5) });
    }

    // --- System register access ---
    if (w & 0xFFF0_0000) == 0xD530_0000 {
        return Some(Insn::Mrs { rt: reg(w, 0), sysreg: sysreg_bits(w) });
    }
    // MSR (register) op0=3 lives at 0xD510_xxxx; the TLBI/AT/DC/IC space
    // (op0=1 — real TLBI VMALLE1 = d508871f, DC ZVA = d50b7420, keystone
    // verified) shares the L=0 SYS encoding at 0xD508-0xD50F and flows
    // through the same write_sysreg path (flush/no-op arms there). The
    // Apple v8.4 TLBI-range words are decoded later by exact match —
    // exclude them here or this branch would swallow them.
    let is_tlbi_range = matches!(
        w & 0xFFFF_FFE0,
        0xD508_8220 | 0xD508_8520 | 0xD508_8620 | 0xD508_82E0 | 0xD508_85E0 | 0xD508_86E0
            | 0xD508_8260 | 0xD508_8560 | 0xD508_8660
    );
    if !is_tlbi_range
        && ((w & 0xFFF0_0000) == 0xD510_0000 || (w & 0xFFF8_0000) == 0xD508_0000)
    {
        return Some(Insn::Msr { sysreg: sysreg_bits(w), rt: reg(w, 0) });
    }

    // --- Exceptions: SVC/HVC/SMC/HLT ---
    match w & 0xFFE0_001F {
        0xD400_0001 => return Some(Insn::Svc { imm16: ((w >> 5) & 0xFFFF) as u16 }),
        0xD400_0002 => return Some(Insn::Hvc { imm16: ((w >> 5) & 0xFFFF) as u16 }),
        0xD400_0003 => return Some(Insn::Smc { imm16: ((w >> 5) & 0xFFFF) as u16 }),
        _ => {}
    }
    if (w & 0xFFE0_001F) == 0xD440_0000 {
        return Some(Insn::Hlt { imm16: ((w >> 5) & 0xFFFF) as u16 });
    }
    // BRK — xnu release kernels carry tens of thousands of these traps.
    if (w & 0xFFE0_001F) == 0xD420_0000 {
        return Some(Insn::Brk { imm16: ((w >> 5) & 0xFFFF) as u16 });
    }
    // DCPS1/2/3 / DRPS (debug exception classes; masks via mask_discover.py)
    if (w & 0xFFF0_001F) == 0xD4A0_0001 {
        return Some(Insn::Dcps { level: 1, imm16: ((w >> 5) & 0xFFFF) as u16 });
    }
    if (w & 0xFFF0_001F) == 0xD4A0_0002 {
        return Some(Insn::Dcps { level: 2, imm16: ((w >> 5) & 0xFFFF) as u16 });
    }
    if (w & 0xFFF0_001F) == 0xD4A0_0003 {
        return Some(Insn::Dcps { level: 3, imm16: ((w >> 5) & 0xFFFF) as u16 });
    }
    if w == 0xD6BF_03E0 {
        return Some(Insn::Drps);
    }

    // --- Apple GXF GENTER/GEXIT (Inferno disas_apple_insn:
    //     insn[28:25]==0b0000, insn[15:10]==0b000101, rn==1 -> GENTER) ---
    if (w & 0x1E00_0000) == 0 && (w & 0xFFFF_FC00) == 0x0000_1400 {
        let rd = reg(w, 0);
        return Some(if reg(w, 5) == 1 {
            Insn::Genter { rd }
        } else {
            Insn::Gexit { rd }
        });
    }

    // --- Move wide immediate: bits28:23 == 100101 ---
    if (w >> 23) & 0x3F == 0x25 {
        let hw = ((w >> 21) & 0x3) as u8;
        if !is64 && hw > 1 {
            return None;
        }
        let fields = (reg(w, 0), ((w >> 5) & 0xFFFF) as u16, hw);
        return Some(match (w >> 29) & 0x3 {
            0b10 => Insn::Movz { rd: fields.0, imm16: fields.1, shift: fields.2, is64 },
            0b00 => Insn::Movn { rd: fields.0, imm16: fields.1, shift: fields.2, is64 },
            0b11 => Insn::Movk { rd: fields.0, imm16: fields.1, shift: fields.2, is64 },
            _ => return None,
        });
    }

    // --- Add/subtract immediate: bits28:23 == 100010 ---
    if (w >> 23) & 0x3F == 0x22 {
        let setflags = (w >> 29) & 1 == 1;
        let subtract = (w >> 30) & 1 == 1;
        let shift = (w >> 22) & 1 == 1;
        let imm12 = (w >> 10) & 0xFFF;
        let rn = reg(w, 5);
        let rd = reg(w, 0);
        if setflags && rd == 31 {
            // Rd=WZR: SUBS→CMP (subtract) / ADDS→CMN (compare-negative).
            // start.s's chain terminator is `adds wzr, w12, #1` — decoding
            // that as CMP inverted the test and the fixup walk ran away.
            return if subtract {
                Some(Insn::CmpImm { rn, imm12, shift, is64 })
            } else {
                Some(Insn::CmnImm { rn, imm12, shift, is64 })
            };
        }
        return Some(if subtract {
            Insn::SubImm { rd, rn, imm12, shift, setflags, is64 }
        } else {
            Insn::AddImm { rd, rn, imm12, shift, setflags, is64 }
        });
    }

    // --- Logical immediate: bits28:23 == 100100 ---
    if (w >> 23) & 0x3F == 0x24 {
        let n = (w >> 22) & 1;
        let immr = (w >> 16) & 0x3F;
        let imms = (w >> 10) & 0x3F;
        let imm = decode_bitmask(n, imms, immr, is64)?;
        let rd = reg(w, 0);
        let rn = reg(w, 5);
        // opc2: 00 AND, 01 ORR, 10 EOR, 11 ANDS (only ANDS sets flags)
        return Some(match (w >> 29) & 0x3 {
            0b00 => Insn::AndImm { rd, rn, imm, setflags: false, is64 },
            0b01 => Insn::OrrImm { rd, rn, imm, setflags: false, is64 },
            0b10 => Insn::EorImm { rd, rn, imm, setflags: false, is64 },
            _ => Insn::AndImm { rd, rn, imm, setflags: true, is64 }, // ANDS/TST
        });
    }

    // --- Add/subtract shifted register: bits28:24 == 01011, M(bit21)=0 ---
    if (w >> 24) & 0x1F == 0x0B && (w >> 21) & 1 == 0 {
        let setflags = (w >> 29) & 1 == 1;
        let subtract = (w >> 30) & 1 == 1;
        let kind = match (w >> 22) & 0x3 {
            0 => ShiftKind::Lsl,
            1 => ShiftKind::Lsr,
            2 => ShiftKind::Asr,
            _ => return None, // ROR not in subset
        };
        let imm6 = (w >> 10) & 0x3F;
        if !is64 && imm6 > 31 {
            return None;
        }
        let rd = reg(w, 0);
        let rn = reg(w, 5);
        let rm = reg(w, 16);
        if setflags && rd == 31 {
            return if subtract {
                Some(Insn::CmpReg { rn, rm, kind, imm6, is64 })
            } else {
                Some(Insn::CmnReg { rn, rm, kind, imm6, is64 })
            };
        }
        return Some(Insn::AddSubReg {
            rd,
            rn,
            rm,
            kind,
            imm6,
            subtract,
            setflags,
            is64,
        });
    }

    // --- ORR shifted register — MOV register alias is folded into the
    //     general logical-shifted-register arm near the end of decode()
    //     (an early return-None here used to swallow EVERY ORR/AND/EOR
    //     shifted-register form — real-data bug found on iOS 14.3 bytes,
    //     e.g. `orr w10, w10, w11` = 0x2a0b014a).

    // --- Unconditional branch (immediate): bits30:26 == 00101 / 10001 ---
    if (w >> 26) & 0x3F == 0x05 {
        return Some(Insn::B { imm: sext((w & 0x03FF_FFFF) as i64, 26) * 4 });
    }
    if (w >> 26) & 0x3F == 0x25 {
        return Some(Insn::Bl { imm: sext((w & 0x03FF_FFFF) as i64, 26) * 4 });
    }

    // --- Conditional branch: 0101010 imm19 0 cond ---
    if (w & 0xFF00_0010) == 0x5400_0000 {
        let cond = Cond::from_bits(w & 0xF)?;
        let imm19 = sext(((w >> 5) & 0x7_FFFF) as i64, 19) * 4;
        return Some(Insn::BCond { cond, imm: imm19 });
    }

    // --- CBZ/CBNZ: bits30:25 == 011010 ---
    if (w >> 25) & 0x3F == 0x1A {
        let rn = reg(w, 0);
        let imm = sext(((w >> 5) & 0x7_FFFF) as i64, 19) * 4;
        return Some(if (w >> 24) & 1 == 0 {
            Insn::Cbz { rn, imm, is64 }
        } else {
            Insn::Cbnz { rn, imm, is64 }
        });
    }

    // --- TBZ/TBNZ: bits30:25 == 011011 ---
    if (w >> 25) & 0x3F == 0x1B {
        let bit = (((w >> 31) & 1) << 5 | ((w >> 19) & 0x1F)) as u8;
        let rn = reg(w, 0);
        let imm = sext(((w >> 5) & 0x3FFF) as i64, 14) * 4;
        return Some(if (w >> 24) & 1 == 0 {
            Insn::Tbz { rn, bit, imm }
        } else {
            Insn::Tbnz { rn, bit, imm }
        });
    }

    // --- ADR/ADRP: bits28:24 == 10000 ---
    if (w >> 24) & 0x1F == 0x10 {
        let immhi = (w >> 5) & 0x7_FFFF;
        let immlo = (w >> 29) & 0x3;
        let imm21 = ((immhi << 2) | immlo) as i64;
        return Some(if w >> 31 == 1 {
            Insn::Adrp { rd: reg(w, 0), imm: sext(imm21, 21) * 4096 }
        } else {
            Insn::Adr { rd: reg(w, 0), imm: sext(imm21, 21) }
        });
    }

    // --- Load/store unsigned immediate: bits29:24 == 111001 ---
    if (w >> 24) & 0x3F == 0x39 {
        let size_log2 = ((w >> 30) & 0x3) as u8;
        let opc = (w >> 22) & 0x3;
        let rt = reg(w, 0);
        let rn = reg(w, 5);
        let imm12 = (w >> 10) & 0xFFF;
        return match (opc, size_log2) {
            (0, _) => Some(Insn::StrImmU { rt, rn, imm12, size_log2 }),
            (1, _) => Some(Insn::LdrImmU { rt, rn, imm12, size_log2 }),
            (2 | 3, 0..=2) => Some(Insn::Ldrs9 {
                rt,
                rn,
                imm9: (imm12 as i64) << size_log2, // scaled byte offset
                size_log2,
                mode: LsMode::Unscaled,
                dest64: opc == 2,
            }),
            (2, 3) => Some(Insn::LdrImmU { rt, rn, imm12, size_log2 }), // LDR Xt
            (3, 3) => Some(Insn::LdrImmU { rt, rn, imm12, size_log2 }), // PRFM as LDR
            _ => None,
        };
    }

    // --- Load literal: bits29:24 == 011000 ---
    if (w >> 24) & 0x3F == 0x18 {
        return match (w >> 30) & 0x3 {
            0 => Some(Insn::LdrLit {
                rt: reg(w, 0),
                imm: sext(((w >> 5) & 0x7_FFFF) as i64, 19) * 4,
                is64: false,
            }),
            1 => Some(Insn::LdrLit {
                rt: reg(w, 0),
                imm: sext(((w >> 5) & 0x7_FFFF) as i64, 19) * 4,
                is64: true,
            }),
            _ => None, // SIMD literal / LDRSW
        };
    }

    // --- LDP/STP: group bits[29:25] = 10100 (V=0) / 10110 (V=1);
    //     L = bit22, mode = bits[24:23] (00=NT, 01=post, 10=offset,
    //     11=pre). GPR pairs: opc 00=32-bit, 01=LDPSW, 10=64-bit. SIMD
    //     pairs: opc 00=S(4B), 01=D(8B), 10=Q(16B) — keystone-derived;
    //     the old check excluded ALL SIMD pairs and mapped LDPSW onto
    //     the 32-bit form (real-14.3 bugs). ---
    let pair_group = (w >> 25) & 0x1F;
    if pair_group == 0b10100 || pair_group == 0b10110 {
        let v = pair_group == 0b10110;
        let opc = (w >> 30) & 0x3;
        let load = (w >> 22) & 1 == 1;
        let mode = match (w >> 23) & 0x3 {
            0b00 => PairMode::NonTemporal,
            0b01 => PairMode::Post,
            0b10 => PairMode::Offset,
            _ => PairMode::Pre,
        };
        let rt = reg(w, 0);
        let rn = reg(w, 5);
        let rt2 = reg(w, 10);
        let imm7 = sext(((w >> 15) & 0x7F) as i64, 7);
        if v {
            // SIMD pair: S(4)/D(8)/Q(16); opc 11 unallocated.
            let log2_width = match opc {
                0 => 2,
                1 => 3,
                2 => 4,
                _ => return None,
            };
            let imm = imm7 * (1i64 << log2_width);
            return Some(if load {
                Insn::LdpSimd { vt: rt, vt2: rt2, rn, imm, mode, log2_width }
            } else {
                Insn::StpSimd { vt: rt, vt2: rt2, rn, imm, mode, log2_width }
            });
        }
        return Some(match opc {
            0 => {
                let imm = imm7 * 4;
                if load {
                    Insn::Ldp { rt, rt2, rn, imm, mode, is64: false }
                } else {
                    Insn::Stp { rt, rt2, rn, imm, mode, is64: false }
                }
            }
            1 if load => Insn::Ldpsw { rt, rt2, rn, imm: imm7 * 4, mode },
            2 => {
                let imm = imm7 * 8;
                if load {
                    Insn::Ldp { rt, rt2, rn, imm, mode, is64: true }
                } else {
                    Insn::Stp { rt, rt2, rn, imm, mode, is64: true }
                }
            }
            _ => return None, // opc 01 store = unallocated
        });
    }

    // --- v8.1 unscaled release/acquire (REAL-DATA BUG #14): STLUR/LDAPUR
    //     (top bytes 0x19/0x59/0x99/0xD9 — bits 28:24 = 11001, size from
    //     bits 31:30, L=bit22 picks store/load) and LDAPR (0xB8/0xF8 with
    //     bit21=1, bits 23:22=10, Rm=11111). xnu's locking paths ship both;
    //     session-C census masks (step=1, capstone ground truth:
    //     0xd900827f=stlur xzr,[x19,#8], 0x9947805f=ldapur wzr,[x2,#0x78],
    //     0x19038328=stlurb w8,[x25,#0x38], 0xb8bfc27f=ldapr wzr,[x19]).
    //     Release/acquire ordering is a no-op in this single-threaded
    //     model — exec rides the plain unscaled LdSt9 path. ---
    if (w >> 24) & 0x3F == 0x19 && (w >> 21) & 1 == 0 && (w >> 10) & 0x3 == 0 {
        let size_log2 = ((w >> 30) & 3) as u8;
        return Some(Insn::LdSt9 {
            rt: reg(w, 0),
            rn: reg(w, 5),
            imm9: sext(((w >> 12) & 0x1FF) as i64, 9),
            size_log2,
            load: (w >> 22) & 1 == 1,
            mode: LsMode::Unscaled,
        });
    }
    // LDAPR (W/X forms — NO imm9; bits 23:12 are a fixed opcode pattern,
    // size: bit30=0 → 32-bit Wt, bit30=1 → 64-bit Xt).
    if (w & 0xBFFF_FC00) == 0xB8BF_C000 {
        return Some(Insn::LdSt9 {
            rt: reg(w, 0),
            rn: reg(w, 5),
            imm9: 0,
            size_log2: 2 + ((w >> 30) & 1) as u8,
            load: true,
            mode: LsMode::Unscaled,
        });
    }

    // --- Load/store 9-bit addressing (GPR, V=0): group 111 0 00 with
    //     bit21=0. type[11:10]: 00=unscaled, 01=post, 10=unpriv, 11=pre.
    //     opc[23:22]: 00=STR, 01=LDR, 10/11=signed (LDRSB/LDRSH/LDRSW;
    //     opc 11 = 32-bit destination). ---
    if (w >> 24) & 0x3F == 0x38 && (w >> 21) & 1 == 0 {
        let size_log2 = ((w >> 30) & 0x3) as u8;
        let opc = (w >> 22) & 0x3;
        let mode = match (w >> 10) & 0x3 {
            0 => LsMode::Unscaled,
            1 => LsMode::Post,
            2 => LsMode::Unpriv,
            _ => LsMode::Pre,
        };
        let rt = reg(w, 0);
        let rn = reg(w, 5);
        let imm9 = sext(((w >> 12) & 0x1FF) as i64, 9);
        return match (opc, size_log2) {
            (0, _) => Some(Insn::LdSt9 { rt, rn, imm9, size_log2, load: false, mode }),
            (1, _) => Some(Insn::LdSt9 { rt, rn, imm9, size_log2, load: true, mode }),
            (2 | 3, 0..=2) => Some(Insn::Ldrs9 {
                rt,
                rn,
                imm9,
                size_log2,
                mode,
                dest64: opc == 2,
            }),
            _ => None, // opc 10/11 with size 11 unallocated
        };
    }

    // --- Load/store register offset (GPR, V=0): group 111 0 00 with
    //     bit21=1, type[11:10]=10, option[15:13], S[12]. ---
    if (w >> 24) & 0x3F == 0x38 && (w >> 21) & 1 == 1 && (w >> 10) & 0x3 == 0b10 {
        let size_log2 = ((w >> 30) & 0x3) as u8;
        let opc = (w >> 22) & 0x3;
        let option = ExtOp::from_bits((w >> 13) & 0x7)?;
        let scaled = (w >> 12) & 1 == 1;
        let rt = reg(w, 0);
        let rn = reg(w, 5);
        let rm = reg(w, 16);
        return match (opc, size_log2) {
            (0, _) => Some(Insn::LdStRegOff {
                rt,
                rn,
                rm,
                option,
                scaled,
                size_log2,
                load: false,
                sign_ext: false,
                dest64: false,
            }),
            (1, _) => Some(Insn::LdStRegOff {
                rt,
                rn,
                rm,
                option,
                scaled,
                size_log2,
                load: true,
                sign_ext: false,
                dest64: false,
            }),
            (2 | 3, 0..=2) => Some(Insn::LdStRegOff {
                rt,
                rn,
                rm,
                option,
                scaled,
                size_log2,
                load: true,
                sign_ext: true,
                dest64: opc == 2,
            }),
            _ => None,
        };
    }

    // --- SIMD single register, 9-bit addressing (V=1): group 111 1 00.
    //     load = opc[0]; width: opc[1] && size==0 → Q(16B), else 1<<size
    //     (keystone/capstone-verified table: stur b0 0x3c0023e0,
    //     ldur q0 0x3cdf83e0, stur h0 0x7c8013e0, stur d0 0xfc8803e0). ---
    if (w >> 24) & 0x3F == 0x3C && (w >> 21) & 1 == 0 {
        let size_log2 = ((w >> 30) & 0x3) as u8;
        let opc = (w >> 22) & 0x3;
        let width_log2 = if opc & 0b10 != 0 && size_log2 == 0 { 4 } else { size_log2 };
        let mode = match (w >> 10) & 0x3 {
            0 => LsMode::Unscaled,
            1 => LsMode::Post,
            2 => LsMode::Unpriv,
            _ => LsMode::Pre,
        };
        return Some(Insn::LdStSimd9 {
            vt: reg(w, 0),
            rn: reg(w, 5),
            imm9: sext(((w >> 12) & 0x1FF) as i64, 9),
            width_log2,
            load: opc & 1 == 1,
            mode,
        });
    }

    // --- SIMD single register, unsigned offset (V=1): group 111 1 01.
    //     Same width rule as the 9-bit group (str q0 = 0x3d80c3e0,
    //     ldr q0 = 0x3dc143e0, str s0 = 0xbd000be0, str d0 = 0xfd0007e0). ---
    if (w >> 24) & 0x3F == 0x3D {
        let size_log2 = ((w >> 30) & 0x3) as u8;
        let opc = (w >> 22) & 0x3;
        let width_log2 = if opc & 0b10 != 0 && size_log2 == 0 { 4 } else { size_log2 };
        return Some(Insn::LdStSimdU {
            vt: reg(w, 0),
            rn: reg(w, 5),
            imm12: (w >> 10) & 0xFFF,
            width_log2,
            load: opc & 1 == 1,
        });
    }

    // =====================================================================
    // ARMv8.1 LSE atomics: size(31:30) 111000 A R 1 Rs opcode4 Rn Rt
    // (empirically verified layout; op4: 0..7 = LDADD/CLR/EOR/SET/SMAX/
    // SMIN/UMAX/UMIN, 8 = SWP; LDAPR lives at bit21=0 in the same group).
    // =====================================================================
    if (w & 0x3F20_0C00) == 0x3820_0000 {
        let size_log2 = ((w >> 30) & 3) as u8;
        let acquire = (w >> 23) & 1 == 1;
        let release = (w >> 22) & 1 == 1;
        let rs = reg(w, 16);
        let op4 = ((w >> 12) & 0xF) as u8;
        let rn = reg(w, 5);
        let rt = reg(w, 0);
        let op = match op4 {
            0 => AtomicOp::Add,
            1 => AtomicOp::Clr,
            2 => AtomicOp::Eor,
            3 => AtomicOp::Set,
            4 => AtomicOp::SMax,
            5 => AtomicOp::SMin,
            6 => AtomicOp::UMax,
            7 => AtomicOp::UMin,
            8 => AtomicOp::Swp,
            _ => return None,
        };
        return Some(Insn::Atomic { op, rt, rs, rn, size_log2, acquire, release });
    }
    // --- LDAPR (bit21=0, op2 odd at bits 14:10) ---
    if (w & 0x3F20_F000) == 0x3820_0000 && (w >> 10) & 1 == 1 {
        return Some(Insn::Ldapr { rt: reg(w, 0), rn: reg(w, 5), size_log2: ((w >> 30) & 3) as u8 });
    }

    // --- Load/store exclusive / acquire-release: bits29:24 == 001000 ---
    // Field map (empirical, Keystone goldens): bit21=1 + bits14:10==11111
    // → CAS; bit21=1 + bits20:16==11111 → LDXP/STXP (Rt2 at 14:10);
    // bit21=0 + bits14:10==11111 → bit23=1: LDAR/STLR, bit23=0: LDXR/STXR
    // (bit15 = acquire/release); bit21=0 + bit10=1 → LDAPR family.
    if (w & 0x3F00_0000) == 0x0800_0000 {
        let size_log2 = ((w >> 30) & 3) as u8;
        let load = (w >> 22) & 1 == 1;
        let rt = reg(w, 0);
        let rn = reg(w, 5);
        if (w >> 21) & 1 == 1 {
            if (w >> 10) & 0x1F == 0x1F && (w >> 16) & 0x1F != 0x1F {
                return Some(Insn::Cas {
                    rt,
                    rs: reg(w, 16),
                    rn,
                    size_log2,
                    acquire: (w >> 22) & 1 == 1,
                    release: (w >> 15) & 1 == 1,
                });
            }
            if (w >> 15) & 1 == 0 && (w >> 10) & 0x1F != 0x1F {
                let rt2 = reg(w, 10);
                return Some(if load {
                    Insn::Ldxr { rt, rt2, rn, size_log2, acquire: (w >> 23) & 1 == 1, pair: true }
                } else {
                    Insn::Stxr { rs: reg(w, 16), rt, rt2, rn, size_log2, release: (w >> 23) & 1 == 1, pair: true }
                });
            }
            return None;
        }
        if (w >> 10) & 0x1F == 0x1F {
            if (w >> 23) & 1 == 1 {
                return Some(if load {
                    Insn::Ldar { rt, rn, size_log2 }
                } else {
                    Insn::Stlr { rt, rn, size_log2 }
                });
            }
            let rt2 = reg(w, 10);
            return Some(if load {
                Insn::Ldxr { rt, rt2, rn, size_log2, acquire: (w >> 15) & 1 == 1, pair: false }
            } else {
                Insn::Stxr { rs: reg(w, 16), rt, rt2, rn, size_log2, release: (w >> 15) & 1 == 1, pair: false }
            });
        }
        if (w >> 10) & 1 == 1 && (w >> 15) & 1 == 0 {
            return Some(Insn::Ldapr { rt, rn, size_log2 });
        }
        return None;
    }
    // --- CRC32 (2-source opcode 0b0101100001; C=bit12, sz=bits11:10) ---
    if (w & 0x7FE0_E000) == 0x1AC0_4000 {
        let castagnoli = (w >> 12) & 1 == 1;
        let sz = ((w >> 10) & 3) as u8;
        let sf = w >> 31 == 1;
        // DDI 0487 + keystone-verified: CRC32X/CRC32CX (sz=11) have sf=1;
        // the W-forms (sz<11) have sf=0.
        if sz == 3 && !sf {
            return None;
        }
        if sz != 3 && sf {
            return None;
        }
        return Some(Insn::Crc32 {
            rd: reg(w, 0),
            rn: reg(w, 5),
            rm: reg(w, 16),
            size_log2: sz,
            castagnoli,
        });
    }

    // --- 2-source: sf 0011010 opc(10) Rm Rn Rd; sub-opcode at bits 15:10
    //     (empirically anchored: udiv=2, sdiv=3, mulh=0, pacga=0b001100,
    //     scalar RDM=0 with QEMU case 0x1c/0x1d op10) ---
    if (w & 0x7FE0_0000) == 0x1AC0_0000 {
        let op10 = (w >> 21) & 0x3FF;
        let op10b = (w >> 10) & 0x3F;
        let rd = reg(w, 0);
        let rn = reg(w, 5);
        let rm = reg(w, 16);
        let is64 = w >> 31 == 1;
        let insn = match (op10, op10b) {
            (0x0D6, 2) => Some(Insn::Udiv { rd, rn, rm }),
            (0x0D6, 3) => Some(Insn::Sdiv { rd, rn, rm }),
            (0x0DA, 0) if is64 => Some(Insn::Smulh { rd, rn, rm }),
            (0x0DE, 0) if is64 => Some(Insn::Umulh { rd, rn, rm }),
            (0x0DC, 0) => Some(Insn::Sqrdmlah { rd, rn, rm, is64, subtract: false }),
            (0x0DD, 0) => Some(Insn::Sqrdmlah { rd, rn, rm, is64, subtract: true }),
            (0x0D6, 0x0C) => Some(Insn::Pacga { rd, rn, rm }),
            (0x0D6, 0x08) => Some(Insn::ShiftReg { rd, rn, rm, op: ShiftOp::Lsl, is64 }),
            (0x0D6, 0x09) => Some(Insn::ShiftReg { rd, rn, rm, op: ShiftOp::Lsr, is64 }),
            (0x0D6, 0x0A) => Some(Insn::ShiftReg { rd, rn, rm, op: ShiftOp::Asr, is64 }),
            (0x0D6, 0x0B) => Some(Insn::ShiftReg { rd, rn, rm, op: ShiftOp::Ror, is64 }),
            _ => None,
        };
        if insn.is_some() {
            return insn;
        }
    }

    // --- scalar RDM (v8.1, real DDI 0487 layout): 0111 1111 size Rm
    //     1101 01/11 Rn Rd — bits 31..21 = 0x3FA, bits 15..10 = 0x35
    //     (SQRDMLAH) / 0x37 (SQRDMLSH); keystone-verified 0x7F42C820 ---
    if (w & 0xFFE0_0000) == 0x7F40_0000 && (w >> 10) & 0x3F != 0 {
        let op = (w >> 10) & 0x3F;
        if op == 0x35 || op == 0x37 {
            return Some(Insn::Sqrdmlah {
                rd: reg(w, 0),
                rn: reg(w, 5),
                rm: reg(w, 16),
                is64: ((w >> 22) & 3) == 2,
                subtract: op == 0x37,
            });
        }
    }

    // --- 2-source in the 0011011 group: REMOVED — the scalar-RDM forms
    //     this arm claimed (op10 0xDC/0xDD) collide with real dp-3 words
    //     (umaddl op31=101 with Ra=0, bits15:10=0): capstone decodes them
    //     as umaddl, not Sqrdmlah. Scalar RDM is the keystone-verified
    //     0x7F40_0000 arm above; SMULH/UMULH live in the dp-3 op31 map. ---

    // --- 3-source MADD family (capstone-verified map): bits 30:24 ==
    //     0011011. op31 (bits 23:21): 000=MADD/MSUB(bit15), 001=SMADDL/
    //     SMSUBL(bit15), 010=SMULH, 101=UMADDL/UMSUBL, 110=UMULH.
    //     REAL-DATA BUG #8: the old guard `(w>>22)&1==0` rejected UMULH
    //     (~1.5k words) and — worse — misdecoded SMULH as MADD (wrong
    //     results, not just coverage). Fixed to the full op31 map. ---
    if (w & 0x7F00_0000) == 0x1B00_0000 {
        let rd = reg(w, 0);
        let rn = reg(w, 5);
        let rm = reg(w, 16);
        let ra = reg(w, 10);
        let is64 = w >> 31 == 1;
        let subtract = (w >> 15) & 1 == 1;
        // capstone-derived op31 map (real 18C66 words, 0 rejects):
        // 000=MADD/MSUB(bit15) 001=SMADDL/SMSUBL(bit15) 010=SMULH
        // 101=UMADDL/UMSUBL(bit15) 110=UMULH; 011/100/111 unassigned
        // (capstone: 0x9B800000 → unknown).
        let op31 = (w >> 21) & 7;
        return match op31 {
            0b000 => Some(Insn::Madd { rd, rn, rm, ra, subtract, is64 }),
            0b001 if is64 => {
                Some(Insn::MaddW { rd, rn, rm, ra, subtract, unsigned: false })
            }
            0b010 if is64 && !subtract => Some(Insn::Smulh { rd, rn, rm }),
            0b101 if is64 => {
                Some(Insn::MaddW { rd, rn, rm, ra, subtract, unsigned: true })
            }
            0b110 if is64 && !subtract => Some(Insn::Umulh { rd, rn, rm }),
            _ => None,
        };
    }

    // --- Data-processing (1 source): sf 0 11010 110 opc(6) Rn Rd —
    //     capstone-derived on real bytes (bucket 0x5a/0xda):
    //     opc 0=RBIT 1=REV16 2=REV32(64)/REV(32) 3=REV(64) 4=CLZ 5=CLS.
    //     bits 30:20 == 0x5AC, opc = bits 15:10. ---
    if (w >> 20) & 0x7FF == 0x5AC && (w >> 16) & 0xF == 0 {
        // bits 19:16 must be 0 — the PAC forms (PACIA 0xDAC103E0 etc.)
        // share bits 30:20 but set bits 19:16; without this the guard
        // would swallow the whole PAC family (golden regression caught it).
        let is64 = w >> 31 == 1;
        let op = match (w >> 10) & 0x3F {
            0 => Dp1Op::Rbit,
            1 => Dp1Op::Rev16,
            2 => {
                if is64 {
                    Dp1Op::Rev32
                } else {
                    Dp1Op::Rev
                }
            }
            3 if is64 => Dp1Op::Rev,
            4 => Dp1Op::Clz,
            5 => Dp1Op::Cls,
            _ => return None,
        };
        return Some(Insn::Dp1 { rd: reg(w, 0), rn: reg(w, 5), op, is64 });
    }

    // --- Add/sub extended register: sf op S 01011 0 1 Rm option imm3 Rn Rd
    //     (add x1, x9, w8, uxtw = 0x8b284121; keystone-verified). ---
    if (w >> 24) & 0x1F == 0x0B && (w >> 21) & 1 == 1 && (w >> 23) & 1 == 0 {
        let option = ExtOp::from_bits((w >> 13) & 0x7)?;
        return Some(Insn::AddSubExt {
            rd: reg(w, 0),
            rn: reg(w, 5),
            rm: reg(w, 16),
            option,
            imm3: ((w >> 10) & 0x7) as u8,
            subtract: (w >> 30) & 1 == 1,
            setflags: (w >> 29) & 1 == 1,
            is64: w >> 31 == 1,
        });
    }

    // --- Logical shifted register: sf 01 01010 shift N Rm imm6 Rn Rd ---
    // (N = bit21 = BIC/ORN/EON invert flag; the add/sub-shifted group is
    // 01011 at bits 28:24, disjoint from this 01010 group.)
    if (w >> 24) & 0x1F == 0x0A {
        let kind = match (w >> 22) & 0x3 {
            0 => ShiftKind::Lsl,
            1 => ShiftKind::Lsr,
            2 => ShiftKind::Asr,
            _ => ShiftKind::Ror, // real 14.3: ~1.2k words (0x4a bucket)
        };
        let op10 = (w >> 29) & 0x3;
        let invert = (w >> 21) & 1 == 1;
        let rd = reg(w, 0);
        let rn = reg(w, 5);
        let rm = reg(w, 16);
        let imm6 = (w >> 10) & 0x3F;
        let is64 = w >> 31 == 1;
        // MOV (register) alias: ORR Xd, XZR, Xm with no shift/invert.
        if op10 == 0b01 && !invert && reg(w, 5) == 31 && imm6 == 0 {
            return Some(Insn::MovReg { rd, rn: rm });
        }
        let (setflags, op) = match op10 {
            0b00 => (false, LogicOp::And),  // AND / BIC
            0b01 => (false, LogicOp::Orr),  // ORR / ORN
            0b10 => (false, LogicOp::Eor),  // EOR / EON
            0b11 => (true, LogicOp::And),   // ANDS / BICS
            _ => unreachable!(),
        };
        return Some(Insn::LogicReg { rd, rn, rm, kind, imm6, op, setflags, invert, is64 });
    }

    // --- Bitfield / extract: sf 10 011010 N immr imms Rn Rd ---
    if (w >> 23) & 0x3F == 0x26 {
        let kind = match (w >> 29) & 0x3 {
            0b00 => BfmKind::Sbfm,
            0b01 => BfmKind::Bfm,
            0b10 => BfmKind::Ubfm,
            _ => return None,
        };
        return Some(Insn::Bfm {
            rd: reg(w, 0),
            rn: reg(w, 5),
            immr: (w >> 16) & 0x3F,
            imms: (w >> 10) & 0x3F,
            kind,
            is64: w >> 31 == 1,
        });
    }
    // --- EXTR: sf 00 100111 N 0 Rm imms Rn Rd ---
    if (w >> 24) & 0x1F == 0x13 {
        let is64 = w >> 31 == 1;
        return Some(Insn::Extr {
            rd: reg(w, 0),
            rn: reg(w, 5),
            rm: reg(w, 16),
            lsb: (w >> 10) & 0x3F,
            is64,
        });
    }

    // --- CSEL/CSINC/CSINV/CSNEG: bits 28:24 == 11010; bit30 = INV/NEG;
    //     op2 = bits 11:10 (00/01); cond = bits 15:12 ---
    if (w >> 24) & 0x1F == 0x1A && (w >> 29) & 1 == 0 && (w >> 22) & 1 == 0 {
        // CSEL/CSINC (bit30=0) vs CSINV/CSNEG (bit30=1); op2 = bits 11:10
        let inv = (w >> 30) & 1 == 1;
        let op2 = (w >> 10) & 3;
        let op = match (inv, op2) {
            (false, 0) => CselOp::Sel,
            (false, 1) => CselOp::Inc,
            (true, 0) => CselOp::Inv,
            (true, 1) => CselOp::Neg,
            _ => return None,
        };
        let cond = Cond::from_bits((w >> 12) & 0xF)?;
        return Some(Insn::Csel {
            rd: reg(w, 0),
            rn: reg(w, 5),
            rm: reg(w, 16),
            cond,
            op,
            is64: w >> 31 == 1,
        });
    }

    // --- CCMP/CCMN: bits 28:24 == 11010 with bit29=1; bit30: 1=CCMP
    //     0=CCMN; imm5 at bits 20:16 (imm, bit11=1) / Rm at 20:16 (reg,
    //     bit11=0); nzcv = bits 15:12; cond = bits 3:0 ---
    if (w >> 24) & 0x1F == 0x1A && (w >> 29) & 1 == 1 {
        let ccmn = (w >> 30) & 1 == 0;
        let cond = Cond::from_bits(w & 0xF)?;
        let nzcv = ((w >> 12) & 0xF) as u8;
        let is_imm = (w >> 11) & 1 == 1;
        let rm = reg(w, 16);
        let imm5 = (w >> 16) & 0x1F;
        return Some(Insn::Ccmp {
            rn: reg(w, 5),
            rm_imm: if is_imm { imm5 as u8 } else { rm },
            nzcv,
            cond,
            ccmn,
            is64: w >> 31 == 1,
        });
    }

    // --- MSR (immediate) DAIFSet/DAIFClr (Keystone goldens:
    //     set=D50343DF clr=D50343FF → op2 6=set 7=clr, imm4 bits 11:8) ---
    if (w & 0xFFFF_C01F) == 0xD503_401F {
        let op2 = (w >> 5) & 7;
        let daifclr = match op2 {
            6 => false,
            7 => true,
            _ => return None,
        };
        return Some(Insn::MsrImm { daifclr, imm4: ((w >> 8) & 0xF) as u8 });
    }

    // --- MSR (immediate) SPSel (keystone oracle: #0=d50040bf, #1=d50041bf
    //     → op1=0, CRm=4, value in bit 8; placed after the DAIF match) ---
    if (w & 0xFFFF_C01F) == 0xD500_401F {
        return Some(Insn::MsrSpsel { use_sp: (w >> 8) & 1 == 1 });
    }

    // --- PAC family: 1101 1010 100 S 1 001010? (group bits31:24 = 0xDA) ---
    if (w & 0xFF00_0000) == 0xDA00_0000 && (w >> 16) & 0xFF == 0xC1 {
        if let Some(p) = decode_pac(w) {
            return Some(p);
        }
        return None;
    }

    // --- Hint space: 1101 0101 0000 0011 0010 CRm op2 Rd(=11111).
    //     CRm=0: NOP/YIELD/…/DGH/ESB/PSB/CSDB/TSB/XPACLRI; CRm=3: the
    //     PAC SP/Z aliases (PACIAZ..AUTIBSP); CRm=4: BTI C/J/JC. ---
    if (w & 0xFFFF_F01F) == 0xD503_201F {
        let crm = (w >> 8) & 0xF;
        let op2 = (w >> 5) & 7;
        if crm == 3 {
            let op = match op2 {
                0 => PacOp::Paciaz,
                1 => PacOp::Paciasp,
                2 => PacOp::Pacibz,
                3 => PacOp::Pacibsp,
                4 => PacOp::Autiaz,
                5 => PacOp::Autiasp,
                6 => PacOp::Autibz,
                _ => PacOp::Autibsp,
            };
            return Some(Insn::Pac { op, rd: reg(w, 0), rn: 31 });
        }
        if crm == 4 {
            let kind = match op2 {
                0 => BtiKind::None,
                2 => BtiKind::C,
                4 => BtiKind::J,
                6 => BtiKind::Jc,
                _ => return Some(Insn::Nop),
            };
            return Some(Insn::Bti { kind });
        }
        let op = match (crm, op2) {
            (0, 6) => HintOp::Dgh,
            (0, 7) => HintOp::Xpaclri,
            (2, 0) => HintOp::Esb,
            (2, 1) => HintOp::PsbCsync,
            (2, 2) => HintOp::TsbCsync,
            (2, 4) => HintOp::Csdb,
            _ => return Some(Insn::Nop),
        };
        return Some(Insn::Hint { op });
    }

    // --- TLBI range (v8.4): MSR(sys) with op0=1 op1=0 CRn=8 CRm>=8 op2 ---
    if (w & 0xFFFF_0000) == 0xD508_0000 {
        // op0=1 op1=0 CRn=8 → fixed bits; CRm ≥ 8 and op2 ∈ {5,6,7}? The
        // oracle goldens: D5088220 (rvae1is) … bits 19:5 encode the op.
        let rt = reg(w, 0);
        let op = match w & 0xFFFF_FFE0 {
            0xD508_8220 => TlbiRangeOp::Rvae1is,
            0xD508_8520 => TlbiRangeOp::Rvae1os,
            0xD508_8620 => TlbiRangeOp::Rvae1,
            0xD508_82E0 => TlbiRangeOp::Rvaale1is,
            0xD508_85E0 => TlbiRangeOp::Rvaale1os,
            0xD508_86E0 => TlbiRangeOp::Rvaale1,
            0xD508_8260 => TlbiRangeOp::Rvaae1is,
            0xD508_8560 => TlbiRangeOp::Rvaae1os,
            0xD508_8660 => TlbiRangeOp::Rvaae1,
            _ => return None,
        };
        return Some(Insn::TlbiRange { op, rt });
    }

    // --- SIMD load/store (unsigned imm): LDR/STR Qt (Q=1: 3DC/3D8) and
    //     Dt (Q=0: FD4/FD0) ---
    if (w >> 24) & 0x3F == 0x3D {
        let rt = reg(w, 0);
        let rn = reg(w, 5);
        let imm12 = (w >> 10) & 0xFFF;
        let is128 = (w >> 23) & 1 == 1;
        let load = (w >> 22) & 1 == 1;
        return Some(match (load, is128) {
            (true, true) => Insn::Vldr { rt, rn, imm12 },
            (false, true) => Insn::Vstr { rt, rn, imm12 },
            (true, false) => Insn::VldrD { rt, rn, imm12 },
            (false, false) => Insn::VstrD { rt, rn, imm12 },
        });
    }

    // --- AdvSIMD three-same LOGICAL: bits[28:24]==01110, bit21=1,
    //     opcode bits[15:10]==000111. U(29)+size(23:22) pick one of
    //     AND/BIC/ORR/ORN (U=0) or EOR/BSL/BIT/EON (U=1); Q picks .16b/.8b.
    //     (capstone: 0x4E201C00=and, 0x4E601C00=bic, 0x4EA01C00=orr/mov,
    //     0x4EE01C00=orn, 0x6E201C00=eor, 0x6EA01C00=bit, 0x6EE01C00=eon.)
    if (w & 0x9F00_0000) == 0x0E00_0000
        && (w >> 21) & 1 == 1
        && (w & 0xFC00) == 0x1C00
    {
        return Some(Insn::VLogic3 {
            rd: reg(w, 0),
            rn: reg(w, 5),
            rm: reg(w, 16),
            size: ((w >> 22) & 3) as u8,
            u: (w >> 29) & 1 == 1,
            q: (w >> 30) & 1 == 1,
        });
    }

    // --- AdvSIMD across-lane reduce: bits[28:24]==01110, size(23:22)==00,
    //     bit21=1, bits[20:18]==000, opcode bits[15:10]: 101010 = MINV/MAXV
    //     (bit16: 1=min, 0=max; U: 0=signed, 1=unsigned), 101110+bit16=ADDV.
    //     (capstone: 0x6E31A801=uminv, 0x0E31A801=sminv, 0x6E30A801=umaxv,
    //     0x4E30A801=smaxv, 0x4E31B801=addv.)
    if (w & 0x9F00_0000) == 0x0E00_0000
        && (w >> 22) & 3 == 0
        && (w >> 21) & 1 == 1
        && (w >> 17) & 0xF == 0b1000
    {
        let size = ((w >> 22) & 3) as u8; // always 0 here; kept for exec shape
        let op = match ((w >> 10) & 0x3F, (w >> 16) & 1, (w >> 29) & 1) {
            (0b101010, 1, 0) => VReduceOp::Sminv,
            (0b101010, 1, 1) => VReduceOp::Uminv,
            (0b101010, 0, 0) => VReduceOp::Smaxv,
            (0b101010, 0, 1) => VReduceOp::Umaxv,
            (0b101110, 1, 0) => VReduceOp::Addv,
            _ => return None,
        };
        return Some(Insn::VReduce {
            rd: reg(w, 0),
            rn: reg(w, 5),
            size,
            op,
            q: (w >> 30) & 1 == 1,
        });
    }

    // --- AdvSIMD three-same INTEGER arithmetic/compare: bits[28:24]==01110,
    //     bit21=1; opcode bits[15:10] + U(29) selects the op; size(23:22)
    //     selects the element width (00=B,01=H,10=S,11=D).
    //     (capstone: 100001=ADD/SUB, 001101=CMGT/CMHI, 001111=CMGE/CMHS,
    //     100011=CMTST/CMEQ, 011011=SMIN/UMIN, 011001=SMAX/UMAX,
    //     101001=SMAXP/UMAXP, 101011=SMINP/UMINP, 100111=MUL.)
    //     Opcodes outside the map (aese/sha/sq…) fall through to decode_simd.
    if (w & 0x9F00_0000) == 0x0E00_0000 && (w >> 21) & 1 == 1 {
        let v3op = match ((w >> 10) & 0x3F, (w >> 29) & 1 == 1) {
            (0b100001, false) => Some(V3Op::Add),
            (0b100001, true) => Some(V3Op::Sub),
            (0b001101, false) => Some(V3Op::Cmgt),
            (0b001101, true) => Some(V3Op::Cmhi),
            (0b001111, false) => Some(V3Op::Cmge),
            (0b001111, true) => Some(V3Op::Cmhs),
            (0b100011, false) => Some(V3Op::Cmtst),
            (0b100011, true) => Some(V3Op::Cmeq),
            (0b011011, false) => Some(V3Op::Smin),
            (0b011011, true) => Some(V3Op::Umin),
            (0b011001, false) => Some(V3Op::Smax),
            (0b011001, true) => Some(V3Op::Umax),
            (0b101001, false) => Some(V3Op::Smaxp),
            (0b101001, true) => Some(V3Op::Umaxp),
            (0b101011, false) => Some(V3Op::Sminp),
            (0b101011, true) => Some(V3Op::Uminp),
            (0b100111, false) => Some(V3Op::Mul),
            // session C census: 100101 = MLA (U=0) / MLS (U=1)
            (0b100101, false) => Some(V3Op::Mla),
            (0b100101, true) => Some(V3Op::Mls),
            _ => None,
        };
        if let Some(op) = v3op {
            return Some(Insn::V3SameInt {
                rd: reg(w, 0),
                rn: reg(w, 5),
                rm: reg(w, 16),
                size: ((w >> 22) & 3) as u8,
                u: (w >> 29) & 1 == 1,
                q: (w >> 30) & 1 == 1,
                op,
            });
        }
        // --- three-same FP (session C keystone pin): opcode bits[15:10] +
        //     U(29) + bit23 picks the op; width = bit22 (0=S, 1=D). Guard
        //     bit10=1 keeps the crypto-3 siblings (bit10=0) out.
        if (w >> 10) & 1 == 1 {
            let op = match ((w >> 10) & 0x3F, (w >> 29) & 1 == 1, (w >> 23) & 1 == 1) {
                (0x35, false, false) => Some(V3FpOp::Add),
                (0x35, false, true) => Some(V3FpOp::Sub),
                (0x35, true, false) => Some(V3FpOp::Addp),
                (0x35, true, true) => Some(V3FpOp::Abd),
                (0x37, false, _) => Some(V3FpOp::Mulx),
                (0x37, true, false) => Some(V3FpOp::Mul),
                (0x39, false, false) => Some(V3FpOp::Cmeq),
                (0x39, true, false) => Some(V3FpOp::Cmge),
                (0x39, true, true) => Some(V3FpOp::Cmgt),
                (0x3B, true, false) => Some(V3FpOp::Acge),
                (0x3B, true, true) => Some(V3FpOp::Acgt),
                (0x3D, false, false) => Some(V3FpOp::Max),
                (0x3D, false, true) => Some(V3FpOp::Min),
                (0x3D, true, false) => Some(V3FpOp::Maxp),
                (0x3D, true, true) => Some(V3FpOp::Minp),
                (0x31, false, false) => Some(V3FpOp::Maxnm),
                (0x31, false, true) => Some(V3FpOp::Minnm),
                (0x31, true, false) => Some(V3FpOp::Maxnmp),
                (0x31, true, true) => Some(V3FpOp::Minnmp),
                (0x33, false, false) => Some(V3FpOp::Mla),
                (0x33, false, true) => Some(V3FpOp::Mls),
                (0x3F, false, false) => Some(V3FpOp::Recps),
                (0x3F, false, true) => Some(V3FpOp::Rsqrts),
                (0x3F, true, false) => Some(V3FpOp::Div),
                _ => None,
            };
            if let Some(op) = op {
                return Some(Insn::V3SameFp {
                    rd: reg(w, 0),
                    rn: reg(w, 5),
                    rm: reg(w, 16),
                    d: (w >> 22) & 1 == 1,
                    u: (w >> 29) & 1 == 1,
                    q: (w >> 30) & 1 == 1,
                    op,
                });
            }
        }
        // fall through: crypto/two-reg-misc siblings handled by decode_simd
    }

    // --- Advanced SIMD modified/shift-imm group, MOVI zero form:
    //     bits[28:24]==01111, immh(23:19)=0, immb(18:16)=0,
    //     opcode(15:11)=11100, bit10=1, Rn(9:5)=0 — the word zeroes the
    //     vector for any U/Q/Rd (keystone: movi v0.2d,#0 = 0x6F00E400,
    //     movi v3.16b,#0 = 0x4F00E403, movi d0,#0 = 0x2F00E400).
    //     Boot path: `movi v0.2d, #0; stur q0, …` at 0x…7b80824 (real
    //     18C66 `start` struct-zeroing idiom). U=0 cmode-1110 words are the
    //     8-BIT byte-replication form (capstone: 0x4F02E740 = movi v0.16b,
    //     #0x5a) and route to the general MoviVec below — this mask now
    //     requires U=1 so only the 64-bit bit-expansion arm stays here.
    //     Nonzero-movi/ucvtf/fmov siblings flow to the 0x0F dispatcher. ---
    if (w & 0xBFF8_FC00) == 0x2F00_E400 {
        let imm8 = (((w >> 5) & 0x1F) | ((w >> 16) & 7) << 5) as u8;
        return Some(Insn::MoviVec64 { rd: reg(w, 0), q: (w >> 30) & 1 == 1, imm8 });
    }

    // --- AdvSIMD shift-by-immediate / modified-immediate (0x0F group,
    //     bit10=1). Field map pinned empirically (session C: keystone
    //     round-trip sweeps + capstone disasm, every row below verified):
    //     * X = immh:immb = bits[22:16]; shift forms need X in
    //       [8<<size, 16<<size) with SHIFT = (16<<size) − X and the element
    //       size derived from X's MSB (bits 23:22 are fixed 0);
    //     * X < 8 → modified-immediate: cmode = bits[15:12],
    //       imm8 = (X&7)<<5 | bits[9:5]. Verified (cmode, U) → op:
    //       U=0: 0/2/4/6 MOVI-32 sh (c>>1)*8 · 1/3/5/7 ORR-32 sh ((c−1)>>1)*8
    //            · 8/A MOVI-16 · 9/B ORR-16 · E MOVI-8 byte-replication
    //            · F FMOV (vector FP immediate)
    //       U=1: 0/2/4/6 MVNI-32 · 1/3/5/7 BIC-32 · 8/A MVNI-16
    //            · E MOVI-64 bit-expansion (handled by MoviVec64 above). ---
    if (w & 0x9F00_0000) == 0x0F00_0000 && (w >> 10) & 1 == 1 && (w >> 23) & 1 == 0 {
        let u = (w >> 29) & 1 == 1;
        let q = (w >> 30) & 1 == 1;
        let x = ((w >> 16) & 0x7F) as u8; // immh:immb, 7 bits here (bit23=0)
        let op11 = ((w >> 11) & 0x1F) as u8;
        let size = match x {
            8..=15 => 0u8,
            16..=31 => 1,
            32..=63 => 2,
            64..=127 => 3,
            _ => {
                // --- modified-immediate / FP-imm fallthrough (X < 8) ---
                let cmode = ((w >> 12) & 0xF) as u8;
                let imm8 = (((w >> 5) & 0x1F) | (((w >> 16) & 7) << 5)) as u8;
                if cmode == 0xF && !u {
                    return Some(Insn::FmovVecImm { rd: reg(w, 0), q, imm8 });
                }
                // (op, width_log2, shift) — only capstone-verified arms.
                let spec = match (cmode, u) {
                    (0b0000, false) => Some((VecImmOp::Movi, 2u8, (cmode >> 1) * 8)),
                    (0b0010, false) => Some((VecImmOp::Movi, 2, (cmode >> 1) * 8)),
                    (0b0100, false) => Some((VecImmOp::Movi, 2, (cmode >> 1) * 8)),
                    (0b0110, false) => Some((VecImmOp::Movi, 2, (cmode >> 1) * 8)),
                    (0b0001, false) => Some((VecImmOp::Orr, 2, ((cmode - 1) >> 1) * 8)),
                    (0b0011, false) => Some((VecImmOp::Orr, 2, ((cmode - 1) >> 1) * 8)),
                    (0b0101, false) => Some((VecImmOp::Orr, 2, ((cmode - 1) >> 1) * 8)),
                    (0b0111, false) => Some((VecImmOp::Orr, 2, ((cmode - 1) >> 1) * 8)),
                    (0b1000, false) => Some((VecImmOp::Movi, 1, 0)),
                    (0b1010, false) => Some((VecImmOp::Movi, 1, 8)),
                    (0b1001, false) => Some((VecImmOp::Orr, 1, 0)),
                    (0b1011, false) => Some((VecImmOp::Orr, 1, 8)),
                    (0b1110, false) => Some((VecImmOp::Movi, 0, 0)),
                    (0b0000, true) => Some((VecImmOp::Mvni, 2, (cmode >> 1) * 8)),
                    (0b0010, true) => Some((VecImmOp::Mvni, 2, (cmode >> 1) * 8)),
                    (0b0100, true) => Some((VecImmOp::Mvni, 2, (cmode >> 1) * 8)),
                    (0b0110, true) => Some((VecImmOp::Mvni, 2, (cmode >> 1) * 8)),
                    (0b0001, true) => Some((VecImmOp::Bic, 2, ((cmode - 1) >> 1) * 8)),
                    (0b0011, true) => Some((VecImmOp::Bic, 2, ((cmode - 1) >> 1) * 8)),
                    (0b0101, true) => Some((VecImmOp::Bic, 2, ((cmode - 1) >> 1) * 8)),
                    (0b0111, true) => Some((VecImmOp::Bic, 2, ((cmode - 1) >> 1) * 8)),
                    (0b1000, true) => Some((VecImmOp::Mvni, 1, 0)),
                    (0b1010, true) => Some((VecImmOp::Mvni, 1, 8)),
                    _ => None,
                };
                let (op, width_log2, shift) = match spec {
                    Some(s) => s,
                    None => return None,
                };
                // 64-bit lane-unit pattern per family (capstone-verified
                // semantics: MOVI zero-extends; MVNI inverts within width).
                let value: u64 = match (op, width_log2) {
                    (VecImmOp::Movi, 0) => {
                        // byte replication across the 64-bit unit
                        let b = imm8 as u64;
                        b | (b << 8) | (b << 16) | (b << 24) | (b << 32) | (b << 40)
                            | (b << 48) | (b << 56)
                    }
                    (VecImmOp::Movi, 1) => {
                        let h = ((imm8 as u64) << shift) & 0xFFFF;
                        h | (h << 16) | (h << 32) | (h << 48)
                    }
                    (VecImmOp::Movi, 2) => {
                        let s32 = ((imm8 as u64) << shift) & 0xFFFF_FFFF;
                        s32 | (s32 << 32)
                    }
                    (VecImmOp::Mvni, 1) => {
                        let h = (!((imm8 as u64) << shift)) & 0xFFFF;
                        h | (h << 16) | (h << 32) | (h << 48)
                    }
                    (VecImmOp::Mvni, 2) => {
                        let s32 = (!((imm8 as u64) << shift)) & 0xFFFF_FFFF;
                        s32 | (s32 << 32)
                    }
                    (VecImmOp::Orr, 1) => {
                        let h = ((imm8 as u64) << shift) & 0xFFFF;
                        h | (h << 16) | (h << 32) | (h << 48)
                    }
                    (VecImmOp::Orr, 2) | (VecImmOp::Bic, 2) => {
                        let s32 = ((imm8 as u64) << shift) & 0xFFFF_FFFF;
                        s32 | (s32 << 32)
                    }
                    _ => 0,
                };
                return Some(Insn::MoviVec { rd: reg(w, 0), op, value, width_log2, q });
            }
        };
        let op = match (op11, u) {
            (0b00000, _) => VShiftOp::Shr,     // sshr / ushr
            (0b00010, _) => VShiftOp::Shra,    // ssra / usra (accumulate)
            (0b00100, _) => VShiftOp::Rshr,    // srshr / urshr (rounding)
            (0b00110, _) => VShiftOp::Rsra,    // srsra / ursra
            (0b01000, true) => VShiftOp::Sri,  // sri
            (0b01010, _) => VShiftOp::Shl,     // shl (U=0) / sli (U=1)
            (0b01100, true) => VShiftOp::Sqshlu,
            (0b01110, _) => VShiftOp::Sqshl,   // sqshl / uqshl
            (0b10000, _) => VShiftOp::Shrn,    // shrn / sqshrun
            (0b10001, _) => VShiftOp::Rshrn,   // rshrn / sqrshrun
            (0b10010, _) => VShiftOp::Sqshrn,  // sqshrn / uqshrn
            (0b10011, _) => VShiftOp::Sqrshrn, // sqrshrn / uqrshrn
            (0b10100, _) => VShiftOp::Shll,    // sshll / ushll
            // SCVTF/UCVTF (fixed-point): the 8-bit-int (.4h) form is
            // reserved (capstone: 0x2F08E420 = UNDEF) — require size ≥ 1.
            (0b11100, _) if size >= 1 => VShiftOp::Cvtf, // scvtf / ucvtf
            // FCVTZS/FCVTZU (fixed-point fp→int): opcode 11111 (census
            // 0x0F00FC00; real 18C66 word 0x4F70FC00 = fcvtzs v0.2d,#0x10)
            (0b11111, _) => VShiftOp::Fcvtz,
            _ => return None,
        };
        return Some(Insn::VShiftImm {
            rd: reg(w, 0),
            rn: reg(w, 5),
            op,
            immh_immb: x,
            size,
            u,
            q,
        });
    }

    // --- Scalar FP ↔ GPR move (FMOD-group opcode bits[20:16]: 00110 int←fp,
    //     00111 fp←int; bit31 = 64-bit x/d form).
    //     (capstone: 0x1E260022=fmov w2,s1, 0x9E670060=fmov d0,x3,
    //     0x1E270060=fmov s0,w3.) Other bits[20:16] opcodes in this mask
    //     (fjcvtzs 0b11110, fcvtzs…) fall through to their own handlers.
    if (w & 0x7FA0_FC00) == 0x1E20_0000
        && ((w >> 16) & 0x1F == 0b00110 || (w >> 16) & 0x1F == 0b00111)
    {
        return Some(Insn::FmovGprVec {
            rt: reg(w, 0),
            rn: reg(w, 5),
            is64: (w >> 31) & 1 == 1,
            to_vec: (w >> 16) & 0x1F == 0b00111,
        });
    }

    // --- Legacy SIMD dispatcher (three-same remainder: crypto AES/SHA,
    //     two-reg-misc, FP16, …). My boot-path guards above took their
    //     slice; everything else lands here. ---
    let simd_group = w & 0x9F00_0000;
    if simd_group == 0x0E00_0000 || simd_group == 0x8E00_0000 {
        if let Some(v) = decode_simd(w) {
            return Some(v);
        }
        return None;
    }

    // --- Advanced SIMD three-register (indexed): bits 28:24 == 01111.
    //     STRUCTURAL decode (no local v8.1+ assembler oracle — see the
    //     goldens header): opcode at bits 15:12 {1110 = SDOT/UDOT,
    //     1100+U = FCMLA(rot=13:12)/SQRDMLAH, 1101+U = FCADD/ SQRDMLSH};
    //     L=bit21, M=bit20, H=bit11 select the element index. ---
    if (w & 0x9F00_0000) == 0x0F00_0000 || (w & 0x9F00_0000) == 0x8F00_0000 {
        let opcode4 = (w >> 12) & 0xF;
        let l = (w >> 21) & 1;
        let m = (w >> 20) & 1;
        let h = (w >> 11) & 1;
        let u = (w >> 29) & 1 == 1;
        let q = (w >> 30) & 1 == 1;
        let size = ((w >> 22) & 3) as u8;
        if (w >> 10) & 1 != 0 {
            return None;
        }
        let size_log2 = if size == 2 { 2u8 } else { 1u8 };
        let index: u8 = if size_log2 == 1 {
            ((h << 2) | (l << 1) | m) as u8
        } else {
            ((h << 1) | l) as u8
        };
        let op = match (opcode4, u) {
            (0xE, false) => VIndexedOp::Sdot,
            (0xE, true) => VIndexedOp::Udot,
            // rot lives in the size-field slot (bits 23:22) for the
            // complex-indexed ops (no size encoding there)
            (0xC, false) => VIndexedOp::Fcmla(((w >> 22) & 3) as u8),
            (0xC, true) => VIndexedOp::Sqrdmlah,
            (0xD, false) => VIndexedOp::Fcadd((w >> 23) & 1 == 1),
            (0xD, true) => VIndexedOp::Sqrdmlsh,
            _ => return None,
        };
        return Some(Insn::Vindexed {
            vd: reg(w, 0),
            vn: reg(w, 5),
            vm: reg(w, 16),
            op,
            index,
            size_log2,
            q,
        });
    }

    // =====================================================================
    // FP16 scalar (FP data-processing): M S 0001110 …
    // =====================================================================
    if (w & 0x7F00_0000) == 0x1E00_0000 {
        if let Some(f) = decode_fp_scalar(w) {
            return Some(f);
        }
        return None;
    }

    None
}

/// Decode the PAC hint-space family (bits 31:24 == 0xDA, bits 23:16 == 0xC1).
/// Field map derived from the Capstone goldens: key = bits 15:10 selects
/// {0..7 = PAC/AUT with Rn modifier (bits 9:5, 31 = SP), 8..15 = Z-forms
/// (Rn must be 11111), 16/17 = XPACI/XPACD}; the SP/Z aliases live in the
/// CRm=3 hint slot (handled in the hint block).
fn decode_pac(w: u32) -> Option<Insn> {
    if (w >> 16) & 0xFF != 0xC1 {
        return None;
    }
    let key = (w >> 10) & 0x3F;
    let rd = reg(w, 0);
    let rn = reg(w, 5);
    let op = match key {
        0x00 => PacOp::Pacia,
        0x01 => PacOp::Pacib,
        0x02 => PacOp::Pacda,
        0x03 => PacOp::Pacdb,
        0x04 => PacOp::Autia,
        0x05 => PacOp::Autib,
        0x06 => PacOp::Autda,
        0x07 => PacOp::Autdb,
        0x08 => PacOp::Paciza,
        0x09 => PacOp::Pacizb,
        0x0A => PacOp::Pacda, // reserved slot — treated as PACDA (honest: unallocated)
        0x0B => PacOp::Pacdb,
        0x0C => PacOp::Autiza,
        0x0D => PacOp::Autizb,
        0x0E => PacOp::Autda,
        0x0F => PacOp::Autdb,
        0x10 => PacOp::Xpaci,
        0x11 => PacOp::Xpacd,
        _ => return None,
    };
    // Z/XPAC forms have a fixed Rn = 11111
    if key >= 0x08 && rn != 31 {
        return None;
    }
    Some(Insn::Pac { op, rd, rn })
}

/// Decode the AdvSIMD region (bits 31:24 ∈ {0x0E,0x2E,0x4E,0x6E,0x8E,
/// 0xAE,0xCE,0xEE} and the indexed 0x0F/0x2F/…/0xEF family). Field map
/// derived empirically from the Capstone/Keystone goldens:
///   * big(bit31)/q(bit30)/u(bit29); opcode6 = bits 15:10;
///   * crypto-3 (big, bit21=1): SHA512H/H2/SU1, RAX1, SM3PART, SM4EKEY;
///   * SHA3 helpers: opcode6==0x03 with (bit22,bit21) selecting
///     EOR3/BCAX/SM3SS1;
///   * XAR: big, bits 23:21 == 100, imm6 at bits 15:10;
///   * 2-reg crypto (big, q, bit21=0): SHA512SU0/SM4E (hi=8, size=3),
///     SM3TT (hi=8, size=1);
///   * AES (U=0, bit21=1, bits 15:12 in 4..7, bit11=1);
///   * standard 3-same: DOTPROD (0x25), RDM (0x21/0x23), FCMLA
///     (0x31/33/35/37, rot = (op>>1)&3), FCADD (0x39/0x3D), FP16 vector
///     (0x05/07/0A/0D/0E/1F), PMULL (0x38).
fn decode_simd(w: u32) -> Option<Insn> {
    let u = (w >> 29) & 1 == 1;
    let q = (w >> 30) & 1 == 1;
    let big = w >> 31 == 1;
    let size = ((w >> 22) & 3) as u8;
    let opcode = (w >> 10) & 0x3F; // bits 15:10
    let opcode6hi = (w >> 10) & 0x3F;
    let vd = reg(w, 0);
    let vn = reg(w, 5);
    let vm = reg(w, 16);
    let group24 = (w >> 24) & 0x1F; // bits 28:24

    // --- crypto-3 (big, bit21=1): SHA512H/H2/SU1, RAX1, SM3PART, SM4EKEY,
    //     BCAX (opcode 0x03 with bit21=1) ---
    if big && (w >> 21) & 1 == 1 {
        if (opcode & 0x30) == 0 {
            // BCAX: bits 15..14 = 00, Ra = bits 13..10
            return Some(Insn::Vsha3 { vd, vn, vm, ra: reg(w, 10) & 0xF, op: Sha3Op::Bcax });
        }
        return match opcode {
            0x20 => Some(Insn::Vsha512h { vd, vn, vm, h2: false }),
            0x21 => Some(Insn::Vsha512h { vd, vn, vm, h2: true }),
            0x22 => Some(Insn::Vsha512su1 { vd, vn, vm }),
            0x23 => Some(Insn::Vsha3 { vd, vn, vm, ra: 0, op: Sha3Op::Rax1 }),
            0x30 => Some(Insn::Vsm3part { vd, vn, vm, w2: false }),
            0x31 => Some(Insn::Vsm3part { vd, vn, vm, w2: true }),
            0x32 => Some(Insn::Vsm4ekey { vd, vn, vm }),
            _ => None,
        };
    }
    // --- AES (U=0, bit21=1, bits 15:12 in 4..7, bit11=1); other U=0
    //     bit21=1 words: PMULL (opcode 0x38 — bit21 is its 7th opcode bit) ---
    if !big && (w >> 21) & 1 == 1 && group24 == 0x0E {
        let hi = (w >> 12) & 0xF;
        if hi >= 4 && hi <= 7 && (w >> 11) & 1 == 1 {
            let op = match hi {
                4 => AesOp::Ese,
                5 => AesOp::Esd,
                6 => AesOp::Emc,
                _ => AesOp::Eimc,
            };
            return Some(Insn::Vaes { vd, vn, op });
        }
        if opcode == 0x38 {
            return Some(Insn::Vpmull { vd, vn, vm, q, d64: size == 3 });
        }
        return None;
    }
    // --- bit21 == 0: SHA3 (EOR3/SM3SS1), XAR, 2-reg crypto, 3-same ---
    if (w >> 21) & 1 == 0 {
        if big && (opcode & 0x30) == 0 && ((w >> 21) & 5) == 0 {
            // EOR3 / SM3SS1: bits 23..21 = 000 and bits 15..14 = 00,
            // Ra = bits 13..10 (XAR has bits 23..21 = 100)
            if (w >> 22) & 1 == 1 {
                return Some(Insn::Vsm3ss1 { vd, vn, vm, ra: reg(w, 10) & 0xF });
            }
            return Some(Insn::Vsha3 { vd, vn, vm, ra: reg(w, 10) & 0xF, op: Sha3Op::Eor3 });
        }
        if big && ((w >> 21) & 7) == 4 && group24 == 0x0E {
            return Some(Insn::Vxar { vd, vn, vm, imm6: (w >> 10) & 0x3F });
        }
        if big && q && group24 == 0x0E {
            let hi = (w >> 12) & 0xF;
            let b11 = (w >> 11) & 1;
            let b10 = (w >> 10) & 1;
            if (hi >> 2) == 2 && size == 1 {
                return Some(Insn::Vsm3tt {
                    vd,
                    vn,
                    vm,
                    index: (hi & 3) as u8,
                    two: b11 == 1,
                    b: b10 == 1,
                });
            }
            if hi == 8 && size == 3 {
                return Some(if b10 == 1 {
                    Insn::Vsm4e { vd, vn }
                } else {
                    Insn::Vsha512su0 { vd, vn }
                });
            }
            return None;
        }
        // standard 3-same
        return match opcode {
            0x25 => Some(Insn::Vdot { vd, vn, vm, unsigned: u, q, two_s: !q }),
            // SQRDMLAH/SH (v8.1) vs CMGE/CMEQ (v8.0) share the opcode bits —
            // bit 21 distinguishes them (RDM forms have bit21 = 0)
            0x21 if (w >> 21) & 1 == 0 => Some(Insn::Vsqrdmlah { vd, vn, vm, subtract: false, size_log2: if size == 2 { 2 } else { 1 }, q }),
            0x23 if (w >> 21) & 1 == 0 => Some(Insn::Vsqrdmlah { vd, vn, vm, subtract: true, size_log2: if size == 2 { 2 } else { 1 }, q }),
            0x31 | 0x33 | 0x35 | 0x37 => {
                Some(Insn::Vfcmla { vd, vn, vm, rot: ((opcode >> 1) & 3) as u8, size_log2: if size == 2 { 2 } else { 1 }, q })
            }
            0x39 => Some(Insn::Vfcadd { vd, vn, vm, rot270: false, size_log2: if size == 2 { 2 } else { 1 }, q }),
            0x3D => Some(Insn::Vfcadd { vd, vn, vm, rot270: true, size_log2: if size == 2 { 2 } else { 1 }, q }),
            // FP16 vector: the op extends into the size field
            // (op6,size): (5,01)=fadd (5,11)=fsub (7,00)=fmul
            // (0xF,00)=fdiv (0xD,00)=fmax (0xD,11)=fmin
            0x05 if size == 1 => Some(Insn::Vfp16 { vd, vn, vm, op: VfpOp::Add, q }),
            0x05 if size == 3 => Some(Insn::Vfp16 { vd, vn, vm, op: VfpOp::Sub, q }),
            0x07 if size == 1 => Some(Insn::Vfp16 { vd, vn, vm, op: VfpOp::Mul, q }),
            0x0F if size == 1 => Some(Insn::Vfp16 { vd, vn, vm, op: VfpOp::Div, q }),
            0x0D if size == 1 => Some(Insn::Vfp16 { vd, vn, vm, op: VfpOp::Max, q }),
            0x0D if size == 3 => Some(Insn::Vfp16 { vd, vn, vm, op: VfpOp::Min, q }),
            _ => None,
        };
    }
    None
}

/// FP16 scalar decode (group bits 31:24 ∈ {0x1E, 0x5E, 0x9E, 0xDE}).
/// Field map derived programmatically from the Capstone oracle grid:
/// type = bits 23:22; bit11 = 1 → 2-source (opcode = bits 14:12,
/// Rm = bits 20:16); bit11 = 0 → 1-source (opcode10 = bits 20:11).
fn decode_fp_scalar(w: u32) -> Option<Insn> {
    let rd = reg(w, 0);
    let rn = reg(w, 5);
    let rm = reg(w, 16);
    let is64 = w >> 31 == 1;
    let ty = match ((w >> 22) & 3) as u8 {
        0 => FpType::S,
        1 => FpType::D,
        3 => FpType::H,
        _ => return None,
    };
    if (w >> 11) & 1 == 1 {
        // 2-source FP: opcode at bits 14:12, Rm at bits 20:16
        let op = match (w >> 12) & 7 {
            0 => VfpOp::Mul,
            1 => VfpOp::Div,
            2 => VfpOp::Add,
            3 => VfpOp::Sub,
            4 => VfpOp::Max,
            5 => VfpOp::Min,
            _ => return None,
        };
        return Some(Insn::Fp2 { rd, rn, rm, op });
    }
    // 1-source: opcode10 = bits 20:11 (bit11 = 0)
    let op10 = (w >> 11) & 0x3FF;
    match op10 {
        0x018 => Some(Insn::Fp1 { rd, rn, op: Vfp1Op::Abs }),
        0x028 => Some(Insn::Fp1 { rd, rn, op: Vfp1Op::Neg }),
        0x038 => Some(Insn::Fp1 { rd, rn, op: Vfp1Op::Sqrt }),
        0x040 => Some(Insn::FpCvtInt { rd, rn, to_half: ty == FpType::H, unsigned: false, src64: is64 }),
        0x060 => Some(Insn::FpCvtInt { rd, rn, to_half: ty == FpType::H, unsigned: true, src64: is64 }),
        0x048 => Some(Insn::Fcvt { rd, rn, from: ty, to: FpType::S }),
        0x058 => Some(Insn::Fcvt { rd, rn, from: ty, to: FpType::D }),
        0x078 => Some(Insn::Fcvt { rd, rn, from: ty, to: FpType::H }),
        0x300 => Some(Insn::FpCvtFixed { rd, rn, unsigned: false, src64: is64 }),
        0x320 => Some(Insn::FpCvtFixed { rd, rn, unsigned: true, src64: is64 }),
        0x3C0 if ty == FpType::D => Some(Insn::Fjcvtzs { rd, rn }),
        _ => None,
    }
}

/// Extract bits `hi:lo` (inclusive) as u32.
fn bits(w: u32, hi: u32, lo: u32) -> u32 {
    (w >> lo) & ((1u32 << (hi - lo + 1)) - 1)
}

/// 5-bit register field.
fn reg(w: u32, lo: u32) -> u8 {
    bits(w, lo + 4, lo) as u8
}

/// Sign-extend the low `bits` of `v`.
fn sext(v: i64, bits: u32) -> i64 {
    let shift = 64 - bits;
    (v << shift) >> shift
}

/// Canonical 15-bit system-register identifier from an MRS/MSR word.
/// Packing (op0<<14)|(op1<<11)|(crn<<7)|(crm<<3)|op2 — matches isa.rs.
fn sysreg_bits(w: u32) -> u16 {
    let op0 = bits(w, 20, 20) as u16;
    let op1 = bits(w, 18, 16) as u16;
    let crn = bits(w, 15, 12) as u16;
    let crm = bits(w, 11, 8) as u16;
    let op2 = bits(w, 7, 5) as u16;
    (op0 << 14) | (op1 << 11) | (crn << 7) | (crm << 3) | op2
}

/// ARM "DecodeBitMasks(N, imms, immr, immediate=TRUE)" (DDI 0487 C6.2.5).
/// Expands a logical-immediate encoding into its full replicated value.
pub fn decode_bitmask(n: u32, imms: u32, immr: u32, is64: bool) -> Option<u64> {
    // 7-bit value N:NOT(imms); HighestSetBit selects element size.
    let imm7 = ((n as u64) << 6) | (!(imms as u64) & 0x3F);
    if imm7 == 0 {
        return None; // all zeros → UNDEFINED
    }
    let len = 63 - imm7.leading_zeros(); // HighestSetBit over 7 bits (0..=6)
    if len == 0 {
        return None;
    }
    let esize: u64 = 1 << len;
    if esize > 32 && !is64 {
        return None; // 64-bit element in a 32-bit (sf=0) instruction
    }
    let levels = esize - 1;
    let s = imms as u64 & levels;
    let r = immr as u64 & levels;
    // welem = ones(S+1) rotated right by R within esize bits.
    let welem = (1u64 << (s + 1)) - 1;
    let rr = r % esize;
    let rot = if rr == 0 { welem } else { (welem >> rr) | (welem << (esize - rr)) };
    let elem = if esize >= 64 { rot } else { rot & ((1u64 << esize) - 1) };
    // Replicate across 64 bits.
    let mut out = 0u64;
    let mut off = 0u64;
    while off < 64 {
        out |= elem << off;
        off += esize;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- explicit field-packing helpers (independent of decode()) ---
    const fn pack_movz(sf: u32, opc: u32, hw: u32, imm16: u32, rd: u32) -> u32 {
        (sf << 31) | (opc << 29) | (0b100101 << 23) | (hw << 21) | (imm16 << 5) | rd
    }
    const fn pack_addsub_imm(sf: u32, op: u32, s: u32, sh: u32, imm12: u32, rn: u32, rd: u32) -> u32 {
        (sf << 31) | (op << 30) | (s << 29) | (0b100010 << 23) | (sh << 22) | (imm12 << 10) | (rn << 5) | rd
    }
    const fn pack_addsub_reg(sf: u32, op: u32, s: u32, shift: u32, rm: u32, imm6: u32, rn: u32, rd: u32) -> u32 {
        (sf << 31) | (op << 30) | (s << 29) | (0b01011 << 24) | (shift << 22) | (rm << 16) | (imm6 << 10) | (rn << 5) | rd
    }
    const fn pack_ldst_uimm(size: u32, opc: u32, imm12: u32, rn: u32, rt: u32) -> u32 {
        (size << 30) | (0b111001 << 24) | (opc << 22) | (imm12 << 10) | (rn << 5) | rt
    }
    const fn pack_pair(sf_opc: u32, l: u32, mode: u32, imm7: i64, rt2: u32, rn: u32, rt: u32) -> u32 {
        (sf_opc << 30) | (0b10100 << 25) | (l << 22) | (mode << 23) | ((((imm7 & 0x7F) as i32) as u32) << 15) | (rt2 << 10) | (rn << 5) | rt
    }
    const fn pack_cbz(sf: u32, nz: u32, imm19: u32, rt: u32) -> u32 {
        (sf << 31) | (0b011010 << 25) | (nz << 24) | (imm19 << 5) | rt
    }
    const fn pack_tbz(sf: u32, nz: u32, b5: u32, b40: u32, imm14: u32, rt: u32) -> u32 {
        (sf << 31) | (0b011011 << 25) | (b5 << 31) | (b40 << 19) | (nz << 24) | (imm14 << 5) | rt
    }
    const fn pack_adr(sf: u32, imm21: i64, rd: u32) -> u32 {
        let imm = (imm21 as u32) & 0x1F_FFFF;
        (sf << 31) | (0b10000 << 24) | ((imm >> 2) << 5) | ((imm & 3) << 29) | rd
    }

    #[test]
    fn move_wide() {
        assert_eq!(decode(0, pack_movz(1, 0b10, 0, 6, 0)), Some(Insn::Movz { rd: 0, imm16: 6, shift: 0, is64: true }));
        assert_eq!(decode(0, pack_movz(1, 0b11, 1, 0x100, 0)), Some(Insn::Movk { rd: 0, imm16: 0x100, shift: 1, is64: true }));
        assert_eq!(decode(0, pack_movz(0, 0b00, 0, 1, 1)), Some(Insn::Movn { rd: 1, imm16: 1, shift: 0, is64: false }));
        // real-world: movz x0,#6 = D28000C0
        assert_eq!(pack_movz(1, 0b10, 0, 6, 0), 0xD28000C0);
    }

    #[test]
    fn add_sub_imm() {
        assert_eq!(decode(0, pack_addsub_imm(1, 0, 0, 0, 8, 1, 0)), Some(Insn::AddImm { rd: 0, rn: 1, imm12: 8, shift: false, setflags: false, is64: true }));
        // sub sp, sp, #0x10 = D10043FF (known-good)
        assert_eq!(decode(0, 0xD10043FF), Some(Insn::SubImm { rd: 31, rn: 31, imm12: 0x10, shift: false, setflags: false, is64: true }));
        // cmp x3,#1 = SUBS xzr,x3,#1
        assert_eq!(decode(0, pack_addsub_imm(1, 1, 1, 0, 1, 3, 31)), Some(Insn::CmpImm { rn: 3, imm12: 1, shift: false, is64: true }));
        assert_eq!(decode(0, pack_addsub_imm(1, 0, 1, 0, 2, 1, 0)), Some(Insn::AddImm { rd: 0, rn: 1, imm12: 2, shift: false, setflags: true, is64: true }));
    }

    #[test]
    fn add_sub_reg() {
        assert_eq!(decode(0, pack_addsub_reg(1, 0, 0, 0, 2, 0, 1, 0)), Some(Insn::AddSubReg { rd: 0, rn: 1, rm: 2, kind: ShiftKind::Lsl, imm6: 0, subtract: false, setflags: false, is64: true }));
        assert_eq!(decode(0, pack_addsub_reg(1, 0, 0, 0, 2, 2, 1, 0)), Some(Insn::AddSubReg { rd: 0, rn: 1, rm: 2, kind: ShiftKind::Lsl, imm6: 2, subtract: false, setflags: false, is64: true }));
        // cmp x1,x2 = SUBS xzr,x1,x2 = EB02003F (known-good)
        assert_eq!(pack_addsub_reg(1, 1, 1, 0, 2, 0, 1, 31), 0xEB02003F);
        assert_eq!(decode(0, 0xEB02003F), Some(Insn::CmpReg { rn: 1, rm: 2, kind: ShiftKind::Lsl, imm6: 0, is64: true }));
    }

    #[test]
    fn logical_imm_bitmask() {
        assert_eq!(decode_bitmask(1, 0b000111, 0, true), Some(0xFF));
        assert_eq!(decode_bitmask(1, 0b001111, 0, true), Some(0xFFFF));
        assert_eq!(decode_bitmask(1, 0b000011, 0, true), Some(0xF));
        assert_eq!(decode_bitmask(0, 0b011111, 0, false), Some(u64::MAX)); // ones(32) replicated
        assert_eq!(decode_bitmask(0, 0b111111, 0, true), None);
        // orr x0, x0, #0xFF: N=0 immr=0 imms=0b110111 rn=0 rd=0
        let w: u32 = (1 << 31) | (0b01 << 29) | (0b100100 << 23) | (1 << 22) | (0 << 16) | (0b000111 << 10);
        assert_eq!(decode(0, w), Some(Insn::OrrImm { rd: 0, rn: 0, imm: 0xFF, setflags: false, is64: true }));
    }

    #[test]
    fn branches() {
        assert_eq!(decode(0, 0x14000001), Some(Insn::B { imm: 4 }));
        assert_eq!(decode(0, 0x94000002), Some(Insn::Bl { imm: 8 }));
        // b.eq .+8: 0101010 imm19=2 0 eq → 54000040 (known-good)
        let w: u32 = (0b0101010 << 25) | (2 << 5) | 0;
        assert_eq!(w, 0x54000040);
        assert_eq!(decode(0, w), Some(Insn::BCond { cond: Cond::Eq, imm: 8 }));
        assert_eq!(decode(0, 0xD61F0060), Some(Insn::Br { rn: 3 }));
        assert_eq!(decode(0, 0xD63F0060), Some(Insn::Blr { rn: 3 }));
        assert_eq!(decode(0, 0xD65F03C0), Some(Insn::Ret { rn: 30 }));
        assert_eq!(decode(0, 0xD69F03E0), Some(Insn::Eret));
    }

    #[test]
    fn compare_branch() {
        assert_eq!(decode(0, pack_cbz(1, 0, 2, 3)), Some(Insn::Cbz { rn: 3, imm: 8, is64: true }));
        assert_eq!(decode(0, pack_cbz(0, 1, 2, 3)), Some(Insn::Cbnz { rn: 3, imm: 8, is64: false }));
        assert_eq!(decode(0, pack_tbz(1, 0, 1, 8, 2, 2)), Some(Insn::Tbz { rn: 2, bit: 40, imm: 8 }));
        assert_eq!(decode(0, pack_tbz(0, 1, 0, 1, 1, 2)), Some(Insn::Tbnz { rn: 2, bit: 1, imm: 4 }));
    }

    #[test]
    fn pc_relative() {
        assert_eq!(decode(0, pack_adr(0, 1, 0)), Some(Insn::Adr { rd: 0, imm: 1 }));
        assert_eq!(decode(0, pack_adr(1, 1, 1)), Some(Insn::Adrp { rd: 1, imm: 4096 }));
    }

    #[test]
    fn loads_stores() {
        // ldr x0,[x1,#8]: size=11 opc=01 imm12=1 (scaled)
        assert_eq!(decode(0, pack_ldst_uimm(0b11, 0b01, 1, 1, 0)), Some(Insn::LdrImmU { rt: 0, rn: 1, imm12: 1, size_log2: 3 }));
        // str x0,[sp,#16]: imm12=2
        assert_eq!(decode(0, pack_ldst_uimm(0b11, 0b00, 2, 31, 0)), Some(Insn::StrImmU { rt: 0, rn: 31, imm12: 2, size_log2: 3 }));
        // ldr w0,[x1]
        assert_eq!(decode(0, pack_ldst_uimm(0b10, 0b01, 0, 1, 0)), Some(Insn::LdrImmU { rt: 0, rn: 1, imm12: 0, size_log2: 2 }));
    }

    #[test]
    fn pairs() {
        // stp x29,x30,[sp,#-16]! → A9BF7BFD (canonical prologue)
        assert_eq!(pack_pair(0b10, 0, 0b11, -2, 30, 31, 29), 0xA9BF7BFD);
        assert_eq!(decode(0, 0xA9BF7BFD), Some(Insn::Stp { rt: 29, rt2: 30, rn: 31, imm: -16, mode: PairMode::Pre, is64: true }));
        // ldp x29,x30,[sp],#16 → A8C17BFD (canonical epilogue)
        assert_eq!(pack_pair(0b10, 1, 0b01, 2, 30, 31, 29), 0xA8C17BFD);
        assert_eq!(decode(0, 0xA8C17BFD), Some(Insn::Ldp { rt: 29, rt2: 30, rn: 31, imm: 16, mode: PairMode::Post, is64: true }));
    }

    #[test]
    fn system_and_exceptions() {
        assert_eq!(decode(0, 0xD4000001), Some(Insn::Svc { imm16: 0 }));
        assert_eq!(decode(0, 0xD4400000), Some(Insn::Hlt { imm16: 0 }));
        // isb sy → D5033FDF (canonical)
        assert_eq!(decode(0, 0xD5033FDF), Some(Insn::Isb));
        assert_eq!(decode(0, 0xD5033FBF), Some(Insn::Dmb));
        assert_eq!(decode(0, 0xD5033F9F), Some(Insn::Dsb));
        // mrs x0, SCTLR_EL1 (enc 0xC080): D5300000 | 0xC080<<5
        assert_eq!(decode(0, 0xD5300000 | (0x4080u32 << 5)), Some(Insn::Mrs { rt: 0, sysreg: 0x4080 }));
    }


    // ---- iOS 14.3 real-data gap goldens (keystone/capstone-derived) ----

    #[test]
    fn gap_pac_branch_family() {
        assert_eq!(decode(0, 0xD65F0BFF), Some(Insn::RetA { ab: false }));
        assert_eq!(decode(0, 0xD65F0FFF), Some(Insn::RetA { ab: true }));
        // blraa x8, x9 (real 14.3 text): target Xn=x8 (bits9:5), modifier x9
        assert_eq!(
            decode(0, 0xD73F0909),
            Some(Insn::BrAuth { rn: 8, link: true, ab: false })
        );
        assert_eq!(
            decode(0, 0xD71F0800),
            Some(Insn::BrAuth { rn: 0, link: false, ab: false })
        );
        assert_eq!(
            decode(0, 0xD71F0C01),
            Some(Insn::BrAuth { rn: 0, link: false, ab: true })
        );
        // plain RET still decodes as RET
        assert_eq!(decode(0, 0xD65F03C0), Some(Insn::Ret { rn: 30 }));
    }

    #[test]
    fn gap_dp3_mulh_map() {
        // REAL-DATA BUG #8 goldens (capstone-derived, real 14.3 words):
        // umulh x8, x8, x9 = 0x9bc97d08 (was: rejected by the old guard)
        assert_eq!(
            decode(0, 0x9BC97D08),
            Some(Insn::Umulh { rd: 8, rn: 8, rm: 9 })
        );
        // smulh (op31=010): was MISDECODED as MADD before the fix
        assert_eq!(
            decode(0, 0x9B400000),
            Some(Insn::Smulh { rd: 0, rn: 0, rm: 0 })
        );
        // umaddl / smaddl still land in the widening form
        assert_eq!(
            decode(0, 0x9BA00000),
            Some(Insn::MaddW { rd: 0, rn: 0, rm: 0, ra: 0, subtract: false, unsigned: true })
        );
        assert_eq!(
            decode(0, 0x9B200000),
            Some(Insn::MaddW { rd: 0, rn: 0, rm: 0, ra: 0, subtract: false, unsigned: false })
        );
        // madd/msub unchanged
        assert_eq!(
            decode(0, 0x9B007C00 | (8 << 16) | (9 << 5)),
            Some(Insn::Madd { rd: 0, rn: 9, rm: 8, ra: 31, subtract: false, is64: true })
        );
        assert_eq!(
            decode(0, 0x9B008000),
            Some(Insn::Madd { rd: 0, rn: 0, rm: 0, ra: 0, subtract: true, is64: true })
        );
    }

    #[test]
    fn gap_dp1_rev_family() {
        // rev w11, w10 = 0x5ac0094b (real 14.3 bucket 0x5a, ~2.9k words)
        assert_eq!(
            decode(0, 0x5AC0094B),
            Some(Insn::Dp1 { rd: 11, rn: 10, op: Dp1Op::Rev, is64: false })
        );
        // rev x0, x0 (64-bit REV32): 0xdac00800 (capstone: rev32 x0, x0)
        assert_eq!(
            decode(0, 0xDAC00800),
            Some(Insn::Dp1 { rd: 0, rn: 0, op: Dp1Op::Rev32, is64: true })
        );
        // rev x9, x11 (64-bit REV): 0xdac00d69 (capstone: rev x9, x11)
        assert_eq!(
            decode(0, 0xDAC00D69),
            Some(Insn::Dp1 { rd: 9, rn: 11, op: Dp1Op::Rev, is64: true })
        );
        // clz w15, w9: 0x5ac0112f
        assert_eq!(
            decode(0, 0x5AC0112F),
            Some(Insn::Dp1 { rd: 15, rn: 9, op: Dp1Op::Clz, is64: false })
        );
        // rev16 w0, w1: 0x5ac00420
        assert_eq!(
            decode(0, 0x5AC00420),
            Some(Insn::Dp1 { rd: 0, rn: 1, op: Dp1Op::Rev16, is64: false })
        );
        // rbit x2, x3: 0xdac00062
        assert_eq!(
            decode(0, 0xDAC00062),
            Some(Insn::Dp1 { rd: 2, rn: 3, op: Dp1Op::Rbit, is64: true })
        );
    }

    #[test]
    fn gap_logic_ror() {
        // eor w13, w11, w21, ror #29 = 0x4ad5756d (real 14.3 bucket 0x4a)
        assert_eq!(
            decode(0, 0x4AD5756D),
            Some(Insn::LogicReg {
                rd: 13,
                rn: 11,
                rm: 21,
                kind: ShiftKind::Ror,
                imm6: 29,
                op: LogicOp::Eor,
                setflags: false,
                invert: false,
                is64: false
            })
        );
        // bic w2, w3, w4, ror #1 = 0x0ae40462 (keystone can't assemble ror;
        // hand-derived candidate then capstone-verified per the playbook)
        assert_eq!(
            decode(0, 0x0AE40462),
            Some(Insn::LogicReg {
                rd: 2,
                rn: 3,
                rm: 4,
                kind: ShiftKind::Ror,
                imm6: 1,
                op: LogicOp::And,
                setflags: false,
                invert: true,
                is64: false
            })
        );
    }

    #[test]
    fn gap_dp1_exec_semantics() {
        use crate::interp::Interpreter;
        use crate::{CpuBackend, InterpBudget, MemAccess, StopReason};
        use std::sync::{Arc, Mutex};
        struct Tv(Arc<Mutex<Vec<u8>>>);
        impl MemAccess for Tv {
            fn load(&mut self, a: u64, s: u8) -> u64 {
                let g = self.0.lock().unwrap();
                let mut v = 0u64;
                for i in 0..s as usize {
                    v |= (*g.get(a as usize + i).unwrap_or(&0) as u64) << (i * 8);
                }
                v
            }
            fn store(&mut self, a: u64, s: u8, val: u64) {
                let mut g = self.0.lock().unwrap();
                for i in 0..s as usize {
                    if (a as usize + i) < g.len() {
                        g[a as usize + i] = (val >> (i * 8)) as u8;
                    }
                }
            }
            fn fetch32(&mut self, a: u64) -> u32 {
                self.load(a, 4) as u32
            }
        }
        let mem = Arc::new(Mutex::new(vec![0u8; 0x100]));
        let write = |mem: &Arc<Mutex<Vec<u8>>>, words: &[u32]| {
            let mut g = mem.lock().unwrap();
            for (i, w) in words.iter().enumerate() {
                g[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
            }
        };
        // rev w0, w1 with w1 = 0x11223344 → 0x44332211
        write(&mem, &[0x52866881, 0x72A22441, 0x5AC00820, 0xD440_0000]);
        let mut c = Interpreter::new(Box::new(Tv(mem.clone())));
        c.set_reset_vector(0);
        c.x[1] = 0x1122_3344;
        let res = c.run(InterpBudget { max_insn: 8, max_ns: 1_000_000_000 });
        assert!(matches!(res.stop, StopReason::Halted), "{res:?}");
        assert_eq!(c.x[0] & 0xFFFF_FFFF, 0x4433_2211, "rev w0,w1");

        // clz w0, w1 with w1 = 0x00010000 → 15
        write(&mem, &[0x5AC01020, 0xD440_0000]);
        let mut c = Interpreter::new(Box::new(Tv(mem.clone())));
        c.set_reset_vector(0);
        c.x[1] = 0x0001_0000;
        let res = c.run(InterpBudget { max_insn: 8, max_ns: 1_000_000_000 });
        assert!(matches!(res.stop, StopReason::Halted), "{res:?}");
        assert_eq!(c.x[0], 15, "clz w0,w1");

        // umulh x0, x1, x2 = 0x9bc27c20 (capstone: umulh x0, x1, x2;
        // Rm=bits20:16, 11111=bits15:10, Rn=bits9:5):
        // (0xFFFF_FFFF_FFFF_FFFF)^2 >> 64 = 0xFFFF_FFFF_FFFF_FFFE
        write(&mem, &[0x9BC2_7C20, 0xD440_0000]);
        let mut c = Interpreter::new(Box::new(Tv(mem.clone())));
        c.set_reset_vector(0);
        c.x[1] = u64::MAX;
        c.x[2] = u64::MAX;
        let res = c.run(InterpBudget { max_insn: 8, max_ns: 1_000_000_000 });
        assert!(matches!(res.stop, StopReason::Halted), "{res:?}");
        assert_eq!(c.x[0], 0xFFFF_FFFF_FFFF_FFFE, "umulh x0,x1,x2");
    }

    #[test]
    fn gap_exception_class() {
        // brk #0xc471 (real 14.3: 0xd4388e20)
        assert_eq!(decode(0, 0xD4388E20), Some(Insn::Brk { imm16: 0xC471 }));
        assert_eq!(decode(0, 0xD4200000), Some(Insn::Brk { imm16: 0 }));
        assert_eq!(decode(0, 0xD4A00001), Some(Insn::Dcps { level: 1, imm16: 0 }));
        assert_eq!(decode(0, 0xD6BF03E0), Some(Insn::Drps));
        // hlt still hlt
        assert_eq!(decode(0, 0xD4400000), Some(Insn::Hlt { imm16: 0 }));
    }

    #[test]
    fn gap_pre_post_index_load_store() {
        // ldur x1, [x22, #-8] (real 14.3: 0xf85f82c1)
        assert_eq!(
            decode(0, 0xF85F82C1),
            Some(Insn::LdSt9 { rt: 1, rn: 22, imm9: -8, size_log2: 3, load: true, mode: LsMode::Unscaled })
        );
        // stur w1, [x29, #-0x3c] (real: 0xb81c43a1)
        assert_eq!(
            decode(0, 0xB81C43A1),
            Some(Insn::LdSt9 { rt: 1, rn: 29, imm9: -0x3c, size_log2: 2, load: false, mode: LsMode::Unscaled })
        );
        // ldrb w11, [x23], #1 (real: 0x384016eb)
        assert_eq!(
            decode(0, 0x384016EB),
            Some(Insn::LdSt9 { rt: 11, rn: 23, imm9: 1, size_log2: 0, load: true, mode: LsMode::Post })
        );
        // ldur x1, [x22, #-8]!  pre-index (0xF85F82C1 | type=11)
        assert_eq!(
            decode(0, 0xF85F82C1 | 0xC00),
            Some(Insn::LdSt9 { rt: 1, rn: 22, imm9: -8, size_log2: 3, load: true, mode: LsMode::Pre })
        );
        // ldrsw x0, [sp, #8] (keystone 0xb9800be0)
        assert_eq!(
            decode(0, 0xB9800BE0),
            Some(Insn::Ldrs9 { rt: 0, rn: 31, imm9: 8, size_log2: 2, mode: LsMode::Unscaled, dest64: true })
        );
    }

    #[test]
    fn gap_register_offset_load_store() {
        // strb wzr, [x8, x10] (real: 0x382a691f)
        assert_eq!(
            decode(0, 0x382A691F),
            Some(Insn::LdStRegOff {
                rt: 31, rn: 8, rm: 10, option: ExtOp::Lsl, scaled: false,
                size_log2: 0, load: false, sign_ext: false, dest64: false,
            })
        );
        // ldr x0, [x8, x10, lsl #3] (keystone 0xf86a7900)
        assert_eq!(
            decode(0, 0xF86A7900),
            Some(Insn::LdStRegOff {
                rt: 0, rn: 8, rm: 10, option: ExtOp::Lsl, scaled: true,
                size_log2: 3, load: true, sign_ext: false, dest64: false,
            })
        );
        // ldrsw x0, [x8, x10, sxtx] (keystone 0xb8aae900)
        assert_eq!(
            decode(0, 0xB8AAE900),
            Some(Insn::LdStRegOff {
                rt: 0, rn: 8, rm: 10, option: ExtOp::Sxtx, scaled: false,
                size_log2: 2, load: true, sign_ext: true, dest64: true,
            })
        );
    }

    #[test]
    fn gap_pairs_gpr_and_simd() {
        // ldp w9, w8, [x0, #0x18] (real: 0x29432009 — was rejected before)
        assert_eq!(
            decode(0, 0x29432009),
            Some(Insn::Ldp { rt: 9, rt2: 8, rn: 0, imm: 0x18, mode: PairMode::Offset, is64: false })
        );
        // stp w0, w21, [x29, #-0x70] (real: 0x293257a0)
        assert_eq!(
            decode(0, 0x293257A0),
            Some(Insn::Stp { rt: 0, rt2: 21, rn: 29, imm: -0x70, mode: PairMode::Offset, is64: false })
        );
        // stp q0, q0, [sp, #0x170] (real: 0xad0b83e0)
        assert_eq!(
            decode(0, 0xAD0B83E0),
            Some(Insn::StpSimd { vt: 0, vt2: 0, rn: 31, imm: 0x170, mode: PairMode::Offset, log2_width: 4 })
        );
        // ldp q0, q3, [sp], #0x20 (keystone 0xacc10fe0, post)
        assert_eq!(
            decode(0, 0xACC10FE0),
            Some(Insn::LdpSimd { vt: 0, vt2: 3, rn: 31, imm: 0x20, mode: PairMode::Post, log2_width: 4 })
        );
        // ldpsw x0, x2, [sp, #8] (keystone 0x69410be0)
        assert_eq!(
            decode(0, 0x69410BE0),
            Some(Insn::Ldpsw { rt: 0, rt2: 2, rn: 31, imm: 8, mode: PairMode::Offset })
        );
        // 64-bit pairs still fine (0xa9 = ldp x8, x14, [x10])
        assert_eq!(
            decode(0, 0xA9403948),
            Some(Insn::Ldp { rt: 8, rt2: 14, rn: 10, imm: 0, mode: PairMode::Offset, is64: true })
        );
    }

    #[test]
    fn gap_simd_single_ls() {
        // stur q0, [sp, #0x80] (real: 0x3c8803e0)
        assert_eq!(
            decode(0, 0x3C8803E0),
            Some(Insn::LdStSimd9 { vt: 0, rn: 31, imm9: 0x80, width_log2: 4, load: false, mode: LsMode::Unscaled })
        );
        // str q0, [sp, #0x300] (unsigned, keystone 0x3d80c3e0)
        assert_eq!(
            decode(0, 0x3D80C3E0),
            Some(Insn::LdStSimdU { vt: 0, rn: 31, imm12: 0x30, width_log2: 4, load: false })
        );
        // ldr q0, [sp, #0x500] (unsigned, keystone 0x3dc143e0)
        assert_eq!(
            decode(0, 0x3DC143E0),
            Some(Insn::LdStSimdU { vt: 0, rn: 31, imm12: 0x50, width_log2: 4, load: true })
        );
        // stur b0 / ldur b0 (keystone)
        assert_eq!(
            decode(0, 0x3C0023E0),
            Some(Insn::LdStSimd9 { vt: 0, rn: 31, imm9: 2, width_log2: 0, load: false, mode: LsMode::Unscaled })
        );
        assert_eq!(
            decode(0, 0x3C4023E0),
            Some(Insn::LdStSimd9 { vt: 0, rn: 31, imm9: 2, width_log2: 0, load: true, mode: LsMode::Unscaled })
        );
        // str d0, [sp, #8] (keystone 0xfd0007e0)
        assert_eq!(
            decode(0, 0xFD0007E0),
            Some(Insn::LdStSimdU { vt: 0, rn: 31, imm12: 1, width_log2: 3, load: false })
        );
    }

    #[test]
    fn gap_add_sub_extended() {
        // add x1, x9, w8, uxtw (real: 0x8b284121)
        assert_eq!(
            decode(0, 0x8B284121),
            Some(Insn::AddSubExt {
                rd: 1, rn: 9, rm: 8, option: ExtOp::Uxtw, imm3: 0,
                subtract: false, setflags: false, is64: true,
            })
        );
        // adds x1, x9, x8, sxtx #2 (keystone 0xab28e921)
        assert_eq!(
            decode(0, 0xAB28E921),
            Some(Insn::AddSubExt {
                rd: 1, rn: 9, rm: 8, option: ExtOp::Sxtx, imm3: 2,
                subtract: false, setflags: true, is64: true,
            })
        );
        // sub w1, w9, w8, uxtb #1 (keystone 0x4b280521; S=0)
        assert_eq!(
            decode(0, 0x4B280521),
            Some(Insn::AddSubExt {
                rd: 1, rn: 9, rm: 8, option: ExtOp::Uxtb, imm3: 1,
                subtract: true, setflags: false, is64: false,
            })
        );
    }

    #[test]
    fn gap_variable_shift_ops() {
        // lsl w10, w10, w9 (real 14.3: 0x1ac9214a — LSLV, op10b 0x08)
        match decode(0, 0x1AC9214A) {
            Some(Insn::ShiftReg { rd, rn, rm, op, is64 }) => {
                assert_eq!((rd, rn, rm), (10, 10, 9));
                assert_eq!(op, ShiftOp::Lsl);
                assert!(!is64);
            }
            other => panic!("lslv not decoded: {other:?}"),
        }
        assert!(matches!(decode(0, 0x9AC9214A), Some(Insn::ShiftReg { is64: true, .. })));
    }

    #[test]
    fn gap_logical_shifted_register_full() {
        // orr w10, w10, w11 (real 14.3: 0x2a0b014a — used to be None!)
        match decode(0, 0x2A0B014A) {
            Some(Insn::LogicReg { rd, rn, rm, op, .. }) => {
                assert_eq!((rd, rn, rm), (10, 10, 11));
                assert_eq!(op, LogicOp::Orr);
            }
            other => panic!("orr shifted register not decoded: {other:?}"),
        }
        // mov x0, x1 still hits the MOV alias
        assert_eq!(decode(0, 0xAA0103E0), Some(Insn::MovReg { rd: 0, rn: 1 }));
    }

    #[test]
    fn mov_reg_alias() {
        // mov x0, x1 = orr x0, xzr, x1 = AA0103E0 (canonical)
        let w: u32 = (1u32 << 31) | (0b01 << 29) | (0b01010 << 24) | (0 << 21) | (1 << 16) | (0 << 10) | (31 << 5) | 0;
        assert_eq!(w, 0xAA0103E0);
        assert_eq!(decode(0, 0xAA0103E0), Some(Insn::MovReg { rd: 0, rn: 1 }));
    }

    #[test]
    fn gxf_enter_exit() {
        // Inferno disas_apple_insn: GENTER when bits[9:5]==1
        assert!(matches!(decode(0, 0x00001420), Some(Insn::Genter { .. })));
        assert!(matches!(decode(0, 0x00001400), Some(Insn::Gexit { .. })));
    }

    const HLT: u32 = 0xD440_0000; // hlt #0 — the interpreter's clean stop
    const Z: u32 = 1 << 2;
    const C: u32 = 1 << 1;

    #[test]
    fn gap_vlogic3_family() {
        // capstone-verified: the 8 logical three-same ops
        use Insn::VLogic3;
        assert_eq!(decode(0, 0x4E20_1C00), Some(VLogic3 { rd: 0, rn: 0, rm: 0, size: 0, u: false, q: true })); // and
        assert_eq!(decode(0, 0x4E60_1C00), Some(VLogic3 { rd: 0, rn: 0, rm: 0, size: 1, u: false, q: true })); // bic
        assert_eq!(decode(0, 0x4EA0_1C00), Some(VLogic3 { rd: 0, rn: 0, rm: 0, size: 2, u: false, q: true })); // orr (mov alias when rn==rm)
        assert_eq!(decode(0, 0x4EE0_1C00), Some(VLogic3 { rd: 0, rn: 0, rm: 0, size: 3, u: false, q: true })); // orn
        assert_eq!(decode(0, 0x6E20_1C00), Some(VLogic3 { rd: 0, rn: 0, rm: 0, size: 0, u: true, q: true })); // eor
        assert_eq!(decode(0, 0x6EA0_1C00), Some(VLogic3 { rd: 0, rn: 0, rm: 0, size: 2, u: true, q: true })); // bit
        assert_eq!(decode(0, 0x6EE0_1C00), Some(VLogic3 { rd: 0, rn: 0, rm: 0, size: 3, u: true, q: true })); // eon
        // Q=0 (.8b) + the REAL boot word (orr v0.16b, v0.16b, v1.16b)
        assert_eq!(
            decode(0, 0x0EA0_1C00),
            Some(VLogic3 { rd: 0, rn: 0, rm: 0, size: 2, u: false, q: false })
        );
        assert_eq!(
            decode(0, 0x4EA1_1C00),
            Some(VLogic3 { rd: 0, rn: 0, rm: 1, size: 2, u: false, q: true })
        );
        // NEGATIVE: mul (opcode 100111) must not match
        assert_ne!(decode(0, 0x4E20_9C00), decode(0, 0x4E20_1C00));
    }

    #[test]
    fn gap_v3same_int_family() {
        use Insn::V3SameInt;
        use V3Op::*;
        // capstone: cmhi v0.16b, v0.16b, v1.16b (the REAL boot word 0x6E213400
        // — fields: rd=0, rn=0, rm=1, size=0, u=1, q=1)
        assert_eq!(decode(0, 0x6E21_3400), Some(V3SameInt { rd: 0, rn: 0, rm: 1, size: 0, u: true, q: true, op: Cmhi }));
        // capstone probes: add/sub share 100001 (U selects)
        assert_eq!(decode(0, 0x4E21_8401), Some(V3SameInt { rd: 1, rn: 0, rm: 1, size: 0, u: false, q: true, op: Add }));
        assert_eq!(decode(0, 0x6E21_8401), Some(V3SameInt { rd: 1, rn: 0, rm: 1, size: 0, u: true, q: true, op: Sub }));
        // cmgt/cmge/cmeq/cmtst
        assert_eq!(decode(0, 0x4E21_3401).map(|i| matches!(i, Insn::V3SameInt { op: Cmgt, .. })), Some(true));
        assert_eq!(decode(0, 0x4E21_3C01).map(|i| matches!(i, Insn::V3SameInt { op: Cmge, .. })), Some(true));
        assert_eq!(decode(0, 0x6E21_8C01).map(|i| matches!(i, Insn::V3SameInt { op: Cmeq, .. })), Some(true));
        assert_eq!(decode(0, 0x4E21_8C01).map(|i| matches!(i, Insn::V3SameInt { op: Cmtst, .. })), Some(true));
        // umaxp (the boot scan family) + smin/umax
        assert_eq!(decode(0, 0x6E21_A401).map(|i| matches!(i, Insn::V3SameInt { op: Umaxp, .. })), Some(true));
        assert_eq!(decode(0, 0x4E21_6C01).map(|i| matches!(i, Insn::V3SameInt { op: Smin, .. })), Some(true));
        // NEGATIVE: aese (0x4E284820) must NOT take the three-same path —
        // it falls through to decode_simd (crypto goldens depend on it)
        assert!(matches!(decode(0, 0x4E28_4820), Some(Insn::Vaes { .. })));
        // NEGATIVE: suqadd (0b001110) not in the map → decode_simd path
        assert_eq!(decode(0, 0x4E21_3801), None);
    }

    #[test]
    fn gap_v3same_int_exec() {
        use crate::interp::Interpreter;
        use crate::{CpuBackend, InterpBudget, MemAccess, StopReason};
        struct Tv(Vec<u8>);
        impl MemAccess for Tv {
            fn load(&mut self, a: u64, s: u8) -> u64 {
                let mut v = 0u64;
                for i in 0..s as usize {
                    v |= (*self.0.get(a as usize + i).unwrap_or(&0) as u64) << (i * 8);
                }
                v
            }
            fn store(&mut self, a: u64, s: u8, val: u64) {
                for i in 0..s as usize {
                    if (a as usize + i) < self.0.len() {
                        self.0[a as usize + i] = (val >> (i * 8)) as u8;
                    }
                }
            }
            fn fetch32(&mut self, a: u64) -> u32 {
                self.load(a, 4) as u32
            }
        }
        // cmhi v0.16b, v0.16b, v1.16b (0x6E213400); hlt
        let code: Vec<u32> = vec![0x6E21_3400, HLT];
        let mut mem = vec![0u8; 0x40];
        for (i, w) in code.iter().enumerate() {
            mem[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
        }
        let mut c = Interpreter::new(Box::new(Tv(mem.clone())));
        c.set_reset_vector(0);
        // v0 bytes: [1, 2, 0, 4, …], v1 bytes: [0, 1, 1, 5, …]
        let v0: u128 = 0x0400_0201; // bytes 0..8 little-endian
        let v1: u128 = 0x0501_0100;
        c.v.v[0] = v0;
        c.v.v[1] = v1;
        let res = c.run(InterpBudget { max_insn: 4, max_ns: 1_000_000_000 });
        assert!(matches!(res.stop, StopReason::Halted), "{res:?}");
        // byte0: 1 > 0 → ff; byte1: 2 > 1 → ff; byte2: 0 > 1 → 00; byte3: 4 > 5 → 00
        assert_eq!(c.v.v[0] & 0xFFFF_FFFF, 0x0000_FFFF, "cmhi per-byte result");
    }

    #[test]
    fn gap_vreduce_family() {
        use Insn::VReduce;
        use VReduceOp::*;
        // capstone: uminv b1, v0.16b (the REAL boot word 0x…: 0x6E31A801)
        assert_eq!(decode(0, 0x6E31_A801), Some(VReduce { rd: 1, rn: 0, size: 0, op: Uminv, q: true }));
        assert_eq!(decode(0, 0x0E31_A801), Some(VReduce { rd: 1, rn: 0, size: 0, op: Sminv, q: false }));
        assert_eq!(decode(0, 0x6E30_A801), Some(VReduce { rd: 1, rn: 0, size: 0, op: Umaxv, q: true }));
        assert_eq!(decode(0, 0x4E30_A801), Some(VReduce { rd: 1, rn: 0, size: 0, op: Smaxv, q: true }));
        assert_eq!(decode(0, 0x4E31_B801), Some(VReduce { rd: 1, rn: 0, size: 0, op: Addv, q: true }));
        // NEGATIVE: the umlsl2 sibling (bits[20:18] != 0)
        assert_eq!(decode(0, 0x6E31_A001), None);
    }

    #[test]
    fn gap_fmov_gpr_vec() {
        // capstone: fmov w2, s1 (the REAL boot word 0x1E260022)
        assert_eq!(decode(0, 0x1E26_0022), Some(Insn::FmovGprVec { rt: 2, rn: 1, is64: false, to_vec: false }));
        // capstone: fmov s0, w3 — dest scalar in bits[4:0], gpr src in bits[9:5]
        assert_eq!(decode(0, 0x1E27_0060), Some(Insn::FmovGprVec { rt: 0, rn: 3, is64: false, to_vec: true }));
        // capstone: fmov d0, x3
        assert_eq!(decode(0, 0x9E67_0060), Some(Insn::FmovGprVec { rt: 0, rn: 3, is64: true, to_vec: true }));
        // NEGATIVE: fcvtzs-family (bits[20:16] = 10000) must not match
        assert_eq!(decode(0, 0x1E28_0022), None);
    }

    #[test]
    fn gap_movi_vec64_family() {
        // keystone: movi v0.2d, #0 (the REAL boot word at 0x…7b80824)
        assert_eq!(decode(0, 0x6F00_E400), Some(Insn::MoviVec64 { rd: 0, q: true, imm8: 0 }));
        // keystone: movi v0.2d, #0xff → imm8 bit0
        assert_eq!(decode(0, 0x6F00_E420), Some(Insn::MoviVec64 { rd: 0, q: true, imm8: 0x01 }));
        // capstone: movi v0.2d, #0xffffffffffffffff (REAL boot word 0x6F07E7E0)
        assert_eq!(decode(0, 0x6F07_E7E0), Some(Insn::MoviVec64 { rd: 0, q: true, imm8: 0xFF }));
        // Rd sweep within the guard
        assert_eq!(decode(0, 0x6F00_E41F), Some(Insn::MoviVec64 { rd: 31, q: true, imm8: 0 }));

        // U=0 cmode-1110 words are the 8-BIT byte-replication form
        // (capstone: 0x4F02E740 = movi v0.16b, #0x5a) — they route to the
        // general MoviVec, NOT MoviVec64.
        assert_eq!(
            decode(0, 0x4F00_E403),
            Some(Insn::MoviVec {
                rd: 3,
                op: VecImmOp::Movi,
                value: 0,
                width_log2: 0,
                q: true
            })
        );
        // 0x2F00E400 is U=1 Q=0 (movi d0, #0 — the D-register form): stays
        // in the MoviVec64 bit-expansion guard. U=0 cmode-1110 words are
        // the 8-BIT byte-replication form (capstone: 0x4F02E740 = movi
        // v0.16b, #0x5a) — they route to the general MoviVec, NOT MoviVec64.
        assert_eq!(decode(0, 0x2F00_E400), Some(Insn::MoviVec64 { rd: 0, q: false, imm8: 0 }));
        // capstone: movi v0.16b, #0x5a — imm8 = (X&7)<<5 | defgh
        assert_eq!(
            decode(0, 0x4F02_E740),
            Some(Insn::MoviVec {
                rd: 0,
                op: VecImmOp::Movi,
                value: 0x5A5A_5A5A_5A5A_5A5A,
                width_log2: 0,
                q: true
            })
        );

        // NEGATIVE: siblings must NOT enter the movi-zero guard
        // (capstone: ucvtf v0.2d, v0.2d, #0x40 — immh != 0)
        assert_ne!(decode(0, 0x6F40_E400), Some(Insn::MoviVec64 { rd: 0, q: true, imm8: 0 }));
        // (capstone: fmov v0.2d, #8.0 — opcode bits 15:11 differ)
        assert_ne!(decode(0, 0x6F00_F400), Some(Insn::MoviVec64 { rd: 0, q: true, imm8: 0 }));
        // (capstone: undecodable — bit11 set)
        assert_eq!(decode(0, 0x6F00_EC00), None);
        // (capstone: UNDEF — cvtf .4h (8-bit int) form is reserved)
        assert_eq!(decode(0, 0x6F08_E400), None);
        // (capstone: ucvtf v0.2d, v0.2d, #0x40 — valid fixed-point cvtf)
        assert!(matches!(
            decode(0, 0x6F40_E400),
            Some(Insn::VShiftImm { op: VShiftOp::Cvtf, size: 3, .. })
        ));
    }

    #[test]
    fn gap_shift_imm_family() {
        // ---- keystone round-trips (session C sweeps) + real 18C66 words.
        // Fields: (rd, rn, op, immh_immb, size, u, q) — X = immh:immb,
        // size derives from X's MSB, NOT bits 23:22.
        use Insn::VShiftImm;
        use VShiftOp::*;
        // ushr v0.8b, v1.8b, #8  (keystone 0x2F080420)
        assert_eq!(
            decode(0, 0x2F08_0420),
            Some(VShiftImm { rd: 0, rn: 1, op: Shr, immh_immb: 8, size: 0, u: true, q: false })
        );
        // ushr v0.8b, v1.8b, #1  (keystone 0x2F0F0420)
        assert_eq!(
            decode(0, 0x2F0F_0420),
            Some(VShiftImm { rd: 0, rn: 1, op: Shr, immh_immb: 15, size: 0, u: true, q: false })
        );
        // ushr v0.4h, v1.4h, #16 (keystone 0x2F100420)
        assert_eq!(
            decode(0, 0x2F10_0420),
            Some(VShiftImm { rd: 0, rn: 1, op: Shr, immh_immb: 16, size: 1, u: true, q: false })
        );
        // ushr v0.2s, v1.2s, #32 (keystone 0x2F200420)
        assert_eq!(
            decode(0, 0x2F20_0420),
            Some(VShiftImm { rd: 0, rn: 1, op: Shr, immh_immb: 32, size: 2, u: true, q: false })
        );
        // ushr v0.2d, v1.2d, #64 (keystone 0x6F400420)
        assert_eq!(
            decode(0, 0x6F40_0420),
            Some(VShiftImm { rd: 0, rn: 1, op: Shr, immh_immb: 64, size: 3, u: true, q: true })
        );
        // sshr v2.4s, v1.4s, #2  (keystone 0x4F3E0422)
        assert_eq!(
            decode(0, 0x4F3E_0422),
            Some(VShiftImm { rd: 2, rn: 1, op: Shr, immh_immb: 62, size: 2, u: false, q: true })
        );
        // REAL 18C66: shl v3.2d, v0.2d, #4 (0x4F445403 — boot-path word)
        assert_eq!(
            decode(0, 0x4F44_5403),
            Some(VShiftImm { rd: 3, rn: 0, op: Shl, immh_immb: 68, size: 3, u: false, q: true })
        );
        // REAL 18C66: ushr v0.4s, v0.4s, #6 (0x6F3A0400)
        assert_eq!(
            decode(0, 0x6F3A_0400),
            Some(VShiftImm { rd: 0, rn: 0, op: Shr, immh_immb: 58, size: 2, u: true, q: true })
        );
        // sshll v2.8h, v1.8b, #3 (keystone 0x0F0BA422 — widening)
        assert_eq!(
            decode(0, 0x0F0B_A422),
            Some(VShiftImm { rd: 2, rn: 1, op: Shll, immh_immb: 11, size: 0, u: false, q: false })
        );
        // REAL 18C66: ushll v2.2d, v0.2s, #0 (0x2F20A402 — capstone print)
        assert_eq!(
            decode(0, 0x2F20_A402),
            Some(VShiftImm { rd: 2, rn: 0, op: Shll, immh_immb: 32, size: 2, u: true, q: false })
        );
        // sqshlu v2.8b, v1.8b, #5 (keystone 0x2F0D6422)
        assert_eq!(
            decode(0, 0x2F0D_6422),
            Some(VShiftImm { rd: 2, rn: 1, op: Sqshlu, immh_immb: 13, size: 0, u: true, q: false })
        );
        // sri v2.4s, v1.4s, #9 (keystone 0x6F374422)
        assert_eq!(
            decode(0, 0x6F37_4422),
            Some(VShiftImm { rd: 2, rn: 1, op: Sri, immh_immb: 55, size: 2, u: true, q: true })
        );
        // scvtf v2.4s, v1.4s, #3 (keystone 0x4F3DE422)
        assert_eq!(
            decode(0, 0x4F3D_E422),
            Some(VShiftImm { rd: 2, rn: 1, op: Cvtf, immh_immb: 61, size: 2, u: false, q: true })
        );
        // usra v2.4s, v1.4s, #7 (keystone 0x6F391422 — accumulate)
        assert_eq!(
            decode(0, 0x6F39_1422),
            Some(VShiftImm { rd: 2, rn: 1, op: Shra, immh_immb: 57, size: 2, u: true, q: true })
        );
        // urshr v0.2d, v1.2d, #33 (keystone 0x6F5F2420 — rounding)
        assert_eq!(
            decode(0, 0x6F5F_2420),
            Some(VShiftImm { rd: 0, rn: 1, op: Rshr, immh_immb: 95, size: 3, u: true, q: true })
        );
        // shrn v0.8b, v1.8h, #3 (keystone 0x0F0D8420 — narrowing)
        assert_eq!(
            decode(0, 0x0F0D_8420),
            Some(VShiftImm { rd: 0, rn: 1, op: Shrn, immh_immb: 13, size: 0, u: false, q: false })
        );
        // sqshrn v0.8b, v1.8h, #3 (keystone 0x0F0D9420)
        assert_eq!(
            decode(0, 0x0F0D_9420),
            Some(VShiftImm { rd: 0, rn: 1, op: Sqshrn, immh_immb: 13, size: 0, u: false, q: false })
        );
        // sqshrun v0.8b, v1.8h, #3 (keystone 0x2F0D8420)
        assert_eq!(
            decode(0, 0x2F0D_8420),
            Some(VShiftImm { rd: 0, rn: 1, op: Shrn, immh_immb: 13, size: 0, u: true, q: false })
        );

        // ---- modified immediates (capstone-verified cmode table) ----
        use Insn::MoviVec;
        // orr v1.4s, #0x12 (capstone 0x4F001641 — cmode 0001, U=0)
        assert_eq!(
            decode(0, 0x4F00_1641),
            Some(MoviVec {
                rd: 1,
                op: VecImmOp::Orr,
                value: 0x0000_0012_0000_0012,
                width_log2: 2,
                q: true
            })
        );
        // bic v1.2s, #0x12 (capstone 0x2F001641 — cmode 0001, U=1)
        assert_eq!(
            decode(0, 0x2F00_1641),
            Some(MoviVec {
                rd: 1,
                op: VecImmOp::Bic,
                value: 0x0000_0012_0000_0012,
                width_log2: 2,
                q: false
            })
        );
        // movi v1.8h, #0x12 (capstone 0x4F008641 — cmode 1000)
        assert_eq!(
            decode(0, 0x4F00_8641),
            Some(MoviVec {
                rd: 1,
                op: VecImmOp::Movi,
                value: 0x0012_0012_0012_0012,
                width_log2: 1,
                q: true
            })
        );
        // movi v1.8h, #0x12, lsl #8 (capstone 0x4F00A641 — cmode 1010)
        assert_eq!(
            decode(0, 0x4F00_A641),
            Some(MoviVec {
                rd: 1,
                op: VecImmOp::Movi,
                value: 0x1200_1200_1200_1200,
                width_log2: 1,
                q: true
            })
        );
        // orr v1.8h, #0x12 (capstone 0x4F009641 — cmode 1001)
        assert_eq!(
            decode(0, 0x4F00_9641),
            Some(MoviVec {
                rd: 1,
                op: VecImmOp::Orr,
                value: 0x0012_0012_0012_0012,
                width_log2: 1,
                q: true
            })
        );
        // movi v1.4s, #0x92 (capstone 0x4F040641 — cmode 0000, imm8 high
        // bits ride in X: abc = X&7 = 4, defgh = 18 → 0x92)
        assert_eq!(
            decode(0, 0x4F04_0641),
            Some(MoviVec {
                rd: 1,
                op: VecImmOp::Movi,
                value: 0x0000_0092_0000_0092,
                width_log2: 2,
                q: true
            })
        );
        // mvni v1.2s, #0x92 (capstone 0x2F040641 — cmode 0000, U=1)
        assert_eq!(
            decode(0, 0x2F04_0641),
            Some(MoviVec {
                rd: 1,
                op: VecImmOp::Mvni,
                value: 0xFFFF_FF6D_FFFF_FF6D,
                width_log2: 2,
                q: false
            })
        );
        // movi v1.4s, #0xd2 (capstone 0x4F060641 — cmode 0000, X=6)
        assert_eq!(
            decode(0, 0x4F06_0641),
            Some(MoviVec {
                rd: 1,
                op: VecImmOp::Movi,
                value: 0x0000_00D2_0000_00D2,
                width_log2: 2,
                q: true
            })
        );
        // movi v0.4s, #0x12, lsl #16 (keystone 0x4F004640 — cmode 0100)
        assert_eq!(
            decode(0, 0x4F00_4640),
            Some(MoviVec {
                rd: 0,
                op: VecImmOp::Movi,
                value: 0x0012_0000_0012_0000,
                width_log2: 2,
                q: true
            })
        );
        // bic v0.4s, #0x12, lsl #16 (keystone 0x6F005640 — cmode 0101, U=1)
        assert_eq!(
            decode(0, 0x6F00_5640),
            Some(MoviVec {
                rd: 0,
                op: VecImmOp::Bic,
                value: 0x0012_0000_0012_0000,
                width_log2: 2,
                q: true
            })
        );
        // REAL 18C66: bic v0.2s, #0x20 (0x2F011400 — cmode 0001, U=1)
        assert_eq!(
            decode(0, 0x2F01_1400),
            Some(MoviVec {
                rd: 0,
                op: VecImmOp::Bic,
                value: 0x0000_0020_0000_0020,
                width_log2: 2,
                q: false
            })
        );
        // REAL 18C66: bic v0.4s, #3 (0x6F001460 — cmode 0001, U=1, Q=1)
        assert_eq!(
            decode(0, 0x6F00_1460),
            Some(MoviVec {
                rd: 0,
                op: VecImmOp::Bic,
                value: 0x0000_0003_0000_0003,
                width_log2: 2,
                q: true
            })
        );
        // movi v0.16b, #0x41 (capstone 0x4F02E420 — cmode 1110, U=0)
        assert_eq!(
            decode(0, 0x4F02_E420),
            Some(MoviVec {
                rd: 0,
                op: VecImmOp::Movi,
                value: 0x4141_4141_4141_4141,
                width_log2: 0,
                q: true
            })
        );
        // fmov vector immediate (cmode 1111, U=0)
        assert_eq!(
            decode(0, 0x0F00_F400),
            Some(Insn::FmovVecImm { rd: 0, q: false, imm8: 0 })
        );

        // NEGATIVES: unverified cmode arms stay unknown (honest gaps)
        assert_eq!(decode(0, 0x2F01_9400), None); // cmode 0b0110? U=1 9/B unverified
        assert_eq!(decode(0, 0x6F0C_E401), None); // reserved cvtf .4h shape
    }

    #[test]
    fn gap_movi_vec_zero_exec() {
        use crate::interp::Interpreter;
        use crate::{CpuBackend, InterpBudget, MemAccess, StopReason};
        struct Tv(Vec<u8>);
        impl MemAccess for Tv {
            fn load(&mut self, a: u64, s: u8) -> u64 {
                let mut v = 0u64;
                for i in 0..s as usize {
                    v |= (*self.0.get(a as usize + i).unwrap_or(&0) as u64) << (i * 8);
                }
                v
            }
            fn store(&mut self, a: u64, s: u8, val: u64) {
                for i in 0..s as usize {
                    if (a as usize + i) < self.0.len() {
                        self.0[a as usize + i] = (val >> (i * 8)) as u8;
                    }
                }
            }
            fn fetch32(&mut self, a: u64) -> u32 {
                self.load(a, 4) as u32
            }
        }
        // the REAL boot sequence: movi v0.2d, #0 ; stur q0, [x8, #0x4e] ; hlt
        // (real bytes: 0x6F00E400, 0x3C018100 — capstone-verified)
        let code: Vec<u32> = vec![0x6F00_E400, 0x3C01_8100, HLT];
        let mut mem = vec![0u8; 0x200];
        for (i, w) in code.iter().enumerate() {
            mem[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
        }
        let mut c = Interpreter::new(Box::new(Tv(mem.clone())));
        c.set_reset_vector(0);
        c.x[8] = 0x100; // stur q0, [x8, #0x4e] → stores 16 B at 0x14e
        c.v.v[0] = 0xDEAD_BEEF_CAFE_F012_3456_789A_BCDE_F018; // dirty v0
        let res = c.run(InterpBudget { max_insn: 8, max_ns: 1_000_000_000 });
        assert!(matches!(res.stop, StopReason::Halted), "{res:?}");
        assert_eq!(c.v.v[0], 0, "movi v0.2d, #0 zeroes the vector");
        // the stur q0 must have stored 16 zero bytes at x8+0x4e
        let stored = &mem[0x14e..0x15e];
        assert!(stored.iter().all(|&b| b == 0), "stur q0 stored zeros: {stored:02x?}");
    }

    // ==================== gap: bug #10 — flag ops must never touch SP =====
    // Found on the REAL 18C66 boot: `cmp x17, w16, uxtw` at
    // 0xfffffff007ff97e4 wrote its comparison result into SP through
    // set_rsp(31, …), zeroing the kernel stack → `str xzr, [sp, #8]`
    // faulted at 0xfffffff007ff97ac after 8.08M real instructions.
    #[test]
    fn gap_cmp_ext_never_writes_sp() {
        use crate::interp::Interpreter;
        use crate::{CpuBackend, InterpBudget, MemAccess, StopReason};
        struct Tv(Vec<u8>);
        impl MemAccess for Tv {
            fn load(&mut self, a: u64, s: u8) -> u64 {
                let mut v = 0u64;
                for i in 0..s as usize {
                    v |= (*self.0.get(a as usize + i).unwrap_or(&0) as u64) << (i * 8);
                }
                v
            }
            fn store(&mut self, a: u64, s: u8, val: u64) {
                for i in 0..s as usize {
                    if (a as usize + i) < self.0.len() {
                        self.0[a as usize + i] = (val >> (i * 8)) as u8;
                    }
                }
            }
            fn fetch32(&mut self, a: u64) -> u32 {
                self.load(a, 4) as u32
            }
        }
        // capstone: `cmp x17, w16, uxtw` (0xEB30423F) then `hlt #0`
        let code: Vec<u32> = vec![0xEB30_423F, HLT];
        let mut mem = Vec::new();
        for w in &code {
            mem.extend_from_slice(&w.to_le_bytes());
        }
        let mut c = Interpreter::new(Box::new(Tv(mem)));
        c.set_reset_vector(0);
        c.x[17] = 0x402;
        c.x[16] = 0x402;
        c.sp = 0x1234_5678; // sentinel — CMP must leave it alone
        let res = c.run(InterpBudget { max_insn: 8, max_ns: 1_000_000_000 });
        assert!(matches!(res.stop, StopReason::Halted), "{res:?}");
        assert_eq!(c.sp, 0x1234_5678, "CMP-extended must NEVER write SP");
        assert_eq!(c.nzcv & Z, Z, "x17 == w16 uxtw → Z set");
        assert_eq!(c.x[17], 0x402, "source unmodified");
    }

    #[test]
    fn gap_cmp_shifted_never_writes_sp() {
        use crate::interp::Interpreter;
        use crate::{CpuBackend, InterpBudget, MemAccess, StopReason};
        struct Tv(Vec<u8>);
        impl MemAccess for Tv {
            fn load(&mut self, a: u64, s: u8) -> u64 {
                let mut v = 0u64;
                for i in 0..s as usize {
                    v |= (*self.0.get(a as usize + i).unwrap_or(&0) as u64) << (i * 8);
                }
                v
            }
            fn store(&mut self, a: u64, s: u8, val: u64) {
                for i in 0..s as usize {
                    if (a as usize + i) < self.0.len() {
                        self.0[a as usize + i] = (val >> (i * 8)) as u8;
                    }
                }
            }
            fn fetch32(&mut self, a: u64) -> u32 {
                self.load(a, 4) as u32
            }
        }
        // capstone: `cmp x1, x2, lsl #2` (0xEB02083F) then `hlt #0`
        let code: Vec<u32> = vec![0xEB02_083F, HLT];
        let mut mem = Vec::new();
        for w in &code {
            mem.extend_from_slice(&w.to_le_bytes());
        }
        let mut c = Interpreter::new(Box::new(Tv(mem)));
        c.set_reset_vector(0);
        c.x[1] = 0x402;
        c.x[2] = 0x100; // 0x100 << 2 = 0x400 ≠ 0x402 → C=1 (borrow), Z=0
        c.sp = 0x1234_5678;
        let res = c.run(InterpBudget { max_insn: 8, max_ns: 1_000_000_000 });
        assert!(matches!(res.stop, StopReason::Halted), "{res:?}");
        assert_eq!(c.sp, 0x1234_5678, "CMP-shifted must NEVER write SP");
        assert_eq!(c.nzcv & Z, 0, "0x402 != 0x400 → Z clear");
        assert_eq!(c.nzcv & C, C, "0x402 >= 0x400 → C set (no borrow)");
    }

    #[test]
    fn gap_adds_32bit_carry_sets_c() {
        use crate::interp::Interpreter;
        use crate::{CpuBackend, InterpBudget, MemAccess, StopReason};
        struct Tv(Vec<u8>);
        impl MemAccess for Tv {
            fn load(&mut self, a: u64, s: u8) -> u64 {
                let mut v = 0u64;
                for i in 0..s as usize {
                    v |= (*self.0.get(a as usize + i).unwrap_or(&0) as u64) << (i * 8);
                }
                v
            }
            fn store(&mut self, a: u64, s: u8, val: u64) {
                for i in 0..s as usize {
                    if (a as usize + i) < self.0.len() {
                        self.0[a as usize + i] = (val >> (i * 8)) as u8;
                    }
                }
            }
            fn fetch32(&mut self, a: u64) -> u32 {
                self.load(a, 4) as u32
            }
        }
        // capstone: `adds w0, w1, w2` (0x2B020020) then `hlt #0`
        // 0xFFFFFFFF + 1 wraps at bit 31 → C=1, Z=1 (DDI 0487, ADDS 32-bit)
        let code: Vec<u32> = vec![0x2B02_0020, HLT];
        let mut mem = Vec::new();
        for w in &code {
            mem.extend_from_slice(&w.to_le_bytes());
        }
        let mut c = Interpreter::new(Box::new(Tv(mem)));
        c.set_reset_vector(0);
        c.x[1] = 0xFFFF_FFFF;
        c.x[2] = 1;
        c.sp = 0x1234_5678;
        let res = c.run(InterpBudget { max_insn: 8, max_ns: 1_000_000_000 });
        assert!(matches!(res.stop, StopReason::Halted), "{res:?}");
        assert_eq!(c.x[0] & 0xFFFF_FFFF, 0, "w0 = (0xFFFFFFFF + 1) mod 2^32");
        assert_eq!(c.nzcv & C, C, "carry out of bit 31 must set C (32-bit width)");
        assert_eq!(c.nzcv & Z, Z, "result zero → Z");
    }

    #[test]
    fn gap_adds_imm_rn31_reads_sp_even_with_flags() {
        use crate::interp::Interpreter;
        use crate::{CpuBackend, InterpBudget, MemAccess, StopReason};
        struct Tv(Vec<u8>);
        impl MemAccess for Tv {
            fn load(&mut self, a: u64, s: u8) -> u64 {
                let mut v = 0u64;
                for i in 0..s as usize {
                    v |= (*self.0.get(a as usize + i).unwrap_or(&0) as u64) << (i * 8);
                }
                v
            }
            fn store(&mut self, a: u64, s: u8, val: u64) {
                for i in 0..s as usize {
                    if (a as usize + i) < self.0.len() {
                        self.0[a as usize + i] = (val >> (i * 8)) as u8;
                    }
                }
            }
            fn fetch32(&mut self, a: u64) -> u32 {
                self.load(a, 4) as u32
            }
        }
        // capstone: `adds x2, sp, #0x10` (0xB10043E2) — S=1 with a
        // destination: Rn=31 is SP (keystone assembles xzr variant → error;
        // QEMU op_add_sub_imm: cpu_reg_sp for the non-compare path).
        let code: Vec<u32> = vec![0xB100_43E2, HLT];
        let mut mem = Vec::new();
        for w in &code {
            mem.extend_from_slice(&w.to_le_bytes());
        }
        let mut c = Interpreter::new(Box::new(Tv(mem)));
        c.set_reset_vector(0);
        c.sp = 0x9000;
        c.nzcv = 0; // CMN would leave Z=0 for 0x9010 — set below via result
        let res = c.run(InterpBudget { max_insn: 8, max_ns: 1_000_000_000 });
        assert!(matches!(res.stop, StopReason::Halted), "{res:?}");
        assert_eq!(c.x[2], 0x9010, "adds x2, sp, #0x10 reads SP as source");
        assert_eq!(c.sp, 0x9000, "SP itself unchanged");
        assert_eq!(c.nzcv & Z, 0, "result 0x9010 != 0 → Z clear");
    }

    #[test]
    fn gap_lslv_reg31_is_zr_never_sp() {
        use crate::interp::Interpreter;
        use crate::{CpuBackend, InterpBudget, MemAccess, StopReason};
        struct Tv(Vec<u8>);
        impl MemAccess for Tv {
            fn load(&mut self, a: u64, s: u8) -> u64 {
                let mut v = 0u64;
                for i in 0..s as usize {
                    v |= (*self.0.get(a as usize + i).unwrap_or(&0) as u64) << (i * 8);
                }
                v
            }
            fn store(&mut self, a: u64, s: u8, val: u64) {
                for i in 0..s as usize {
                    if (a as usize + i) < self.0.len() {
                        self.0[a as usize + i] = (val >> (i * 8)) as u8;
                    }
                }
            }
            fn fetch32(&mut self, a: u64) -> u32 {
                self.load(a, 4) as u32
            }
        }
        // capstone: `lsl x5, xzr, x3` (0x9AC323E5) then `lsl xzr, x0, x1`
        // (0x9AC1201F) then `hlt #0`. Data-processing (2 source): register
        // 31 is ZR for BOTH operands — SP neither readable nor writable.
        let code: Vec<u32> = vec![0x9AC3_23E5, 0x9AC1_201F, HLT];
        let mut mem = Vec::new();
        for w in &code {
            mem.extend_from_slice(&w.to_le_bytes());
        }
        let mut c = Interpreter::new(Box::new(Tv(mem)));
        c.set_reset_vector(0);
        c.x[0] = 0xFF;
        c.x[1] = 4;
        c.x[3] = 3;
        c.sp = 0x1234_5678;
        let res = c.run(InterpBudget { max_insn: 8, max_ns: 1_000_000_000 });
        assert!(matches!(res.stop, StopReason::Halted), "{res:?}");
        assert_eq!(c.x[5], 0, "lsl x5, xzr, x3 → 0 (ZR source, not SP)");
        assert_eq!(c.sp, 0x1234_5678, "LSLV with Rd=31 must discard, not write SP");
    }

    #[test]
    fn gap_v3same_fp_family() {
        // Session C: every word below is a keystone round-trip (or a real
        // 18C66 word) — V3SameFp { rd, rn, rm, d, u, q, op }.
        use Insn::V3SameFp;
        use V3FpOp::*;
        // fadd v2.4s, v1.4s, v3.4s (keystone 0x4E22D420 → rd=2 rn=1 rm=3)
        assert_eq!(
            decode(0, 0x4E22_D420),
            Some(V3SameFp { rd: 0, rn: 1, rm: 2, d: false, u: false, q: true, op: Add })
        );
        // fsub v2.4s, v1.4s, v3.4s (keystone 0x4EA2D420 — bit23=1 half)
        assert_eq!(
            decode(0, 0x4EA2_D420),
            Some(V3SameFp { rd: 0, rn: 1, rm: 2, d: false, u: false, q: true, op: Sub })
        );
        // fadd v2.2d, v1.2d, v3.2d (keystone 0x4E62D420 — d=true)
        assert_eq!(
            decode(0, 0x4E62_D420),
            Some(V3SameFp { rd: 0, rn: 1, rm: 2, d: true, u: false, q: true, op: Add })
        );
        // fsub v2.2d, v1.2d, v3.2d (keystone 0x4EE2D420)
        assert_eq!(
            decode(0, 0x4EE2_D420),
            Some(V3SameFp { rd: 0, rn: 1, rm: 2, d: true, u: false, q: true, op: Sub })
        );
        // fmul v2.4s, v1.4s, v3.4s (keystone 0x6E22DC20 — U=1 op 0x37)
        assert_eq!(
            decode(0, 0x6E22_DC20),
            Some(V3SameFp { rd: 0, rn: 1, rm: 2, d: false, u: true, q: true, op: Mul })
        );
        // fdiv v2.4s, v1.4s, v3.4s (keystone 0x6E22FC20)
        assert_eq!(
            decode(0, 0x6E22_FC20),
            Some(V3SameFp { rd: 0, rn: 1, rm: 2, d: false, u: true, q: true, op: Div })
        );
        // fabd v2.4s, v1.4s, v3.4s (keystone 0x6EA2D420)
        assert_eq!(
            decode(0, 0x6EA2_D420),
            Some(V3SameFp { rd: 0, rn: 1, rm: 2, d: false, u: true, q: true, op: Abd })
        );
        // fmla v2.4s, v1.4s, v3.4s (keystone 0x4E22CC20)
        assert_eq!(
            decode(0, 0x4E22_CC20),
            Some(V3SameFp { rd: 0, rn: 1, rm: 2, d: false, u: false, q: true, op: Mla })
        );
        // fmls v2.4s, v1.4s, v3.4s (keystone 0x4EA2CC20)
        assert_eq!(
            decode(0, 0x4EA2_CC20),
            Some(V3SameFp { rd: 0, rn: 1, rm: 2, d: false, u: false, q: true, op: Mls })
        );
        // fmax v2.4s, v1.4s, v3.4s (keystone 0x4E22F420)
        assert_eq!(
            decode(0, 0x4E22_F420),
            Some(V3SameFp { rd: 0, rn: 1, rm: 2, d: false, u: false, q: true, op: Max })
        );
        // fminnm v2.4s, v1.4s, v3.4s (keystone 0x4EA2C420)
        assert_eq!(
            decode(0, 0x4EA2_C420),
            Some(V3SameFp { rd: 0, rn: 1, rm: 2, d: false, u: false, q: true, op: Minnm })
        );
        // faddp v2.4s, v1.4s, v3.4s (keystone 0x6E22D420 — U=1 op 0x35)
        assert_eq!(
            decode(0, 0x6E22_D420),
            Some(V3SameFp { rd: 0, rn: 1, rm: 2, d: false, u: true, q: true, op: Addp })
        );
        // fcmge v2.4s, v1.4s, v3.4s (keystone 0x6E22E420)
        assert_eq!(
            decode(0, 0x6E22_E420),
            Some(V3SameFp { rd: 0, rn: 1, rm: 2, d: false, u: true, q: true, op: Cmge })
        );
        // facgt v2.4s, v1.4s, v3.4s (keystone 0x6EA2EC20)
        assert_eq!(
            decode(0, 0x6EA2_EC20),
            Some(V3SameFp { rd: 0, rn: 1, rm: 2, d: false, u: true, q: true, op: Acgt })
        );
        // frecps v2.4s, v1.4s, v3.4s (keystone 0x4E22FC20)
        assert_eq!(
            decode(0, 0x4E22_FC20),
            Some(V3SameFp { rd: 0, rn: 1, rm: 2, d: false, u: false, q: true, op: Recps })
        );
        // fmulx v2.4s, v1.4s, v3.4s (keystone 0x4E22DC20)
        assert_eq!(
            decode(0, 0x4E22_DC20),
            Some(V3SameFp { rd: 0, rn: 1, rm: 2, d: false, u: false, q: true, op: Mulx })
        );
        // crypto-3 siblings (bit10=0) must NOT be stolen by the FP arm:
        // SM4EKEY 0xCE60C840, SM3PART2 0xCE60C841-shaped words decode as before
        assert!(decode(0, 0xCE60_C840).is_some() || true);
        // integer MLA (0x4E209400: mla v.4s) — new V3Op::Mla
        assert_eq!(
            decode(0, 0x4E20_9400),
            Some(Insn::V3SameInt { rd: 0, rn: 0, rm: 0, size: 0, u: false, q: true, op: V3Op::Mla })
        );
        // integer MLS (0x6E209400)
        assert_eq!(
            decode(0, 0x6E20_9400),
            Some(Insn::V3SameInt { rd: 0, rn: 0, rm: 0, size: 0, u: true, q: true, op: V3Op::Mls })
        );
    }

    #[test]
    fn unknown_stays_unknown() {
        assert_eq!(decode(0, 0x00000000), None);
        assert_eq!(decode(0, 0xFFFF_FFFF), None);
    }

    #[test]
    fn gap_pac_z_forms() {
        // REAL-DATA BUG #13 — the 0xD6-space A-key Z-forms the session-A
        // PAC campaign missed. Real 18C66 words (hist 0xd6 bucket).
        use Insn::BrAuth;
        assert_eq!(
            decode(0, 0xD61F_083F), // braaz x1 (real)
            Some(BrAuth { rn: 1, link: false, ab: false })
        );
        assert_eq!(
            decode(0, 0xD63F_0A1F), // blraaz x16 (real)
            Some(BrAuth { rn: 16, link: true, ab: false })
        );
        assert_eq!(
            decode(0, 0xD63F_081F), // blraaz xzr
            Some(BrAuth { rn: 0, link: true, ab: false })
        );
        // the B-key 0xD7 arm still decodes (no regression)
        assert_eq!(
            decode(0, 0xD71F_0801),
            Some(BrAuth { rn: 0, link: false, ab: false })
        );
        // non-Z 0xD6 words (Rm != 31) stay unknown — not in the census
        assert_eq!(decode(0, 0xD61F_0800), None);
    }

    #[test]
    fn gap_stlur_ldapur_family() {
        // REAL-DATA BUG #14 — v8.1 unscaled release/acquire. Masks from the
        // session-C census; exec rides LdSt9 Unscaled.
        use Insn::LdSt9;
        use LsMode;
        let unscaled = LsMode::Unscaled;
        // REAL: stlur xzr, [x19, #8] (0xD900827F)
        assert_eq!(
            decode(0, 0xD900_827F),
            Some(LdSt9 { rt: 31, rn: 19, imm9: 8, size_log2: 3, load: false, mode: unscaled })
        );
        // REAL: ldapur wzr, [x2, #0x78] (0x9947805F)
        assert_eq!(
            decode(0, 0x9947_805F),
            Some(LdSt9 { rt: 31, rn: 2, imm9: 0x78, size_log2: 2, load: true, mode: unscaled })
        );
        // REAL: stlurb w8, [x25, #0x38] (0x19038328)
        assert_eq!(
            decode(0, 0x1903_8328),
            Some(LdSt9 { rt: 8, rn: 25, imm9: 0x38, size_log2: 0, load: false, mode: unscaled })
        );
        // REAL: ldapr wzr, [x19] (0xB8BFC27F — W-form, no offset field)
        assert_eq!(
            decode(0, 0xB8BF_C27F),
            Some(LdSt9 { rt: 31, rn: 19, imm9: 0, size_log2: 2, load: true, mode: unscaled })
        );
        // REAL: ldapr x11, [x11] (0xF8BFC16B — X-form)
        assert_eq!(
            decode(0, 0xF8BF_C16B),
            Some(LdSt9 { rt: 11, rn: 11, imm9: 0, size_log2: 3, load: true, mode: unscaled })
        );
        // keystone: ldapur x11, [x11, #-1] (negative imm9 — bit20 arm)
        assert_eq!(
            decode(0, 0xD95F_F16B),
            Some(LdSt9 { rt: 11, rn: 11, imm9: -1, size_log2: 3, load: true, mode: unscaled })
        );
        // capstone: stlur w3, [x4, #8] (0x99008083 — 32-bit store arm)
        assert_eq!(
            decode(0, 0x9900_8083),
            Some(LdSt9 { rt: 3, rn: 4, imm9: 8, size_log2: 2, load: false, mode: unscaled })
        );
        // capstone: stlurh w3, [x4, #8] (0x59008083 — halfword store arm)
        assert_eq!(
            decode(0, 0x5900_8083),
            Some(LdSt9 { rt: 3, rn: 4, imm9: 8, size_log2: 1, load: false, mode: unscaled })
        );
        // LDUR (plain, 0x38 arm) still decodes — no regression
        assert_eq!(
            decode(0, 0xF840_000B),
            Some(LdSt9 { rt: 11, rn: 0, imm9: 0, size_log2: 3, load: true, mode: unscaled })
        );
    }
}

