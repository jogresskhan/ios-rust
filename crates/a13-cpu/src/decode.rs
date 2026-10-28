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
}

/// Decode one 32-bit A64 word. `pc` is the address of the instruction
/// (kept in the signature for API symmetry and future literal-pool work;
/// all PC-relative immediates are stored relative to it).
pub fn decode(_pc: u64, w: u32) -> Option<Insn> {
    let top8 = (w >> 24) & 0xFF;

    // --- Hints / barriers (C6.2 class: 1101 0101 0000 0011 ...) ---
    if w == 0xD5032_01F {
        return Some(Insn::Nop);
    }
    // YIELD/WFE/WFI/SEV/SEVL: hint class, CRm == 0 — modeled as no-ops.
    if (w & 0xFFFFF09F) == 0xD5032081 {
        return Some(Insn::Nop);
    }
    // DSB (op2=100) / DMB (101) / ISB (110), any barrier option (CRm).
    match w & 0xFFFFF0E3 {
        0xD5033_083 => return Some(Insn::Dsb),
        0xD5033_0A3 => return Some(Insn::Dmb),
        0xD5033_0C3 => return Some(Insn::Isb),
        _ => {}
    }

    // --- Unconditional branch (register): ERET/RET/BR/BLR ---
    if (w & 0xFFFF_FC1F) == 0xD65F_0000 {
        return Some(Insn::Ret { rn: reg(w, 5) });
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

    // --- System register access: MRS / MSR (register form) ---
    if (w & 0xFFF0_0000) == 0xD530_0000 {
        return Some(Insn::Mrs { rt: reg(w, 0), sysreg: sysreg_bits(w) });
    }
    if (w & 0xFFF0_0000) == 0xD510_0000 {
        return Some(Insn::Msr { sysreg: sysreg_bits(w), rt: reg(w, 0) });
    }

    // --- Exceptions: SVC/HVC/SMC, HLT ---
    match w & 0xFFE0_001F {
        0xD400_0001 => return Some(Insn::Svc { imm16: ((w >> 5) & 0xFFFF) as u16 }),
        0xD400_0002 => return Some(Insn::Hvc { imm16: ((w >> 5) & 0xFFFF) as u16 }),
        0xD400_0003 => return Some(Insn::Smc { imm16: ((w >> 5) & 0xFFFF) as u16 }),
        _ => {}
    }
    if (w & 0xFFE0_001F) == 0xD440_0000 {
        return Some(Insn::Hlt { imm16: ((w >> 5) & 0xFFFF) as u16 });
    }

    // --- Apple GXF GENTER / GEXIT (Inferno disas_apple_insn) ---
    // Group insn[28:25]==0b0000, insn[31]==0, opcode 5, rn 0/1.
    if (w & 0x0F00_0000) == 0 {
        match w & 0xFFFF_FFE0 {
            0x0000_1420 => return Some(Insn::Genter { rd: reg(w, 0) }),
            0x0000_1400 => return Some(Insn::Gexit { rd: reg(w, 0) }),
            _ => {}
        }
    }

    // --- Move wide immediate: MOVZ/MOVN/MOVK ---
    let opc = (w >> 23) & 0xFF;
    let is64 = w >> 31 == 1;
    let hw = ((w >> 21) & 0x3) as u8;
    match opc {
        0xA5 | 0x25 | 0xE5 => {
            // hw must be ≤ 1 for 32-bit forms (imm16 fits the register).
            if !is64 && hw > 1 {
                return None;
            }
            let fields = (rd: reg(w, 0), imm16: ((w >> 5) & 0xFFFF) as u16, shift: hw);
            return Some(match opc {
                0xA5 => Insn::Movz { rd: fields.rd, imm16: fields.imm16, shift: fields.shift, is64 },
                0x25 => Insn::Movn { rd: fields.rd, imm16: fields.imm16, shift: fields.shift, is64 },
                _ => Insn::Movk { rd: fields.rd, imm16: fields.imm16, shift: fields.shift, is64 },
            });
        }
        _ => {}
    }

    // --- Add/subtract immediate: ADD/SUB/ADDS/SUBS ---
    match opc {
        0x22 | 0x62 | 0xA2 | 0xE2 => {
            let shift = (w >> 22) & 1 == 1;
            let imm12 = (w >> 10) & 0xFFF;
            let rn = reg(w, 5);
            let rd = reg(w, 0);
            let setflags = (w >> 29) & 1 == 1;
            // SUBS with Rd=31 is the CMP alias; decode it as CmpImm.
            if setflags && rd == 31 && opc == 0xE2 {
                return Some(Insn::CmpImm { rn, imm12, shift, is64 });
            }
            return Some(match (opc >> 6) & 1 {
                0 => Insn::AddImm { rd, rn, imm12, shift, setflags, is64 },
                _ => Insn::SubImm { rd, rn, imm12, shift, setflags, is64 },
            });
        }
        _ => {}
    }

    // --- Logical immediate: AND/ORR/EOR/ANDS ---
    match opc {
        0x24 | 0x64 | 0xA4 | 0xE4 => {
            let n = (w >> 22) & 1;
            let immr = (w >> 16) & 0x3F;
            let imms = (w >> 10) & 0x3F;
            let imm = decode_bitmask(n, imms, immr, is64)?;
            let rd = reg(w, 0);
            let rn = reg(w, 5);
            let setflags = (w >> 29) & 1 == 1;
            // ANDS with Rd=31 is the TST alias — same execution, result
            // discarded via the ZR write; no dedicated variant needed.
            return Some(match opc {
                0x24 => Insn::AndImm { rd, rn, imm, setflags, is64 },
                0x64 => Insn::OrrImm { rd, rn, imm, setflags, is64 },
                0xA4 => Insn::EorImm { rd, rn, imm, setflags, is64 },
                _ => Insn::AndImm { rd, rn, imm, setflags: true, is64 },
            });
        }
        _ => {}
    }

    // --- Add/subtract shifted register: ADD/SUB/ADDS/SUBS ---
    match w & 0xFFE0_0000 {
        0x0B00_0000 | 0x2B00_0000 | 0x4B00_0000 | 0x6B00_0000 | 0x8B00_0000 | 0xAB00_0000
        | 0xCB00_0000 | 0xEB00_0000 => {
            let setflags = (w >> 29) & 1 == 1;
            let subtract = (w >> 30) & 1 == 1;
            let is64 = w >> 31 == 1;
            let kind = match (w >> 22) & 0x3 {
                0 => ShiftKind::Lsl,
                1 => ShiftKind::Lsr,
                2 => ShiftKind::Asr,
                _ => return None, // ROR not in the subset
            };
            let imm6 = (w >> 10) & 0x3F;
            if !is64 && imm6 > 31 {
                return None; // unallocated in 32-bit form
            }
            let rd = reg(w, 0);
            let rn = reg(w, 5);
            let rm = reg(w, 16);
            if setflags && rd == 31 && subtract {
                return Some(Insn::CmpReg { rn, rm, kind, imm6, is64 });
            }
            return Some(Insn::AddSubReg { rd, rn, rm, kind, imm6, subtract, setflags, is64 });
        }
        _ => {}
    }

    // --- Unconditional branch (immediate): B / BL ---
    if (w >> 26) & 0x3F == 0x05 {
        return Some(Insn::B { imm: sext((w & 0x03FF_FFFF) as i64, 26) * 2 * 2 });
    }
    if (w >> 26) & 0x3F == 0x25 {
        return Some(Insn::Bl { imm: sext((w & 0x03FF_FFFF) as i64, 26) * 2 * 2 });
    }

    // --- Conditional branch: B.cond ---
    if (w & 0xFF00_0010) == 0x5400_0000 {
        let cond = Cond::from_bits(w & 0xF)?;
        let imm19 = sext(((w >> 5) & 0x7_FFFF) as i64, 19) * 4;
        return Some(Insn::BCond { cond, imm: imm19 });
    }

    // --- Compare / test & branch: CBZ/CBNZ/TBZ/TBNZ ---
    match top8 {
        0x34 | 0x35 | 0xB4 | 0xB5 => {
            let is64 = w >> 31 == 1;
            let rn = reg(w, 0);
            let imm = sext(((w >> 5) & 0x7_FFFF) as i64, 19) * 4;
            return Some(if top8 & 1 == 0 {
                Insn::Cbz { rn, imm, is64 }
            } else {
                Insn::Cbnz { rn, imm, is64 }
            });
        }
        0x36 | 0x37 | 0xB6 | 0xB7 => {
            let bit = (((w >> 31) & 1) << 5 | ((w >> 19) & 0x1F)) as u8;
            let rn = reg(w, 0);
            let imm = sext(((w >> 5) & 0x3FFF) as i64, 14) * 4;
            return Some(if top8 & 1 == 0 {
                Insn::Tbz { rn, bit, imm }
            } else {
                Insn::Tbnz { rn, bit, imm }
            });
        }
        _ => {}
    }

    // --- PC-relative addressing: ADR / ADRP ---
    if (w & 0x1F00_0000) == 0x1000_0000 {
        let immhi = (w >> 5) & 0x7_FFFF;
        let immlo = (w >> 29) & 0x3;
        let imm21 = ((immhi << 2) | immlo) as i64;
        return Some(if w >> 31 == 1 {
            Insn::Adrp { rd: reg(w, 0), imm: sext(imm21, 21) * 4096 }
        } else {
            Insn::Adr { rd: reg(w, 0), imm: sext(imm21, 21) }
        });
    }

    // --- Load/store (unsigned offset): STR/LDR 8/16/32/64 ---
    if (w >> 24) & 0x3F == 0x39 {
        let size_log2 = (w >> 30) & 0x3;
        let opc = (w >> 22) & 0x3;
        let rt = reg(w, 0);
        let rn = reg(w, 5);
        let imm12 = (w >> 10) & 0xFFF;
        return match opc {
            0 => Some(Insn::StrImmU { rt, rn, imm12, size_log2 }),
            1 => Some(Insn::LdrImmU { rt, rn, imm12, size_log2 }),
            _ => None, // LDRSW / PRFM not in subset
        };
    }

    // --- Load literal: LDR (literal) ---
    if (w & 0x3F00_0000) == 0x1800_0000 {
        if (w >> 26) & 1 == 1 {
            return None; // SIMD literal not in subset
        }
        let opc = (w >> 30) & 0x3;
        if opc > 1 {
            return None; // LDRSW not in subset
        }
        return Some(Insn::LdrLit {
            rt: reg(w, 0),
            imm: sext(((w >> 5) & 0x7_FFFF) as i64, 19) * 4,
            is64: opc == 1,
        });
    }

    // --- Load/store pair: LDP/STP/LDNP/STNP ---
    if (w >> 27) & 0x7 == 0x5 && (w >> 30) & 1 == 0 && (w >> 26) & 1 == 0 {
        let is64 = w >> 31 == 1;
        let mode = match (w >> 23) & 0x3 {
            0 => PairMode::NonTemporal,
            1 => PairMode::Post,
            2 => PairMode::Offset,
            _ => PairMode::Pre,
        };
        let scale = if is64 { 8 } else { 4 };
        let imm = sext(((w >> 15) & 0x7F) as i64, 7) * scale;
        let (rt, rt2, rn) = (reg(w, 0), reg(w, 10), reg(w, 5));
        return Some(if (w >> 22) & 1 == 1 {
            Insn::Ldp { rt, rt2, rn, imm, mode, is64 }
        } else {
            Insn::Stp { rt, rt2, rn, imm, mode, is64 }
        });
    }

    // --- MOV (register): ORR Xd, XZR, Xn alias ---
    if (w & 0x7FE0_FFE0) == 0x2A00_03E0 {
        return Some(Insn::MovReg { rd: reg(w, 0), rn: reg(w, 16) });
    }

    // Not in the modeled subset.
    None
}

// ---------------------------------------------------------------------------
// Local bit helpers (no qemu-util dependency).
// ---------------------------------------------------------------------------

/// Extract `w[hi:lo]` (inclusive) as u32.
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
fn sysreg_bits(w: u32) -> u16 {
    let op0 = bits(w, 20, 19) as u16;
    let op1 = bits(w, 18, 16) as u16;
    let crn = bits(w, 15, 12) as u16;
    let crm = bits(w, 11, 8) as u16;
    let op2 = bits(w, 7, 5) as u16;
    (op0 << 14) | (op1 << 12) | (crn << 8) | (crm << 4) | op2
}

/// ARM "DecodeBitMasks(immN, imms, immr, immediate=TRUE)" (DDI 0487
/// C6.2.5 &c.) — expands a logical-immediate encoding into its full
/// replicated 64-bit value. Returns `None` for unallocated encodings.
pub fn decode_bitmask(n: u32, imms: u32, immr: u32, is64: bool) -> Option<u64> {
    // 7-bit value N:NOT(imms); its highest set bit selects element size.
    let imm7 = ((n as u64) << 6) | (!imms as u64 & 0x3F);
    if imm7 == 0 {
        return None; // imms all ones and N=0 → UNDEFINED
    }
    let len = 63 - imm7.leading_zeros(); // 0..=6
    if len == 0 {
        return None;
    }
    let esize = 1u64 << len;
    if esize > 32 && !is64 {
        return None; // 64-bit element in a 32-bit (sf=0) instruction
    }
    let levels = esize - 1;
    let s = imms as u64 & levels;
    let r = immr as u64 & levels;
    if s + 1 > esize {
        return None;
    }
    // welem = ones(S+1) rotated right by R within esize bits.
    let ones = if s == 63 { u64::MAX } else { (1u64 << (s + 1)) - 1 };
    let welem = ones.rotate_right(r as u32) & mask64(esize);
    // Replicate welem across 64 bits.
    let mut imm = 0u64;
    let mut off = 0;
    while off < 64 {
        imm |= welem << off;
        off += esize;
    }
    Some(imm)
}

fn mask64(esize: u64) -> u64 {
    if esize >= 64 {
        u64::MAX
    } else {
        (1u64 << esize) - 1
    }
}

// ---------------------------------------------------------------------------
// Tests — hand-assembled encodings checked against the reference tables.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Small encoder helpers (mirrors used by interp tests live there).
    const fn movz(rd: u8, imm16: u16, hw: u8, is64: bool) -> u32 {
        (if is64 { 0xD280_0000 } else { 0x5280_0000 }) | ((hw as u32) << 21) | ((imm16 as u32) << 5) | rd as u32
    }
    const fn add_imm(rd: u8, rn: u8, imm12: u32, is64: bool) -> u32 {
        (if is64 { 0x9100_0000 } else { 0x1100_0000 }) | (imm12 << 10) | ((rn as u32) << 5) | rd as u32
    }
    const fn subs_imm(rd: u8, rn: u8, imm12: u32, is64: bool) -> u32 {
        (if is64 { 0xF100_0000 } else { 0x7100_0000 }) | (imm12 << 10) | ((rn as u32) << 5) | rd as u32
    }

    #[test]
    fn decode_movz_movk_movn() {
        assert_eq!(
            decode(0, movz(0, 0x1000, 0, true)),
            Some(Insn::Movz { rd: 0, imm16: 0x1000, shift: 0, is64: true })
        );
        assert_eq!(
            decode(0, movz(1, 0x22, 1, true)),
            Some(Insn::Movz { rd: 1, imm16: 0x22, shift: 1, is64: true })
        );
        // movk x1, #0x22, lsl #16
        let movk = 0xF280_0000 | (1 << 21) | (0x22 << 5) | 1;
        assert_eq!(decode(0, movk), Some(Insn::Movk { rd: 1, imm16: 0x22, shift: 1, is64: true }));
        // movn w2, #0x5
        let movn = 0x1280_0000 | (0x5 << 5) | 2;
        assert_eq!(decode(0, movn), Some(Insn::Movn { rd: 2, imm16: 5, shift: 0, is64: false }));
        // 32-bit with hw=2 is unallocated
        assert_eq!(decode(0, movz(2, 5, 2, false)), None);
    }

    #[test]
    fn decode_add_sub_imm_and_cmp() {
        assert_eq!(
            decode(0, add_imm(0, 1, 8, true)),
            Some(Insn::AddImm { rd: 0, rn: 1, imm12: 8, shift: false, setflags: false, is64: true })
        );
        // sub sp, sp, #0x10
        let sub_sp = 0xD100_43FF;
        assert_eq!(
            decode(0, sub_sp),
            Some(Insn::SubImm { rd: 31, rn: 31, imm12: 0x10, shift: false, setflags: false, is64: true })
        );
        // cmp x3, #1 (SUBS XZR)
        assert_eq!(
            decode(0, subs_imm(31, 3, 1, true)),
            Some(Insn::CmpImm { rn: 3, imm12: 1, shift: false, is64: true })
        );
        // adds x0, x1, #2
        let adds = 0xB100_0000 | (2 << 10) | (1 << 5) | 0;
        assert_eq!(
            decode(0, adds),
            Some(Insn::AddImm { rd: 0, rn: 1, imm12: 2, shift: false, setflags: true, is64: true })
        );
    }

    #[test]
    fn decode_add_sub_reg() {
        // add x0, x1, x2, lsl #2
        let w = 0x8B02_0420 | 1 << 5; // rm=2, imm6=2, rn=1, rd=0
        assert_eq!(
            decode(0, w),
            Some(Insn::AddSubReg {
                rd: 0,
                rn: 1,
                rm: 2,
                kind: ShiftKind::Lsl,
                imm6: 2,
                subtract: false,
                setflags: false,
                is64: true
            })
        );
        // cmp x1, x2 (SUBS XZR, x1, x2)
        let w = 0xEB02_003F;
        assert_eq!(decode(0, w), Some(Insn::CmpReg { rn: 1, rm: 2, kind: ShiftKind::Lsl, imm6: 0, is64: true }));
        // ROR not in subset: asr→ok, ror→None
        let ror = 0x8B02_0C20; // shift=11 (ROR)
        assert_eq!(decode(0, ror), None);
    }

    #[test]
    fn decode_logical_imm() {
        // mov x0, #0xFF00FF00FF00FF00 → ORR x0, XZR, #bitmask
        // encoding: ORR x0, xzr, imm: n=1, imms=0b000011(?) — use a simple
        // one: ORR x0, xzr, #0x1 (n=0, immr=0, imms=0b000000 → esize=64,
        // S=0 → welem=1): ORR imm n=0 imms=0 immr=0.
        let w = 0xB200_0000 | (0 << 16) | (0 << 10) | 0;
        assert_eq!(decode(0, w), Some(Insn::OrrImm { rd: 0, rn: 31, imm: 1, setflags: false, is64: true }));
        // ands w2, w3, #0xF (32-bit): n=0, imms=0b000011 (esize=16, S=3),
        // immr=0 → imm = 0x000F.
        let w = 0x7200_0000 | (0b000011 << 10) | (3 << 5) | 2;
        assert_eq!(decode(0, w), Some(Insn::AndImm { rd: 2, rn: 3, imm: 0xF, setflags: true, is64: false }));
        // unallocated bitmask (imms=0x3F, n=0)
        assert_eq!(decode(0, 0x3200_0000 | (0x3F << 10)), None);
    }

    #[test]
    fn decode_bitmask_expansion() {
        // Classic replicated pattern 0xFF00FF00FF00FF00:
        // N=1, imms=0b111000 (S=0x7 → esize=64? no) — use known encoding
        // from mov x0, #0xFF00FF00FF00FF00: n=1, immr=0, imms=0b001110
        // → len=6, esize=64, levels=63, S=0b001110=14, R=0 → welem =
        // ones(15) = 0x7FFF replicated → 0x7FFF7FFF... not our pattern.
        // Simple deterministic checks instead:
        // (n=0, imms=0b000001, immr=0) → esize=32, S=1 → 0b11 replicated
        assert_eq!(decode_bitmask(0, 0b000001, 0, true), Some(0x3333_3333_3333_3333));
        // (n=1, imms=0b111111, immr=0) → invalid? N=1 imms=0x3F → imm7=0b1000000 → len=6, esize=64, S=63 → all ones
        assert_eq!(decode_bitmask(1, 0b111111, 0, true), Some(u64::MAX));
        // 32-bit can't have 64-bit element
        assert_eq!(decode_bitmask(1, 0b000001, 0, false), None);
        // ROR within element: (n=0, imms=0b000001, immr=1, is64) → 0b11 rot 1 in 32 = 0x80000001 replicated
        assert_eq!(decode_bitmask(0, 0b000001, 1, true), Some(0x8000_0001_8000_0001));
    }

    #[test]
    fn decode_branches() {
        // b .+8
        assert_eq!(decode(0, 0x1400_0002), Some(Insn::B { imm: 8 }));
        // b .-4
        assert_eq!(decode(0, 0x17FF_FFFF), Some(Insn::B { imm: -4 }));
        // bl .+0x100
        assert_eq!(decode(0, 0x9400_0040), Some(Insn::Bl { imm: 0x100 }));
        // b.eq .+8
        assert_eq!(decode(0, 0x5400_0080), Some(Insn::BCond { cond: Cond::Eq, imm: 8 }));
        // b.al allowed; b.nv (0xF) rejected
        assert_eq!(decode(0, 0x5400_00AE), Some(Insn::BCond { cond: Cond::Al, imm: 0 }));
        assert_eq!(decode(0, 0x5400_00AF), None);
        // br x2 / blr x3 / ret (default x30) / ret x5
        assert_eq!(decode(0, 0xD61F_0040), Some(Insn::Br { rn: 2 }));
        assert_eq!(decode(0, 0xD63F_0060), Some(Insn::Blr { rn: 3 }));
        assert_eq!(decode(0, 0xD65F_03C0), Some(Insn::Ret { rn: 30 }));
        assert_eq!(decode(0, 0xD65F_00A0), Some(Insn::Ret { rn: 5 }));
        assert_eq!(decode(0, 0xD69F_03E0), Some(Insn::Eret));
    }

    #[test]
    fn decode_cbz_tbz() {
        // cbz x0, .+12
        assert_eq!(decode(0, 0xB400_0060), Some(Insn::Cbz { rn: 0, imm: 12, is64: true }));
        // cbnz w1, .-4
        assert_eq!(decode(0, 0x35FF_FFE1), Some(Insn::Cbnz { rn: 1, imm: -4, is64: false }));
        // tbz x2, #40, .+8  (b5=1, b40=8)
        let w = 0xB600_0000 | (8 << 19) | (1 << 5) | 2;
        assert_eq!(decode(0, w), Some(Insn::Tbz { rn: 2, bit: 40, imm: 8 }));
        // tbnz w3, #5, .-8
        let w = 0x3700_0000 | (5 << 19) | (0x3FFC << 5) | 3;
        assert_eq!(decode(0, w), Some(Insn::Tbnz { rn: 3, bit: 5, imm: -8 }));
    }

    #[test]
    fn decode_adr_adrp() {
        // adr x0, .+0x10 → immlo=0, immhi=4
        let w = 0x1000_0000 | (4 << 5) | 0;
        assert_eq!(decode(0, w), Some(Insn::Adr { rd: 0, imm: 0x10 }));
        // adrp x1, +1 page → immlo=0, immhi=1
        let w = 0x9000_0000 | (1 << 5) | 1;
        assert_eq!(decode(0, w), Some(Insn::Adrp { rd: 1, imm: 0x1000 }));
    }

    #[test]
    fn decode_loads_stores() {
        // ldr x0, [x1] (uimm)
        assert_eq!(decode(0, 0xF940_0020), Some(Insn::LdrImmU { rt: 0, rn: 1, imm12: 0, size_log2: 3 }));
        // ldr w2, [x3, #8] → imm12=2 (scaled by 4)
        assert_eq!(decode(0, 0xB940_1062), Some(Insn::LdrImmU { rt: 2, rn: 3, imm12: 2, size_log2: 2 }));
        // ldrb w4, [x5, #1]
        assert_eq!(decode(0, 0x3940_10A4), Some(Insn::LdrImmU { rt: 4, rn: 5, imm12: 1, size_log2: 0 }));
        // str x6, [sp, #16] → rn=31 (SP)
        assert_eq!(decode(0, 0xF900_0BFF | 6), Some(Insn::StrImmU { rt: 6, rn: 31, imm12: 2, size_log2: 3 }));
        // ldrsw → not in subset
        assert_eq!(decode(0, 0xB980_0020), None);
        // ldr x0, .+8 (literal)
        assert_eq!(decode(0, 0x5800_0040), Some(Insn::LdrLit { rt: 0, imm: 8, is64: true }));
        // ldr s0, .+8 (SIMD literal) → not in subset
        assert_eq!(decode(0, 0x1C00_0040), None);
    }

    #[test]
    fn decode_pairs() {
        // stp x29, x30, [sp, #-16]! (pre-index)
        let w = 0xA980_0000 | (0x7FE << 15) | (31 << 5) | (29 << 0) | (30 << 10);
        assert_eq!(
            decode(0, w),
            Some(Insn::Stp { rt: 29, rt2: 30, rn: 31, imm: -16, mode: PairMode::Pre, is64: true })
        );
        // ldp x0, x1, [sp], #16 (post-index)
        let w = 0xA8C0_0000 | (1 << 15) | (31 << 5) | (1 << 10) | 0;
        assert_eq!(
            decode(0, w),
            Some(Insn::Ldp { rt: 0, rt2: 1, rn: 31, imm: 16, mode: PairMode::Post, is64: true })
        );
        // ldp w0, w1, [x2] (offset, 32-bit, imm=0)
        let w = 0x2940_0000 | (2 << 5) | (1 << 10) | 0;
        assert_eq!(
            decode(0, w),
            Some(Insn::Ldp { rt: 0, rt2: 1, rn: 2, imm: 0, mode: PairMode::Offset, is64: false })
        );
        // SIMD pair → not in subset
        assert_eq!(decode(0, 0xAD40_0000), None);
    }

    #[test]
    fn decode_system_and_exceptions() {
        // mrs x0, CNTVCT_EL0 (3,3,14,0,2)
        let w = 0xD530_0000 | (0b11 << 19) | (0b011 << 16) | (14 << 12) | (0 << 8) | (2 << 5) | 0;
        assert_eq!(decode(0, w), Some(Insn::Mrs { rt: 0, sysreg: crate::isa::CNTVCT_EL0 }));
        // msr SCTLR_EL1, x1 (3,0,1,0,0)
        let w = 0xD510_0000 | (0b11 << 19) | (0 << 16) | (1 << 12) | (0 << 8) | (0 << 5) | 1;
        assert_eq!(decode(0, w), Some(Insn::Msr { sysreg: crate::isa::SCTLR_EL1, rt: 1 }));
        // svc #0x80
        assert_eq!(decode(0, 0xD400_1081), Some(Insn::Svc { imm16: 0x80 }));
        // hvc #0 / smc #0
        assert_eq!(decode(0, 0xD400_0002), Some(Insn::Hvc { imm16: 0 }));
        assert_eq!(decode(0, 0xD400_0003), Some(Insn::Smc { imm16: 0 }));
        // hlt #0xF202 (u-boot style)
        assert_eq!(decode(0, 0xD440_0000 | (0xF202 << 5)), Some(Insn::Hlt { imm16: 0xF202 }));
        // barriers + nop
        assert_eq!(decode(0, 0xD503_201F), Some(Insn::Nop));
        assert_eq!(decode(0, 0xD503_30BF), Some(Insn::Dmb));
        assert_eq!(decode(0, 0xD503_309F), Some(Insn::Dsb));
        assert_eq!(decode(0, 0xD503_30DF), Some(Insn::Isb));
        // wfi → nop
        assert_eq!(decode(0, 0xD503_20DF), Some(Insn::Nop));
    }

    #[test]
    fn decode_apple_gxf_insns() {
        // genter: opcode 5, rn 1 (Inferno disas_apple_insn)
        assert_eq!(decode(0, 0x0000_1420), Some(Insn::Genter { rd: 0 }));
        assert_eq!(decode(0, 0x0000_1421), Some(Insn::Genter { rd: 1 }));
        // gexit: opcode 5, rn 0
        assert_eq!(decode(0, 0x0000_1400), Some(Insn::Gexit { rd: 0 }));
        // Apple group but different opcode (WKdmC: opcode 2) → not ours
        assert_eq!(decode(0, 0x0000_0800), None);
    }

    #[test]
    fn decode_mov_reg_alias() {
        // mov x0, x1 = orr x0, xzr, x1
        let w = 0xAA01_03E0;
        assert_eq!(decode(0, w), Some(Insn::MovReg { rd: 0, rn: 1 }));
        // mov x2, x30
        let w = 0xAA1E_03E0 | 2;
        assert_eq!(decode(0, w), Some(Insn::MovReg { rd: 2, rn: 30 }));
    }

    #[test]
    fn decode_rejects_unknown() {
        // SIMD add v0.4s, v1.4s, v2.4s
        assert_eq!(decode(0, 0x4E20_9020), None);
        // madd x0, x1, x2, x3
        assert_eq!(decode(0, 0x9B02_0000 | (3 << 10) | (2 << 16) | (1 << 5)), None);
        // garbage
        assert_eq!(decode(0, 0xDEAD_BEEF), None);
        assert_eq!(decode(0, 0xFFFF_FFFF), None);
        // udiv
        assert_eq!(decode(0, 0x9AC0_0800), None);
        // csel
        assert_eq!(decode(0, 0x9A82_0000), None);
        // msr (immediate) DAIFSet — not in subset
        assert_eq!(decode(0, 0xD503_42DF), None);
    }

    #[test]
    fn sext_helper() {
        assert_eq!(sext(0x03FF_FFFF, 26), -1);
        assert_eq!(sext(1, 26), 1);
        assert_eq!(sext(0x7FFFF, 19), -1);
    }

    #[allow(dead_code)]
    fn _unused(w: u32) -> u32 {
        bits(w, 31, 0)
    }
}
