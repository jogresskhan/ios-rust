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
    let is64 = w >> 31 == 1;

    // --- Hint NOP (YIELD/WFE/WFI/SEV/SEVL/NOP family) ---
    if (w & 0xFFFF_F01F) == 0xD503_201F {
        return Some(Insn::Nop);
    }
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
    if (w & 0xFFF0_0000) == 0xD510_0000 {
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
            return Some(Insn::CmpImm { rn, imm12, shift, is64 });
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
            return Some(Insn::CmpReg { rn, rm, kind, imm6, is64 });
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

    // --- ORR shifted register — MOV register alias only (honest subset):
    //     sf 01 01010 0000 0 Rm 000000 Rn(=31) Rd  ->  MOV Xd, Xn ---
    if (w >> 24) & 0x1F == 0x0A && (w >> 29) & 0x3 == 0b01 && (w >> 21) & 1 == 0 {
        if reg(w, 5) == 31 && (w >> 10) & 0x3F == 0 && (w >> 22) & 0x3 == 0 {
            return Some(Insn::MovReg { rd: reg(w, 0), rn: reg(w, 16) });
        }
        return None; // general logical-shifted not in subset
    }

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
            (2, 3) => Some(Insn::LdrImmU { rt, rn, imm12, size_log2 }), // LDR Xt
            (3, 3) => Some(Insn::LdrImmU { rt, rn, imm12, size_log2 }), // PRFM as LDR
            _ => None, // LDRSW not in subset
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

    // --- LDP/STP: bits29:25 == 10100, opc 01(32)/10(64) ---
    if (w >> 25) & 0x1F == 0b10100 {
        let is_pair64 = match (w >> 30) & 0x3 {
            0b01 => false,
            0b10 => true,
            _ => return None, // SIMD pairs not in subset
        };
        let load = (w >> 22) & 1 == 1;
        let mode = match (w >> 23) & 0x3 {
            0b00 => PairMode::NonTemporal,
            0b01 => PairMode::Post,
            0b10 => PairMode::Offset,
            _ => PairMode::Pre,
        };
        let imm7 = sext(((w >> 15) & 0x7F) as i64, 7);
        let imm = imm7 * if is_pair64 { 8 } else { 4 };
        let rt = reg(w, 0);
        let rn = reg(w, 5);
        let rt2 = reg(w, 10);
        return Some(if load {
            Insn::Ldp { rt, rt2, rn, imm, mode, is64: is_pair64 }
        } else {
            Insn::Stp { rt, rt2, rn, imm, mode, is64: is_pair64 }
        });
    }

    None
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

    #[test]
    fn unknown_stays_unknown() {
        assert_eq!(decode(0, 0x00000000), None);
        assert_eq!(decode(0, 0xFFFF_FFFF), None);
    }
}

