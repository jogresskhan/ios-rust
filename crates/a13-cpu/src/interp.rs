//! interp — the A13 interpreter backend (always-built CpuBackend).
//!
//! Executes the [`crate::decode`] subset over a [`MemAccess`] (usually the
//! machine Bus). Unknown words STOP with `StopReason::UnknownInsn` — never
//! silently skipped (matches the lib.rs contract and Inferno's honesty
//! rules). SVC stops with `Panic` (kernel-panic hook); HLT halts cleanly;
//! barriers are no-ops.

use crate::decode::{Cond, Insn, PairMode, ShiftKind};
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
}

pub struct Interpreter {
    pub x: [u64; 31],
    pub pc: u64,
    pub sp: u64,
    pub nzcv: u32, // N Z C V in bits 3..0
    pub halted: bool,
    pub sys: SystemRegs,
    pub gxf_config: u64,
    pub gxf_status: u64,
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
            sys: SystemRegs::default(),
            gxf_config: 0,
            gxf_status: 0,
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
        }
        self.pc = pc + 4;
        Ok(())
    }

    fn read_sysreg(&mut self, enc: u16) -> u64 {
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
            _ => {
                self.unknown_sysreg_reads += 1;
                0
            }
        }
    }

    fn write_sysreg(&mut self, enc: u16, v: u64) {
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
