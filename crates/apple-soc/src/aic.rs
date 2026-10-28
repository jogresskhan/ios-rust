//! aic — Apple Interrupt Controller (AIC v2), T8030.
//!
//! Faithful Rust port of ChefKiss Inferno `hw/intc/apple_aic.c`
//! (AGPL-3.0, © 2024-2026 Visual Ehrmanntraut, Christian Inci).
//!
//! Register offsets and the IRQ/IPI state machine match the C exactly:
//! the EIR bitmap words, the destination masks, the per-CPU IPI state and
//! the IACK arbitration order (lowest-numbered unmasked pending IRQ first —
//! `find_next_bit32` from 0, *not* highest-first).
//!
//! Simplifications (documented deviations):
//! * one `Aic` instance serves every CPU view; `current_cpu` selects the
//!   CPU for WHOAMI/IACK/IPI just like QEMU's per-CPU MemoryRegions did.
//! * the `Pn` per-CPU alias window (0x5000..) is translated into the
//!   global window exactly like the C (`addr - 0x5000 + 0x2000 - 0x80*cpu`).
//! * unimplemented reads return 0 (contract) instead of the C's
//!   `(uint64_t)-1`; misses are counted in `unknown_reads`.
//! * IRQ output lines live in [`vm_core::IrqState`] (line N = CPU N)
//!   instead of qemu_irq; `update()` runs after writes and on tick.

use std::collections::BTreeMap;

use vm_core::{Device, IrqState};

/// IRQ count (hardcoded for T8030 in the C as well).
pub const AIC_INT_COUNT: u32 = 576;
/// T8030 has 6 CPUs (P-cores + E-cores, minus SEP when present — the
/// machine passes the real count; 6 is the C's `AIC_CPU_COUNT`).
pub const AIC_CPU_COUNT: u32 = 6;
pub const AIC_VERSION: u32 = 2;

pub const REG_AIC_REV: u64 = 0x0000;
pub const REG_AIC_CAP0: u64 = 0x0004;
pub const REG_AIC_CAP1: u64 = 0x0008;
pub const REG_AIC_RST: u64 = 0x000C;

pub const REG_AIC_GLB_CFG: u64 = 0x0010;
pub const AIC_GLBCFG_IEN: u32 = 1 << 0;
pub const AIC_GLBCFG_AEWT: u32 = 0xF << 4;
pub const AIC_GLBCFG_SEWT: u32 = 0xF << 8;
pub const AIC_GLBCFG_AIWT: u32 = 0xF << 12;
pub const AIC_GLBCFG_SIWT: u32 = 0xF << 16;
pub const AIC_GLBCFG_SYNC_ACG: u32 = 1 << 29;
pub const AIC_GLBCFG_EIR_ACG: u32 = 1 << 30;
pub const AIC_GLBCFG_REG_ACG: u32 = 1 << 31;

pub const REG_AIC_WHOAMI: u64 = 0x2000;
pub const REG_AIC_IACK: u64 = 0x2004;
pub const REG_AIC_IPI_SET: u64 = 0x2008;
pub const REG_AIC_IPI_CLR: u64 = 0x200C;
pub const AIC_IPI_NORMAL: u32 = 1 << 0;
pub const AIC_IPI_SELF: u32 = 1 << 31;
pub const REG_AIC_IPI_MASK_SET: u64 = 0x2024;
pub const REG_AIC_IPI_MASK_CLR: u64 = 0x2028;
pub const REG_AIC_IPI_DEFER_SET: u64 = 0x202C;
pub const REG_AIC_IPI_DEFER_CLR: u64 = 0x2030;

pub const REG_AIC_EIR_DEST_BASE: u64 = 0x3000; // + n*4
pub const REG_AIC_EIR_SW_SET_BASE: u64 = 0x4000; // + n*4
pub const REG_AIC_EIR_SW_CLR_BASE: u64 = 0x4080; // + n*4
pub const REG_AIC_EIR_MASK_SET_BASE: u64 = 0x4100; // + n*4
pub const REG_AIC_EIR_MASK_CLR_BASE: u64 = 0x4180; // + n*4
pub const REG_AIC_EIR_INT_RO_BASE: u64 = 0x4200; // + n*4

pub const REG_AIC_WHOAMI_PN_BASE: u64 = 0x5000; // + n*0x80, sub 0x00
pub const REG_AIC_IACK_PN: u64 = 0x5004; // + n*0x80
pub const REG_AIC_IPI_SET_PN: u64 = 0x5008; // + n*0x80
pub const REG_AIC_IPI_CLR_PN: u64 = 0x500C; // + n*0x80
pub const REG_AIC_IPI_MASK_SET_PN: u64 = 0x5024; // + n*0x80
pub const REG_AIC_IPI_MASK_CLR_PN: u64 = 0x5028; // + n*0x80
pub const REG_AIC_IPI_DEFER_SET_PN: u64 = 0x502C; // + n*0x80
pub const REG_AIC_IPI_DEFER_CLR_PN: u64 = 0x5030; // + n*0x80

// IACK return vectors.
pub const K_AIC_INT_SPURIOUS: u32 = 0x00000;
pub const K_AIC_INT_EXT: u32 = 0x10000;
pub const K_AIC_INT_IPI: u32 = 0x40000;
pub const K_AIC_INT_IPI_NORM: u32 = 0x40001;
pub const K_AIC_INT_IPI_SELF: u32 = 0x40002;

pub const K_AIC_MAX_EXTID: u32 = AIC_INT_COUNT;
pub const K_AIC_VEC_IPI: u32 = K_AIC_MAX_EXTID;
pub const K_AIC_NUM_INTS: u32 = K_AIC_VEC_IPI + 1;
pub const K_AIC_NUM_EIRS: u32 = AIC_INT_COUNT >> 5;

pub const K_AICWT: u64 = 64000; // ns; the C's AIC poll timer period
const K_CNTFRQ: u64 = 24_000_000;

#[derive(Debug, Default, Clone)]
struct AicCpu {
    ipi_mask: u32,
    pending_ipi: u32,
    deferred_ipi: u32,
}

/// Apple AIC v2 (T8030).
#[derive(Debug)]
pub struct Aic {
    pub num_cpu: u32,
    pub num_irq: u32,
    pub num_eir: u32,
    /// CPU the WHOAMI/IACK/IPI registers act on (QEMU per-CPU region).
    pub current_cpu: u32,
    /// Offset of the shared timebase relative to the AIC base (the C's
    /// `time_base` = timebase_node.reg - aic_node.reg).
    pub time_base: u64,
    pub global_cfg: u32,
    eir_state: Vec<u32>,
    eir_mask: Vec<u32>,
    eir_dest: Vec<u32>,
    cpus: Vec<AicCpu>,
    /// IRQ line per CPU (index = CPU id) after the last `update()`.
    pub irq_lines: IrqState,
    pub last_iack: u32,
    /// Virtual clock captured by [`Device::tick`].
    now_ns: u64,
    pub unknown_reads: u64,
    pub unknown_writes: u64,
}

// qemu/bitops.h equivalents over u32 words.
fn test_bit32(words: &[u32], n: u32) -> bool {
    (words[(n >> 5) as usize] >> (n & 31)) & 1 != 0
}
fn set_bit32(words: &mut [u32], n: u32) {
    words[(n >> 5) as usize] |= 1 << (n & 31);
}
fn clear_bit32(words: &mut [u32], n: u32) {
    words[(n >> 5) as usize] &= !(1 << (n & 31));
}
/// find_next_bit32: first set bit >= start, else `limit`.
fn find_next_bit32(words: &[u32], limit: u32, start: u32) -> u32 {
    let mut n = start;
    while n < limit {
        if test_bit32(words, n) {
            return n;
        }
        n += 1;
    }
    limit
}
fn find_first_bit32(words: &[u32], limit: u32) -> u32 {
    find_next_bit32(words, limit, 0)
}

impl Aic {
    pub fn new(num_cpu: u32) -> Self {
        let num_eir = K_AIC_NUM_EIRS;
        let num_irq = num_eir * 32;
        let mut aic = Aic {
            num_cpu,
            num_irq,
            num_eir,
            current_cpu: 0,
            time_base: 0,
            global_cfg: 0,
            eir_state: vec![0; num_eir as usize],
            eir_mask: vec![0; num_eir as usize],
            eir_dest: vec![0; num_irq as usize],
            cpus: vec![AicCpu::default(); num_cpu as usize],
            irq_lines: IrqState::new(),
            last_iack: 0,
            now_ns: 0,
            unknown_reads: 0,
            unknown_writes: 0,
        };
        aic.reset();
        aic
    }

    /// Legacy reset (the C's `apple_aic_reset`): mask all IRQs, clear
    /// destinations, mask all IPIs.
    pub fn reset(&mut self) {
        self.eir_mask.iter_mut().for_each(|w| *w = 0xFFFF_FFFF);
        self.eir_dest.iter_mut().for_each(|w| *w = 0);
        for cpu in &mut self.cpus {
            cpu.ipi_mask = AIC_IPI_NORMAL | AIC_IPI_SELF;
            cpu.pending_ipi = 0;
            cpu.deferred_ipi = 0;
        }
    }

    /// qdev gpio-in: `apple_aic_set_irq`.
    pub fn set_irq_input(&mut self, irq: u32, level: bool) {
        if irq >= self.num_irq {
            return;
        }
        if level {
            set_bit32(&mut self.eir_state, irq);
        } else {
            clear_bit32(&mut self.eir_state, irq);
        }
    }

    /// Public input used by the machine when lines come from `IrqState`.
    pub fn feed(&mut self, ext: &IrqState) {
        for (&num, &level) in &ext.levels {
            self.set_irq_input(num, level);
        }
    }

    /// The C's `apple_aic_update`: fold deferred IPIs, arbitrate EIRs
    /// across CPUs, drive the per-CPU IRQ output lines.
    pub fn update(&mut self) {
        let mut intr: u32 = 0;
        let mut potential: u32 = 0;

        for cpu in &mut self.cpus {
            cpu.pending_ipi |= cpu.deferred_ipi;
            cpu.deferred_ipi = 0;
        }

        for (i, cpu) in self.cpus.iter().enumerate() {
            if (cpu.pending_ipi & AIC_IPI_SELF) & !cpu.ipi_mask != 0 {
                intr |= 1 << i;
            }
            if !cpu.ipi_mask & AIC_IPI_NORMAL != 0
                && cpu.pending_ipi & ((1u32 << self.num_cpu) - 1) != 0
            {
                intr |= 1 << i;
            }
        }

        let mut i: i64 = -1;
        loop {
            let next = find_next_bit32(&self.eir_state, self.num_irq, (i + 1) as u32);
            if next >= self.num_irq {
                break;
            }
            i = next as i64;
            let dest = self.eir_dest[next as usize];
            if !test_bit32(&self.eir_mask, next) && dest != 0 {
                if intr & dest == 0 {
                    // The interrupt doesn't have a CPU that can process it yet.
                    let cpu = dest.trailing_zeros().min(self.num_cpu - 1);
                    intr |= 1 << cpu;
                    potential |= dest;
                } else {
                    for k in 0..self.num_cpu {
                        if intr & (1 << k) == 0 && potential & (1 << k) != 0 {
                            intr |= 1 << k;
                            break;
                        }
                    }
                }
            }
        }

        let mut levels: BTreeMap<u32, bool> = self.irq_lines.levels.clone();
        for cpu in 0..self.num_cpu {
            levels.insert(cpu, intr & (1 << cpu) != 0);
        }
        self.irq_lines.levels = levels;
        self.irq_lines.pending = self.irq_lines.levels.values().any(|&l| l);
    }

    /// The C's `apple_aic_emulate_timer` (24 MHz shared counter).
    fn emulate_timer(&self) -> u64 {
        let period_ns = if 1_000_000_000u64 > K_CNTFRQ {
            1_000_000_000 / K_CNTFRQ
        } else {
            1
        };
        self.now_ns / period_ns
    }

    fn cpu_mut(&mut self, cpu: u32) -> Option<&mut AicCpu> {
        self.cpus.get_mut(cpu as usize)
    }

    /// Global-window write (`addr` already re-based for the Pn alias).
    fn write_global(&mut self, addr: u64, val: u32) {
        match addr {
            REG_AIC_RST => self.reset(),
            REG_AIC_GLB_CFG => self.global_cfg = val,
            REG_AIC_IPI_SET => {
                let cpu_id = self.current_cpu;
                for i in 0..self.num_cpu {
                    if val & (1 << i) != 0 {
                        self.cpus[i as usize].pending_ipi |= 1 << cpu_id;
                    }
                }
                if val & AIC_IPI_SELF != 0 {
                    if let Some(o) = self.cpu_mut(cpu_id) {
                        o.pending_ipi |= AIC_IPI_SELF;
                    }
                }
                self.update();
            }
            REG_AIC_IPI_CLR => {
                let cpu_id = self.current_cpu;
                for i in 0..self.num_cpu {
                    if val & (1 << i) != 0 {
                        self.cpus[i as usize].pending_ipi &= !(1 << cpu_id);
                    }
                }
                if val & AIC_IPI_SELF != 0 {
                    if let Some(o) = self.cpu_mut(cpu_id) {
                        o.pending_ipi &= !AIC_IPI_SELF;
                    }
                }
                self.update();
            }
            REG_AIC_IPI_MASK_SET => {
                if let Some(o) = self.cpu_mut(self.current_cpu) {
                    o.ipi_mask |= val & (AIC_IPI_NORMAL | AIC_IPI_SELF);
                }
            }
            REG_AIC_IPI_MASK_CLR => {
                if let Some(o) = self.cpu_mut(self.current_cpu) {
                    o.ipi_mask &= !(val & (AIC_IPI_NORMAL | AIC_IPI_SELF));
                }
            }
            REG_AIC_IPI_DEFER_SET => {
                let cpu_id = self.current_cpu;
                for i in 0..self.num_cpu {
                    if val & (1 << i) != 0 {
                        self.cpus[i as usize].deferred_ipi |= 1 << cpu_id;
                    }
                }
                if val & AIC_IPI_SELF != 0 {
                    if let Some(o) = self.cpu_mut(cpu_id) {
                        o.deferred_ipi |= AIC_IPI_SELF;
                    }
                }
                self.update();
            }
            REG_AIC_IPI_DEFER_CLR => {
                let cpu_id = self.current_cpu;
                for i in 0..self.num_cpu {
                    if val & (1 << i) != 0 {
                        self.cpus[i as usize].deferred_ipi &= !(1 << cpu_id);
                    }
                }
                if val & AIC_IPI_SELF != 0 {
                    if let Some(o) = self.cpu_mut(cpu_id) {
                        o.deferred_ipi &= !AIC_IPI_SELF;
                    }
                }
                self.update();
            }
            REG_AIC_EIR_DEST_BASE..=REG_AIC_EIR_DEST_BASE + AIC_INT_COUNT * 4 => {
                let vector = (addr - REG_AIC_EIR_DEST_BASE) / 4;
                if (vector as u32) < self.num_irq {
                    self.eir_dest[vector as usize] = val;
                }
            }
            REG_AIC_EIR_SW_SET_BASE..=REG_AIC_EIR_SW_SET_BASE + K_AIC_NUM_EIRS * 4 => {
                let eir = (addr - REG_AIC_EIR_SW_SET_BASE) / 4;
                if (eir as u32) < self.num_eir {
                    self.eir_state[eir as usize] |= val;
                    self.update();
                }
            }
            REG_AIC_EIR_SW_CLR_BASE..=REG_AIC_EIR_SW_CLR_BASE + K_AIC_NUM_EIRS * 4 => {
                let eir = (addr - REG_AIC_EIR_SW_CLR_BASE) / 4;
                if (eir as u32) < self.num_eir {
                    self.eir_state[eir as usize] &= !val;
                    self.update();
                }
            }
            REG_AIC_EIR_MASK_SET_BASE
                ..=REG_AIC_EIR_MASK_SET_BASE + K_AIC_NUM_EIRS * 4 => {
                let eir = (addr - REG_AIC_EIR_MASK_SET_BASE) / 4;
                if (eir as u32) < self.num_eir {
                    self.eir_mask[eir as usize] |= val;
                    self.update();
                }
            }
            REG_AIC_EIR_MASK_CLR_BASE
                ..=REG_AIC_EIR_MASK_CLR_BASE + K_AIC_NUM_EIRS * 4 => {
                let eir = (addr - REG_AIC_EIR_MASK_CLR_BASE) / 4;
                if (eir as u32) < self.num_eir {
                    self.eir_mask[eir as usize] &= !val;
                    self.update();
                }
            }
            _ => self.unknown_writes += 1,
        }
    }

    /// Global-window read (`addr` already re-based for the Pn alias).
    fn read_global(&mut self, addr: u64) -> u64 {
        match addr {
            REG_AIC_REV => AIC_VERSION as u64,
            REG_AIC_CAP0 => {
                (((self.num_cpu - 1) as u64) << 16) | self.num_irq as u64
            }
            REG_AIC_GLB_CFG => self.global_cfg as u64,
            REG_AIC_WHOAMI => self.current_cpu as u64,
            REG_AIC_IACK => {
                // qemu_irq_lower(o->irq) — lines are recomputed below.
                let cpu_id = self.current_cpu;
                let mut result: u32;
                let o = &self.cpus[cpu_id as usize];
                if o.pending_ipi & AIC_IPI_SELF & !o.ipi_mask != 0 {
                    self.cpus[cpu_id as usize].ipi_mask |= AIC_IPI_SELF;
                    result = K_AIC_INT_IPI | K_AIC_INT_IPI_SELF;
                } else if !o.ipi_mask & AIC_IPI_NORMAL != 0
                    && o.pending_ipi & ((1u32 << self.num_cpu) - 1) != 0
                {
                    self.cpus[cpu_id as usize].ipi_mask |= AIC_IPI_NORMAL;
                    result = K_AIC_INT_IPI | K_AIC_INT_IPI_NORM;
                } else {
                    result = K_AIC_INT_SPURIOUS;
                    let mut i: i64 = -1;
                    loop {
                        let next =
                            find_next_bit32(&self.eir_state, self.num_irq, (i + 1) as u32);
                        if next >= self.num_irq {
                            break;
                        }
                        i = next as i64;
                        if !test_bit32(&self.eir_mask, next)
                            && self.eir_dest[next as usize] & (1 << cpu_id) != 0
                        {
                            set_bit32(&mut self.eir_mask, next);
                            result = K_AIC_INT_EXT | (next & 0x3FF);
                            break;
                        }
                    }
                }
                self.last_iack = result;
                self.update();
                result as u64
            }
            REG_AIC_IPI_MASK_SET | REG_AIC_IPI_MASK_CLR => {
                self.cpus[self.current_cpu as usize].ipi_mask as u64
            }
            REG_AIC_EIR_DEST_BASE..=REG_AIC_EIR_DEST_BASE + AIC_INT_COUNT * 4 => {
                let vector = (addr - REG_AIC_EIR_DEST_BASE) / 4;
                if (vector as u32) < self.num_irq {
                    self.eir_dest[vector as usize] as u64
                } else {
                    self.unknown_reads += 1;
                    0
                }
            }
            REG_AIC_EIR_MASK_SET_BASE
                ..=REG_AIC_EIR_MASK_SET_BASE + K_AIC_NUM_EIRS * 4 => {
                let eir = (addr - REG_AIC_EIR_MASK_SET_BASE) / 4;
                if (eir as u32) < self.num_eir {
                    self.eir_mask[eir as usize] as u64
                } else {
                    self.unknown_reads += 1;
                    0
                }
            }
            REG_AIC_EIR_MASK_CLR_BASE
                ..=REG_AIC_EIR_MASK_CLR_BASE + K_AIC_NUM_EIRS * 4 => {
                let eir = (addr - REG_AIC_EIR_MASK_CLR_BASE) / 4;
                if (eir as u32) < self.num_eir {
                    self.eir_mask[eir as usize] as u64
                } else {
                    self.unknown_reads += 1;
                    0
                }
            }
            REG_AIC_EIR_INT_RO_BASE..=REG_AIC_EIR_INT_RO_BASE + K_AIC_NUM_EIRS * 4 => {
                let eir = (addr - REG_AIC_EIR_INT_RO_BASE) / 4;
                if (eir as u32) < self.num_eir {
                    self.eir_state[eir as usize] as u64
                } else {
                    self.unknown_reads += 1;
                    0
                }
            }
            _ => {
                if addr == self.time_base + 0x20 {
                    self.emulate_timer() & 0xFFFF_FFFF
                } else if addr == self.time_base + 0x28 {
                    (self.emulate_timer() >> 32) & 0xFFFF_FFFF
                } else {
                    self.unknown_reads += 1;
                    0
                }
            }
        }
    }

    /// Translate a Pn (per-CPU alias) offset into the global window,
    /// exactly like the C: `addr - 0x5000 + 0x2000 - 0x80*cpu`.
    fn pn_rebase(&mut self, addr: u64) -> Option<(u32, u64)> {
        if !(REG_AIC_WHOAMI_PN_BASE..=REG_AIC_WHOAMI_PN_BASE + AIC_CPU_COUNT * 0x80 - 4)
            .contains(&addr)
        {
            return None;
        }
        let cpu = ((addr - 0x5000) / 0x80) as u32;
        if cpu >= self.num_cpu {
            return None;
        }
        Some((cpu, addr - 0x5000 + 0x2000 - 0x80 * cpu as u64))
    }
}

impl Device for Aic {
    fn name(&self) -> &'static str {
        "aic"
    }

    fn read(&mut self, off: u64, _size: u8) -> u64 {
        if let Some((cpu, rebased)) = self.pn_rebase(off) {
            self.current_cpu = cpu;
            return self.read_global(rebased);
        }
        self.read_global(off)
    }

    fn write(&mut self, off: u64, _size: u8, val: u64) {
        let val = val as u32;
        if let Some((cpu, rebased)) = self.pn_rebase(off) {
            self.current_cpu = cpu;
            self.write_global(rebased, val);
            return;
        }
        self.write_global(off, val);
    }

    fn tick(&mut self, now_ns: u64) {
        self.now_ns = now_ns;
        self.update();
    }
}

/// The `ios-rust verify` parity walk: ported register map.
pub fn regs_documented() -> &'static [(&'static str, u64)] {
    &[
        ("REG_AIC_REV", REG_AIC_REV),
        ("REG_AIC_CAP0", REG_AIC_CAP0),
        ("REG_AIC_CAP1", REG_AIC_CAP1),
        ("REG_AIC_RST", REG_AIC_RST),
        ("REG_AIC_GLB_CFG", REG_AIC_GLB_CFG),
        ("REG_AIC_WHOAMI", REG_AIC_WHOAMI),
        ("REG_AIC_IACK", REG_AIC_IACK),
        ("REG_AIC_IPI_SET", REG_AIC_IPI_SET),
        ("REG_AIC_IPI_CLR", REG_AIC_IPI_CLR),
        ("REG_AIC_IPI_MASK_SET", REG_AIC_IPI_MASK_SET),
        ("REG_AIC_IPI_MASK_CLR", REG_AIC_IPI_MASK_CLR),
        ("REG_AIC_IPI_DEFER_SET", REG_AIC_IPI_DEFER_SET),
        ("REG_AIC_IPI_DEFER_CLR", REG_AIC_IPI_DEFER_CLR),
        ("REG_AIC_EIR_DEST(0)", REG_AIC_EIR_DEST_BASE),
        ("REG_AIC_EIR_SW_SET(0)", REG_AIC_EIR_SW_SET_BASE),
        ("REG_AIC_EIR_SW_CLR(0)", REG_AIC_EIR_SW_CLR_BASE),
        ("REG_AIC_EIR_MASK_SET(0)", REG_AIC_EIR_MASK_SET_BASE),
        ("REG_AIC_EIR_MASK_CLR(0)", REG_AIC_EIR_MASK_CLR_BASE),
        ("REG_AIC_EIR_INT_RO(0)", REG_AIC_EIR_INT_RO_BASE),
        ("REG_AIC_WHOAMI_Pn(0)", REG_AIC_WHOAMI_PN_BASE),
        ("REG_AIC_IACK_Pn(0)", REG_AIC_IACK_PN),
        ("REG_AIC_IPI_SET_Pn(0)", REG_AIC_IPI_SET_PN),
        ("REG_AIC_IPI_CLR_Pn(0)", REG_AIC_IPI_CLR_PN),
        ("REG_AIC_IPI_MASK_SET_Pn(0)", REG_AIC_IPI_MASK_SET_PN),
        ("REG_AIC_IPI_MASK_CLR_Pn(0)", REG_AIC_IPI_MASK_CLR_PN),
        ("REG_AIC_IPI_DEFER_SET_Pn(0)", REG_AIC_IPI_DEFER_SET_PN),
        ("REG_AIC_IPI_DEFER_CLR_Pn(0)", REG_AIC_IPI_DEFER_CLR_PN),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iack_returns_lowest_pending_and_acks() {
        let mut aic = Aic::new(AIC_CPU_COUNT);
        aic.eir_dest[5] = 1; // IRQ 5 -> CPU 0
        aic.eir_dest[7] = 1; // IRQ 7 -> CPU 0
        aic.set_irq_input(7, true);
        aic.set_irq_input(5, true);
        aic.update();

        aic.current_cpu = 0;
        let v = aic.read(REG_AIC_IACK, 4) as u32;
        assert_eq!(v, K_AIC_INT_EXT | 5, "lowest-numbered pending IRQ wins");
        // IACK masks the line (level ack) — second IACK gets the next one.
        let v2 = aic.read(REG_AIC_IACK, 4) as u32;
        assert_eq!(v2, K_AIC_INT_EXT | 7);
        let v3 = aic.read(REG_AIC_IACK, 4) as u32;
        assert_eq!(v3, K_AIC_INT_SPURIOUS);
    }

    #[test]
    fn mask_blocks_delivery() {
        let mut aic = Aic::new(AIC_CPU_COUNT);
        aic.eir_dest[10] = 1;
        aic.set_irq_input(10, true);
        // All lines start masked after reset.
        aic.update();
        assert!(!aic.irq_lines.levels[&0]);
        // Unmask word 0 bits 10.
        aic.write(REG_AIC_EIR_MASK_CLR_BASE, 4, 1 << 10);
        assert!(aic.irq_lines.levels[&0]);
    }

    #[test]
    fn sw_set_clr_and_int_ro() {
        let mut aic = Aic::new(AIC_CPU_COUNT);
        aic.write(REG_AIC_EIR_SW_SET_BASE, 4, 0x3);
        assert_eq!(aic.read(REG_AIC_EIR_INT_RO_BASE, 4) as u32, 0x3);
        aic.write(REG_AIC_EIR_SW_CLR_BASE, 4, 0x1);
        assert_eq!(aic.read(REG_AIC_EIR_INT_RO_BASE, 4) as u32, 0x2);
    }

    #[test]
    fn self_ipi_and_ack() {
        let mut aic = Aic::new(AIC_CPU_COUNT);
        aic.current_cpu = 2;
        // Unmask SELF IPI for CPU 2.
        aic.write(REG_AIC_IPI_MASK_CLR, 4, AIC_IPI_SELF as u64);
        // Raise self IPI through the Pn alias of CPU 2.
        let pn = REG_AIC_WHOAMI_PN_BASE + 2 * 0x80 + REG_AIC_IPI_SET - REG_AIC_WHOAMI;
        aic.write(pn, 4, AIC_IPI_SELF as u64);
        assert!(aic.irq_lines.levels[&2]);
        let v = aic.read(REG_AIC_IACK, 4) as u32;
        assert_eq!(v, K_AIC_INT_IPI | K_AIC_INT_IPI_SELF);
    }

    #[test]
    fn cap_and_rev() {
        let mut aic = Aic::new(6);
        assert_eq!(aic.read(REG_AIC_REV, 4), AIC_VERSION as u64);
        assert_eq!(aic.read(REG_AIC_CAP0, 4), ((6 - 1) << 16) | 576);
    }
}
