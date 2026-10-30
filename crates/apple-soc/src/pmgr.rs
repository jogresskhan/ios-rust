//! pmgr — Apple PMGR (power/clock manager), T8030 `pmgr1,t8030`, 44 reg windows.
//!
//! Session-N rewrite (M5 attach-spec §4) replacing the synthetic psreg model:
//! AppleT8030PMGR addresses registers by the LINEAR byte offset across the
//! CONCATENATED 44-window reg map (measured: the driver reads through a
//! vtable-slot helper with the byte offset as an argument —
//! m5-peripheral-queue §2.1). Window 0 (abs 0x23B000000+0x100000) holds the
//! APSC CPU-cluster pstate regs (0xE2020/0xE2588, measured poll targets of
//! `_waitAPSCPending`) and the ps-regs gate table (window offset 0x80000,
//! ADT-confirmed).
//!
//! Semantics (m5-peripheral-specs §8 + attach-spec §4.3/§4.4):
//! * APSC + gate reads = the PS-register format: bits 3:0 PS_TARGET (R/W),
//!   bits 7:4 PS_ACTUAL (RO mirror of TARGET — makes every poll converge on
//!   the first read), bit 28 AUTO_ENABLE passed through. Power-on default
//!   target 0xF ⇒ reads 0xFF ("ACTIVE", never left).
//! * Everything else: scratch R/W — store on write, read returns the stored
//!   word (0 if never written), counted. No offset is rejected; no access can
//!   stall. Gate stride 0x18 is UNCONFIRMED (queue §7.2) — harmless: the
//!   mirror is stride-independent, a wrong stride degrades to "always
//!   powered", never to a hang.
//!
//! One [`PmgrCore`] is shared by 44 [`PmgrWindow`] boxes (Arc<Mutex>) — the
//! spec §4.2 shape. Boot gates (`clock-gates` of every /arm-io node) seed
//! `gates` with target 0xF at attach (the defect-(e) fix).

use std::sync::{Arc, Mutex};
use vm_core::Device;

/// Linear offset of the ps-regs (gate) window inside the concatenated map.
pub const PMGR_PSREG_WINDOW: u64 = 0x80000;
/// Gate-record stride — UNCONFIRMED (queue §7.2); mirror semantics are
/// stride-independent (see module doc).
pub const PMGR_GATE_STRIDE: u64 = 0x18;
/// APSC CPU-cluster pstate regs (linear offsets in window 0; w1 = cluster).
pub const PMGR_APSC: [u64; 2] = [0xE2020, 0xE2588];

/// T8030 pmgr reg windows — abs bases AFTER the arm-io `ranges` translation,
/// in ADT `reg` order (attach-spec §4.1; the translated raw windows from the
/// real n104ap 18C66 DeviceTree, `ios-rust adt windows` is the generator).
pub const PMGR_WINDOWS: &[(u64, u64)] = &[
    (0x23B000000, 0x100000), // w0  main pmgr-reg: APSC + ps-regs
    (0x23D200000, 0x100000), // w1  AON (fuses)
    (0x23D004000, 0x1000),   // w2
    (0x210E20000, 0x15000),  // w3
    (0x210F00000, 0x50000),  // w4
    (0x210E40000, 0x10000),  // w5
    (0x210E50000, 0x1000),   // w6
    (0x210E70000, 0x90000),  // w7
    (0x210050000, 0x10000),  // w8  cpufreq cluster E0
    (0x210150000, 0x10000),  // w9  cpufreq cluster E1
    (0x210250000, 0x10000),  // w10 cpufreq cluster E2
    (0x210350000, 0x10000),  // w11 cpufreq cluster E3
    (0x211E20000, 0x15000),  // w12 mirrored P-cluster set
    (0x211F00000, 0x50000),  // w13
    (0x211E40000, 0x10000),  // w14
    (0x211E50000, 0x1000),   // w15
    (0x211E70000, 0x90000),  // w16
    (0x211050000, 0x10000),  // w17
    (0x211150000, 0x10000),  // w18
    (0x23BC1C000, 0x40000),  // w19
    (0x23B280000, 0x40000),  // w20 temp-sensor block
    (0x23D180000, 0x2000),   // w21 spmi0/1/2 live at +0x700/…4700/…8700 (B1 lets spmi win)
    (0x23D100000, 0x80000),  // w22 ⊃ dockchannel-uart + pmp AON windows (B1)
    (0x23B204000, 0x10000),  // w23
    (0x26B8EC000, 0x10000),  // w24 GPU (overlaps w25 — B1)
    (0x26B8F4000, 0x10000),  // w25 GPU
    (0x262000000, 0xD000),   // w26 media vnom pages
    (0x264000000, 0xD000),   // w27
    (0x266000000, 0xD000),   // w28
    (0x268000000, 0xD000),   // w29
    (0x26A000000, 0xD000),   // w30
    (0x22A000000, 0xD000),   // w31
    (0x231000000, 0xD000),   // w32
    (0x205000000, 0xD000),   // w33
    (0x60C000000, 0xD000),   // w34
    (0x234000000, 0xD000),   // w35
    (0x200148000, 0xD000),   // w36
    (0x279000000, 0xD000),   // w37
    (0x225000000, 0x15000),  // w38 cpupm (overlaps 39/40 — B1)
    (0x225004000, 0x4000),   // w39 cpupm
    (0x225008000, 0x4000),   // w40 cpupm
    (0x226000000, 0x15000),  // w41 cpupm (overlaps 42/43 — B1)
    (0x226004000, 0x4000),   // w42 cpupm
    (0x226008000, 0x4000),   // w43 cpupm
];

/// Shared state for all 44 windows.
pub struct PmgrCore {
    /// linear offset → last written word (scratch; never-written reads 0)
    scratch: std::collections::BTreeMap<u64, u32>,
    /// APSC cluster target nibbles (linear 0xE2020 / 0xE2588), default 0xF
    apsc_target: [u32; 2],
    /// gate id → target nibble (default 0xF; seeded from clock-gates at attach)
    pub gates: std::collections::BTreeMap<u32, u32>,
    pub unknown_reads: u64,
    pub unknown_writes: u64,
}

impl PmgrCore {
    fn new() -> Self {
        PmgrCore {
            scratch: std::collections::BTreeMap::new(),
            apsc_target: [0xF, 0xF],
            gates: std::collections::BTreeMap::new(),
            unknown_reads: 0,
            unknown_writes: 0,
        }
    }

    /// The PS-format read answer: `((target & 0xF) << 4) | (target & 0xF)`
    /// plus the AUTO_ENABLE bit passed through from the stored word.
    fn ps_read(word: u32, target: u32) -> u64 {
        let t = target & 0xF;
        (((t << 4) | t) | (word & 0x1000_0000)) as u64
    }

    fn read(&mut self, lin: u64) -> u64 {
        // APSC polls (measured `_waitAPSCPending` targets).
        if let Some(i) = PMGR_APSC.iter().position(|&a| a == lin) {
            let word = self.scratch.get(&lin).copied().unwrap_or(0) as u32;
            return Self::ps_read(word, self.apsc_target[i]);
        }
        // Gate table span (stride-unconfirmed mitigation — see module doc).
        if (PMGR_PSREG_WINDOW..PMGR_PSREG_WINDOW + 248 * PMGR_GATE_STRIDE).contains(&lin) {
            let id = ((lin - PMGR_PSREG_WINDOW) / PMGR_GATE_STRIDE) as u32;
            let target = self.gates.get(&id).copied().unwrap_or(0xF);
            let word = self.scratch.get(&lin).copied().unwrap_or(0) as u32;
            return Self::ps_read(word, target);
        }
        match self.scratch.get(&lin) {
            Some(v) => *v as u64,
            None => {
                self.unknown_reads += 1;
                0
            }
        }
    }

    fn write(&mut self, lin: u64, val: u64) {
        let v = (val & 0xFFFF_FFFF) as u32;
        if let Some(i) = PMGR_APSC.iter().position(|&a| a == lin) {
            self.apsc_target[i] = v & 0xF; // low nibble = TARGET ⇒ ACTUAL follows
        }
        self.scratch.insert(lin, v);
        self.unknown_writes += 1;
    }

    /// Host-side: seed a boot gate (from a node's `clock-gates` prop).
    pub fn seed_gate(&mut self, id: u32) {
        self.gates.entry(id).or_insert(0xF);
    }

    /// Host-side: is a gate powered (target/actual nibble 0xF)?
    pub fn gate_on(&self, id: u32) -> bool {
        self.gates.get(&id).copied().unwrap_or(0xF) & 0xF == 0xF
    }
}

/// One bus window. `lin` = byte offset of THIS window inside the concatenated
/// map (the summation over the window table), so every box sees one
/// contiguous register space — exactly how the kernel addresses it.
pub struct PmgrWindow {
    pub core: Arc<Mutex<PmgrCore>>,
    pub lin: u64,
}

impl PmgrWindow {
    pub fn new(core: Arc<Mutex<PmgrCore>>, lin: u64) -> Self {
        PmgrWindow { core, lin }
    }
    pub fn name(&self) -> &'static str {
        "pmgr"
    }
}

impl Device for PmgrWindow {
    fn name(&self) -> &'static str {
        "pmgr"
    }
    fn read(&mut self, off: u64, _size: u8) -> u64 {
        self.core.lock().unwrap().read(self.lin + off)
    }
    fn write(&mut self, off: u64, _size: u8, val: u64) {
        self.core.lock().unwrap().write(self.lin + off, val)
    }
}

/// Build the shared core (with boot gates seeded from `clock_gates`) plus one
/// box per window in [`PMGR_WINDOWS`], with correct concatenated `lin` offsets.
pub fn new_44_window(clock_gates: &[u32]) -> (Arc<Mutex<PmgrCore>>, Vec<PmgrWindow>) {
    let core = Arc::new(Mutex::new(PmgrCore::new()));
    {
        let mut c = core.lock().unwrap();
        for id in clock_gates {
            c.seed_gate(*id);
        }
    }
    let mut lin = 0u64;
    let mut windows = Vec::with_capacity(PMGR_WINDOWS.len());
    for &(_base, size) in PMGR_WINDOWS {
        windows.push(PmgrWindow { core: core.clone(), lin });
        lin += size;
    }
    (core, windows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apsc_mirror_converges_first_read() {
        let (_core, mut wins) = new_44_window(&[]);
        // w0 APSC: default target 0xF ⇒ read 0xFF (ACTIVE, never left).
        assert_eq!(wins[0].read(PMGR_APSC[0], 4), 0xFF);
        assert_eq!(wins[0].read(PMGR_APSC[1], 4), 0xFF);
        // Driver writes a lower target; ACTUAL mirrors ⇒ poll converges.
        wins[0].write(PMGR_APSC[0], 4, 0xB);
        assert_eq!(wins[0].read(PMGR_APSC[0], 4), 0xBB);
        // AUTO_ENABLE bit passes through from the stored word.
        wins[0].write(PMGR_APSC[1], 4, 0x1000_000C);
        assert_eq!(wins[0].read(PMGR_APSC[1], 4), 0x1000_00CC);
    }

    #[test]
    fn gates_read_ff_and_seed() {
        let (core, mut wins) = new_44_window(&[49, 76, 128]);
        {
            let c = core.lock().unwrap();
            assert!(c.gate_on(49));
            assert!(c.gate_on(76));
            assert!(c.gate_on(999)); // unseeded ⇒ default 0xF (always powered)
        }
        // Gate window read: 0x80000 + id*0x18.
        assert_eq!(wins[0].read(PMGR_PSREG_WINDOW + 49 * 0x18, 4), 0xFF);
        // Linear windows: w22 starts at sum of sizes of w0..w21 — write via
        // the w22 box, read back via w0 at the same concatenated offset.
        let lin22: u64 = PMGR_WINDOWS[..22].iter().map(|&(_, s)| s).sum();
        wins[22].write(0x1234, 4, 0x42);
        assert_eq!(wins[0].read(lin22 + 0x1234, 4), 0x42);
    }

    #[test]
    fn scratch_everywhere_never_stalls() {
        let (_core, mut wins) = new_44_window(&[]);
        wins[0].write(0xE4000, 4, 0xCAFE);
        assert_eq!(wins[0].read(0xE4000, 4), 0xCAFE);
        assert_eq!(wins[1].read(0xABCDEF, 4), 0); // any offset answers
    }
}
