# BOOT-PLAN — from 9 retired instructions to a booted homescreen

**Mission:** first restore well-made → first boot → home screen seen in full GUI,
on the pure-Rust engine, with real Apple 18C66 bytes. Everything measured, nothing
claimed that was not run. This file is the worklist any AI session picks up.

**Status marker:** `[ ]` open · `[~]` in progress · `[x]` done (with the measured
evidence next to it). Update it at the END of every work block.

**The loop every session/bot follows:**
1. `cd /home/z/work/ios-rust && git log --oneline -1` — where are we?
2. Pick the FIRST open milestone below; read its "how" + "acceptance".
3. Work with the RE toolkit (`tools/re/README.md` — oracle, mask_discover,
   coverage-probe, Ghidra). Never hand-split instruction bits.
4. Test: `cargo test --workspace` green + run the stage command + record numbers.
5. Commit locally, then `source ~/.config/ios-rust/s3.env &&
   python3 tools/s3_backup.py snapshot ios-research-vault` (S3 = storage of record,
   GitHub suspended). Update PARITY.md + parity.json honestly.

---

## M1 — ISA closure: every instruction class decoded  [~] (98.87% decode / 98.9% exec)

**Progress (2026-10-29, session B — boot-driven):** the boot-real campaign
pulled SIMD families forward: MOVI-64 (bit→byte imm expansion, measured
12/12 vs capstone), three-same logical (8 ops), three-same integer
(ADD/SUB/CM*/MIN/MAX/P/MUL), across-lane reduces ({S,U}MINV/MAXV, ADDV
with the Apple zero-extension semantics the kernel DEPENDS on — bug #12),
scalar↔GPR fmov. **decode 98.69% → 98.87%** (7876635/7966342), exec probe
98.9%. Bugs #10/#10b fixed (SP corruption via flag-setting add/sub —
see Layer 2.11c). Remaining buckets: FP three-same (fadd/fsub/fmla,
0x4e), shift-imm remainder (sqshlu/uqshl/sri/sli, 0x6f), scalar FP
(0x1e), SIMD ld/st multiple (0x4c/0x3c), ~46k literal-pool words.

**REAL-DATA BUG #8 (correctness!):** the dp-3 guard `(w>>22)&1==0` rejected
UMULH (~1.5k words) AND misdecoded SMULH (op31=010) as MADD — silently wrong
results on real bytes, masked by synthetic tests.
**REAL-DATA BUG #9:** the "QEMU 0x1C/0x1D-anchored" Sqrdmlah goldens
(0x9B820020/0x1B820020) are unassigned encodings — capstone: UNDEFINED; the
thief arm that produced them also stole real umaddl words. Deleted; real
scalar RDM stays in the keystone-verified 0x7F40_0000 arm.

Remaining buckets (hist, real 18C66 words): 0x4e+0x6e+0x0e ~19.7k SIMD
three-same/different · 0x6f+0x4f ~11.2k SIMD shift-imm · 0x1e(+0xbc share)
~7.5k scalar FP · 0x4c+0x3c ~5.3k SIMD ld/st · ~50k in 0xff/0x00 pools (data).

Remaining real-byte classes (hist on 18C66 `__TEXT_EXEC.__text`, 7,966,342 words;
decode 98.59% / exec 98.6%; unknown 112,101 words of which ~51k are literal pools):

| bucket | words | family | how (tool-assisted) |
|---|---|---|---|
| 0x4e + 0x6e + 0x0e | ~19.7k | AdvSIMD three-same / three-different (`add v0.2d,…`, `ext`, `xtn`) | `mask_discover.py --range` per opcode column; exec: lane-wise f64/u64 ops |
| 0x6f + 0x4f | ~11.2k | AdvSIMD shift/immediate imm (`movi v0.2d,#0`, `shl v3.2d,#4`) | same; exec: per-lane shift/imm |
| 0x1e (+0xbc FP share) | ~7.5k | scalar FP (`fmov w16, s0`, FCMP/FCSEL/FMADD/FCVT/SCVTF) | exec on f32/f64; FP flags in FPCR/FPSCR model |
| 0x5a | ~3.7k | dp-1-source: RBIT/REV16/REV32/REV/CLZ/CLS | trivial decode+exec |
| 0x4c + 0x3c | ~5.3k | AdvSIMD load/store multiple + register-offset (`st2 {v3.2d,…}`, `str q5,[x10,x8]`) | extend LdStRegOff + new LdStMult |
| 0x9b | ~1.5k | dp-3 op31 map hole: SMULH/UMULH rejected by a too-narrow guard | capstone-derived masks (bug #8 candidate) |
| 0x4a | ~1.2k | logical shifted register with ROR (`eor w13,w11,w21,ror #29`) | ShiftKind::Ror + rotate exec |

**Acceptance:** `coverage-probe` sweep ≥ 99.3% decode AND exec probe ≥ 99.3%;
every new family pinned by capstone/keystone-derived `gap_*` goldens;
`cargo test -p a13-cpu` green.

## M2 — rebase / chained-fixups image loading  [ ]  ← THE first-boot unlock

**Evidence this is the unlock (2026-10-29):** boot-real now retires
**8,136,610 real instructions** (kernel's own thread_starts chained walk
completes, MMU walks its own tables with 0 faults) and stops at
`ldr w9,[x0,#4]` with `x0 = [x20+8] = NULL` @ 0x…81377b4 — the kernel
dereferencing an **un-rebased chained-fixup pointer from `__DATA`** while
parsing "LSSeaico…" launch-services data. The kernel's OWN thread_starts
walk works because it rebases with its own loop; the general `__DATA`
pointers are still OUR (iBoot's) job.

The kernel's first function RETs; the first indirect call jumps through a GOT
entry that ships ZEROED — iBoot rebases it. We must do what iBoot does:

1. Parse the prelinked kernel collection's Mach-O headers (`crates/macho`,
   `crates/kernelcache::prelink`): segments, LC_DYLD_INFO/DYLD_CHAINED_FIXUPS.
2. Implement `DYLD_CHAINED_PTR_64` walk: stride, ordinals, rebase targets
   (slide = image_base − preferred_base), bind fixups.
3. Apply into the kernel RAM before exec.
4. **Acceptance:** `boot-first` retires ≥ 10,000 real instructions (vs 9 today)
   and stops at a NEW named point — never again at the first indirect call.
5. Record: instructions retired, stop reason/pc, next missing device.

## M3 — MMU / TLB  [ ]

xnu builds its own page tables during early boot; the interpreter must walk them.

1. `a13-cpu`: TTBR0/TTBR1_EL1, TCR_EL1 (TG0/TG1, T0SZ/T1SZ), 4 KiB + 16 KiB
   granule walks (L0→L3), AF/dbm/access-permission faults, attr indirection
   (MAIR: device-nGnRE vs normal — device attrs must hit the Bus, normal must
   hit RAM cache).
2. Start with 2-stage-off (EL1 only), stage-1 translation on fetch+load+store.
3. **Acceptance:** guest writes TTBR0/TCR (they are currently no-ops), sets
   `SCTLR_EL1.M=1`, and execution CONTINUES with translated fetches; boot-first
   retires ≥ 1,000,000 insns with the MMU live.
4. Tool: QEMU `-d trace:arm_ttbr_write` equivalents via `ios-re-toolkit` QEMU
   lane for ground truth on TCR values the real kernel writes.

## M4 — IRQ / AIC / timers  [ ]

1. Model `apple-aic` v1 (devices crate has a stub): event reg, IPI regs,
   pending-set/clear, mask; wire to `vm-core::irq::IrqController`.
2. Generic timer: CNTFRQ/CNTP/CNTV emulation, deadline → IRQ 29 (cntv) — the
   heartbeat xnu's sched needs.
3. **Acceptance:** boot-first reaches a WFI-and-resumes loop (stop=WFI no longer
   terminal; timer IRQ wakes it); ≥ 10M insns retired.

## M5 — peripherals the real boot path touches  [ ]

Current: 59/105 /arm-io peripherals modeled, 35 named-unmatched
(`PARITY.md` 2.11a list). Order by what the boot trace touches first:

1. Re-run boot with a device-access log; rank missing compatibles by hit count.
2. PMGR (clock gates — xnu polls pstate/clock-tree early), UART (have), SART,
   DART (for ANS2/NVMe rootfs reads), ANS2 NVMe + SGP (rootfs!), SMC, WDT.
3. **Acceptance:** no unknown-device aborts on the boot path; NVMe read path
   returns real rootfs bytes from `full-root.apfs`.

## M6 — userspace: DSC → dyld → launchd → SpringBoard → GUI  [ ]

1. DSC (dyld shared cache) rebase — `crates/dsc` parses; add the same
   chained-fixup rebase as M2, then map images at their addrs.
2. dyld: minimal `_dyld_start` → `dyld::start` → `launchd` exec path; mach-o
   loader in-engine (crates/macho), CS validation SKIP (honest: no AMFI yet).
3. Mach IPC surface in `crates/xnu` (mach_traps has the table) — enough traps
   for launchd's bootstrap: `host_self`, `task_self`, `mach_port_allocate`,
   `bootstrap_check_in` (implement a tiny bootstrap server in-engine).
4. SpringBoard render: framebuffer compositor (crates/vm-core::framebuffer has
   paint stubs) — replace synthetic paint with real BACKBOARD layers once
   SpringBoard's IOKit surface calls land on our IOSurface/IOFB models.
5. **Acceptance (the mission):** `boot-first` paints a REAL SpringBoard frame —
   icons rendered from the staged rootfs payload, not `Stage::Homescreen` art —
   and the BMP is visually verifiable.

---

## Standing rules (inherited from the ledger)

* Real bytes only; every claim carries its measured number.
* `gap_*` goldens come from capstone/keystone, never mental bit-splitting.
* Honest limits stay listed until they are fixed — no silent upgrades.
* Commit + S3 snapshot at the end of EVERY block (see loop above).
* Schedule: a recurring job continues this plan every 2 hours.
