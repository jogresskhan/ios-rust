# M3 MMU groundwork — inventory + plan (2026-10-29, session F)

> Regenerated (condensed) after the session-F sandbox reset destroyed the
> original 471-line note; findings below are the subagent's verified report.

## What is ALREADY real (BOOT-PLAN M3 text is stale)

`crates/a13-cpu/src/mmu.rs` (263 lines) is a genuine 4K/16K stage-1 walker +
software TLB, wired end-to-end in the interpreter:

* TTBR0/1_EL1 → `mmu.set_ttbr*` (interp.rs ~3821-3828)
* TCR_EL1 → `set_tcr` (~3829-3832; TG0[15:14] TG1[31:30] T0SZ[5:0] T1SZ[21:16])
* SCTLR_EL1.M → `set_enabled` (~3817-3820)
* fetch/load/store all translate via `vaddr()` (interp.rs:331) called from
  `fetch` (:370), `ld` (:349), `st` (:362) — the only 3 physical-memory sites.

**Measured on the real boot path** (PARITY 2.11c): 8,136,610 insns retired,
460 walks, 9.1M TLB hits, 0 walk faults — through the kernel's OWN tables
(start.s builds them at LOAD_PA+0x700000: L1' @+0x4000, L2' @+0xC000).

**Real register values (measured, not assumed):**
* TCR_EL1 = `0x0008_0022_6519_A519` → T0SZ=T1SZ=25 (39-bit VA), TG0/TG1=16K,
  IPS=40-bit PA, TBI0=1 (boot_real.rs:20-22; fields re-decoded)
* SCTLR flip = `0x3454_593D | 0x40000000` (M bit)
* TTBR0/TTBR1/MAIR values were NEVER captured (no sysreg-write trace yet).

## Still missing / no-op (the true M3 gap list)

1. **MAIR write dropped, read always 0** — real round-trip bug
   (write arm `MAIR_EL1 => {}`; read arm reads the never-filled store).
   **FIXED this session** (interp.rs write arm + `Mmu::set_mair`/`attr_byte`,
   goldens `gap_mair_roundtrip` / `gap_mair_mmu_attr_byte` — REAL-DATA BUG #18).
2. ESR_EL1 / FAR_EL1 / PAR_EL1 do not exist.
3. No permission/AF/XN enforcement; descriptor attr bits decoded only.
4. No exception vectoring at all (SVC → Panic, faults → CPU stop) — the
   first real permission/AF fault will stop the run instead of vectoring.
5. TBI0/A1/EPD ignored; address-size faults unmodeled.
6. TLBI range decodes but flushes wholesale (interp.rs ~3191-3201).

## Risks (top 5)

1. MAIR/TTBR ground values uncaptured → attr routing ungrounded until a
   boot-real sysreg-write trace runs.
2. No exception model → any enforced fault halts the boot path.
3. Start-level rule/T0SZ legality derived from first principles + kernel
   observation, not DDI0487-verified (TODO-verify before enforcement).
4. Measured TCR has TBI0=1; emulator ignores it — harmless for kernel text,
   a trap for M6 userspace VAs.
5. Single-granule + ASID-less full-flush TLB shape is wrong for later
   SMP/ASID work.

## Sensible next increments (evidence-first)

a. Capture TTBR0/TTBR1/MAIR/SCTLR writes during boot-real (sysreg-write
   trace) — grounds attr routing and closes risk #1.
b. AF + AP[2:1] enforcement OFF by default behind a flag, with goldens on
   synthesized descriptors (walk-4K-hit, walk-16K-hit, block-at-L2,
   permission-fault, AF-fault) — per the test plan in the original note.
c. ESR/FAR synthesized on the existing fault paths so vectoring has
   something honest to deliver when M4 adds vectors.
