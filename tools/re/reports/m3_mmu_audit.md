# M3 MMU audit — stage-1 walker vs the BOOT-PLAN acceptance (2026-10-29, task 2-b)

RESEARCH ONLY audit. Every claim anchored to file:line. "absent" = grep-verified
zero hits in `crates/` unless stated. Working dir: `/home/z/work/ios-rust`.

Sources read in full: `crates/a13-cpu/src/mmu.rs` (282 lines),
`crates/a13-cpu/src/isa.rs` (340), the sysreg/memory/arm paths of
`crates/a13-cpu/src/interp.rs`, `crates/a13-cpu/src/lib.rs`,
`crates/ios-rust/src/boot_real.rs` (400), `crates/ios-rust/src/boot_first.rs`
(budget), `crates/vm-core/src/bus.rs` (routing), `docs/BOOT-PLAN.md` M3,
`PARITY.md` 2.11c, `tools/re/notes/m3-mmu-groundwork.md`.

---

## 0. Verdict in one paragraph

The M3 plan text ("guest writes TTBR0/TCR — currently no-ops") is stale: all of
TTBR0/TTBR1/TCR/SCTLR/MAIR are captured *and* consumed (interp.rs:3817–3832,
3863–3866), and `crates/a13-cpu/src/mmu.rs` is a genuine 4K/16K L0..L3 stage-1
walker with a page-keyed TLB, already exercised on the kernel's own tables
(460 walks, 9.1M TLB hits — PARITY 2.11c:433). The M2 stop itself
(`TranslationFault(load, invalid descriptor) va=0x4 pc=0xfffffff0081377b4`,
BOOT-PLAN.md:174) is an MMU-mediated fault in virtual mode, so *some large
unmeasured fraction* of the 8.1M retired insns ran with translated
fetch/load/store. What actually stands between us and closing M3: (1) the
≥1,000,000-insn "MMU live" gate is **not measurable** — nothing records the
SCTLR.M arm point; (2) permission/AF/XN enforcement and attr-driven routing are
absent (BOOT-PLAN M3 bullet 1 requires MAIR device-vs-normal); (3) every
translated fault is a **terminal CPU stop** (no ESR/FAR/VBAR vectoring); (4) the
walker has **zero direct tests** (`translate()` has exactly one caller,
interp.rs:336; mmu.rs has no `mod tests`); (5) minor silent-degrade traps
(64K granule, T0SZ=0 remap) that should fault loudly. Roughly 70 lines make the
acceptance measurable+honest; ~150 more close the structural gaps; enforcement
must wait for M4 vectoring or it would make boot *worse*.

---

## 1. `crates/a13-cpu/src/mmu.rs` — complete public inventory

Header honesty statement (mmu.rs:10–18): covers 4K/16K granules, 48-bit VAs,
L0..L3 tables/blocks/pages, TLB keyed by page invalidated by TLBI/TTBR/TCR;
"attribute bits are decoded but not enforced"; not covered: secure/EL2 stage 2,
52-bit PAs, permission faults (AP/XN), AF, contiguous hints.

### Types
| Item | Lines | Notes |
|---|---|---|
| `enum XlateKind { Fetch, Load, Store }` | 26–30 | + `as_str()` 33–40. Passed into `translate` but **never referenced in its body** (signature mmu.rs:158; zero uses below) — it only labels the host-side `StopReason::TranslationFault` (interp.rs:337–342). No kind-dependent behavior exists. |
| `struct Mmu` | 43–66 | pub: `enabled`:45, `mair`:54, `walks`:61, `tlb_hits`:62, `faults`:63, `last_fault_chain`:65. private: `tcr`:47, `ttbr0`:48, `ttbr1`:49, `granule_log2`:55, `t0sz`:56, `t1sz`:57, `tlb: HashMap<u64,u64>`:59. |

### Methods (all of them)
| Method | Lines | Behavior / decoded vs enforced |
|---|---|---|
| `new()` | 75–91 | `enabled=false`, granule=4K, `t0sz=t1sz=16` (48-bit). |
| `set_tcr(v)` | 94–111 | Decodes TG0 `[15:14]` (:99), TG1 `[31:30]` (:100), `t0sz` `[5:0]` (:102), `t1sz` `[21:16]` (:103). Granule = 16K iff `tg0==0b10 \|\| tg1==0b01` (:101), **else 4K — a 64K encoding (tg0=0b01/tg1=0b11) silently walks as 4K**. **One `granule_log2` shared by BOTH ranges** (architecturally TG0/TG1 are independent). `t0sz==0`/`t1sz==0` silently remapped to 16 (:104–109) — hides a config instead of faulting. Flushes TLB on any change (:110). NOT decoded: TBI0/TBI1, EPD, IRGN/ORGN, SH, A1, IPS, DS. |
| `set_ttbr0(v)` | 113–116 | Masks PA to 48-bit (:114, drops ASID `[63:48]` — fine for the single-ASID model), **flushes whole TLB** (:115). |
| `set_ttbr1(v)` | 118–121 | Same (:119–120). |
| `set_mair(v)` | 125–127 | Store only; **no TLB flush** (documented rationale :123–124 — attrs don't affect addresses). |
| `attr_byte(attrindx)` | 132–134 | Real MAIR decode `mair>>(n*8)&0xFF`. **Never called by the walker** — its only callers are tests (interp.rs:4418–4422, 4426–4428). The descriptor's AttrIndx field `[4:2]` is never extracted anywhere. |
| `set_enabled(on)` | 136–141 | Flush on 0↔1 edge (:137–139). |
| `flush()` | 143–145 | `tlb.clear()`. |
| `page_mask()` | 147–150 | From granule. |
| `translate(mem, va, kind)` | 154–261 | The walker — detailed below. |
| `dump(max)` / `tlb_size()` / `config_str()` | 264–266 / 268–270 / 272–281 | Diagnostics. |

### `translate()` internals (mmu.rs:154–261)
- MMU off → pass-through VA (:160–162).
- TLB lookup keyed `va >> g`, hit increments `tlb_hits` (:163–168).
- Range select: TTBR1 iff top `t1sz` bits all-ones (:170–174); VA must fall in
  *one* of the two ranges or fault `"address not in either TTBR range"`
  (:183–188); `va_bits` must be 1..=52 (:178–181).
- Bits-per-level `bpl` = 11 (16K) / 9 (4K) (:190). Start level = largest s with
  `(4-s)*bpl + g >= va_bits` (:194–204) — e.g. the measured kernel config
  (16K, T0SZ=25 → 39-bit VA) starts at **L1** with a truncated 3-entry index
  (:222–226), matching the bootstrap layout comment.
- Descriptor fetch is `mem.load(desc_addr, 8)` (:227–228) — a **direct
  `MemAccess` call (physical bus)**, not `self.ld`, so no translation recursion.
- Faults (each bumps `faults`): invalid descriptor (:230–234, stores
  `last_fault_chain`), invalid table descriptor (:249–251), table-at-L3
  (:255–258), plus range/va-bits faults above.
- Leaf (L3 page or L1/L2 block): OA = desc bits above `leaf_shift`, PA =
  OA | (va & leaf_mask) (:237–247); TLB insert is **per granule page** (:246 —
  a 2 MB block still caches as 16K pages; correct, just more walks).
- **Attribute bits of the descriptor are never extracted**: AP[2:1]/AP[0], XN,
  PXN, AF, Contiguous, AttrIndx[4:2], SH, nG — none appear in the body. The
  header's "decoded but not enforced" (mmu.rs:14–15) overstates: *nothing*
  decodes them in the walk path; only the MAIR-side `attr_byte` helper exists.
- Docstring drift: ":152–153 On failure returns `(va, kind-str)`" — actually
  returns `(va, detail)`; the kind string is added by interp `vaddr`.

### Test coverage
`translate()` has **exactly one caller** in the tree (interp.rs:336) and **zero
direct tests**: mmu.rs has no `#[cfg(test)]` module; the only MMU-adjacent goldens
are the MAIR round-trip / `attr_byte` tests (interp.rs:4398–4429, added for
REAL-DATA BUG #18). No synthesized-table walk golden exists (4K hit, 16K
L1-start, L2 block, fault shapes — the test list proposed in
tools/re/notes/m3-mmu-groundwork.md:56–58 was never written).

---

## 2. Sysreg register table — captured / consumed / no-op

Interpreter sysreg plumbing: `Insn::Mrs` → `read_sysreg` (interp.rs:2777–2779 →
3711), `Insn::Msr` → `write_sysreg` (2781–2783 → 3804). Encodings in
`interp.rs::sysreg` (68–140). Note there is a **second, dead** sysreg table:
`isa::SystemRegTable` (isa.rs:174–302) is referenced only inside isa.rs itself
(its doc at isa.rs:88 and its own test :328) — the live interpreter uses
`interp::SystemRegs` (interp.rs:24–65).

| Register | Captured? | Consumed by walker/MMU? | Verdict | Anchors |
|---|---|---|---|---|
| **SCTLR_EL1** | yes — `sys.sctlr_el1 = v` | **yes — M bit**: `mmu.set_enabled(v & 1 == 1)` (bit 0 = M) | captured+consumed (M only). C/I/WXN/EE/SA… stored but **not consumed** (no cache/XN model) | interp.rs:3817–3820; read 3729 |
| **TTBR0_EL1** | yes (:3822) | **yes** — `mmu.set_ttbr0` → walk table base + full TLB flush | captured+consumed (ASID field ignored) | interp.rs:3821–3824; mmu.rs:113–116, 206–210 |
| **TTBR1_EL1** | yes (:3826) | **yes** — `mmu.set_ttbr1` | captured+consumed | interp.rs:3825–3828; mmu.rs:118–121 |
| **TCR_EL1** | yes (:3830) | **yes** — `mmu.set_tcr` (TG0/TG1/T0SZ/T1SZ + flush) | captured+consumed; TBI0/TBI1/EPD/IRGN/ORGN/SH/A1/IPS ignored | interp.rs:3829–3832; mmu.rs:94–111 |
| **MAIR_EL1** | yes — `sysreg_store` + `mmu.set_mair` (:3863–3866) | stored on the Mmu (:125–127) but **no consumer**: `attr_byte` has 0 non-test callers; AttrIndx never extracted | captured; consumed-by-nothing (bug #18 round-trip fixed, goldens interp.rs:4398–4429) | interp.rs:3790 (read), 3860–3866 |
| **TLBI** (op0raw=0-op0=1, CRn=8 family via `Msr`) | no (not a register) | **yes — full flush** of the software TLB, bumps group 17 | consumed (coarse) | interp.rs:3869–3874 |
| **TLBI range** (`Insn::TlbiRange`, 8 encodings) | `last_tlbi_range` record (base/scale/num) | **yes — full flush** (range decoded but flushed wholesale) | consumed (coarse) | decode.rs:2111–2122; interp.rs:3191–3201; field 182–183 |
| **VBAR_EL1** | yes (write :3835, read :3735) | **no** — never consumed; there is no exception vectoring at all | captured, unconsumed | interp.rs:3835; ERET only sets pc=ELR (:2787–2789) |
| **ESR_EL1** | **absent** | absent | no constant, no field, no synthesis | grep: 0 hits in a13-cpu |
| **FAR_EL1** | **absent** | absent | fault VA lives only in the host-side `StopReason::TranslationFault{va..}` (lib.rs:70) — not guest-visible | lib.rs:70; interp.rs:337–342 |
| **PAR_EL1** | **absent** | absent | AT S1E1R/W also **absent** (no `Insn::At` variant in decode.rs) → would stop as UnknownInsn | decode.rs Insn enum (134–, 467–) |
| ELR_EL1 / SPSR_EL1 | yes (:3836–3837) | ELR consumed by ERET (:2787–2789); SPSR unconsumed | captured+consumed (ELR only) | interp.rs:2787–2789 |
| DC ZVA (CRn=7, CRm=4, op2=1) | n/a | **yes — executes as 8 translated stores** through `self.st` (vaddr) | consumed, correctly translated | interp.rs:3875–3888 |
| other DC/IC cache ops | n/a | no-op (comment: no cache model) | no-op by design | interp.rs:3875–3876 |
| MIDR/CNTPCT/CNTFRQ/CTR/CurrentEL/ID_AA64MMFR0/1/APPLE_BOOT_STAGE/OSLAR | yes (derived) | consumed by kernel polls (boot-stage bit 1 OR-in :3787–3789) | captured+consumed | interp.rs:3772–3792 |
| SVC/HVC/SMC | n/a | — | stop `Panic` (no vectoring) | interp.rs:2784–2785 |

Reset-value drift worth noting: `isa.rs` documents `SCTLR_EL1_RESET =
0x00C5_0800` (isa.rs:147–151), but the live `Interpreter` starts from
`SystemRegs::default()` → `sctlr_el1 = 0` (interp.rs:24–31 derive, :252
`..SystemRegs::default()`). The RES1 bits are **not** set on the path that
actually runs. Cosmetic today (kernel writes a full constant before use), but
it is a doc-vs-code lie in isa.rs.

---

## 3. Arming path trace — `msr sctlr_el1` → translated execution

1. Guest executes `msr sctlr_el1, xN` → decoded as `Insn::Msr` →
   `self.write_sysreg(sysreg, x[N])` (interp.rs:2781–2783).
2. `write_sysreg` SCTLR_EL1 arm (interp.rs:3817–3820): stores the full value in
   `sys.sctlr_el1`, then **`self.mmu.set_enabled(v & 1 == 1)`** — bit 0 is
   SCTLR.M. (The mission prompt said `#1<<2`; bit 2 is SCTLR.C — the *code*
   checks bit 0, which is correct for M. The real kernel flip is
   `0x3454_593D | 0x4000_0000`, whose bit 0 = 1 — boot_real.rs:18, 24.)
3. `Mmu::set_enabled(true)` flushes the TLB on the 0→1 edge (mmu.rs:136–141).
4. From the next `step()` on: `step` fetches via `self.fetch(pc)`
   (interp.rs:501–503) → `fetch` calls `vaddr(va, XlateKind::Fetch)`
   (interp.rs:370–373) → `vaddr` (interp.rs:331–343): **if
   `self.mmu.enabled` → `self.mmu.translate(&mut *self.mem, va, kind)`** → PA;
   fault → `StopReason::TranslationFault { pc, va, kind, detail }`.
5. Data path: `ld` (interp.rs:349–358) / `st` (362–366) translate then issue
   `MemAccess::load/store` at the PA. **All** memory-touching insns funnel
   through `ld`/`st`/`load_vec`/`store_vec` — grep shows the only direct
   `MemAccess` sites are ld/st/fetch (:351, :364, :372): uimm loads/stores
   (:673–689), load-literal (:683–689), LDP (:725–756), SIMD multi/single
   (:696–788, :1271–1390, :2702–2720), atomics/LSE (:2809–2871), string ops
   (:3527–3548), DC ZVA (:3880–3887). No bypass exists.
6. **TLB invalidation on TTBR/TCR writes: YES, hooked** — `set_tcr` flush
   (mmu.rs:110), `set_ttbr0/1` flush (mmu.rs:115, 120), `set_enabled` flush
   (mmu.rs:138–139), every CRn=8 TLBI write flushes (interp.rs:3871–3874),
   TlbiRange flushes (interp.rs:3200). MAIR write deliberately does not flush
   (mmu.rs:123–127). All flushes are **wholesale** (no ASID/VA targeting).
7. **Absent**: nothing records *when* the flip happened. `Interpreter.executed`
   is private with no getter (interp.rs:185) and is only surfaced at `run()`
   end via `RunResult.executed` (lib.rs:74–77). There is no `mmu_live_from` /
   armed-at-index anywhere (grep "armed|live": only comments interp.rs:189).

---

## 4. Memory routing today — Bus vs RAM, and what MAIR would add

- After translation, the PA goes to the machine bus through
  `BusMem` (boot_real.rs:153–164) → `vm_core::Bus::read/write`
  (vm-core/src/bus.rs:43–64), which **dispatches purely by address** to
  attached regions (`Bus::attach` bus.rs:31); unmapped accesses return
  `unmapped_read_zeros` and bump `unmapped_reads`/`unmapped_writes`
  (bus.rs:16–18, 50–51, 64). DRAM is a plain `Ram` byte-vec (bus.rs:135–174) —
  there is no cache at all.
- Therefore **"device-nGnRE must hit the Bus, normal must hit RAM" is already
  true — incidentally, by PA, not by attribute**: a VA the kernel maps Device
  (AIC/UART physmap) translates to an MMIO PA and the Bus routes it to the
  device; normal VAs translate to DRAM PAs and hit Ram. `Mmu`/`XlateKind`
  output feeds this routing (translated PA is the only address the Bus ever
  sees — interp.rs:351/364/372), and no access bypasses translation.
- What the attr decode would *add* is not routing but: (a) misroute protection
  / assertions (a Device-attr access landing on DRAM, or normal-cacheable
  landing on MMIO — real HW also targets by PA, so this is defensible), (b)
  cache effects & ordering (none modeled — DC/IC ops are no-ops,
  interp.rs:3875–3876), (c) **access-width side effects** already handled at
  the Bus/Ram level (sub-word loads masked, bus.rs:161–174; ld masks too,
  interp.rs:352–357).
- Silent-zero danger: an unmapped MMIO read returns 0 and only bumps a counter
  that **no boot report prints** (`grep unmapped crates/ios-rust/src` → 0 hits;
  the fields exist at bus.rs:16–18 but `BootRealReport` doesn't carry them).

---

## 5. Gap analysis vs M3 acceptance and the BOOT-PLAN bullet list

BOOT-PLAN M3 (docs/BOOT-PLAN.md:187–211): bullet 1 = TTBR/TCR + 4K/16K walks +
"AF/dbm/access-permission faults, attr indirection (MAIR: device-nGnRE vs
normal)"; bullet 2 = stage-1 on fetch+load+store; bullet 3 acceptance = guest
writes TTBR0/TCR, sets `SCTLR_EL1.M=1`, execution CONTINUES with translated
fetches; boot-first retires ≥ 1,000,000 insns with the MMU live.

Ranked by **(blocks-boot? / false-execution-risk?)**:

| # | Gap | Blocks boot? | False-execution risk | Evidence |
|---|---|---|---|---|
| G1 | **Faults are terminal CPU stops.** No ESR/FAR synthesis, no vectoring at VBAR_EL1, no PAR, AT absent. Every walk fault / future permission fault kills the run instead of entering the kernel's own handler. | **YES — highest.** The M2 stop already demonstrates the mode of death. | Low (it stops loudly, doesn't mis-execute) | interp.rs:337–342 → run loop returns (lib.rs run loop :3926–3946); VBAR captured but unconsumed (:3835); ESR/FAR/PAR absent |
| G2 | **M3 acceptance not measurable.** No marker at the SCTLR.M edge → "MMU-live insn window" can't be reported; per-kind fault tally absent; also claim drift: PARITY 2.11c:433 says "0 walk faults" while the *terminal stop of the very same run* is a `TranslationFault` (a stopping walk fault necessarily bumps `mmu.faults`, mmu.rs:230–234) — the two published numbers (8,136,610 PARITY:429 vs 8,135,842 BOOT-PLAN:167) also disagree. | No (measurement), but **blocks claiming M3 honestly** | Bookkeeping | interp.rs:185, 3817–3820; boot_real.rs:245–250, 278–281; PARITY.md:421–433 |
| G3 | **Permission/AF/XN enforcement absent; `kind` dead in `translate`.** A guest access HW would fault on (NULL page, RO text write, XN data-exec) silently succeeds. | No (kernel's early map is permissive) | **High once M2-unlock runs further** — silent corruption instead of a named stop | mmu.rs:154–261 (kind unused), header mmu.rs:17–18; BOOT-PLAN bullet 1 explicitly lists "AF/dbm/access-permission faults" |
| G4 | **Attr indirection decoded-but-unused.** `attr_byte` has zero non-test callers; AttrIndx[4:2] never extracted; device-vs-normal classification not computed. Routing is PA-incident (§4), so bullet 1's "device must hit Bus" is currently satisfied by luck of the map, not by the model. | No | Low now; medium at cache/DMA modeling time | mmu.rs:132–134; interp.rs:4413–4429 (tests only) |
| G5 | **Granule/config hardening.** (a) 64K TG encodings silently degrade to 4K walks (mmu.rs:99–101); (b) one `granule_log2` shared by TTBR0 and TTBR1 ranges (mmu.rs:55); (c) `T0SZ==0/T1SZ==0` silently remapped to 16 instead of faulting (mmu.rs:104–109) — can mistranslate where ARM would address-size-fault; (d) TBI0/TBI1 ignored — measured TCR has **TBI0=1** (boot_real.rs:20–22), so a top-byte-tagged VA would fault "not in either range". | Latent (kernel uses TG0=TG1=16K, T0SZ=T1SZ=25 — boot_real.rs:20–22) | Medium (silent wrong-walk is the worst class) | mmu.rs:94–111 |
| G6 | **Zero walker unit tests.** `translate()` has one caller (interp.rs:336), mmu.rs has no test module; no 4K/16K/block/fault goldens. Any M2/M4 refactor can regress the walker unguarded. | No | Process risk | §1 test coverage |
| G7 | **Wholesale TLBI/flush model.** All TLBI variants and every TTBR/TCR write flush the entire TLB; no ASID, no VA-range invalidate. Correct (never stale) but hit-rate collapses under later per-task ASID churn; `TlbiRange` records base/scale/num then ignores them (interp.rs:3193–3200). | No | Low (perf only, pre-sched) | mmu.rs:110/115/120/138–139; interp.rs:3869–3874, 3191–3201 |
| G8 | **isa.rs `SystemRegTable` is dead code** with a reset value (`0x00C5_0800`, isa.rs:147–151) the interpreter never uses (interp.rs:252 → 0). Honesty cleanup only. | No | None (doc drift) | isa.rs:174–302; interp.rs:24–31, 252 |
| G9 | **52-bit PA / secure / EL2 stage 2** — out of scope, fails loudly per header (mmu.rs:17–18); PAs masked to 48-bit (mmu.rs:114/119/244) — fine for the 40-bit-IPS kernel. | No | None for this fixture | mmu.rs:17–18, 244 |

Acceptance-line status: *"guest writes TTBR0/TCR … sets SCTLR_EL1.M=1 and
execution CONTINUES with translated fetches"* — **already true on the real
fixture** (the run died 8.1M insns in, in virtual mode, of an MMU-mediated
load fault). What is NOT yet true: the *≥1M with MMU live* number is
unmeasurable (G2), and bullet 1's fault/attr items are genuinely open (G3, G4).
The stale plan text "they are currently no-ops" (BOOT-PLAN.md:207) should be
corrected to match the wired state.

---

## 6. Instrumentation plan (MEASURE ≥1M MMU-live insns) — proposals only

Instruction retirement today: `Interpreter::run` counts each successful
`step()` (+ the HLT) into private `executed` (interp.rs:3923–3946), returned as
`RunResult.executed` (lib.rs:74–77). boot-first → `boot_first::run` stages then
calls `boot_real::run(&staged, 12_000_000)` (boot_first.rs:34, 249); boot-real
issues **one single `cpu.run(InterpBudget { max_insn, max_ns })`**
(boot_real.rs:245–250) — **there is no resume loop**: a TranslationFault is a
terminal stop for the invocation; `print_report` then formats the stop
(`TranslationFault(kind, detail) va pc`, boot_real.rs:325–331), the MMU line
`config · walks · tlb hits · faults` (:334–337), the fault descriptor chain
(:375–380) and the honest verdict (:383–399). MMU counters already surfaced:
`mmu_walks / mmu_tlb_hits / mmu_faults` (BootRealReport fields boot_real.rs:69–72,
filled :278–281 from mmu.rs:61–63).

Proposed metric additions (NOT implemented):

1. **`mmu_live_from: Option<u64>`** — in the SCTLR_EL1 write arm
   (interp.rs:3817–3820), on the 0→1 edge record `self.executed` before
   `set_enabled`. Report `mmu_live_insns = res.executed − mmu_live_from`.
   *This is THE M3 gate number.* ~10 lines + 2 report fields.
2. **Translated-access counter** — either derive `walks + tlb_hits` (both pub,
   already reported) or bump an explicit `mmu.accesses` in `vaddr`
   (interp.rs:331–343); report hit-rate. ~5 lines.
3. **Per-kind fault tally** `{fetch, load, store}` × detail (invalid-desc /
   out-of-range / va-bits / table-at-L3) — field adds at the six `faults += 1`
   sites (mmu.rs:179, 187, 203, 231, 250, 256). ~20 lines.
4. **Leaf-level histogram `leaf_at_level: [u64;4]`** — proves the 16K L1-start
   truncated-index walks actually dominate on real tables (claimable parity
   evidence). ~10 lines.
5. **Sysreg-write trace ring** for TTBR0/TTBR1/TCR/MAIR/SCTLR with the insn
   index (capture in each write arm, interp.rs:3817–3866; surface in
   BootRealReport) — closes "TTBR/MAIR ground values never captured"
   (m3-mmu-groundwork.md:25, 42–43). ~25 lines.
6. **Surface `Bus::unmapped_reads/unmapped_writes`** (bus.rs:16–18) in
   BootRealReport + print_report — today an unmapped MMIO read is silent-zero
   with an invisible counter. ~8 lines.
7. **Verdict line**: `M3: MMU live for {N} insns (gate ≥ 1,000,000) ✅/❌ ·
   walk faults {k}` appended to print_report's honest verdict
   (boot_real.rs:383–399). ~5 lines.
8. Re-measure and reconcile the published numbers (PARITY "0 walk faults"
   vs the terminal-fault stop) when these counters land.

With #1+#2+#7 alone the M3 acceptance sentence becomes a printed, checkable
claim on the next boot-real run.

---

## 7. Risk list for the M2-unlock (rebased/chained-fixup pointers → kernel runs further)

1. **Any walk fault = dead run (G1).** First symptom: `stop:
   TranslationFault(kind, detail) va=… pc=…` + descriptor-chain dump
   (boot_real.rs:327–329, 375–380). Likely triggers: NULL/garbage-page probes
   (the va=0x4 load already seen), walks of VAs outside both ranges
   (mmu.rs:183–188), unmapped MMIO behind a not-yet-populated L2' entry.
2. **Device-region access through `vaddr()`** — AIC/UART reads/writes in
   virtual mode: translation PA-routes them to the Bus correctly (§4), so
   functionally OK *if* the kernel's physmap covers them. If a mapping is
   missing, the symptom is **silent zeros** (bus.rs:50–51) with an unprinted
   counter — kernel takes a wrong-but-alive path (e.g. AIC version = 0) instead
   of a diagnosable stop. Mitigate with metric #6 before M5 device work.
3. **Kernel reprograms TCR for real pmap** after bootstrap (plausible: per-task
   4K user tables or 64K page tables on some configs): 64K silently-4K (G5a)
   and the T0SZ=0 remap (G5c) become live mistranslation sources; single
   shared granule (G5b) breaks TG0≠TG1 configs. Watch for fault chains that
   start at L0 with plausible-looking descriptors.
4. **ASID/TTBR0 churn**: every TTBR0 write flushes everything (mmu.rs:113–116)
   — correct but the TLB hit-rate (9.1M/460 today) collapses if the kernel
   switches ASID per thread pre-M4; perf only.
5. **Cache ops stay no-ops while SCTLR.C/I are set** (the flip value has C=1):
   fine for coherence-less reads (everything reads RAM), but DC CIVAC-before-
   DMA patterns can't be validated; keep on the ledger.
6. **WXN**: the flip value `0x3454_593D` has WXN=0 — lucky, because WXN
   enforcement doesn't exist (G3). If a later kernel config sets WXN, XN
   descriptors will be silently ignored.
7. **PAC'd indirect branches deeper in boot**: PAC is a permissive QARMA model
   (interp.rs:9–14) — a mismatched sign would send PC wild and surface as a
   walk fault at a garbage VA (terminal per #1). Not an MMU bug, but it will
   *look* like one in the stop reason.

---

## 8. MINIMAL WORK PLAN (ordered; est. diff sizes; no Rust changes made by this audit)

| Step | Content | Est. diff | Why first |
|---|---|---|---|
| **1** | Instrumentation §6 #1+#2+#6+#7 (`mmu_live_from`, accesses/hit-rate, unmapped bus counters, M3 verdict line) + re-run boot-real + reconcile the PARITY/BOOT-PLAN numbers and the stale "no-ops" text (BOOT-PLAN.md:207, PARITY.md:433). | ~30–40 lines, report-only | Makes the M3 gate **measurable and honest** with zero behavior change; unblocks claiming M3 the moment M2 stops moving. |
| **2** | Synthesized walker goldens in a new `mmu.rs` test module: 4K L3 hit, 16K L1-start truncated index (real kernel shape), 2MB L2 block, invalid-desc fault (+ `last_fault_chain`), out-of-range fault, TLB hit then flush-on-TTBR-write, 64K-TG **fault** assertion after step 3. | ~60 lines (tests) | Locks the walker before M2/M4 churn (G6). No production change. |
| **3** | Loud-fail hardening (G5): 64K TG encodings → walk fault "granule unsupported"; drop the `T0SZ==0→16` remap → fault; (optionally) honor TBI0/TBI1 by masking the top byte before the range check, flag-gated. | ~30 lines + tests | Converts silent wrong-walk traps into named stops before the kernel's own TCR games begin. |
| **4** | ESR/FAR synthesis (G1 groundwork): on any TranslationFault record `FAR_EL1 = va` and synthesize an ESR (EC 0x24/0x25, IL=1, DFSC from walk level — the chain already carries the level, mmu.rs:64–65, 229) into `SystemRegs`; do **not** vector yet. Report ESR/FAR in print_report. | ~60 lines | Gives M4 vectoring something honest to deliver; makes stop diagnostics ESR-shaped. |
| **5** | Attr indirection measurement (G4): extract AttrIndx[4:2] at leaf, call `attr_byte`, classify Device/Normal, store attr on the TLB entry (value → `(pa, attr)`); add a **device-attr-on-RAM / normal-on-unmapped** counter. No routing change (PA routing already correct, §4). | ~40 lines | Closes BOOT-PLAN bullet 1's attr item as *measured*, defers enforcement. |
| **6** | AP/XN/AF enforcement **behind `Mmu.enforce_permissions: bool` (default OFF)** — Fetch→XN/PXN, Load/Store→AP[2:1], AF=0→fault — **only when M4 lands VBAR vectoring**; ship both together or enforcement just relocates the boot death (G1 dependency). | ~80–120 lines + goldens | Last, deliberately: enforcement before vectoring makes boot strictly worse. |
| **7** | Honesty cleanup (G8): delete or wire up `isa::SystemRegTable`; make `SystemRegs` reset `sctlr_el1` to the documented RES1 value or fix the isa.rs doc. | ~15 lines | Doc-vs-code lie removal. |

Steps 1–2 (~100 lines) are the minimum to *close M3 as written, honestly*:
the acceptance sentence is already true on the fixture; step 1 makes the
≥1M-with-MMU-live number real; step 2 makes it regression-proof. Steps 3–5
(~130 lines) close the structural M3 bullet-1 items that M2-unlock will start
hitting (risk list §7). Step 6 is gated on M4.

*End of audit — no source files were modified.*
