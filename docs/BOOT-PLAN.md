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

## M1 — ISA closure: every instruction class decoded  [x] (99.31% decode / 99.3% exec — gate ≥99.3% CLEARED)
**Progress (2026-10-29, sessions D+E — the M1 acceptance run):** the five
remaining families landed and the gate CLEARED: **decode 99.03% → 99.31%
(7,911,692/7,966,342; unknown 55,284 of which 36,792 are ≥16-word literal-pool
runs = data), exec probe 98.9% → 99.3%** on the real 18C66 text. Families:
SIMD ld/st register-offset Q/S/D (opc<0>=L, opc<1>=Q; S=size 10, D=size 11 —
~5.5k words), load/store MULTIPLE structures (bit23=post, op4 bits 15:12,
type bits 11:10 — de-interleave exec), SINGLE structure + LD1R/2R/3R/4R
(index = Q:S:size per lane class), indexed by-element FP (fmla/fmls/fmul/
fmulx) + INT (mla/mls/smlal/umlal/smlsl/umlsl/smull/umull/sqdmull/sqdmlal/
sqdmlsl/sqdmulh/sqrdmulh) + FP16FML (fmlal/fmlsl) — capstone-authoritative
map from pin_m1d3.py (62-combo brute force; index = H:L:M .h / H:L .s / H .d,
rm 4-bit when M is an index bit), scalar FP (fcmp/fcmpe, fccmp/fccmpe, fcsel,
fmov reg/imm via VFP-ExpandImm, FCVT{N,A,P,M,Z}S/U plain+fixed-point,
SCVTF/UCVTF, FMOV gpr↔fp, ADDP/FADDP scalar), 2-reg-misc (rev64/32/16,
abs/neg/fabs/fneg/fsqrt, xtn/sqxtn/uqxtn/sqxtun, fcvtn/fcvtxn/fcvtl,
fcvtzs/u + scvtf/ucvtf vector, saddlv/uaddlv/addv/sadalp/uadalp, cls/clz/cnt,
cm*#0, saddlp/uaddlp, suqadd/usqadd), permute (zip/uzp/trn), ext, dup
(elem+gpr), ins (gpr+lane), umov/smov, tbl/tbx, SHA1 (h/c/p/m/su0/su1),
SHA256 (h/h2/su0/su1 — 2-round compression semantics textbook-verified in
python), PMULL .1q (d64), SIMD LDR literal + LDRSW literal + PRFM-literal,
FMOV vector .2d/.4s immediate.
**REAL-DATA BUG #15:** the across-lane reduce guard swallowed three-same
insns with Vm=16/17 (fadd v0.4s,v0.4s,v16.4s = 0x4E30D400 — ~1.5k kernel
words). **REAL-DATA BUG #16:** FCVTL (2-reg-misc opcode 011110, size=01)
silently decoded as AESIMC (same opcode, size=00) — size==00 guard added.
**REAL-DATA BUG #17:** ADC/ADCS/SBC/SBCS (0x1A group, bit23=0, opcode
15:10=000000) decoded as CSEL/CSINC (bit23=1 arm) — keystone cross-check
0x1A020020 adc vs 0x1A820020 csel; ~1.5k words carried wrong semantics.
Goldens: gap_simd_regoff_mult_single, gap_indexed_std_family,
gap_scalar_fp_family, gap_permute_copy_sha, gap_2reg_misc_literals_adc +
the generated 100-row capstone-named table (goldens_m1.rs). `cargo test
--workspace`: 288 passed / 0 failed. boot-first re-run (IOS_RUST_DRAM_MB=2048
— sandbox memory limit): irestore+staging ✅, ADT-driven machine assembly ✅,
9 insns retired, stop Halted (M2 zeroed-GOT stop — unchanged, not ISA).


**Progress (2026-10-29, session C second half — three-same FP + unscaled
AR):** three-same FP landed, 24 ops (fadd/fsub/fabd/faddp/fmul/fmulx/fdiv/
fcmeq/fcmge/fcmgt/facge/facgt/fmax/fmin/fmaxnm/fminnm/fmaxp/fminp/
fmaxnmp/fminnmp/fmla/fmls/frecps/frsqrts) — the field map is keystone-
pinned and NOT the textbook layout: width = bit22, opcode-pair half =
bit23, bit10=1 (crypto-3 is bit10=0). Integer three-same gained MLA/MLS
(opcode 100101). **REAL-DATA BUG #13:** BRAAZ/BLRAAZ — the 0xD6-space
A-key Z-forms (~428 words) the session-A PAC campaign missed; masks
0xFFFFFC1F == 0xD61F_081F / 0xD63F_081F. **REAL-DATA BUG #14:**
STLUR/LDAPUR/LDAPR (v8.1 unscaled release/acquire ≈1.1k words) mapped
onto LdSt9 Unscaled (release/acquire = no-op here — honest); LDAPR has NO
imm9 (bits 23:12 fixed pattern, size from bit30). FCVTZS/U fixed-point
vector (opcode 11111; real 0x4F70FC00). **decode 98.89% → 99.03%
(7,889,208/7,966,342), exec probe 98.9% → 99.1%**; `cargo test
--workspace` 100 passed / 0 failed; boot-first after the families:
9 insns retired, stop Halted (M2 stop = zeroed GOT entry, not ISA).
Remaining buckets to the ≥99.3% acceptance (hist, fresh):

| bucket | words | family | how |
|---|---|---|---|
| 0x4c+0xbc+0x3c+0xfc | ~9.7k | SIMD ld/st multiple + register-offset + LDR-literal | LdStRegOff V=1 + new LdStMult; masks from the full-space census |
| 0x4f (rest) | ~3.5k | indexed-multiply (smull/umlal/sqdmull/fmul/fmla/fcmla-elem, bit10=0) | op4 map + L/M/H index; FIRST check the existing Vindexed (0xC,U=0) vs census sqdmulh collision |
| 0x1e+0x5e+0x7e | ~4.1k | scalar FP remainder (fcmp/fcmpe, fcsel, fmov-imm, scvtf/ucvtf scalar) | op10 census windows 0x1E4/0x5E4/0x7E4 |
| 0x4e+0x6e (rest) | ~3.4k | EXT, DUP-from-GPR | ext mask 0x9F600400/0x0E000000 (verify low bits); dup needs its real window (bits 15:10 = 000011) |
| 0x0e+0x2e (rest) | ~2.5k | 2-reg-misc narrowing: xtn/sqxtn/uqxtn/sqxtun/fcvtl/fcvtn/addp-scalar/uaddlv | Rm=0 census rows |
| data | ~52k | literal pools + ASCII (0xff/0x00/0x45/0xfe…) | NOT decodable — honest floor |

**Progress (2026-10-29, session C first half — shift-imm + modified-
immediate):** the 0x0F group decoded+executed end to end: SSHR/USHR/SSRA/
USRA/SRSHR/URSHR/SRSRA/URSRA/SHL/SLI/SRI/SQSHL/UQSHL/SQSHLU + narrowing
(SHRN/RSHRN/SQSHRN/UQSHRN/SQSHRUN/SQRSHRN/UQRSHRN/SQRSHRUN) + widening
(SSHLL/USHLL) + fixed-point (SCVTF/UCVTF vector) + MOVI/MVNI/ORR-imm/
BIC-imm (cmode table capstone-verified) + FMOV vector immediate. **decode
98.87% → 98.89%** (7,878,033/7,966,342); exec probe 98.9%. Every field
rule pinned by keystone sweeps (shift = (16<<size)−X right forms,
X−(8<<size) left forms; SSRA=op2, RSHR=op4, SRSRA=op6 — NOT 1/2/3 as
first guessed). Environment notes: the sandbox reset twice mid-session;
the 18C66 IPSW constant in ipsw_range.py had drifted back to 14.0-beta
once (re-fixed, CLI now matches README); guest DRAM is now
IOS_RUST_DRAM_MB-overridable (sandbox has 3 GB, 1 GiB window verified
end-to-end).

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

## M2 — rebase / chained-fixups image loading  [x] (2026-10-29 session F: boot-first 9 → 8,135,842 insns, new named stop)

**Premise corrected by byte-level census** (`tools/re/extraction/m2_fixup_census.py`,
notes in `tools/re/notes/m2-chained-fixups-census.md`): the real 18C66
`kernelcache.release.iphone12b` is an **old-style bare-kernel Mach-O** —
25 load commands, **no LC_DYLD_CHAINED_FIXUPS, no LC_DYLD_INFO, no fileset
entries**; all `__PRELINK_*` segments are zero-size. There is no iBoot-side
fixup walk to implement. What the file really ships:

* `__TEXT,__thread_starts` — u32 (start,end) range list; the **kernel
  itself** scans those ranges at boot for chained entries and rebases them
  (loop at 0x…7b802b8 — already executes correctly in the emulator).
* `__DATA_CONST,__auth_ptr` — 544/544 entries ship NON-zero as
  pre-signed PAC slots holding offsets from the preferred base (measured:
  entry[1] = 0x80100000_00a14000; 0xa14000 = `__TEXT_EXEC` − link base).
  Our handoff loads at the preferred layout (slide 0), so they are valid
  as shipped.
* `__DATA,__data` ships mostly zero — filled by the kernel's own boot.

**The real first-boot unlock was the harness**: `boot-first` was executing
`__TEXT_EXEC.__text[0]` with no handoff state and a 20k cap (hence "9 insns,
Halted"). Session F wired it to the real iBoot→xnu handoff contract
(`boot_real::run`: boot_args at physBase in x0, LC_UNIXTHREAD entry at load
PA, MMU off) with a 12M budget.

**Acceptance (measured 2026-10-29, debug build, IOS_RUST_DRAM_MB=1024):**
`boot-first fixtures /tmp/bootfirst` retires **8,135,842 real instructions**
(gate ≥ 10,000 — CLEARED; was 9), SHA-384 component verification ✅
(KernelCache == Customer Erase/Upgrade identities), MMU 460 walks / 0
faults, and stops at a NEW named point — never again at the first indirect
call:

```
stop: TranslationFault(load, invalid descriptor) va=0x4 pc=0xfffffff0081377b4
lr=0xfffffff007b8cc10 (the /cpus caller) · x9="LSSealio" (AppleSPU ALS
Sealion driver string) · x0 = [x20+8] = NULL — kernel CPU enumeration
reading DeviceTree globals that ship zero (x[0x…7744988] DT-ptr,
w[0x…7744998] DT-flag; both 0 in __DATA_CONST,__const) behind the
memory-init gate at 0x…b83f54 (`bl 0x…8136f10; tbnz w0,#0 → skip stores`).
```

**Next missing device/evidence (handed to the next work block):** a live
sysreg/DT trace to determine whether the 0x…7b83fa0 store site executes and
what the gate returns in-emulator — i.e., why the kernel's DT globals are
not populated on our path. Recorded in `tools/re/notes/m2-chained-fixups-census.md`.

## M3 — MMU / TLB  [x] (2026-10-30 session G: MMU live for 8,110,809 of 8,135,842 insns — gate ≥1,000,000 CLEARED)

**Session G evidence (2026-10-30, debug build, IOS_RUST_DRAM_MB=1024,
`boot-first fixtures /tmp/bootfirst`, log `/tmp/bootfirst-m3.log`):**
the acceptance sentence is now measured, not asserted. The guest (real
18C66 `start`) writes TCR/TTBR0/TTBR1/MAIR — all captured AND consumed —
flips `SCTLR_EL1.M`, and execution continues translated:

* **MMU live for 8,110,809 of 8,135,842 retired insns** (arming edge at
  insn 25,033; gate ≥ 1,000,000 — CLEARED). Insns retired byte-identical
  to the M2 session run (8,135,842) — zero behavioral drift from the M3
  changes.
* **460 walks / 9,125,225 TLB hits / hit-rate 100.0% / faults 1**
  (load — the known DT stop). Leaf histogram **L0 0 · L1 0 · L2 459 ·
  L3 0**: every bootstrap translation terminates at an L2 32 MiB block
  descriptor, exactly the start.s shape.
* **MAIR attr measurement (recorded, not enforced):** device pages 0 /
  normal pages 459; misroute tallies device→RAM 0, normal→MMIO 0 (DRAM
  window 0x8_0000_0000..+memSize; the first run's 459 false
  normal→MMIO tallies were a ram_top semantics bug in the new report
  code — size vs window end — fixed same session).
* **ESR/FAR synthesis live at the stop:** FAR_EL1 = 0x4, ESR_EL1 =
  0x96000006 (EC 0b100101 data abort, WnR 0, IL=1, DFSC 0b110 =
  translation fault L2) — agrees with the dumped descriptor chain
  (L1 @0x…704000 valid table → L2 @0x…70c000 invalid).
* **Walker goldens (9 new mmu tests)**: 4K L3 page walk, 16K L1-start
  truncated index + 32 MiB L2 block (the real kernel shape), invalid-desc
  fault chain + per-kind tally, out-of-range VA, 64K/reserved/TG0≠TG1
  TCR loud-fail, T0SZ=0 no-remap fault, attr device/normal + misroute,
  flag-gated TBI masking, ESR shapes. **REAL-DATA BUG #19** found by
  these goldens (not by the real run — the kernel's tables happen to be
  granule-aligned): the walker masked TTBR to granule alignment, but the
  START-level table may be truncated (xnu's 8-entry L1') and needs only
  8-byte alignment — a truncated L1' at a non-granule-aligned base
  silently walked table 0. Fixed; descriptor-encoded next-level table
  addresses keep the granule mask (architecturally required).
* **Loud-fail hardening:** 64K granule / reserved TG encodings /
  TG0≠TG1 mixes now set `config_fault` and fault on first walk
  (previously 64K silently walked as 4K); T0SZ/T1SZ=0 no longer remapped
  to 16 (faults via the va-bits check); TBI0/TBI1 decoded (TCR shows
  TBI0=1 on the real run), masking flag-gated `honor_tbi` (default off —
  behavior identical to the measured baseline).
* `cargo test --workspace`: **298 passed / 0 failed** (290 + 8 net new
  goldens + report plumbing).

**Honest limits carried forward (tracked, not hidden):** permission/AF/XN
ENFORCEMENT is still absent (attrs recorded-not-enforced) — deliberately
gated on M4 exception vectoring, because enforcement without vectoring
just relocates the boot death into a terminal stop (audit
`tools/re/reports/m3_mmu_audit.md` §8 step 6). TLB invalidation is
wholesale (no ASID/VA-range targeting — correct, never stale, hit-rate
collapses only under per-task ASID churn). Secure/EL2 stage-2, 52-bit PA,
contiguous hints: fail loudly per module header. PAR/AT instructions
absent (M4). PARITY 2.11c's "0 walk faults" wording is reconciled here:
the terminal DT stop IS walk fault #1 (per-kind tally: fetch 0 / load 1 /
store 0).

**Progress (2026-10-29 session F, groundwork + first fix):** the M3 section
text was stale — `crates/a13-cpu/src/mmu.rs` is already a real 4K/16K
stage-1 walker wired to TTBR/TCR/SCTLR (460 walks, 9.1M TLB hits, 0 faults
on the kernel's own tables — see PARITY 2.11c). REAL-DATA BUG #18 found and
fixed: the MAIR_EL1 write arm dropped the value (`=> {}`), so every MRS
read 0 — now round-trips AND feeds `Mmu::set_mair`/`attr_byte` (attr
indirection source); goldens `gap_mair_*`. Honest gaps remaining: no
permission/AF/XN enforcement, no ESR/FAR/PAR, no exception vectoring,
MAIR/TTBR ground values never captured from a real run. Full inventory +
plan: `tools/re/notes/m3-mmu-groundwork.md`.

xnu builds its own page tables during early boot; the interpreter must walk them.

1. `a13-cpu`: TTBR0/TTBR1_EL1, TCR_EL1 (TG0/TG1, T0SZ/T1SZ), 4 KiB + 16 KiB
   granule walks (L0→L3), AF/dbm/access-permission faults, attr indirection
   (MAIR: device-nGnRE vs normal — device attrs must hit the Bus, normal must
   hit RAM cache). **[session G: TTBR/TCR/MAIR captured+consumed, 4K/16K walks
   golden-pinned, attr indirection measured; permission/AF enforcement
   deliberately deferred to M4 (vectoring dependency) — honest limit above.]**
2. Start with 2-stage-off (EL1 only), stage-1 translation on fetch+load+store.
   **[done — measured 8.11M translated insns.]**
3. **Acceptance:** guest writes TTBR0/TCR, sets `SCTLR_EL1.M=1`, and
   execution CONTINUES with translated fetches; boot-first retires
   ≥ 1,000,000 insns with the MMU live. **[MEASURED 2026-10-30: MMU live
   8,110,809 insns — CLEARED. The old "currently no-ops" parenthetical was
   stale since session F and is corrected here.]**
4. Tool: QEMU `-d trace:arm_ttbr_write` equivalents via `ios-re-toolkit` QEMU
   lane for ground truth on TCR values the real kernel writes.
   **[ground truth obtained statically instead: TCR
   0x0008_0022_6519_A519 read from `__DATA_CONST[0x77020c8]` (16K/16K,
   T0SZ=T1SZ=25, TBI0=1, IPS=40-bit) and now surfaced live in the boot
   report's MMU config line.]**

## M4 — IRQ / AIC / timers  [~] (session M 2026-10-30: FIVE engine bugs + one staging gap fixed — the #32 physmap abort is GONE, the 10.8M panic is GONE, the 34.6M hw_lock panic is GONE; boot runs the 48M budget CLEAN with live UART init + the first real MMIO census; WFI clause still open)

**Session M evidence (2026-10-30, release build, IOS_RUST_DRAM_MB=1024):**
SIX REAL-DATA bugs found+fixed in one block (430 workspace tests 0 failed, +1 golden
update + 1 isolated probe test):

* **AT S1E1R + PAR_EL1 (a13-cpu, THE session-L physmap abort root):** xnu's kvtophys
  (0x…8169574) is `at s1e1r, x0; isb; mrs x1, par_el1` + bfxil — with AT decoded into
  the op0=1/CRn=7 catch-all it returned PA 0; the pmap-walk fallback then failed and
  phystokv(0) landed at gVirtBase−gPhysBase = 0xFFFFFFE806000000 (the session-L abort,
  FAR measured). Implemented: PAR_EL1 (read/write) + the full AT family (S1E0R/W,
  S1E1R/W, S12E0/E1R/W, S1E1RP/WP) executing the REAL stage-1 walk with F-bit fault
  reporting; at_ops counter in the report (63 AT ops in the final run). TPIDRRO_EL1
  (bug #33 read half) reads 0 (boot CPU). xnu source ground truth: osfmk/arm/
  arm_vm_init.c from apple-oss-distributions xnu-7195.121.3 (the exact 18C66 tree) —
  the whole physmap pre-init loop decoded against it.
* **PAC AUT accept-and-strip + XPACD sign-extension (a13-cpu):** the pmap walk's
  `autda x16; xpacd x17; cmp` check brk'd (#0xc472 @0x…7b78664, insn 10,836,209) —
  build-time-signed __auth_ptr pointers cannot validate under a public QARMA model and
  the old poison-bits model broke the compare. AUT of a pointer we did not sign now
  accept-and-strips, COUNTED (pac_aut_unverified: 163 in the final run); XPACD now
  sets bits[63:48] = copies of bit 47 (ARM DDI 0487) — the old mask-only form made
  the accept-and-strip compare fail.
* **arm-io ranges translation in attach_from_adt (apple-soc, THE first-MMIO root):**
  the first live MMIO census (IOS_RUST_MMIO_LOG — 17 accesses!) caught the kernel
  writing the CONSOLE UART at 0x235200000 (real SoC base) while devices attached at
  the raw ADT reg (0x35200000). /arm-io children now translate through the real
  `ranges` property (u64 triples), fallback = the session-H pinned rule (+0x2_00000000
  below 0x1_00000000). Result: UART0/1/2/3 + pmgr/aic/wdt/dart/ans2 all live at the
  kernel's addresses; s3c-uart serves the console writes.
* **/chosen/dram-base + dram-size staging (boot_real, kernel-NAMED):** the panic
  formatter caught the kernel's own message: "%s: Unable to find 'dram-base' entry in
  the 'chosen' DT node" (arm_init, SecureDTGetProperty @0x…7b80d34; fmt 0x…73676f4;
  GDB-trap 0xE7FFDEFF at insn 11,419,858). The IPSW template ships neither prop
  (iBoot adds them); staging now inserts both u64s = the machine's real DRAM geometry
  (0x800000000/0x40000000), consistent with boot_args and the DRAM region.
* **#37 LSE CAS fields swapped (a13-cpu, THE lck_rw panic root):** capstone prints the
  COMPARAND first ("casa x1, x2, [x2]" = 0xC8E17C42: x1@bits[20:16], x2@bits[4:0]) —
  the decoder mapped rt→bits[4:0]/rs→bits[20:16], so every CAS compared the NEW-value
  register against memory and never stored. Measured: kernel_pmap's lck_rw word never
  gained the lock bit → lck_rw_done panicked "Releasing non-exclusive RW lock without
  a reader refcount!" at insn 11,463,447 (PPL pmap path 0x…988a87c → lock 0x…7b868dc /
  unlock 0x…7b87124). Fixed + goldens corrected + the Atomic/LDADD family re-verified
  (its field order is genuinely rs-first — distinct from CAS).
* **#38 logical-immediate W-form upper-half leak (a13-cpu, THE hw_lock panic root):**
  AND/ORR/EOR immediate didn't zero Xd's upper 32 bits for W destinations — `mov w9,
  #0x3ffffffc` (ORR-imm bitmask) left x9 = 0x3ffffffc3ffffffc, the hw_lock destroy
  path's `cmp x9, x8, lsr #2` (0xEB48093F @0x…7b88174) then FAILED → w2=0 → the
  destroy continuation RE-ACQUIRED the destroyed lock → "hw_lock_bit(): timed out"
  at insn 34,620,897. Fixed for AndImm/OrrImm/EorImm (Movz/Movn/Movk were already
  correct); isolated probe test cmp_lsr2_then_cset_eq_yields_one pins the sequence.

Boot frontier: the panic-formatter chain (0x…7a58458 = panic-with-percpu-context)
no longer fires anywhere in 48M insns; the boot's first kernel-named wall is now a
kernel-HANDLED load abort FAR 0x10c @ELR 0x…7b1e150 (NULL+0x10c percpu-style deref,
ESR 0x96000005 — delivered 1, panic 0, budget stop 48M clean). uart0 console writes
land on s3c-uart (TX not yet observed — the kernel initializes ULCON/UCON/UFCON/baud
but kprintf has not run by 48M). Bug #33's GXF-write half remains open. M4 acceptance
(WFI-resume ≥10M) NOT cleared — honest.

## M4 — IRQ / AIC / timers  [~] (session L 2026-10-30: bugs #34/#35/#36 fixed — the #32 guard-spin is GONE; boot now executes arm_vm_init's physmap phase live; WFI clause still open)

**Session L evidence (2026-10-30, debug build, IOS_RUST_DRAM_MB=1024, 48M budget):**
THREE REAL-DATA bugs found+fixed in one block (429 workspace tests 0 failed, +4 goldens):

* **#34 (a13-cpu, THE #32 ROOT):** the #31 fix over-corrected — the SHIFTED-register
  add/sub form reads Rn=31 as XZR (only the EXTENDED form maps Rn=31 to SP; `cmp sp, x18`
  = 0xEB3263FF is EXTENDED, bit21=1). Live proof: the kernel qsort's `neg x19, x20`
  (0xCB1403F3) produced sp−0x4C8 instead of −0x4C8 (watched at insn 8,255,253); the
  corrupted stride made med3 hand the comparator a phystokv(sp−0x4C8) element pointer —
  the entire #32 abort + corrupted-ELR cascade. Goldens: gap_neg_shifted_rn31_reads_xzr,
  gap_cmp_xzr_shifted_ignores_sp, gap_cmp_sp_extended_still_reads_sp,
  gap_qsort_med3_neighbors_with_fixed_neg. All prior #31 goldens re-verified (they are
  extended-form encodings).
* **#35 (boot_real staging):** flat-file staging put __BOOTDATA/__PRELINK_INFO 0xB0000
  below their VA-implied PAs (fileoff != vmaddr−LINK_BASE after __DATA's BSS) — the
  kernel's tables resolved __BOOTDATA VAs onto __PRELINK_INFO plist bytes; the
  init-entry cursor 0x…9b031e8 read "<key>UID" (FAR 0x4449553e79656b3c). Fixed:
  per-segment staging at PA = VA − LINK_BASE + LOAD_PA.
* **#36 (boot_real DeviceTree):** the kernel reads /chosen/random-seed (helper
  0x…81383ac: SecureDTLookupEntry(0, "/chosen") + SecureDTGetProperty(entry,
  "random-seed"), expected 0x40) and panics "Expected 64 seed bytes from bootloader,
  but got 0" when the value is the IPSW's 64-ZERO-byte template. Fixed:
  iBoot-equivalent in-place fill with DETERMINISTIC emulated entropy (sha256 label ×2;
  hardware-RNG parity = tracked honest limit).

Boot frontier: init-entry sort+calls run on REAL entries; arm_vm_init's
arm_vm_physmap_slide phase (0x7b82e34) executes FOR THE FIRST TIME in any session.
New frontier (next block): the L2-table free-list allocation ([0x7701cf8] → 0x…7b72f88)
returns empty → ptov_lookup(0) → phystokv(0) abort @0x…7b82fec (insn 8,514,106; FAR
0xffffffe806000000; kernel-HANDLED, panic 0, 48M clean). Bug #33 (TPIDRRO_EL1 + Apple
EL2 GXF sysregs) still open. M4 acceptance (WFI-resume ≥10M) NOT cleared — honest.

## M4 — IRQ / AIC / timers  [~] (session K 2026-10-30: bugs #28-#31 fixed — gcd loop + MUL/SP + PAC-strip + Rn=31-SP; boot panic-free through vm_mem_bootstrap __init_entry_set callbacks, one kernel-HANDLED physmap abort; WFI clause pending: #32 corrupted-ELR ERET stop)

**Session K evidence (2026-10-30, release build, IOS_RUST_DRAM_MB=1024):**
FOUR engine-semantics bugs fixed in one block (all keystone/capstone-pinned,
19 new goldens, 425 workspace tests 0 failed):
* **#28 MSUB operand order** (`Xd = Xa − Xn·Xm`): the session-J gcd
  divergence RESOLVED — the timebase helper @0x…7b92d20 completes
  (ratio 125/3, Hz 24e6) and the boot advances past arm_vm_init's
  clock setup. Notes: tools/re/notes/m4-gcd-clock-re.md.
* **#29 MUL = MADD with Ra=31 → XZR**: the "Section
  __BOOTDATA,__init_entry_set has invalid size" vm_mem_bootstrap panic
  (insn 8,255,200) resolved — the div-by-6 multiply-magic check passes.
* **#30 PAC canonical strip**: `blraa x27,x26` (0xD73F0B7A
  @0x…7f2f658) no longer fetches tagged pointers; the
  __init_entry_set constructor callbacks run (the physmap load-abort
  they trigger is handled BY THE KERNEL — delivered 1, panic 0).
* **#31 add/sub Rn=31 = SP**: the vector-page stack guard's
  `cmp sp, x18` now compares the real SP (N=1 verified in-golden).
* **#32 (open, next block):** after the handled physmap abort the
  ERET lands on a corrupted ELR 0x00FFFFF00815F200 (top 16 bits
  0x00FF, should be 0xFFFF) → `b 0x…81601d8` → the guard → spin.
  Candidate: a top-half mis-model in the C sleh path (BFM/extr/MOVK
  family). Tooling added: IOS_RUST_STOP_PC_RANGE, IOS_RUST_TRACE_DEEP,
  guard-chain dump.

**Session J evidence (2026-10-30, IOS_RUST_DRAM_MB=1024):** boot-first
8,194,993 → 48,000,000 (48M budget stop, clean) → **2,000,000,000 insns
retired with stop=Budget · clean · panic() 0 · sync aborts 0 · exceptions
delivered 0 · bus unmapped 0/0** — the real kernel runs 2 GIGA insns
without a single fault after bug #27. The 2G stop is a NEW class (next
block's RE target, bug #28): a diverging **Euclid GCD loop** at
0x…7b92d68-78 (`udiv x12,x10,x12; msub x12,x12,x11,x10; cbnz`) called
from arm_vm_init (lr 0x…7b80a30): the pair is (24,000,000 = the timebase,
2⁶⁴−24,000,000 = a SIGNED-NEGATIVE operand) — unsigned-udiv Euclid on a
negative operand never terminates (the residue stays wrapped). Some
upstream clock-frequency derivation produces a wrapped value — candidate
link to bug #25's unresolved placeholders (clock fields reading reference
bytes). RE next: the gcd args' provenance at the 0x…7b80a30 call site.

**Session J model changes (all keystone/capstone-pinned, 6 new goldens):**
* **Staged layout end_kern = the kernel's own VA span (bug #22 follow-up):**
  end_kern = round_16K(max(vmaddr+vmsize)) = 0xFFFFFFF0_09C60000 — NOT
  round_page(file bytes) (the VA span ends 0xB3000 above the file-backed
  end; the kernel's `end_kern` writer @0x…7b83758 measures
  0xFFFFFFF009C60000). All staging rounds are 16K (ARM64 xnu page size):
  dt_pa 0x803C60000 · boot_args 0x803C98000 · topOfKernelData 0x803C9C000
  (the e[DT] physmap tail entry is now positive and whole-page — the
  rebase lands deviceTreeP on the REAL blob; SecureDTInit's node table
  builds with real 0x9c6xxxx KVAs). Golden `staged_layout_uses_va_span_end_kern`.
* **REAL-DATA BUG #27 — BFM family width formula was simply wrong:**
  `width = bits − imms − 1` (plus a rotate model) turned
  `bfxil x14,x15,#0,#56` — the arm_vm_init packed-pointer rebase decoder
  (`lsl #13 → sbfx #0,#43 → bfxil #0,#56 → add x22 → add 0x0FF8FFC000`)
  — into an 8-bit insert, storing 0xfffe00ee488b0058 instead of
  0xfffffff007724458 into the DT-registry array base (object 0x…772478c
  field +0x14; the array-push `str w19,[x9]` @0x…7b8cd70 then faulted —
  the session-I stop). Found via `IOS_RUST_WATCH_VA` store-watch: exactly
  ONE corrupting write at insn 107,008 (pc=0x…7b80340, the walker).
  Fix per keystone/capstone truth table: imms ≥ immr → extract
  src[imms:immr] insert at LSB (bfxil family); imms < immr → wrap insert
  at lsb = bits−immr (bfi family). Also fixed on the same evidence:
  ubfiz's missing field mask (Ubfm s<r branch) and sbfiz's rotate-model
  (Sbfm s<r branch must sign-extend THEN shift). Goldens include the
  verbatim decode pipeline → 0xfffffff007724458.

**Session I evidence (2026-10-30, IOS_RUST_DRAM_MB=1024, /tmp/bf-bug26.log):**
boot-first panic-point 8,135,842 → **8,194,993 retired insns** with
`panic() calls: none`; stop = `ExceptionRecursion(identical-exception-loop)
elr=0x…816c38c far=0x100 cycles=96` — the kernel's exception-report
formatter refault loop, now entered WITHOUT a panic via a garbage
array-base write (`str w19,[x9]` @0x…7b8cd70, x9 = madd(x19,x25,
[x24+0x14]) = 0xfffe00ee488b0058; first abort insn 8,181,649, esr
0x96000050 = write + L1 translation fault). Next block RE target: the
constructor of that array object (x24 provenance).

**Session-H stop ROOT-CAUSED (notes/m4-text-zeroing-re.md):** NOT a remap
storm, NOT a stale TLB — a recursive exception-report stack overflow:
DT-pointer panic (see bug #25) → panic_impl percpu deref with TPIDR_EL1=0
→ unhandled-exception reporter (@0x…81607b8, `bl 0x…816c458`) → formatter
refault (`ldr x11,[x10,#0x100]` @0x…816c38c) → 21,270 cycles × 0x4F0
stack descent zeroing ~24 MB of __DATA/__TEXT_EXEC. The "stale TLB /
remap storm" wording below is retired; the real VBAR_EL1 vector table is
0xfffffff008160000 (the 0x…8165000 stub is `b .` slots).

**Session I model changes (all measured, 4 new goldens):**
* **TPIDR_EL1 honest seed** — the kernel's own cpu_data_init stores
  intstack_top (0x98e4658) at cpu_data[0]+0x4f8 ⇒ base 0x9a4aac8;
  `discover_cpu_data0` (guest-bytes fingerprint scan) existed but had
  ZERO call sites (M4-B timeout casualty). Now called lazily at the
  first `mrs tpidr_el1` while 0; measured live seed
  tpidr = 0xfffffff009a4aac8. The percpu abort storm is gone.
* **Undefined-instruction vectoring** — the kernel ships deliberate
  0xE7FFDEFF markers (ARM GDB trap, 2 file sites in the panic path);
  real HW raises EC=UNCATEGORIZED (ESR 0x0200_0000 — ISS==0 per the
  vendored sleh.c:694 assert) and the kernel's handle_uncategorized
  routes to DebuggerCall. Model: undecodable + live VBAR + budget →
  VBAR+0x200; pre-VBAR keeps the terminal stop.
* **Named-stop guardrails** — `ExceptionRecursion` at ≥96 identical
  (kind,esr,far,elr) re-entries (the storm cycled 21,270 times) or
  exception entry with SP below the real __TEXT_EXEC base.

**Two REAL-DATA bugs found+fixed this session:**

* **#25 DT placeholder lengths** — the IPSW blob ships 87 properties with
  bit31 SET in the length word (identity/metadata; data = SysCfg
  references like b"syscfg/SrNm/0x20,zeroes/"). iBoot resolves them from
  the SysCfg partition pre-handoff; the raw kernel DT walker
  (0x…8136fd4) added the RAW length and its own bounds check panicked —
  THE panic firing at insn 8,135,397 in every recent run. Fix:
  iBoot-equivalent-without-SysCfg flag-clear pass on the staged copy
  (walk consumes the blob exactly; 87 cleared). Honest limit: the
  kernel reads each placeholder's own reference bytes as the value.
* **#26 __DATA BSS not zero-filled** — the harness flat-wrote the whole
  kernel file; __DATA's BSS tail (737,280 B) got the NEXT file bytes
  (the embedded IOCatalogue personalities plist text), so the kernel's
  cursor at BSS 0x…9adf638 read "HostFami" ASCII as a pointer
  (far=0x696d614674736f48 @ insn 8,148,893). Fix: iBoot-equivalent
  per-segment BSS zero-fill after staging.

**Honest limits carried forward:** M4 acceptance: the **≥10M clause is
cleared 244× over (2G clean insns)**; the WFI-and-resume clause is NOT
yet exercised (0 WFI in 2G insns — the kernel is stuck in the bug-#28
gcd before reaching the idle loop). AIC v1 + timer-FIQ models landed but
still see 0 device accesses through 2G insns (M5 census: the boot path
stays sysreg/DRAM-only — M5 attach work correctly waits). Identity
placeholders stay unresolved reference strings (no SysCfg device);
PAR/AT S1E1R + PAR_EL1 still absent; permission/AF/XN enforcement still
gated. cargo test --workspace: **406 passed / 0 failed**
(IOS_RUST_DRAM_MB=768 on the 3 GiB host — honest workaround, unchanged
behavior on 4+ GiB hosts; +3 goldens over session I's 403).

1. Model `apple-aic` v1 (devices crate has a stub): event reg, IPI regs,
   pending-set/clear, mask; wire to `vm-core::irq::IrqController`.
2. Generic timer: CNTFRQ/CNTP/CNTV emulation, deadline → IRQ 29 (cntv) — the
   heartbeat xnu's sched needs.
3. **Acceptance:** boot-first reaches a WFI-and-resumes loop (stop=WFI no longer
   terminal; timer IRQ wakes it); ≥ 10M insns retired.

**Session H REAL-DATA bugs (kept for the ledger — #20-#24):**

* **#20 boot_args DeviceTreeP** — the M2-era builder wrote the DT pointer
  at +0x28/+0x30 (inside Boot_Video); the kernel reads deviceTreeP@0x60 /
  deviceTreeLength@0x68 (PE_init_platform, pe_init.c:390-391; kernel-side
  proof `ldr x9,[x19,#0x60]` @0x…81399c8). Fixed + revision=2 + golden.
* **#21 ADT reg little-endian** — `AdtNode::reg_entries` parsed BE; the
  real n104ap tree is LE (`/arm-io/aic` reg = 0x3b100000/0x8000 as LE
  u64 pairs) — all 59 modeled windows attached at garbage bases
  (aic@0x103B). Fixed + LE format rule (len%16==0 → u64 pairs; %16==8 →
  u32 pairs; len==4 → bare u32) + real-bytes golden + arm-io `ranges`
  translation (child 0..0x1_00000000 → +0x2_00000000, 0x6_.. → identity,
  read from the real ranges property).
* **#22 staging layout** — hardcoded TOP_OF_KERNEL_DATA = DT_PA =
  0x8_0400_0000 sat exactly AT topOfKernelData while end_kern (45.7 MB
  image) is 0x803BAD000 — the DT blob was outside the physmap region
  arm_vm_init maps ([end_kern, topOfKernelData)), the slide landed
  deviceTreeHead on the region start and SecureDT panicked "Device tree
  pointer outside of device tree region" (string 0x…73adec0). Layout now
  computed from real sizes: image → end_kern → DT → boot_args →
  topOfKernelData; deviceTreeP = blob bootstrap-KVA (PA + virtBase −
  physBase, the identity arm_vm_physmap_slide subtracts). Plus iBoot-
  equivalent DT staging: the real blob ships all 6 /cpus nodes
  "waiting"; cpu0 patched to "running" in-place (ml_is_boot_cpu,
  machine_routines.c:924 needs exactly one running node).
* **#24 CCMP/CCMN field swap** — decode read cond from bits 3:0 and nzcv
  from 15:12; keystone 4-sample pin proves cond is ALWAYS bits 15:12 and
  nzcv ALWAYS bits 3:0 in BOTH forms (`ccmp x13, x8, #0, ls` =
  0xFA4891A0: cond@15:12=9, nzcv@3:0=0). The real DT-walk sequence
  `cmp x12,x8; ccmp x13,x8,#0,ls; b.lo` branched with correct registers
  and panicked the boot. Fixed decode + register-form VALUE semantics
  (the old row also used the reg NUMBER as an immediate) + 4 new
  goldens; the old FA430822 row was self-consistent with the swap
  (capstone: `ccmp x1, #3, #2, eq`).

**M4 infrastructure landed (uncommitted-from-timeout M4-B work, now
tested):** exception vectoring with budget (100k), take_exception
(ELR/FAR/ESR/SPSR + DAIF masking), timer-FIQ delivery (CNTV_CTL
ISTATUS → VBAR+0x300 when DAIF.F clear), AIC IRQ line, WFI counters +
ns fast-forward, cpu_data[0] discovery scan, GXF context seed,
`IOS_RUST_WATCH` env-gated watchpoint diagnostics (pc/lr/x0..x22 log,
zero drift). **Spec corrections from the real kernel (M4-B notes,
tools/re/notes/m4-aic-timer-re.md — capstone, 318 lines):** the timer
deadline path is **FIQ, not IRQ 29** (sleh_fiq reads CNTV_CTL ISTATUS;
BOOT-PLAN's "IRQ 29" corrected here); CNTFRQ never read (24 MHz from
pe_identify_machine defaults, no /cpus timebase prop exists); VBAR_EL1
early = 0xfffffff008165000 (session-I correction: that address is the
BOOT STUB table — `b .` slots; the real vector table the kernel runs is
0xfffffff008160000); machine_idle @0x81699a0 = the only idle WFI;
AIC v1 offsets per pexpert AIC.h (kext does the init, not pexpert).

**Honest limits carried forward (session H — superseded by session I's
list above; kept verbatim minus the retired storm wording):** M4
acceptance NOT met (no WFI loop yet); PAR/AT S1E1R + PAR_EL1 still
absent (kvtophys sites will need them); permission/AF/XN enforcement
still gated on vectoring (now EXISTS — enforcement can land next).
cargo test at session H: **394 passed / 0 failed** (DRAM_MB=768 — the
4 GiB default window cannot allocate on the 3 GiB host; the env knob is
the honest workaround, default behavior unchanged on big hosts).

1. Model `apple-aic` v1 (devices crate has a stub): event reg, IPI regs,
   pending-set/clear, mask; wire to `vm-core::irq::IrqController`.
2. Generic timer: CNTFRQ/CNTP/CNTV emulation, deadline → IRQ 29 (cntv) — the
   heartbeat xnu's sched needs.
3. **Acceptance:** boot-first reaches a WFI-and-resumes loop (stop=WFI no longer
   terminal; timer IRQ wakes it); ≥ 10M insns retired.

## M5 — peripherals the real boot path touches  [~] (session N 2026-10-30: FIRST live census at the session-M frontier — the rank-1 unknown-device is dockchannel-uart, modeled + served; B1 bus rule + PMGR 44-window + dapf shims landed; PMGR/AIC/WDT/SART/ANS still 0 touches through 400M — the wall between 48M and 400M is M4's open percpu abort, not M5 devices)

**Session N evidence (release build, IOS_RUST_DRAM_MB=1024, 430→434 workspace
tests 0 failed):**

* **M5 task 1 DONE — the first post-M census** (`IOS_RUST_MMIO_LOG`, run
  transcripts `/tmp/m5/`): at the session-M 48M frontier the real boot path
  touches exactly **17 device-MMIO accesses, all named**: rank 1 =
  `dockchannel-uart` w1 FIFO page `0x23D10C000` (8 hits, `w,r` pairs at
  0x0/0x4/0x8/0xC — the OLD tree's only UNMAPPED window), rank 2 = uart0
  console init @`0x235200000` (9). A 400M-budget extension run (new
  `IOS_RUST_BOOT_FIRST_MAX_INSN` env knob, default unchanged 48M) measured
  **0 additional device touches through 400M** — 1 kernel-HANDLED sync abort
  (FAR 0x10c, ESR 0x96000005, ELR 0x…7b1e150 — session-M's percpu deref),
  panic 0, bus unmapped 0/0, WFI 0, AT ops 63, pac-aut-unverified 163.
  Honest conclusion: the 48M→400M stretch loops inside M4's open percpu
  wall; PMGR/AIC/WDT/SART/ANS/SMM touches all sit BEHIND it.
* **B1 bus rule (vm-core `Bus::find`, attach-spec §0):** overlapping windows
  now resolve SMALLEST-matching-region-wins, tie → last attached. Required
  because the real ADT nests device pages inside larger windows (pmgr w22 ⊃
  dockchannel+pmp; mca-switch ⊃ mca0/1; SEPROM ⊃ dart-sep…). The old
  lowest-base-first `position()` shadowed nested devices forever.
* **PMGR 44-window rewrite (attach-spec §4, `apple-soc/src/pmgr.rs`):** the
  synthetic psreg model replaced wholesale by `PmgrCore` (Arc-shared) +
  44 `PmgrWindow` boxes with CONCATENATED linear offsets — the measured
  AppleT8030PMGR addressing model. APSC polls 0xE2020/0xE2588 answer the
  PS-format mirror ((TARGET<<4)|TARGET, default 0xF ⇒ 0xFF "ACTIVE");
  gate reads at 0x80000+id*0x18 (stride-unconfirmed mitigation: any read in
  the span answers, wrong stride degrades to always-powered, never a hang);
  boot `clock-gates` from the ADT seed the gate table; everything else
  scratch R/W. Fallback map attaches the same 44 windows.
* **dockchannel-uart (attach-spec §5.1, `apple-soc/src/dockchannel.rs`):**
  the s3c-uart mis-model (wrong protocol + console-sink corruption risk)
  replaced by a 2-window shared-core scratch shim with a DEDICATED TX sink.
  Measured upgrade over the spec's RAZ: the 48M census PROVED the kernel
  touches w1 early, so reads echo stored config (write-then-readback safe).
  After the fix the census is **17/17 named, 0 UNMAPPED**.
* **dapf shims (attach-spec §5.2, `apple-soc/src/dapf.rs`):** dapf-disp0 +
  dapf-aop re-classified out of the adp-v4/aop mis-models (DAPF = DART SID
  filter); TCR store-on-write/boot-safe bypass, rest RAZ. classify() wins
  over disp/dart/aop arms; dockchannel intercepts before the uart arm.
* **Per-window exact sizes:** the blanket `size.max(0x1000)` rounding is gone
  (0x1000 floor only for zero-size windows) — no more 0x1000 shadows grown
  from 0x18-byte pages. Dead `dart-ans` fallback arm deleted (P4). New
  `ios-rust adt windows|find` diagnostic subcommand (IM4P→LZFSE→flat ADT,
  window map + physical-address owner lookup — the census naming tool).
* Census-tool staleness note: `m5_mmio_census.py`'s "BAD base (reg_entries
  BE bug)" annotations are STALE (P1 landed sessions ago; the attached bases
  it prints are the REAL ones). The ranked tables + attach map remain
  authoritative. Next tooling pass should drop the stale cross-check text.

**Honest limits carried forward:** M5 acceptance NOT met — "no
unknown-device aborts" is true at the current frontier (0/0 unmapped), but
the NVMe-rootfs-bytes clause is untested: ANS/NVMe/SART are 0-touch through
400M because M4's percpu wall (bug #33 GXF-write half + the FAR 0x10c
handled-abort loop) gates everything past 48M. SART v1 rewrite + ANS
dual-window + SMC endpoint specs (attach-spec §5.4-5.6) are READY but
unlanded — they move the ledger only when the frontier reaches them.
`cargo test --workspace`: **434 passed / 0 failed** (+4: pmgr×2 new tests
rewritten + dockchannel×1 + dapf×1; the pmgr gate_roundtrip test was
replaced by the 3-test pmgr suite).

Current: 59/105 → **103 modeled windows / 105 /arm-io children** (44 pmgr
windows + dockchannel×2 + dapf×2 added; 35 classify-miss nodes unchanged —
skip-list per m5-peripheral-queue §5). Order by what the boot trace touches first:

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

## M5 — peripherals the real boot path touches  [~] (session O 2026-10-30: REAL-DATA BUG #39 — the CCMP/SBCS decoder collision — killed the percpu wall; boot now reaches the kernel's OWN panic "kernel_memory_allocate() failed to alloc global_waitqs" at 22.5M; 0 sync aborts through 48M; next wall is vm_map hole-state in kernel_map)

**Session O evidence (release build, IOS_RUST_DRAM_MB=1024, 434→437
workspace tests 0 failed):**

* **The percpu wall was OUR decoder, not the kernel.** The session-M wall
  (kernel-HANDLED abort FAR 0x10c @ELR 0x…7b1e150, then a 48M→400M spin) is
  fully deconstructed: first-abort FP-chain walk (new M5-O diagnostic) →
  `vm_map_store_entry_unlink(map=NULL, entry=0x…6e2ee230)` ← coalesce ←
  lookup+coalesce ← vm_map_wire-ish ← kernel_map-views table load ← zone
  zinit callbacks ('zcc_magazine_zone') ← `kernel_bootstrap` stage walker.
  Per-instruction PC watches isolated the X0 zeroing to 0x…7b0b598; the
  verbatim word **0xFA4E0160** is `ccmp x11, x14, #0, eq` (capstone) but our
  ADC/SBCS arm (bit23 check only) claimed it: cond=eq ⇒ bits[15:12]=0000,
  bits[11:10]=00, nzcv=0 ⇒ the word fits SBCS's shape (bits[15:10]=000000,
  Rd-slot=nzcv=0) → `sbcs x0, x11, x14` → X0=0 → unlink(NULL) → FAR 0x10c →
  the vector-prologue stack-guard spin at 0x…8160410 ate the budget.
* **Decoder fix:** ADC arm requires bits[23:21]==000; CSEL arm pins bit21;
  CCMP arm pins bit22==1 && bit21==0. 0xFA8E2C00 (capstone-invalid) now
  None. Keystone set (1A020020/3A020020/5A020020/BA020020/DA020020/
  FA4891A0/FA4329A9/BA41C005) re-verified.
* **Frontier move (measured):** 48M: aborts 1 → **0**, panic 0, budget stop
  clean. 400M: no loop — the kernel advances into **waitq bootstrap** and
  calls ITS OWN panic at insn 22,505,463:
  `"kernel_memory_allocate() failed to alloc global_waitqs" ", error: %d,
  whsize: 0x%x"` (fmt 0x…735e028; panic wrapper 0x…987b99c from 0x…7ab6f30;
  whsize 0x4000). The post-panic prologue spin is the panic path's exception
  loop (named, not silent).
* **M5 task 1 status:** the device census (17/17 named through the old
  frontier) is unaffected; PMGR/AIC/WDT/SART/ANS remain 0-touch because the
  boot is still pre-scheduler. SART v1 + ANS dual-window + SMC specs stay
  staged (attach-spec §5.4-5.6).
* **Next block (M5/P):** RE the `kernel_memory_allocate` failure inside
  kernel_map: kr value unpacking at the panic call, `vm_map_find_space`
  hole/first_free state after kmem_init's pmap_virtual_region reservations,
  and the kernel_map[4] views table fill (measured: 0x…2e8/0x…2f0/0x…2f8 =
  0x…6e2c5ec0/0x…6e2c5c90/0x…6e2c5b78 at 21.48M-21.49M; count 0x…2d8=2,
  budget 0x…2e0=0x16f18000). Then re-run: the waitqs allocation should
  succeed and the boot frontier moves past 22.5M.
* **New tools:** first-abort FP chain + per-frame saved-x19/x20 window in
  the boot-real report; IOS_RUST_WATCH PC-watching used to bisect register
  corruption (log format `[watch] insn=… pc=…`).

`cargo test --workspace`: **437 passed / 0 failed** (+3 gap39 goldens).

## M5 — peripherals the real boot path touches  [~] (session P 2026-10-30: THREE real-data bugs — #40 W-form add/sub+logic upper-half leak (THE waitqs wall), #41 /chosen/lock-regs aperture populate, #42 PSTATE.PAN — frontier 22.5M-panic → 155M FIPS POST; next wall = bug #43 the SHA1 crypto-op value semantics in the HMAC KAT)

**Session P evidence (release build, IOS_RUST_DRAM_MB=1024, 437→444
workspace tests 0 failed):**

* **#40 (the waitqs wall root):** waitq_bootstrp `neg w19,w8`
  (0x4B0803F3) ran at 64-bit width → x19 = 0xffffffff00004000 (whsize
  garbage) → kernel_memory_allocate → KERN_RESOURCE_SHORTAGE → the
  kernel's OWN "failed to alloc global_waitqs" panic at 22,505,463. The
  W-form masking discipline from bug #38 (logical-IMMEDIATE) was missing
  in AddImm/SubImm/AddSubReg (result + Rn read) and LogicReg (Orr/Eor/
  Bic/Eon). Fixed + 4 verbatim-word goldens.
* **#41:** with the wall down the kernel reached its own "lock-regs:
  cannot find required property 'aperture-count'" at 22,688,176 — the
  AMCC aperture parser (0x…7b7c390) needs 22 properties the IPSW EDT
  stub doesn't carry (iBoot fills them). New `adt dump` diagnostic
  pinned the stub; dt_populate_amcc_lockregs stages the honest
  emulator config (1×16KB RAM-backed aperture @ DRAM midpoint,
  page-size-shift 14, reg locks 0). Real iBoot AMCC geometry = tracked
  gap.
* **#42:** the scheduler INVARIANT `mrs x8, pan; cbz → panic "context
  switch with PAN disabled"` fired at 23,684,722 — the kernel was
  context-switching threads and our PSTATE had no PAN bit; 95 msr-pan
  sites were dropped and the SPSel decode mask even swallowed PAN
  words. PAN now tracked (Msr/Mrs + SPSR bit23 save/restore), SPSel
  arm op2-pinned. Access gating NOT enforced (honest limit). +3
  goldens.
* **Frontier:** 48M budget stop now CLEAN (0 panics/aborts); 400M run
  advances through zone/scheduler bring-up and dies in the kernel's
  own **"FIPS Kernel POST Failed"** at 155,032,147 — decomposed to the
  HMAC-SHA1 KAT vector 0 memcmp: computed
  491327a2e130799174899c2f7a9cbef2002b9571 vs expected
  886eae70f36bd3805eeb1274b3248fccf5e15b80 (stop-memdump). **Bug #43
  (open):** sha1c/p/m + sha1su0/su1 VALUE semantics never
  oracle-verified; next block rebuilds them against a real oracle and
  re-runs the KAT.
* **M5 task 1 status:** unchanged — 17/17 device accesses named at the
  48M frontier; PMGR/AIC/WDT/SART/ANS still 0-touch (pre-scheduler at
  48M is now past — re-census at the 155M frontier pending #43).
* **New tools:** `ios-rust adt dump`; MMIO log value column;
  IOS_RUST_STOP_DUMP_MEM stop-memdump; oracle script
  tools/re/oracle/derive_sha1_arm.py (pipeline reconstruction, first
  pass).

`cargo test --workspace`: **444 passed / 0 failed** (+7 goldens).

## M5 — peripherals the real boot path touches  [~] (session Q 2026-10-30: BUG #43 CLOSED — the SHA1/SHA256 crypto-instruction VALUE semantics rebuilt against QEMU + the ARM ISA pseudocode + end-to-end hashlib reproduction; the FIPS POST KAT blocker is engine-fixed, re-run pending)

**Session Q evidence (dev build, 448 workspace tests 0 failed):**

* **The whole SHA crypto family was decode-verified but never
  value-verified** (the session-D landing note said so itself). Three
  independent oracles now agree on the semantics:
  1. QEMU `target/arm/tcg/crypto_helper.c` — verbatim port of every helper.
  2. ARM A64 ISA pseudocode (DDI 0602): SHA1C's per-round
     `<y, x> = ROL(y:x, 32)` 160-bit fold (E lives in the SCALAR Vn.S[0],
     Vn is never written back); SHA256H2's operand swap
     `SHA256hash(V[n], V[d], V[m], FALSE)` — its Vn must be the ORIGINAL
     a..d, which is exactly why Linux's sha2-ce does
     `mov dg2v.16b, dg0v.16b` before the h/h2 pair.
  3. End-to-end: `tools/re/oracle/derive_sha1_arm.py` v2 reproduces
     hashlib.sha1 and hashlib.sha256 exactly (4/4 vectors each) under the
     Linux/OpenSSL caller choreography — sha1h ping-pong for E, K
     pre-added into W, su0(A,B,C)+su1(A,D) rotating schedule.
* **Engine tests:** the interpreter computes the REAL SHA-1("abc") digest
  through actual instruction words (20 four-round groups,
  a9993e36…d89d asserted), a two-group sha256h/h2 pipeline golden, and 10
  per-instruction value goldens. 448 passed / 0 failed (+4).
* **Session-R (next block):** re-run the real boot — the kernel's FIPS
  POST HMAC-SHA1 KAT vector 0 (the 155,032,147 stop) should now compute
  886eae70f36bd3805eeb1274b3248fccf5e15b80 and the frontier moves past
  the POST; then re-census MMIO at the new frontier (PMGR/AIC/WDT/SART/
  ANS touches expected once the scheduler runs) and re-run the M5 device
  gate honestly.
* Also in this session: the session-RAM bounding fixes (console sink cap,
  drain_serial take-not-clone, trace_tick env caching, s3_backup
  streaming+prune) — see the fix(ram) commit.

## M5 — peripherals the real boot path touches  [~] (session R 2026-10-31: the never-done re-run — TWO more engine bugs closed: #46 LD1-multi-register was LD4-interleaved (THE HMAC-SHA1 KAT root — session Q's SHA fix was correct), #47 AESE/AESD ran keyless (THE RNG-init wall — the AES-XTS early PRNG emitted one constant block); frontier 155,032,147-panic → 155,053,017; next wall = BUG #48 the portable-C HMAC-SHA-512 KAT)

**Session R evidence (release build, IOS_RUST_DRAM_MB=1024, fixtures =
freshly range-fetched iOS 14.3 / 18C66 — the build the RE addresses are
pinned to; `boot-real` now honors its [fixtures-dir] arg):**

* **Fixtures pinning measured:** the 13.7 EDT ships NO /chosen/lock-regs
  (byte-search: 0 hits for lock-regs/aperture/amcc/ctrr) — the 14.3 EDT
  ships the subtree STUB-EMPTY exactly as the #41 note says. The prior
  "lock-regs node not found" failure was a fixture-build mismatch, not a
  staging bug; the error message now names the pinning.
* **#46 (the Q re-run verdict):** with the SHA ops fixed the KAT STILL
  failed at the identical insn 155,032,147 — computed 6c829016… vs
  expected 886eae70…. New repro test runs the kernel's OWN SHA-1 vng
  compress (0x82c16f0..0x82c1b64, 285 words) with the real KAT key/msg:
  diverges at block 1 → per-insn step dump → `ld1 {v0..v3}, [x2], #64`
  loaded v0 = W[0,16,32,48] — the interleaved LD4 layout applied to LD1.
  LD1/ST1 (op4 2/6/7/A) copy each register from a CONTIGUOUS structure;
  only LD2/LD3/LD4 (op4 8/4/0) interleave. Lossless across spill
  round-trips (why the boot survived), fatal to layout consumers.
* **#47:** after #46 the RNG init panicked −10 = CCERR_OUT_OF_ENTROPY.
  0x82b8668 = read_random health check (nonce 32 B + entropy 64 B must
  differ; ct_equal at 0x82d48cc returns nonzero on DIFFER). Stop-dump:
  the PRNG emitted ONE 16-byte block repeated — the interpreter's Vaes
  read the state from Vn and passed key=0 (the EOR Vn of AESE/AESD
  dropped) → every AES round keyless → AES-XTS early PRNG constant.
  Fixed per ARM DDI/QEMU; FIPS-197 C.1 through real AESE/AESMC/EOR words
  in tests/aes_vaes_kat.rs (ARM-feed schedule: middle round keys
  pre-InvMixColumns'd — the AESMC after AESE pulls MixColumns over the
  key; verified against scripts/aes_check.py variant B).
* **Frontier:** HMAC-SHA1 KAT MATCHES, RNG init passes, boot advances to
  insn 155,053,017: fipspost_post −1075 on a LATER vector —
  **HMAC-SHA-512** (BUG #48 OPEN). Portable C (no vng SHA-512 in the
  image — 10 sha512-family words total). Computed 4d14f3ea… vs expected
  5705bfd5…; vectors at rodata key@0x73c34bc (110 B), msg@0x73c352b
  (128 B), digest@0x73c35ac; di struct @0x77c2ed0 (IV @0x7051cf8,
  init/final ≈0x82e3774/0x82de00c PAC'd); K tables @0x7051690/0x7052640,
  NO direct ADRP (chained-fixup GOT — the K-base pointer must be read
  from running memory or the GOT decoded to find the compress).
* **Next block (M5/session S):** locate the portable-C SHA-512 compress
  (GOT walk via running-memory dumps, or a cchmac-call repro in the
  fips_hmac_kat.rs style with the extracted key/msg and the resolved di
  struct), bisect the first wrong instruction (same
  decode-verified-never-value-verified class), fix, and re-run — the
  FIPS POST is the last corecrypto gate before the boot proceeds into
  the kext/IOKit bring-up that M5's device census then re-measures, and
  M6 (DSC → dyld → launchd → SpringBoard → GUI) opens behind it.
* Tests: **451 passed / 0 failed** (+3: AES engine KAT, SHA-1 KAT repro
  ×2 groups; +1 ignored step-dump tool). Docs: PARITY session R,
  parity.json 451.

## M5 — peripherals the real boot path touches  [~] (session R part 3 (2026-10-31): BUG #48 CLOSED IN-SESSION — REAL-DATA BUG #49, the SIMD EXT operand order + half-width concat, was the HMAC-SHA-512 root; frontier 155,053,017 → 155,673,736; all FIPS-POST HMAC vectors now PASS; BUG #50 OPEN = POST test 4 (−4075, ≈ aes_ecb) with the AES round instructions verified both directions against FIPS-197 C.1)

**Part-3 evidence (same session, after #46/#47):**

* The failing vector was HMAC-SHA-512 (64-byte digest). Repro
  `tests/fips_sha512_kat.rs` runs the kernel's OWN NEON-generic SHA-512
  compress (0xfffffff0082e67f0..0x82e7c84 — located via the sha512 di
  struct @0x77c2ed0 whose init pointer tail-jumps there; K table
  @0x7052640, adrp-patched to a local page; NO sha512h instructions in
  the whole image — this is the generic-NEON implementation with
  ror/eor/add rounds and an ext/ushr/shl SIMD schedule). Diverged at
  block 1: the schedule's `ext v18.16b, v4.16b, v5.16b, #8` produced
  (W8, 0) instead of (W9, W10).
* **#49 root:** VExt built `(Rm.low8 : Rn.low8)` — operands swapped AND
  only the low 8 bytes of each (every .16b EXT with index ≥ 8 zeroed its
  high half). Fix: `result.B[i] = (Vn:Vm).B[i + imm4]` — Vn's full 16
  bytes first, Vm's second, byte-indexed window. (A second slip — the
  byte offset multiplied by 8 again in the rewrite — was caught
  immediately by the new `fips_ext_micro` test; both are now pinned.)
* AES-128 DECRYPT through real AESD/AESIMC/EOR words added to
  `tests/aes_vaes_kat.rs` — FIPS-197 C.1 inverse round-trips. Notable
  measured asymmetry: the decrypt feed schedule is the PLAIN rk_r
  (AddRoundKey precedes InvMixColumns in the FIPS InvCipher), unlike
  encrypt's aesimc(rk_r).
* **Frontier:** the POST's KAT memcmp loop now completes with ZERO
  failures (the stop at the fail branch never fires), and the boot
  advances to insn **155,673,736** where fipspost_post returns **−4075**
  = test 4 KAT failure (per the corecrypto test order ≈ aes_ecb; tests
  1-3 = hmac/integrity/indicator pass). BUG #50 OPEN: the AES round
  instructions are verified both directions — the miss is in the ECB
  mode glue, the kernel's key-schedule expansion, or the KAT plumbing.
  Next block: same recipe — locate fipspost_post_aes_ecb (or the 18C66
  equivalent of test 4), extract the KAT key/plaintext/ciphertext,
  repro through the engine, bisect.
* Tests: **455 passed / 0 failed** (+2 SHA-512 KAT, +1 AES decrypt KAT,
  +1 EXT micro, +1 ignored SHA-512 step tool).

## M5 — peripherals the real boot path touches  [~] (session S (2026-10-31): REAL-DATA BUG #50 — the AESE/AESD AddRoundKey ORDER — was the fipspost AES-ECB KAT root; frontier 155,673,736 → 155,746,479; fipspost_post_aes_ecb returns 0 — the whole-KAT memcmp loop completed; BUG #51 OPEN = a corecrypto workspace-alloc abort 88k insns later)

**Session-S evidence (release build, IOS_RUST_DRAM_MB=1024, 463
workspace tests 0 failed):**

* **The OOM class is closed at the engine level too:** `vm_core::Ram` is
  now LAZILY COMMITTED (empty Vec + geometric ensure(); uncommitted
  reads are 0 exactly like the old zero-filled Vec; the region-end
  read-0/write-drop quirks preserved and pinned by tests;
  `Device::write_ram_bulk` keeps `Bus::write_raw`/DMA lazy-aware so a
  fresh Ram no longer silently swallows bulk loads). Peak RSS for a
  10M-insn boot on IOS_RUST_DRAM_MB=1024: **112 MB**. One staging-site
  fix in boot_real (the `pause.data[..4]` slice) — plus the process
  lesson: `cargo test` does NOT rebuild `target/release/ios-rust`, so
  the first "zero drift" check had silently run the STALE eager binary;
  the frontier was re-verified on the fresh build.
* **New diagnostic:** `IOS_RUST_STOP_DUMP_ADDRS="0xva[:0xlen],…"` —
  running-memory dumps at explicit VAs at a stop-PC stop. The STATIC
  image's __DATA_CONST descriptor slots hold Apple pre-signed pointers
  whose bits 47:0 are NOT VAs; only the RUNNING slots (re-signed by the
  kernel's own PACIA during slide) expose the real functions:
  encrypt mode 0x77c1cd0 → init 0x82a8aa0 (plain keyexp dispatch) / ecb
  0x82cae30; decrypt mode 0x77c2a70 → init 0x82a8b10 (keyexp+AESIMC,
  0x82a89f0: rk1..rk9 InvMixColumns'd) / ecb 0x82b2320.
* **#50 root:** AESE/AESD XORed the round key AFTER the SubBytes/
  ShiftRows table. ARM does it BEFORE: `AESE(Vd,Vn) =
  SubBytes(ShiftRows(Vd ^ Vn))` (QEMU aese_kernel: "The Arm AddRoundKey
  comes first, while the API AddRoundKey comes last"). The kernel's vng
  ECB loop feeds the PLAIN schedule and only the XOR-first table makes
  that the true cipher; the decrypt pairs the same XOR-first AESD with
  the AESIMC'd middle-key schedule. Verified numerically both directions
  AND through the kernel's own code (tests/fips_aes_ecb_kat.rs —
  keyexp 0x82a87d0 + ECB 0x82cae30 verbatim at real VAs, one 24 MiB
  window, the kernel's own ADRPs resolving unchanged).
* **How test 4 was identified:** fipspost_post (0x829fb3c) encodes the
  failing test index in the return value — `sub w0, wN, #0x3e8/#0x7d0/
  #0xbb8/#0xfa0` = err − 1000·test#; test 4 = bl 0x82a37a4 whose rodata
  string is `fipspost_post_aes_ecb` (two one_shot 0x82a3908 calls —
  encrypt then decrypt — each memcmp'd, −75 = memcmp fail).
* **The old aes_vaes_kat "ARM-feed" was a CIRCULAR golden:** its
  pre-InvMixColumns'd middle keys exactly compensated the XOR-last bug
  (FIPS-197 C.1 passed while every real kernel block was wrong).
  Rewritten kernel-mirroring; aes_fips197 unit test feeds plain keys.
* **Frontier move (measured):** fipspost_post_aes_ecb returns 0
  (x19=0 at the 0x82a38d0 return stop) — the POST's KAT memcmp loop
  completes; the boot advances to insn **155,746,479** where a
  corecrypto WORKSPACE ALLOCATION aborts: "alloc ws" → "internal error,
  file radar to (corecrypto | all)" (fn 0x82b0708 → abort helper
  0x82da904 → panic @ insn 155,746,369, lr 0x82b0bd8).
  **BUG #51 OPEN:** the allocator behind cc_alloc (kalloc?) fails
  during the POST's later tests (likely ECC/bignum KATs — 0x82b0708 is
  deep in the bignum region). Next block: RE the workspace-alloc path
  (who provides cc_alloc in xnu, what it calls, why it returns
  NULL/throws), same recipe as #46-#50.
* **Next block (M5/session T):** disassemble 0x82b0708's alloc call
  chain (the `bl 0x82c2250`-region allocator plumbing), find the
  underlying kernel allocation (kalloc/kmem_alloc?) and why it fails in
  our model; fix; re-run. The FIPS POST is now ONE wall from completion
  — behind it, kext/IOKit bring-up and the M5 device census re-measure,
  then M6 (DSC → dyld → launchd → SpringBoard → GUI) opens.
* Tests: **463 passed / 0 failed** (+2 fips_aes_ecb_kat: keyexp golden
  + ECB KAT; +1 ignored step-dump tool).

## M5 — peripherals the real boot path touches  [~] (session T (2026-10-31): REAL-DATA BUG #51 — the SBCS borrow-out carry flag wrapped at b==u64::MAX — was the FIPS-POST reciprocal-invariant abort; frontier 155,746,479 → 181,012,637; BUG #52 OPEN = the RSA self-check fails with 6 alternating limbs off by −1)

**Session-T evidence (release build, IOS_RUST_DRAM_MB=1024, 474
workspace tests 0 failed):**

* **#51 root (found the campaign way — kernel-bytes repro + python
  oracle):** the abort at insn 155,746,479 ('alloc ws' → 'internal
  error, file radar to (corecrypto | all)') was corecrypto's Newton-
  reciprocal fn 0x82b0708: its post-loop division check (C = 2^2048 −
  q·input, three unrolled C_low−=input / D−=borrow rounds, abort unless
  some round borrows) saw ZERO borrows. The repro (tests/fips_sqrt_kat.rs
  + tests/sqrt_kat_data.rs — 12.8 KB of verbatim kernel bytes over 14
  code ranges incl. the PPL memset/memcpy; the captured call
  x0=arena, x1=0x10 words, the 128B buffer @0xffffffe802fab410) proved
  the engine's 9-iteration loop AND the 34-word MUL3 product match the
  python model bit-for-bit — and stage dumps pinned the first divergence
  INSIDE sub#1 (C −= product): every OTHER word of the 0xFF…FF limb run
  came out 1 instead of 0. interp add_with_flags computed the sub carry
  as `a >= b + !carry_in` — when b==u64::MAX and the carry-in is clear,
  the u64 sum wraps to 0 and the compare yields C=1 for a limb that DID
  borrow (0 − MAX − 1 = 0 with borrow-out). Fix: overflow-safe
  `a > b || (a == b && borrow_in == 0)` (+11 fips_sqrt_kat tests:
  memset/clear/shr-0/shr-1/mul/sub/count goldens, the end-to-end repro,
  and the direct sbcs_max_borrow_edge pin).
* **Frontier move (measured):** 156M budget stop CLEAN (no aborts/
  panics) → 200M-budget run reaches insn **181,012,637** where the
  kernel's OWN panic fires: "FIPS Kernel POST Failed (%d)!" (fmt
  0x73c4ca3, wrapper 0x82e8670 ← fipspost_post's RSA test).
* **BUG #52 (scoped, next block):** the POST's test 6 (ccrsa — the
  0x82a4ee4 fn: sign_pkcs1v15 → import → verify → cycle; key blob
  0x4a5 B @0x7044828, KAT data 0x101 B @0x703c34c) fails at the SIGN
  step with error −27 (log 'FAILED: ccrsa_sign_pkcs1v15', w8=0x35 line).
  Decomposed: the sign body 0x82b34cc → modexp 0x82d8d0c → the CRT
  private op 0x82d8f60 (returns 0) → the public-op self-check
  0x82b7a3c (fills x23, returns 0) → constant-time compare 0x82d48cc
  returns 1 = MISMATCH. Stop-dump of the two buffers at 0x82d8eb8
  (insn 180,993,288): the verify value x23 @0xffffffe802faaad0 vs the
  input copy x21 @0xffffffe802faabd0 differ in EXACTLY six words —
  8, 10, 12, 14, 16, 18 (offsets 0x40..0x90, stride 0x10) — each ONE
  LESS than expected (…FE vs …FF in the low byte). Signature of a
  lost carry/borrow in a 2-word-unrolled helper inside the Montgomery
  modmul chain (the same class as #51, different site). Next: capture
  the 0x82d8f60 call args (sig-out x0, key-struct x1, x19, x22), run
  the kernel's own CRT code on the engine with a python-RSA oracle,
  bisect the first divergent Montgomery round.
* Honest note: an earlier ccrsa_sign call at insn 156,025,900 (a
  non-POST kernel caller) passes its first check but never reaches the
  self-check block — its flow diverges inside 0x82d00cc/0x82d8d0c;
  same suspected root, to be confirmed by the repro.
* Tests: **474 passed / 0 failed**.
