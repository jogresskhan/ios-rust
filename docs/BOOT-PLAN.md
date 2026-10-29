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

## M3 — MMU / TLB  [ ]

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
