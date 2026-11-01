# M5 completion ledger — the bug list to "M5 finished" + the census-table gap analysis

*Generated 2026-10-31 session U (repo df7c84a; frontier 186,277,728 real insns).
UPDATED 2026-11-01 session V (repo f41bced; frontier 327,096,716 real insns):
#53 and #54 CLOSED, the FIPS POST COMPLETES, bug #55 open.
This is the working answer to "list all the bugs till M5 to finish, then from
that table list the gaps". Sources: BOOT-PLAN.md session blocks, PARITY.md,
parity.json, tools/re/notes/m5-device-census.md (+ session-N/M updates),
session-T/V boot logs, and this session's RE evidence.*

## Where the boot stands

Real 18C66 kernel, pure-Rust A13 interpreter, MMU live. **The FIPS POST
COMPLETES — all 17 tests PASS** (hmac, integrity, indicator, aes_ecb,
aes_cbc, rsa_sig, ecdsa, ecdh, aes_ccm, aes_cmac, pbkdf, kdf_ctr, aes_gcm,
aes_xts, tdes_cbc, drbg_ctr, drbg_hmac) — zero panics. **Frontier
327,096,716 insns** (186.3M before #53; 221.9M before #54). The boot now runs
~105M insns into post-POST territory (kernel device/IOKit bring-up) and dies
on bug #55: a FIQ delivery after `msr daifclr` faults the exception frame
push at the sp.

## A. The bug list (open items between here and "M5 finished")

### A1. OPEN engine bugs on the boot path (blockers, in order)

| # | bug | state | evidence / next move |
|---:|---|---|---|
| **#55** | **FIQ-after-daifclr: the exception frame push faults at the sp** (insn 327,096,716): the AST path (bl 0x7b8ba64 from 0x7a8d824) unmasking DAIF via `msr daifclr,#7` @0x7b8ba90 → the engine's post-insn check delivers the FIQ to 0x815f300 → the frame push faults with far = sp (0x…2d1bd80; L3 walk invalid @0x80d82d550) → nested aborts → ExceptionRecursion (stack-descended-into-text), elr ends 0x0 | **OPEN, scoped** | Odd fact: the SAME page accepted the AST fn's own prologue pushes moments earlier. Suspects: (a) the single-bank `self.sp` model (ARM banks SP per EL/SPSel — see MsrSpsel's honesty note); (b) a stuck `timer_fiq_pending` (should the FIQ even be pending?); (c) a stale/mutating page table at VA 0x…2d1b000. Next: stop at 0x815f300 and dump/walk the stack page; single-step the AST-loop bit-2 clear (0x7a4f61c → `str w9,[x8,#0x4c]`) to see why the loop re-takes. |
| #56+ | Post-POST territory is UNCHARTED (PMGR/IOKit/scheduling bring-up, ~105M insns of it already runs clean) | expected | The campaign's measured rate: ~1 real-data bug per 1-6M insns of new frontier. Expect kext/IOKit service-registration and scheduler-fidelity walls. Same recipe per bug: stop → dump → KAT with the kernel's own bytes + python oracle → fix → re-measure. |
| — | panic-formatter fault (the pre-#53-era note): the post-panic backtrace faults (elr=0x7a584fc markers) | cosmetic | Only fires on panics; with the POST passing, moot until the next real panic. |
| — | Earlier ccrsa_sign caller @ insn 156,025,900 (non-POST) never reached its self-check block | probably fixed by #52 | Confirm on a budget run past 156M (the current boots all pass it silently). |

### A2. M5 acceptance clauses still open (work, not bugs)

| clause | from | what's missing |
|---|---|---|
| **M5 census re-measure at the new frontier** | BOOT-PLAN M5 task 1 | The ranked MMIO table (m5_mmio_census.py) was last measured at the 48M-era frontier (17/17 named, 0 UNMAPPED). Re-run with IOS_RUST_MMIO_LOG once the POST passes — driver-init touches (PMGR clock/power, AIC IRQ unmask, timers) start right after. |
| **NVMe rootfs clause**: "NVMe read path serves real rootfs bytes" | BOOT-PLAN M5 acceptance | ANS2/NVMe model is a queue skeleton (PARITY 40→structural); must serve real blocks from the git-tracked full-root.apfs when the kernel mounts root. Untested — the boot has not reached storage init. |
| **M4 WFI-resume ≥10M clause** | BOOT-PLAN M4 acceptance | M4's ≥10M-clean clause is cleared 244× over (2G insns), but WFI-and-resume has never executed (0 WFI so far); M5's idle/timer path depends on it. |

### A3. Closed-bug ledger (context: the campaign so far)

33 real-data engine bugs closed on the boot path (#20 boot_args DT pointer,
#21 ADT reg endianness, #22 DT staging layout, #23 boot-cpu DT, #24 CCMP
decode, … #39 CCMP/SBCS decoder collision [the percpu wall], #40 W-form
upper-half leak, #41 lock-regs aperture, #42 PSTATE.PAN, #43 SHA value
semantics, #46 LD1 interleave, #47 keyless AESE, #48 HMAC-SHA-512 EXT order,
#49 SIMD EXT operands, #50 AESE/AESD AddRoundKey order, #51 SBCS borrow-out
carry wrap, **#52 ADCS carry-out wrap [this session]**) — every one found by
the same loop: real-bytes boot → stop/dump → kernel-code KAT → fix → re-measure.

## B. The gap analysis (from the census table)

### B1. Device-model coverage at the last full census (48M-era + session-N fixes)

| class | count | items |
|---|---:|---|
| Modeled + attached (correct LE bases since #21) | 59 windows | dart:16, mca:7, smc:4, s3c-uart:4, i2c:4, aop:3, spmi-pmu:3, aic:2, gpio:2, spi:2, adp-v4:2, pmgr, apple-wdt, aes, sep-sim, ans2-nvme, sart, typec-otg, mipi-dsi, scaler, apcie |
| Named-unmatched (no Rust model) | 35 nodes | aft, amc, ane, atc-phy, avd, ave, bluetooth, dwi, error-handler, gfx-asc, isp, jpeg0, jpeg1, mcc, mtrtempsensor6/7/8/11/13/14/15, nco, pmp, pwm, rsm, sgx, sio, sochot0, tempsensor0-5, wlan |
| Boot-path windows touched (last measured) | 17/17 named, 0 UNMAPPED | console UART0 + dockchannel-uart were the rank-1 items; PMGR/AIC/WDT/SART/ANS measured **0 touches** through 400M (the wall between is the FIPS POST, not devices) |

### B2. The gaps that matter, ranked for "boot to homescreen"

1. **Verification gap (the biggest)**: most modeled devices are structural
   ports, not golden-trace-verified models — PARITY layer-2: AIC v2 35%,
   DART (4-level walker) unverified against real traffic, DisplayPipe/MIPI-DSI
   frame-contract only, ANS2 queue skeleton. The boot will exercise them in
   exactly this order: PMGR (clock/power gates on driver probe) → AIC (first
   IRQ registration) → timers → UART console full output → WDT → SART →
   ANS/NVMe (rootfs mount).
2. **PMGR is the first predicted real gap**: 0 touches so far, but every
   Apple-SoC driver gates its clock through pmgr pstates at probe time; the
   44-window PMGR map is staged (session-N) but the pstate state machine is
   unverified. Expect a bug #54+ class here.
3. **NVMe/ANS2 — required for the M5 acceptance clause**: queue skeleton
   only; needs the admin/IO queue pair + real block reads from full-root.apfs.
4. **AIC IRQ delivery**: the engine polls the IRQ line after each retired
   insn (DAIF-gated), but no real driver has registered/unmasked yet — the
   first AIC unmask will test the mask/pending/distribute path live.
5. **Unmodeled nodes**: none are on the measured boot path; the highest
   post-POST risks are the tempsensor/mtrtempsensor family (thermal kexts
   probe early), pmp/pwm/nco (support circuitry), and error-handler. GPU
   (sgx/ane/avd/isp) matters only after G4 (GUI) opens.
6. **Census staleness**: the ranked table predates four frontier moves
   (48M → 155M → 181M → 186M); the re-measure (A2) will re-rank everything
   automatically.

### B3. Mission-level gaps beyond M5 (for orientation)

- M6 opens after M5: kext/IOKit bring-up → launchd → SpringBoard (G3→G4),
  with the display pipeline (DisplayPipe + MIPI-DSI + scaler) and the
  framebuffer contract as the next modeling wave.
- CPU honest remainders (PARITY): FCMLA by-element golden pending; FP16 .8h
  vector arithmetic unverifiable by local oracles; decode 99.31% with the
  remainder dominated by data-in-text runs.
- The C-engine lane (ChefKiss Inferno) remains the device-level executor of
  record for G1/G2; the Rust engine's G2+ path is what M4/M5/M6 are building.

## C. What "M5 finished" concretely requires (the finish line)

1. Bug #53 fixed (validator) + the POST's remaining phases green (any #54+
   found on the way, same recipe).
2. Boot passes the FIPS POST → kernel proceeds into driver init.
3. Census re-measured at the new frontier: every touched window named, 0
   UNMAPPED aborts (M5 acceptance clause 1).
4. NVMe read path serves real rootfs bytes from full-root.apfs (M5
   acceptance clause 2) — the rootfs mount succeeds.
5. M4's WFI-resume clause exercised (the idle loop appears after driver
   init; ≥10M insns across WFI wakeups).
6. PARITY.md/parity.json updated with the measured outcomes — then M6
   (kext/IOKit bring-up) opens.
