# M5 completion ledger — the bug list to "M5 finished" + the census-table gap analysis

*Generated 2026-10-31 session U (repo df7c84a; frontier 186,277,728 real insns).
This is the working answer to "list all the bugs till M5 to finish, then from
that table list the gaps". Sources: BOOT-PLAN.md session blocks, PARITY.md,
parity.json, tools/re/notes/m5-device-census.md (+ session-N/M updates),
session-T boot logs, and this session's RE evidence.*

## Where the boot stands

Real 18C66 kernel, pure-Rust A13 interpreter, MMU live, FIPS-POST in progress:
tests 1-6 PASS (HMAC-SHA1, HMAC-SHA-512, AES-ECB, the reciprocal invariant,
RSA sign/verify self-check) — **frontier 186,277,768 insns** (was 181,012,637
before bug #52). Current wall: POST phase 7 (ECDSA) — bug #53.

## A. The bug list (open items between here and "M5 finished")

### A1. OPEN engine bugs on the boot path (blockers, in order)

| # | bug | state | evidence / next move |
|---:|---|---|---|
| **#53** | **FIPS-POST ECDSA validation rejects a VALID generated keypair** (phase 7, POST rc −7075 = −75−7000; panic @ insn 186,277,618 — the panic's printed %d is stale x1 garbage, real rc read at the 0x82a05e8 stop) | **OPEN, scoped** | Chain: kext_start 0x82e2248 → fipspost_post 0x829fb3c → fipspost_post_ecdsa 0x82a4b74 → ccec_generate_key_fips 0x82db720 → generate 0x82b0608 **ret 0** → validate 0x82c3cb0 → 0x82c5244/0x82c5020 sets the fail flag. **The generated key is PROVEN CORRECT**: workspace dumps (boot-T-53ws.log) hold d @ws+0x70 and Q @ws+0x10 with **Q == d·G on-curve (python-verified)** — so the VALIDATOR diverges, not the generator. Field cores verified EXACT vs unicorn (mul 0x82b6020 = a·b·R⁻¹ mod p, sqr 0x82b6260, reduce 0x82b6f60 — bit-for-bit QEMU agreement). Remaining suspects: the exponentiation/inverse dispatcher 0x82bd568 (ws-based; the affine-conversion modular inverse), the pairwise-recompute point-mult, or an instruction form unique to that chain. Next: extend the unicorn cross-check (built + working this session) over 0x82c5020's call graph with the dumped d/Q as inputs. |
| #54+ | The POST's remaining phases 8-17 each may hide one more engine bug (the campaign's measured rate: ~1 real-data bug per 1-6M insns of new frontier) | expected | Phases after ecdsa (per fipspost_post's call table): ecdh 0x82a4660, 0x82aa898, 0x82b3760, 0x82b81a0, 0x82c9b04, 0x82a39f4, 0x82a3ea4, 0x82a5184, 0x82a40b0, 0x82a4394 — per the session-T prediction these include TDES and DRBG tests. Same recipe per bug: stop → dump → KAT with the kernel's own bytes + python/unicorn oracle → fix. |
| — | panic-formatter fault: after the FIPS panic, the backtrace path faults (sync abort elr=0x7a584fc, ExceptionRecursion guardrail) | cosmetic but masking | The panic machinery dies while printing; fixing it (or modeling the missing debug-data deref) would surface kernel console output — useful for everything after. |
| — | Earlier ccrsa_sign caller @ insn 156,025,900 (non-POST) never reached its self-check block | probably fixed by #52 | Confirm on the next boot run past 186M. |

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
