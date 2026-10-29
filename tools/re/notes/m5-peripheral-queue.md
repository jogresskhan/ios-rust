# M5 peripheral queue — modeled-vs-missing census + boot-critical driver measurement (T8030, 18C66)

Task 2-b, RESEARCH ONLY (no Rust edits). Sources: the real 18C66 kernelcache
`/tmp/kc18c66.macho` (45,778,056 B decompressed; capstone-only measurement —
tool: `tools/re/reports/m5_kext_mmio.py` + one-off scripts, method in §4),
`/home/z/tmp-re/armio_rows.json` (105-row ADT arm-io table), `/home/z/tmp-re/phandles.txt`
(293-entry phandle map), `/home/z/tmp-re/adt-n104ap.bin` (raw flat tree),
`/home/z/tmp-re/extras.txt` + `m4_sysreg_table.out` (prior mining, see
notes/vault-mining-m4m5.md). Complements `m5-adt-census.md` (static ADT),
`m5-device-census.md` (runtime MMIO census), `m5-peripheral-specs.md` (upstream
register specs — this note MEASURES the Apple drivers against them).

Headline: **the 18C66 drivers access registers almost exclusively through
virtual register-access helpers (offset passed as an argument), so whole-image
immediate scans under-measure. Direct `str/ldr [base,#imm]` evidence exists
only where it matters most: SART (new v1 layout), ANS2 BOOT_STATUS, AIC kext
(already in m4-aic-timer-re.md).** Three T8030-UNCERTAIN items from
m5-peripheral-specs.md are now RESOLVED by measurement: SART layout, SMC
transport, PMGR offset model.

---

## 1. Modeled-vs-missing census — 105 `/arm-io` children

Re-verified from `armio_rows.json` (105 rows = all children; 13 zero-size rows
= 11 no-reg nodes + wlan/bluetooth which have `#reg`=0; 77 rows carry IRQs;
0 ragged regs):

| bucket | count | notes |
|---|---:|---|
| total /arm-io children | **105** | matches PARITY 2.11a count |
| reg-bearing | **94** | 11 nodes have no `reg` (skipped by `attach_from_adt`) |
| modeled (classify() attach) | **59** | dart×16, mca×7, smc×4, s3c-uart×4, i2c×4, aop×3, spmi-pmu×3, aic×2, gpio×2, spi×2, adp-v4×2, + 10 singletons (pmgr, apple-wdt, aes, sep-sim, ans2-nvme, sart, typec-otg, mipi-dsi, scaler, apcie) |
| unimplemented_devices | **35** | boot-relevant subset queued in §2; the rest skippable (§5) |
| no-reg (skipped) | **11** | mapper-gfx-asc, alc0/2, dietempctl0, vtempctl0, smctempsensor0, cpu-debug-interface, aod2, pearl-sep, haptics-support-interface, audio-resource-manager |

Known model defects carried from m5-adt-census (all still open unless fixed by
session-H's reg_entries LE fix, PARITY 2.12 bug #21): (a) FALLBACK_MAP base
drift — wdt/ans2-nvme/sart/pmgr/gpio/adp-v4/mipi-dsi wrong; (b) `dockchannel-uart`
modeled as S3C UART (wrong protocol); (c) `dapf-disp0`/`dapf-aop` modeled as
adp-v4/aop (DAPF = DART address filter); (d) `aic-timebase` attached as a
second `Aic` (it is the banked timebase page); (e) nothing reads
`clock-gates`/`interrupts` from the ADT.

IRQ-parent resolution (phandles.txt): aic = phandle **26 (0x1A)**, referenced as
`interrupt-parent` by **90 nodes** (all arm-io device nodes + 6 /cpus children);
the rest route via gpio (131–137 to aic anyway) and the smc-pmu/spmi subtrees.
`Aic::new(640)` covers max observed HW IRQ 541; IPI space starts at 576.

## 2. Boot-critical queue (measured offset→semantics where the binary gives it)

### 2.1 PMGR — `AppleT8030PMGR` (pmgr @0x23B000000+0x100000, 44 reg windows)
* **Linear-offset model (measured):** the driver reads registers through a
  helper reached via vtable slot `self+0x958` with the **byte offset as an
  argument**; offsets are LINEAR across the concatenated 44-window reg map.
  `_waitAPSCPending` (fn 0xfffffff008b74ee0, entry asserted by pretty-string
  ref 0x8b7ab14←0x8b75160) polls **0xE2020 / 0xE2588** (args w2 = 0xE2588,
  0xE2020 = 0xE2588−0x568; w1 = 0/1 = cluster select) — both < 0x100000, i.e.
  inside the main pmgr-reg window → abs **0x23B0E2020 / 0x23B0E2588**. APSC =
  the CPU-cluster pstate controller the kernel polls on every pstate transition.
* ps-regs window at **+0x80000** (ADT-confirmed), gate table = 352×24 B records,
  gate id = config word0>>24, full id→name map in m5-adt-census §4 (boot gates:
  aic=49 always-on, uart0=76, ans=128, darts 176–185, disp0=160–163).
* Emulator action: attach PMGR as ONE device spanning the concatenated windows
  (window0 = 0x23B000000+0x100000 …), answer gate-poll reads with
  PS_ACTUAL=0xF, R/W-scratch the rest.
* `initDriver` (fn 0x8b6df18) and `configCPUComplexPowerState` (0x8b6feb8)
  route through helpers — no direct immediates (honest limit).

### 2.2 SART-ANS — `AppleSARTMarconi` (sart-ans @0x27AC50000+0x8000, `sart-version=1`)
**NEW measured layout — supersedes the v0/v2 tables in m5-peripheral-specs §4
(neither matches; T8030 ships "v1"/Marconi):**
* Mapped base in ivar `[self+0xa0]`; entry count from provider in `[self+0xa8]`.
* **Entries are 8-byte-strided pairs:** `PADDR(idx) @ base+8*idx+4`,
  `CONFIG(idx) @ base+8*idx`.
* Value builders (fns 0xfffffff0085e8c30 / 0x85e8c68, capstone-verbatim):
  * PADDR value = **PA >> 12**; asserts PA 4 KB-aligned (`tst x1,#0xffe`),
    PA < **0x1_FFFF_F000**.
  * CONFIG value = **(size >> 12) | flag**, flag = **0x100000** if the region's
    flag bit is set else **0x300000**; asserts size 4 KB-aligned,
    size < **0x7_FFFF_F001**.
* Program loop (inside `start` fn 0x85e87bc..0x85e8c0c): for each 16-byte
  region row {PA, size, flags}: `str PADDR, [base+idx*8+4]` …
  `str CONFIG, [base+idx*8]`; afterwards a **verify pass re-reads PADDR/CONFIG
  and compares** (0x85e8b0c–0x85e8b44) — mismatch → panic.
* Cross-proof: the kernel's own MMIO whitelist (`pmap-io-ranges`, §3) tags
  0x27AC50000+0x8000 as **"SRT1"** (= SART v1). The 2 GiB PA cap matches the
  ANS/RTKit shared-memory carve-outs.

### 2.3 ANS2 NVMe — `AppleANS2NVMeController` (ans @0x277400000+0xC000 + 0x27ACC0000+0x60000 …)
* **ANS_BOOT_STATUS measured:** fn 0x93a3bfc does `mov w1, #0x1300` →
  readRegister (vtable slot `self+0x620`) → `cmp w0, 0xDE71CE55` (w22 built by
  `mov w22,#0xce55; movk w22,#0xde71,lsl #16` @0x93a3c28), retry loop budget
  **0x186A0** (100,000 iterations). Exactly the Linux/m1n1 contract; **0x1300
  is now measured**, not just upstream.
* Register access goes through the helper (offset in w1) — doorbell offsets
  (0x1000-family admin doorbells vs 0x2490C linear-SQ doorbells) are NOT
  immediate-visible; **the t8015-vs-t8103 submit-path decision stays open**
  (decide from which doorbell the driver writes first at runtime).
* Region split measured from `pmap-io-ranges`: two **"NVMe"-tagged** pages
  0x27ACE8000+0x4000 and 0x27ACF4000+0x4000 sit INSIDE the ans window
  0x27ACC0000+0x60000 (offsets +0x28000 and +0x34000) — the NVMe
  controller/doorbell BAR is a sub-page of the "ans" region, not reg[0]
  (0x277400000 = the ASC/RTKit coprocessor side).
* Driver family present in the image: `AppleEmbeddedNVMeController`
  (IONVMeFamily-557.60.1) + `AppleANS2NVMeController` + `AppleANS3NVMeController`
  strings; also `nvme-fw-minor-check-disable`, `iobsd-wait-time`.

### 2.4 SMC — `AppleSMC` (smc @0x23E400000+0x20000)
**Transport RESOLVED by measurement: endpoint/mailbox, NOT an MMIO key/cmd handshake.**
* `_sendKeyMsgAndPollForResponse` (fn 0x84f5e30): 8-byte message buffer at
  `self+0x102`, 4-bit rolling msg-id at `self+0x112` (`orr w8, w8, w9, lsl #4`),
  send/poll via the endpoint object at `[self+0xc0]` (IOService call chain),
  poll budget **1,000,000 µs in 1000-loop chunks** (w0=0xF4240, w1=0x3e8,
  fn 0x84f6fd8), response check: 24-byte (0x18) result packet, result byte
  0x70/'p' = retry path, id echo compared against `self+0x103`.
* Matches the Linux `macsmc` semantics already in m5-peripheral-specs §6;
  the "SMC_KEY/VAL/CMD/RES/FLAGS MMIO offsets" from the task brief are **not
  in this driver** — model SMC as an RTKit-style endpoint, shared-buffer data.

### 2.5 WDT — kernel-side watchdog (wdt @0x23D2B0000+0x4000, IRQ 237)
* No `AppleT8030Watchdog` kext: the strings ("-wdt-no-iokit", "watchdog
  disabled by boot-arg", "PanicWatchdogEnabled", "WDT timeout: CPU %d failed to
  respond", fn 0x91c6f3c/0x91c8498) show IOKit watchdog handling lives in
  in-kernel `IOWatchdog`/pexpert; register pokes route through helpers (no
  direct immediates measured).
* Keep the m1n1/Linux map (m5-peripheral-specs §7) for the emulator: boot-critical
  behavior is only **CTRL=0 disable** + reboot `BITE=0x100000, CUR=0, CTRL=4`;
  kick = write CUR 0. wdt has no clock-gates (always-on; `clock-ids=[4]` only).

### 2.6 GPIO — `AppleGPIOICController` / `AppleT8006GPIOIC` (gpio @0x23C100000+0x100000)
* `start` (fn 0x87ef584) uses provider calls throughout (`#gpio-pins=212`,
  `#gpio-int-groups=7`, IRQs 131–137 into AIC). No direct immediates; treat as
  interrupt-source shim (grouped IRQ fan-in to AIC) until the boot path reaches
  it. The class-name string `AppleT8006GPIOIC` @0x7442fda identifies the base
  IC controller (T8006-era class reused on T8030).

### 2.7 DART — `AppleT8020DART` (16 dart nodes) + **DART-ANS does not exist**
* Confirmed again: no `dart-ans`/`dart-ans2` node on T8030 (ans is SART-only);
  `FALLBACK_MAP`'s dart-ans entry must be dropped. The 16 real DARTs are all in
  `pmap-io-ranges` tagged **"DART"** or **"SMMU"** (second windows), plus four
  **"DSID"**-tagged APCIe DART pages 0x601008000/0x602008000/0x603008000/
  0x604008000 — the first TWO have **no /arm-io node** (only dart-apcie2/3 do):
  the apcie node itself (22 reg windows) owns 0x601008000/0x602008000.
* DART register offsets: upstream T8020 map (m5-peripheral-specs §3) stands;
  18C66's driver (code around 0x971b9e8) routes via helpers — T8030-UNCERTAIN
  bits unchanged (PARAMS1 PAGE_SHIFT=14, TTBR shift 12).

## 3. `pmap-io-ranges` decoded — the kernel's own MMIO window whitelist
(`/defaults/pmap-io-ranges` in the real ADT; 768 B = **32 records × 24 B** =
{u64 base, u64 size, u32 flags, u32 fourcc} — decodes cleanly, unlike the
16-word truncation in extras.txt):
```
base          size       tag    → node
0x620000000   0x40000000 PCIe   (1 GiB APCIe fabric window)
0x2412C0000   0x4000     DART   dart-sep        0x235004000  0x4000 DART dart-sio
0x24AC00000   0x4000     DART   dart-aop        0x23B300000  0x4000 DART dart-pmp
0x239024000   0x4000     DART   dart-usb        0x239028000  0x4000 DART dart-usb (2nd)
0x267030000   0x4000     DART   dart-ave        0x267040000  0x4000 DART dart-ave (2nd)
0x267020000   0x4000     SMMU   dart-ave (3rd)  0x269010000  0x4000 DART dart-avd
0x26B800000..2 0x4000×3  DART   dart-ane (3 windows)
0x265004000   0x4000     DART   dart-jpeg0      0x26500C000  0x4000 DART dart-jpeg1
0x263200000   0x4000     DART   dart-scaler
0x22BAC8000..8 0x4000    DART/SMMU×5 dart-isp (5 windows, alternating tags)
0x230704000   0x4000     DART   dart-disp0      0x230700000  0x4000 SMMU (2nd)
0x601008000   0x4000     DSID   apcie dart 0    0x602008000  0x4000 DSID apcie dart 1
0x603008000   0x4000     DSID   dart-apcie2     0x604008000  0x4000 DSID dart-apcie3
0x27ACE8000   0x4000     NVMe   (inside ans +0x28000)
0x27ACF4000   0x4000     NVMe   (inside ans +0x34000)
0x27AC50000   0x8000     SRT1   sart-ans  ← SART v1 confirmed by tag
0x23D328000   0x4000     DART   dart-rsm
```
Emulator use: this is the ground-truth list of windows the kernel will treat as
device memory — validate `Bus::attach` windows against it (window-by-window,
NOT the merged regions), and it independently confirms SART-v1 + the two NVMe
sub-pages. SMMU-tagged windows = second/aux DART windows (SMMU-shared pages).

## 4. Method (reproducible)
1. Kext/driver locate: this 18C66 cache is an **old-style prelinked static
   kernel** (18 top-level LC_SEGMENT_64, no LC_FILESET_ENTRY; kexts linked into
   __TEXT/__TEXT_EXEC; 524 Info dicts in `__PRELINK_INFO` @fileoff 0x2a6c000
   with `ModuleIndex`/`_PrelinkBundlePath`, no per-kext load addrs).
2. Driver functions found via `__PRETTY_FUNCTION__` strings (e.g.
   "AppleT8030PMGR::initDriver(IOService *)") → ADRP-tracked lite scan of
   __TEXT_EXEC/__PPLTEXT/__TEXT for refs → each ref site is a 0x30-byte
   panic-stub → find the real caller via BL-target scan → pacibsp word-scan
   (0xd503237f) for fn top → disassemble.
3. Scripts: `tools/re/reports/m5_kext_mmio.py` (driver string→xref→MMIO ops);
   one-off probe tables cached at /tmp (m5_xrefs.json, m5_fn_tops.json).
   PAC Notes: blraa/retaa vtable calls everywhere — offsets measured are
   helper ARGUMENTS where noted, not immediates.

## 5. First-touch ranking (PREDICTED — measured pre-stop = 0 touches)
Measured fact (m5-device-census, re-confirmed by this task's baseline): the
whole 8.14M-insn boot path touches **zero** device MMIO before the
TranslationFault stop, so the ranking below is the predicted post-DT-fix order
(kernel init → IOKit probe order), to be re-measured by re-running
`m5_mmio_census.py` after the path extends:

| rank | window | why first |
|---:|---|---|
| 0 | (none) | kernel early path (M4 vectoring, /cpus walk) is sysreg/DRAM-only — measured |
| 1 | pmgr 0x23B000000 | AppleT8030PMGR probe = first heavy MMIO consumer (gates/pstates feed everything; APSC polls on CPU pstate) |
| 2 | aic 0x23B100000 + aic-timebase 0x23B108000 | AIC kext probe (mask-all init = the missing byte-verified loop, m4-aic-timer-re §4) + timer IRQ delivery 60/63/66/69/94/97 |
| 3 | wdt 0x23D2B0000 | kernel watchdog init (CTRL=0 disable) at arm_init time |
| 4 | sart-ans 0x27AC50000 → ans 0x277400000/0x27ACC0000 | ANS2 storage chain: RTKit boot → SART carve-outs → NVMe doorbells → BOOT_STATUS 0x1300 poll (rootfs gate) |
| 5 | smc 0x23E400000 (+ aop/sio/pmp coprocessors) | SMC endpoint boot (charger/buttons idle until userland) |
| 6 | gpio 0x23C100000 | interrupt fan-in; buttons/backlight events |
| 7 | disp0/mipi-dsim 0x23000000/0x230400000 | M6 GUI; framebuffer sink already separate |

## 6. Skip-list candidates (model or RAZ only if touched)
* **Safe skip (inert per ADT + no boot path):** 12 temp sensors
  (tempsensor0–5, mtrtempsensor6/7/8/11/13/14/15), amc, aft, wlan, bluetooth,
  sochot0, dietempctl0/vtempctl0/smctempsensor0 (no-reg), nco, pwm, isp, sgx,
  gfx-asc, jpeg0/1, ave, avd, ane, aod2/pearl-sep/haptics-support-interface/
  audio-resource-manager/mapper-gfx-asc/alc0/2/cpu-debug-interface (no-reg).
* **Do NOT skip (early even if unmodeled):** dwi (0x23B200000, gate 50),
  mcc (0x200100000), error-handler (0x200100000), rsm (0x23D325000),
  atc-phy (0x239000000), sio (0x236400000), pmp (0x23BC00000) — per
  m5-adt-census §7; RAZ-with-log is acceptable short-term.
* **Mis-models to fix before M5 attach work:** dockchannel-uart (≠S3C UART),
  dapf-disp0/dapf-aop (DAPF ≠ display pipe / ≠aop), aic-timebase (banked
  timebase page, not a second interrupt controller).

## 7. Open items for the next M5 block
1. ANS2 doorbell decision (t8015-style 0x1000-family vs t8103-style 0x2490C):
   re-run `m5_mmio_census.py` once the path reaches ANS2 and log which helper
   offsets the driver writes first.
2. PMGR gate-stride (0x18?) confirmation against the driver's psreg math
   (initDriver helper chain) — the ADT gives the id table, not the stride.
3. AIC kext MASK_SET-all-ones loop byte-verify (carried from m4-aic-timer-re §4).
4. Wire `pmap-io-ranges` (§3) as the window-validation table in the M5 attach
   audit (`m5_mmio_census.py --adt` cross-check).
5. Commit the m5_kext_mmio.py helper + cached xref tables for reuse.
