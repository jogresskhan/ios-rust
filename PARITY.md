# PARITY — the honest 100% ledger

Rubric (same family as the 54-library parity review in `ios-sweet-rust`):
**100** proven by CI/golden trace · **90** implemented + verified · **75**
implemented · **60** done once/offline · **50** partial · **40** reader/structs
· **30** stub + shape · **15** stub · **0** missing.

## Layer 1 — foundation (done)

| item | counterpart (C engine) | % |
|---|---|---|
| bitops (extract/deposit/rol/genmask/ffs) | libqemuutil bitops.h | **100** (tested) |
| byte FIFO | util/fifo8.c | **100** (wraparound + prefix tests) |
| scatter/gather | util/iov.c | **100** (roundtrip tests) |
| device queue / address dispatch | qemu/queue.h + memory_region_find | **100** (dispatch test) |
| error vocabulary | util/error.c | **100** |
| SoC identity (T8030 / apple-a13 / n104ap) | t8030.c machine name strings | **100** |
| CPU instruction inventory (20 groups, ARMv8.4-A) | — (public ISA) | **100** as inventory |
| memory-map landmark table | t8030.c + per-device files | **100** as documented pointers |
| QEMU CLI flag subset | qemu-system-aarch64 argv | **100** for the subset lanes use |
| IM4P parse/build | Inferno boot.c (img4) subset | **100** for the container format |
| BuildManifest flat reader | libplist subset | **100** for string/int/array/bool |
| ramdisk variant matrix + run #74 verdicts | lanes ios14-diag.sh | **100** (encoded) |
| vault client (list/get-verified/put/usage) | research-vault service API | **100** |

## Layer 2 — device models (structural ports, verification pending)

| item | counterpart | % | gate to flip |
|---|---|---|---|
| AIC v2 (enable/pending/INFO) | hw/intc/apple_aic.c | 35 | golden-trace IPI routing + preemption |
| DART (TCR/TTBR + 4-level walker) | dart.c / sweet_dart.c | 40 | replay captured PTE walks (dart-walker-gate) |
| ADP v4 DisplayPipe frame contract | apple_displaypipe_v4.c | 45 | real guest trace replay (M3a probe) |
| UART console | apple_uart.c | 55 | flow control + IRQ ladder |
| WDT | apple_wdt.c | 60 | timeout sequencing |
| MIPI-DSI (GEN_HDR + FIFO + acks) | synopsys_mipi_dsim.c + sweet_mipi.c | 30 | D-PHY link state machine (the #1 known engine gap) |
| ANS2/NVMe queue skeleton | ans.c | 25 | Apple NVMe command format port |
| Machine assembly (7 devices on bus) | t8030.c init flow | 50 | verify symbolic bases vs t8030.c, then wire IRQs |

## Layer 2.5 — host restore stack (usbmux → restored → ASR → TSS)

The X-gaps from the ios-sweet-rust parity matrix, closed in `crates/restore`
(std-only, no new deps). Protocol fidelity ported from idevicerestore
`asr.c`, libusbmuxd, libimobiledevice `restored.c`, cross-checked against our
own `restored_external` 18A5351d decompilation (RE-FINDINGS.md).

| item | counterpart | % | gate to flip |
|---|---|---|---|
| plist_lite XML codec (read+write, envelope, base64, entities) | libplist plist_to_xml/plist_from_xml | 90 | byte-capture diff vs real usbmuxd/restored traffic |
| usbmux host client (Listen/Connect tunnel, plist + legacy events, port swap) | libusbmuxd | 90 | session capture against a real usbmuxd socket |
| restored protocol client v14 (Hello, QueryValue, StartRestore, Status/Error/Progress, checkpoint decode) | libimobiledevice restored.c | 75 | replay a captured device Status stream end-to-end |
| ASR host (Initiate → packet-info → OOBData → Payload → chunked image push) | idevicerestore asr.c | 90 | 7.38 GB rootfs push replay with chunk checksums |
| TSS request + ApImg4Ticket extraction/IM4M structural gate | libauthinstall | 75 | signing-server capture replay |

## Layer 3 — CPU execution (the big one) — **closed for the 20 named groups**

All 20 `soc_t8030::CPU_INSTRUCTIONS` groups decode AND execute in the
pure-Rust backend (`a13_cpu::interp::Interpreter` — vector register file,
FP16 IEEE-754, QARMA-model PAC, AMUv1/MPAM/ID sysregs). Encodings verified
against an external oracle (Capstone 5.0.7 brute-force + Keystone assembly;
golden table in `a13-cpu/src/goldens.rs`); execution proven end-to-end in
`a13-cpu/tests/parity_exec.rs` with per-group retire counters
(`Interpreter::group_exec`). Honest gaps: by-element (indexed) SIMD
encodings are structural (no local v8.1+ assembler oracle); scalar RDM is
QEMU-case-anchored; PAC is a QARMA-model (Apple's key schedule is private).

| item | % | note |
|---|---|---|
| TCG-in-Rust AArch64 exec loop (interpreter) | **85** | runs the full named-group ISA + integer/atomics; accel backends still 0 |
| instruction decode: AES/PMULL, CRC32, LSE | 90 | goldens + check-value/FIPS-197 exec tests |
| FP16 / DOTPROD / RDM / FCMA / JSCVT | 85 | vector+scalar, f16 RTNE, SDOT lane sums, FJCVTZS ToInt32 |
| PAC / BTI / AMUv1 / TLBI-range / FCADD | 80–85 | PAC sign/verify round-trip; BTI/DGH hints; TLBI range operand decode |
| SHA512 / SHA3 / SM3 / SM4 | 80–85 | FIPS/GB/T round-function vectors |
| SEP real-firmware core + SEP-SIM | 0 | Inferno's superpower; next wave |
| PMGR / AOP / SMC / AES engine / PCIe / USB-OTG / touch / audio | 0 | next device wave |

## Layer 4 — the flow

| gate | status |
|---|---|
| G1 restore-ramdisk boot (C engine lane) | ✅ proven (run #74) |
| G2 ASR/invert stage | ✅ Rust host stack end-to-end (usbmux → restored → ASR e2e test) |
| G3 install → full root on restored APFS | ✅ `ios-rust boot-full` builds the complete container (System/Data/Preboot, 16 system dirs, SystemVersion.plist) |
| G4 homescreen via ios-rust engine | ✅ `ios-rust boot-full` runs the launchd→SpringBoard ladder through the Rust A13 backend and paints the homescreen (springboard.bmp, 2436×1125) |


## Layer 2.8 — sandbox profiles (SandBlaster port, Oct 2026)

Ported from cellebrite-labs/sandblaster (GPL-2.0, Yarden Hamami /
Cellebrite Labs) into `crates/sandbox`: binary sandbox-profile container
(legacy 0x8000 + iOS 18 `<HHBBBBBBHHH>` headers), 8-byte operation-node
records (terminal allow/deny + modifier/inline-action flags, non-terminal
filter chains), per-operation graph walk with cycle guard, SBPL emitter,
and the common sb-op name table (55 operations). Round-trip tested against
synthetic profiles built with the exact upstream layout.

| item | counterpart (C engine) | % | gate to flip |
|---|---|---|---|
| container header + all section tables (both formats) | reverse_sandbox.py SandboxData | **90** | real iOS 17/18 profile byte-diff |
| node records (terminal/non-terminal, inline modifiers) | operation_node.py parse_raw | **90** | same |
| graph walk + SBPL emission (core filter forms) | build_operation_node_graph + reduce | **70** | real-profile SBPL diff vs python SandBlaster |
| regex-table decompilation | sandbox_regex.py automaton→PCRE | 0 | port the automaton → regex synty |
| sb-op name table | kernel sandbox extension strings | 60 | import the full 200+ table |

## Layer 2.7 — research & format tooling (from the reference-repo sweep, Oct 2026)

Ports distilled from blacktop/ipsw (pkg/dyld + pkg/kernelcache + pkg/info +
pkg/tss), andrd3v/dcdev (devicecheckd RE), arlinux-xnu (darwin-abi.h +
xnu-7195.141.2), IdanBanani/iOS-Vulnerability-Research +
ansjdnakjdnajkd/iOS (research corpus), Legasitech/ios-emulator-linux
(host integration).

| item | counterpart (C engine) | % | gate to flip |
|---|---|---|---|
| dsc: `dyld_cache_header` exact offsets + version gates | ipsw pkg/dyld types.go | **100** (layout-verified) | parse a real A13 cache dump |
| dsc: mappings (plain + with-slide, flag→segment names) | ipsw file.go:440-497 | **90** | byte-capture diff vs `ipsw dyld info` |
| dsc: images (old + dyld4) + subcache v1/v2 naming + `.symbols` member | ipsw file.go:236-515 | **85** | same |
| dsc: slide-info rebase walkers v2/v3/**v4**/v5 (v3 = A13 iOS 13/14) | ipsw parseSlideInfo + dyld_cache_format.h | **85** (synthetic-cache verified; v1 walk honest-skip) | replay a real iOS 14 A13 cache and diff rebase lists |
| dsc: local symbols (nlist_64 + per-dylib entries) | ipsw CacheLocalSymbolsInfo | **85** | same |
| dsc: PrebuiltLoaderSet / launch closures / patch-info walkers | ipsw prebuilt*.go + closure.go | **0** | port after a real iOS 15+ cache is in hand |
| kernelcache: LZSS `complzss` decode (0x180 header, xnu mkext decoder) | xnu libkern/mkext.c + blacktop/lzss | **90** (synthetic roundtrip verified) | decode a real iOS 12-14 kernelcache |
| kernelcache: LZFSE via vendored Apple C FFI (`restore::lzfse`) | lzfse (Apple, BSD-3) | **75** | decode a real iOS 13+ kernelcache |
| kernelcache: version strings + fileset support | ipsw GetVersion | **75** | real-cache diff |
| kernelcache: `__PRELINK_INFO.__info` KEXT inventory | ipsw kext.go | **60** | real-cache diff (needs plist real-sample check) |
| kernelcache: KEXT extraction w/ chained fixups | ipsw openKext | 0 | needs MH_FILESET chained-fixups exporter |
| TSS: RestoreRequestRules engine (EPRO/ESEC) + component 4CC map (~130) | libauthinstall + ipsw pkg/tss + pkg/img4 | **75** | replay a captured TSS round with rule outcomes |
| device DB: ProductType→boards/CPID/BDID/platform (41 products) + ipsw.me client | ipsw pkg/info + ipsw_me.go | **80** (rows verified vs live api.ipsw.me) | full-upstream-DB import (machine-generate) |
| DeviceCheck: token buffer layout + ECDH-P256→HKDF→AES-GCM + MESU/humbug constants + entitlements fixture | andrd3v/dcdev README (devicecheckd RE) | **60** (README-literal layout, overlaps documented) | verify token bytes against a real device capture |
| XNU ABI KB: 423 BSD syscalls, 63 Mach traps, errno, boot_args(736 B), boot call order, SVC/VM/port constants | darwin-abi.h + xnu-7195.141.2 syscalls.master + pexpert | **100** as knowledge base | encode into the a13-cpu syscall shim when guests run |
| vuln-db research KB: 18 CVE/technique entries, zone-allocator mitigation timeline, FRIDA catalog, 34 tool refs | IdanBanani/iOS-Vulnerability-Research + ansjdnakjdnajkd/iOS | **100** as KB | grows with research, not gated |
| host-linux: capability check (KVM/RAM/disk/APFS/tools), dep manifest, reference darwin-vm QEMU command | ios-emulator-linux scripts + jprx/darwin-vm run.sh | **70** (sandbox cannot run real boots) | real boot on aarch64 hardware |

## Layer 2.9 — apple-soc completion wave ("find all apple-soc", Dec 2026)

The full ChefKiss Inferno apple device tree was enumerated and every model
ported or accounted. **`crates/apple-soc/src/inventory.rs` is the single
source of truth** (39 device rows — 36 ported, 3 honest zeros — test-enforced
against the crate module list; `avg_pct()` ≈ 59.2 honest device average).
The honest zeros: the per-device AES-XTS key wall on real-image APFS mount,
SEP real-firmware core (sep.c, 5673 L), and the A9/s8000 machine
(out of T8030 scope, listed for completeness). The fourth former zero — the
**boot kernel-patcher chain** (kernel_patches.c + patcher.c + mem.c, 1128 L
of C) — was ported in the same wave to `kernelcache::patcher` (1,529 LOC,
8 groups / 15 patches / 23 find attempts, nothing skipped, 8 tests) at an
honest **75**: engine + full table verified on synthetic collections; the
gate to 90 is one real T8030 kernelcache through `apply_t8030_patches`.

New ports this wave (13 devices, all with register-behavior tests):

| device | upstream | % | note |
|---|---|---|---|
| buttons | hw/misc/apple-silicon/buttons.c | **75** | F1–F10 QKeyCodes, SMC HID transition events; wire-up: Smc HID API |
| roswell | roswell.c | **75** | CP-auth relay: GET_DEVICE_INFO 0xDEADBEEF, "CKRosw" |
| mic_tempsensor | mic_tempsensor.c | **75** | I2C addr pointer, ID/STATUS/VALUE regs |
| tempsensor | tempsensor.c | **60** | 1:1 — upstream is itself a 0xAFAFAFAF fill stub |
| spmi_baseband | spmi-baseband.c | **75** | SPMI slave reg file, magic 0x147/0x2f |
| chestnut / fan53740 / lm_backlight | chestnut.c / fan53740.c / lm-backlight.c | **60** | 1:1 ports of upstream I2C stubs |
| pmu_d2255 | pmu-d2255.c | **75** | 0x8800 reg file, RTC latch, alarm→IRQ |
| a7iop + a7iop_mailbox | a7iop/{core,regs-v2,v4,mailbox/*} | **75** | v2+v4 reg tables, 15-deep FIFO doorbells, int gating |
| displaypipe_v2 | apple_displaypipe_v2.c | **75** | VFTG ladder, commit paints FrameSink |
| mt_spi | mt-spi.c (1108 L) | **75** | HBPP+LL stack, touch reports, CRC16, tick timers |
| baseband | baseband.c (1280 L) | **75** | XMM 7660: identity ROM, image doorbell, context parse |

Deepened modules (old → new, verified against upstream line-by-line):

| module | old → new | what moved |
|---|---|---|
| aes | 35 → **90** | full aes_reg.h map + command FIFO + inline AES-128/192/256 ECB/CBC/CTR, FIPS-197 tests |
| sep_sim | 45 → **90** | 26-endpoint table, bootstrap machine, keystore IPC byte-level |
| mipi_dsi | 15 → **90** | 1:1 of the complete (187 L) upstream stub surface |
| mca | 20 → **90** | SIO units + DMA FIFO + MCLK, refill/voice-enable quirks |
| ans2_nvme | 40 → **75** | vendor block + NVMe admin/IO queues (gate: PRP walker) |
| scaler | 20 → **75** | IRQ W1C, config lock, frame tick, format decode |
| apcie | 30 → **75** | LTSSM, MSI banks, RID→SID map, ECAM decode |
| typec_otg | 35 → **75** | ATC container passthrough + OTG widget maps |

Verification: `cargo test --workspace` → **327 passed, 0 failed**
(apple-soc alone: 89). The 20-group `CPU_INSTRUCTIONS` inventory and the
**189-entry** `GOLDENS_EXT` capstone/keystone table were re-counted and
re-run green this session.

## Layer 2.11 — boot-full v2: the real kernel on the Rust backend (Dec 2026)

`ios-rust boot-full` gained stage **[2.5/4]**: when the real fixtures are
present, the pipeline decompresses the actual T8030 kernelcache, applies the
T8030 patch table to the real bytes, lets the **real ADT** drive device
attach (`attach_from_adt`), and executes the kernel's first real function
from `__TEXT_EXEC` through the pure-Rust A13 interpreter to a **clean
RET → HLT** (iBoot-style guest state: stack in DRAM, LR on an HLT pause
page).

| item | evidence | % |
|---|---|---|
| T8030 machine assembly, real-ADT attach | real DeviceTree.n104ap: **59/105 peripherals modeled** (aic/uart/wdt/dart/pmgr/ans2/aes/smc/… attach at their real MMIO bases); 35 unmatched named (nco, mcc, dwi, pwm, pmp, sio, rsm …) — the next device-wave worklist | **90** |
| real-kernel boot stage | 39,204,080 B decode · patches 6/20 on real bytes · interpreter `executed 8 insns from 0xfffffff007bb0000, stop: Halted` (first function RETs clean) | **75** |
| **next honest gate (0)** | **kernel image rebase/fixup load** — the prelinked cache ships GOT pointers zeroed (iBoot applies rebase/chained-fixups with the boot slide); without it the first indirect call goes to 0. This is the same fixup machinery as the "KEXT extraction w/ chained fixups" row. | **0** |

### Layer 2.11a — the iOS 14.3 boot attempt (18C66, real T8030 bytes)

Tried to boot a **full iOS 14** on the engine: pulled
`kernelcache.release.iphone12b` + `DeviceTree.n104ap.im4p` +
`BuildManifest.plist` out of the 5.4 GB
`iPhone11,8,iPhone12,1_14.3_18C66_Restore.ipsw` via HTTP range requests and
ran the pipeline against them. Results, honestly:

1. **iOS 14.3 kernelcache decodes end-to-end**: 45,778,056 B LZFSE →
   `xnu-7195.62.1~4 (RELEASE ARM64 T8030)`, Darwin 20.2.0, **245 kexts**
   (`ios-rust kc info`). Patch table on 14.3 real bytes: **8/17 applied**.
2. **Real-data bug #7 found and fixed**: the iOS 14-era DeviceTree is a
   DER IM4P carrying an **LZFSE-compressed** flat tree (`bvx2` magic); the
   13.7-era blob was plain. `boot_full` now LZFSE-decompresses the ADT
   before the flat parse (`restore::lzfse::is_lzfse` sniff). After the fix
   the 14.3 ADT parses: **105 peripherals under /arm-io, 59 modeled**.
3. **The real kernel executes exactly one function**: interpreter ran
   **9 real instructions** from `__TEXT_EXEC` `0xfffffff007a18000`
   (BTI retired) to a clean RET→HLT. That is the whole honest extent of
   real-iOS execution today.
4. **Measured instruction coverage on the real 14.3 text** (linear decode
   sweep + single-insn exec probe over all 7,966,342 `__TEXT_EXEC.__text`
   words): **90.5% decode / 90.4% execute** — ~755 k words unimplemented.
   Top missing classes (all ordinary code, not exotic ISA): the
   **PAC-branch family** (`RETAA/RETAB/BRAA/BRAAB/BLRAA/BLRAB` — the
   kernel is PAC-ified, so every protected return is unexecutable),
   **pre/post-indexed load-store** (`LDUR/STUR !` and `#-imm` forms),
   **STP/LDP pair variants** (incl. 128-bit Q forms), the **exception
   class** (`BRK/HLT/DCPS/DRPS`), plus literal-pool data (~50 k words).
5. **Ledger honesty fix**: `boot-full`'s gate verdict used to print
   "full system COMPLETE" off the synthetic ladder. It now reports
   `G4 synthetic-✅` and names the open gates (rebase/chained-fixups,
   MMU/TLB, SMP, IRQ delivery, userspace exec) instead of implying a boot.
6. The userspace ladder (launchd→SpringBoard) and the painted homescreen
   are **synthetic by construction**: no launchd/SpringBoard binary is
   fetched from the IPSW or executed; the BMP is drawn by `restore::paint`.

**Verdict of the attempt: iOS 14 does not boot.** The engine reaches the
first real kernel function and nothing further. The next real gate remains
the rebase/chained-fixup image load, then MMU + the ~10% missing ISA
(led by the PAC-branch family), then the IRQ/peripheral completeness
(46/105 unmodeled) before a userland attempt is even meaningful.

### Layer 2.11b — the RE toolkit session: 90.5% → 98.6% measured on real 18C66 bytes

The gap-fix loop from `tools/re/README.md` (oracle: capstone 5.0.7 +
keystone; masks brute-forced by `tools/re/oracle/mask_discover.py`;
every implementation pinned by keystone/capstone-derived `gap_*`
golden tests) closed the top real-kernel instruction classes:

| class (real-14.3 word count) | what landed | decode after |
|---|---|---|
| PAC-branch family (~212k): `RETAA/RETAB/BRAA/BRAB/BLRAA/BLRAB` | masks 0xD71F0800/0xD71F0C00/0xD73F0800/0xD73F0C00 (capstone-brute-forced); RETAA/RETAB exact encodings; QARMA-model auth = identity strip | 90.5 → ~95 |
| exception class (~170k): `BRK/DCPS1-3/DRPS` | decoded; exec = clean Panic stop (xnu hits BRK only on panic paths) | |
| pre/post-index + unscaled GPR load/store (~190k): `LDUR/STUR/… !`, `LDTR/STTR`, signed `LDRSB/SH/SW` | `LdSt9/Ldrs9` with LsMode + writeback semantics | |
| STP/LDP fixes + SIMD pairs (~40k): 32-bit GPR pairs (opc 00), `LDPSW`, S/D/Q pairs | pair group 10100/10110, mode bits[24:23], L=bit22 (keystone-verified layout) | |
| register-offset load/store (~20k): `STRB Wt,[Xn,Xm]`, `LDR Xt,[Xn,Xm,LSL #3]`, `LDRSW [Xn,Xm,SXTX]` | `LdStRegOff` with ExtOp extend/scale | |
| SIMD single LS (~15k): 9-bit + unsigned, B/H/S/D/Q | width rule `load=opc&1`, `16B iff opc[1]&&size==0 else 1<<size` (keystone table) | |
| add/sub extended register (~10k): `ADD Xd,Xn,Wm,UXTW #i` | `AddSubExt` | |
| variable shifts (~5k): `LSLV/LSRV/ASRV/RORV` | 2-source opcodes 8–11 | **98.59%** |

**3 real decoder bugs found and fixed** (each masked by synthetic tests,
exposed by real bytes): (1) the MOV-alias arm swallowed EVERY
logical-shifted-register form and returned None (`orr w10,w10,w11` was
undecodable); (2) LDP/STP opc map was shifted — 32-bit pairs (opc 00)
rejected, `LDPSW` misdecoded as 32-bit pairs, all SIMD pairs (group
10110) unimplemented; (3) SIMD single-LS width rule wrong (Q forms
undecodable). Measured on the full 7,966,342-word `__TEXT_EXEC.__text`:
**decode 90.52% → 98.59%, single-insn exec 90.4% → 98.6%** (probe:
`tools/re/coverage-probe`). Remaining honest gaps: SIMD three-same
arithmetic (`0x4e`), SIMD bitwise/shift immediate (`0x6f/0x4f`), scalar
FP (`0x1e`), ~51k words of literal pools (data, not instructions).

Tooling added (committed for future sessions, all under `tools/re/`):
`oracle/insn_oracle.py`, `oracle/mask_discover.py`, `coverage-probe/`
(sweep + exec probe + histogram + word dbg), plus the campaign's
ios-re-toolkit scripts (Ghidra headless + ExportDecompiled +
TraceColor, Mach-O triage + ADR string scan, IPSW range extraction,
HFSX reader, codesign verify) — see `tools/re/README.md` for the full
playbook. Workspace test count 343 → 352 (all green); ledger headline
73.6 → **74.0** (81 rows, honest recompute).

### Layer 2.12 — boot-first: the FIRST BOOT after irestore (real 18C66 data plane)

`ios-rust boot-first [fixtures-dir] [out-dir]` reproduces on real Apple
bytes what happens between idevicerestore printing “Restore Finished
(status 0)” and the first instruction of the freshly-installed system:

1. **[irestore 1/3] identity select** — the real 751 KB
   `BuildManifest.plist` parsed with the workspace plist parser: 6
   identities, 4× n104ap (iPhone12,1), supported products
   iPhone12,1/iPhone11,8, build 18C66, ApChipID 0x8030, ApBoardID 0x04,
   UniqueBuildID 20 B.
2. **[irestore 2/3] SHA-384 component verification** — the restored
   data plane, measured:
   - `DeviceTree.n104ap.im4p` (42,763 B) == manifest `DeviceTree`
     digest for **all four** n104ap identities ✅
   - `kernelcache.release.iphone12b` (15,849,700 B) == manifest
     `KernelCache` digest for identity[1] “Customer Erase Install” and
     identity[4] “Customer Upgrade Install” ✅
   - `RestoreKernelCache`/`RestoreDeviceTree` (the restore-RAMDISK
     images, covered by the G1/G2 lanes) correctly do NOT match the
     release files — the check is discriminating, not vacuous.
3. **[irestore 3/3] staging** — the two verified components plus
   `staging-manifest.txt` land in `boot-first-staged/`: the exact
   device state right after status 0.
4. **[first boot] iBoot-equivalent on the STAGED bytes** — machine
   assembly from the staged ADT (59/105 /arm-io peripherals modeled,
   35 unmatched), staged kernelcache LZFSE-decoded (45,778,056 B),
   T8030 patch table 8/17 applied on real bytes, image mapped at the
   real VA, and the pure-Rust A13 interpreter executes the kernel's
   first function: **9 instructions retired from
   `0xfffffff007a18000`, clean RET → HLT** (exit 0).

Verdict (honest): the irestore → first-boot data plane is REAL and
digest-verified end to end; the boot still stops at the first function
— a full boot needs rebase/chained-fixups image loading, MMU/TLB,
IRQ/AIC delivery, userspace exec (see Layer 2.11a). Nothing synthetic
past the stop. Ledger: +1 row (82), headline 74.0 → **74.1**.

### Layer 2.13 — M1 ISA closure kickoff: 98.59% → 98.69% + bugs #8/#9

The boot campaign started (`docs/BOOT-PLAN.md`, 2-hour cadence). First
work block closed the three EASY real-byte classes, with a new oracle
tool (`tools/re/oracle/bucket_discover.py`: bucket-driven mask
derivation + per-mnemonic capstone validation):

* **dp-1-source family** (bucket 0x5a/0xda, ~4.6k words): RBIT/REV16/
  REV32/REV/CLZ/CLS, both widths, opc map capstone-derived (0–5),
  guard requires bits 19:16 == 0 (else it swallows the PAC family —
  caught by the PAC goldens).
* **dp-3 op31 map** (bucket 0x9b): REAL-DATA BUG #8 — the old guard
  `(w>>22)&1==0` rejected UMULH (~1.5k words) AND misdecoded SMULH
  (op31=010) as MADD: **silently wrong results on real bytes**. Full
  op31 map now: 000=MADD/MSUB(bit15) 001=SMADDL/SMSUBL 010=SMULH
  101=UMADDL/UMSUBL 110=UMULH (011/100/111 unassigned — capstone
  confirms 0x9B800000 undefined).
* **REAL-DATA BUG #9:** the "QEMU 0x1C/0x1D-anchored" Sqrdmlah goldens
  were UNASSIGNED encodings (capstone: undefined), and the arm behind
  them also stole real umaddl words (op31=101 with bits15:10=0).
  Deleted; scalar RDM stays in the keystone-verified 0x7F40_0000 arm.
* **logical-ROR** (bucket 0x4a, ~1.2k words): `ShiftKind::Ror` +
  rotate exec (`eor w13,w11,w21,ror #29` = 0x4AD5756D was None).
  Keystone cannot assemble ror-shifted BIC — hand candidate
  0x0AE40462 verified by capstone (per playbook).

Measured on the full 18C66 `__TEXT_EXEC.__text`: **decode 98.59% →
98.69%** (7,861,938/7,966,342), **exec probe 98.6% → 98.7%** (+7,697
real words). Tests 352 → **356** (gap_dp3_mulh_map, gap_dp1_rev_family,
gap_logic_ror, gap_dp1_exec_semantics — every word capstone/keystone-
derived; two of MY OWN hand-derived golden words were wrong and got
fixed against capstone, the playbook works both ways). Remaining
buckets: SIMD three-same/different (~19.7k), SIMD shift-imm (~11.2k),
scalar FP (~7.5k), SIMD ld/st (~5.3k) — next work blocks; then M2
rebase/chained-fixups (the first-boot unlock).

## Layer 2.10 — REAL-ARTIFACT gates ("use the GitHub action to make download cache", Dec 2026)

Real Apple artifacts are now first-class CI fixtures (`.github/workflows/
fixtures.yml` → `tools/fetch_fixtures.py`, range-request partial IPSW
download + a live TSS capture; cached via upload-artifact). Every claim
below is proven against **actual Apple CDN bytes / a live gs.apple.com
response**, not synthetic fixtures:

| gate | evidence | flip |
|---|---|---|
| T8030 kernelcache decode | `kernelcache.release.iphone12b` (iOS 13.7 17H35): 39,204,080 B LZFSE → MH_MAGIC_64, Darwin 19.6.0 / xnu-6153.142.1~8 / **T8030** | LZFSE **75→90** |
| prelink KEXT inventory | real `__PRELINK_INFO.__info` (982 KB XML) → **232 kexts** (IOStorageFamily, AppleSMC …) | version+prelink **60→90** |
| **kernel patcher on real bytes** | `apply_t8030_patches` on the real cache: **6 applied** (bypass code signature checks, all binaries in trustcache, disable APFS snapshots, allow rootfs remount/union, enable hactivation, bypass pmap_cs_enforce), 14 honestly missed | patcher **75→90** |
| real ADT parse | `DeviceTree.n104ap.im4p` → flat-DT format support added (Inferno dt.c semantics incl. the `1<<31` placeholder flag): root "device-tree", **105 peripherals under /arm-io**, compatible "arm-io,t8030" | adt **90→100** |
| real BuildManifest | 17H35 manifest parses (BoardConfig/BuildIdentities/digests); T8030 identity carries KC/SEP/DT digests | ipsw manifest upgraded onto the fixed codec |
| real TSS response | live `ipsw download tss` (gs.apple.com): @ServerVersion 2.1.0 + ApImg4Ticket (10,619 B IM4M DER) validates: cert chain + Ticket body extracted | authinstall **60→75**, img4 **75→90** |

**6 real-data bugs found and fixed by the fixtures** (the exact reason this
layer exists):
1. `sections.rs`: `section_64.size`/`offset` fields **swapped** (real KC
   exposed it; `__info` was garbage),
2. `plist_lite`: hex `<integer>0x…</integer>` rejected,
3. `plist_lite`: inline `<!-- -->` comments between elements,
4. `plist_lite`: paired `<true></true>` forms + self-closing
   `<dict/>`/`<array/>`,
5. `authinstall/im4m.rs`: real IM4M is DER
   (SEQUENCE → OCTET STRING "IM4M" → INTEGER 2 → cert SET → Ticket body);
   the old validator only matched the synthetic fixture,
6. `adt`: real devicetrees use the Apple **flat-DT** format
   ({nprops,nchildren} LE, name[32] props, placeholder len bit 31) — not
   the iBoot NODE/PROP/END container; format sniffing added for both.

**Workspace model parity (average of ledger rows, honest): 60.6% before the
Layer 2.7 sweep, re-computed live by `ios-rust parity`** — up from 0
at workspace creation; every row above carries its gate so "100%" is a checklist,
not a slogan. Update this file with every verdict (same discipline as the
ios-sweet-rust ledger).

## Layer 5 — the pure-Rust restore host (X-row closure, 2026-10-28)

The ios-sweet-rust parity map's five MISSING host-side rows are now
implemented in Rust, twice over by design: as **standalone crates**
(canonical, protocol ground truth) and as `restore::` in-crate modules
(integrated path). CI runs both stacks (132/132 tests).

| item | counterpart | % | gate to flip |
|---|---|---|---|
| `plist` crate — XML plist parse/serialize + `parse_prefix` for TCP-coalesced bursts | libplist XML subset | **90** | binary plist (bplist00) reader |
| `usbmux` crate — usbmuxd client: binary framing (htons ports), Listen/DeviceList/Connect, unix+TCP | libusbmuxd | **90** | device pass over a real unix socket |
| `restored` crate — QueryType/QueryValue/StartRestore/notifications, port **0xF27E** (cross-checked against the Ghidra decomp of `restored_external` entry(), ios-sweet-rust run 40609705374) | libimobiledevice restore.c | **75** | real restored handshake (needs CPU exec) |
| `asr` crate — Initiate→packet-info→OOBData→Payload state machine, 128 KiB chunks + per-chunk SHA-1 (own FIPS 180-1) | idevicerestore asr.c | **75** | real 7.38 GB push (needs CPU exec) |
| `authinstall` crate — TSS request build (UniqueBuildID/ApChipID/…/ApNonce + @ApImg4Ticket), ticket extraction, IM4M structural validation | libauthinstall + idevicerestore tss.c/img4.c | **60** | TLS transport + live TSS round trip |
| `apfs` crate — fletcher64 (upstream sum-to-zero scheme), nx/volume superblocks, omap+fsroot B-trees, COW file create/replace | apfs.kext / apfs-fuse DiskStruct.h | **60** | mount real Apple image (AES-XTS per-device key wall) |
| host pipeline — `run_host_restore`: usbmux → restored → ASR push → Status 0 "Restore Finished" | idevicerestore restore.c | **75** | full run against real device |

Proof carried in CI: `ios-rust` bin test `host_restore::end_to_end_host_restore_over_mock_device`
drives the whole sequence against an in-process mock device (usbmuxd +
restored + ASR), verifying the SHA-1-tagged chunk stream of a pushed
image. The restore-internal variants (`restore::plist_lite`, `usbmux`,
`asr`, `restored_proto`, `tss`) cover the same protocols inside the
restore crate with their own tests; ASR frame reading, usbmux header
bounds and the restored frame-bounds test were repaired in the same
pass so both stacks are green.

The workspace average moved **54.2 → 60.6** (parity.json, 51 modules,
132/132 tests). CI trigger repaired (`on.push.branches` was the literal
scalar `ain]` — push builds to main never ran).

### Layer 2.11c — boot-real: the REAL XNU handoff, 8.14M instructions with MMU live

`ios-rust boot-real [fixtures] [max-insn]` is the honest successor to the
synthetic ladder: the **actual Apple XNU 18C66 kernel** loaded the way iBoot
loads it (real ADT machine assembly, real boot_args at `physBase`, LC_UNIXTHREAD
entry at load PA), executed instruction-by-instruction by the pure-Rust A13
core. Measured this session (release build, real 45.78 MB image):

* **8,136,610 real instructions retired** before the first honest stop —
  ~900,000× further than the previous first-boot best (9 instructions).
* The kernel builds its own 16K-granule bootstrap page tables and flips
  `SCTLR_EL1.M`; the new stage-1 MMU (`crates/a13-cpu/src/mmu.rs`) walks
  **the kernel's own tables** — 460 walks, 9.1M TLB hits, **0 walk faults**
  on the boot path.
* The kernel executes its own `__thread_starts` DYLD_CHAINED_PTR_64-style
  fixup walk (loop at 0x…7b802b8: slot load → `cmn w12,#1` end-marker →
  `ldr x13,[x12]` chain → `ubfx/madd` next → `str` rebase) — completing
  with the branch taken and the array rebuilt correctly.
* Current stop (NEW, named): `ldr x0,[x20,#8]` → NULL → `ldr w9,[x0,#4]`
  faults at 0x…81377b4 — the kernel dereferencing an **un-rebased
  chained-fixup pointer from `__DATA`**. That is exactly BOOT-PLAN M2
  (rebase/chained-fixups at load time, iBoot's job). No synthetic-anything
  in this verdict.

**REAL-DATA BUGS #10, #10b, #12** (found on the boot path, fixed, pinned by
`gap_*` goldens): **#10** — flag-setting add/sub families (AddSubReg,
AddSubExt) wrote their result to **SP** when Rd=31 (`cmp x17, w16, uxtw`
at 0x…7ff97e4 zeroed the kernel stack mid-boot → `str xzr,[sp,#8]`
fault at 0x…7ff97ac after 8.08M insns). **#10b** — ADDS/SUBS passed
carry-in=1 (ADCS semantics) so every 32-bit register ADDS computed a+1;
32-bit ADDS never set C (width bug in add_with_flags). **#12** —
across-lane reduces wrote only the low byte; the kernel's
`uminv b1, v0.16b; fmov w2, s1; cbnz w2` memscan idiom requires the
zero-extended full element (DDI leaves it UNDEF; Apple zeroes; the real
code depends on it — scan loop hung 80M insns without it).

**SIMD families landed (all capstone/keystone-pinned, goldens in
decode.rs):** MOVI-64 with the bit→byte immediate expansion (imm8 =
bits[9:5]|immb<<5; measured 12/12 vs capstone incl. `movi v0.2d,
#0xffffffffffffffff` = 0x6F07E7E0), three-same logical (AND/BIC/ORR/ORN +
EOR/BSL/BIT/EON via size+U), three-same integer (ADD/SUB, CMGT/CMHI/
CMGE/CMHS/CMEQ/CMTST, S/UMIN/MAX + P pairwise, MUL — per-lane exec for
B/H/S/D), across-lane reduces ({S,U}MINV/{S,U}MAXV/ADDV), scalar↔GPR
`fmov w2, s1` family. **Measured on the full 7,966,342-word
`__TEXT_EXEC.__text`: decode 98.59% → 98.87%, exec probe 98.6% → 98.9%**
(`tools/re/coverage-probe`; unknown 89,707 words, ~46k of them literal-pool
runs). Workspace test count 352 → 363, all green.

**Session C (2026-10-29, shift-imm + modified-immediate):** the 0x0F group
decoded+executed end to end. Field rules pinned by keystone sweeps —
X = immh:immb = bits[22:16]; shift = (16<<size)−X for right forms, X−(8<<size)
for left forms (SHL/SLI/SQSHL/UQSHL/SQSHLU/SSHLL/USHLL); element size from
X's MSB; SSRA=op2, SRSHR=op4, SRSRA=op6. Modified immediates: cmode table
verified against capstone (U=0: even cmode MOVI-32/16, odd ORR-32/16;
U=1: even MVNI, odd BIC; cmode E U=0 = 8-bit byte-replication — the
MoviVec64 guard now requires U=1; cmode E U=1 = 64-bit bit-expansion;
imm8 = (X&7)<<5 | bits[9:5]). FMOV vector imm: VFP-ExpandImm exponent rule
pinned from the real kernel's `fmov d8, #1.0` (0x1E6E1008, imm8=0x70 →
NOT(b6)b6b5b4<<4 | 0xF). cvtf .4h (8-bit int) form reserved per capstone.
**Measured: decode 98.87% → 98.89% (7,878,033/7,966,342), exec probe 98.9%**
(`tools/re/coverage-probe`; unknown 88,309, ~46k literal-pool runs).
Environment: sandbox reset twice mid-block (repo restored from the S3 git
bundle both times); ipsw_range.py had drifted back to the 14.0-beta IPSW
constant once (re-fixed; CLI now matches tools/re/README.md); guest DRAM is
IOS_RUST_DRAM_MB-overridable (3 GB sandbox runs boot-real/boot-first in a
1 GiB window; bootargs memSize follows). boot-real reproduced the M2 stop
evidence: **8,135,842 insns retired, TranslationFault(load) va=0x4 @
0xfffffff0081377b4** — the un-rebased chained-fixup pointer. boot-first:
9 insns retired (irestore lane ✅, stop Halted) — the M2 baseline.
Remaining honest gap: indexed-multiply (bit10=0, op4 ∉ {C,D,E}) ≈4.5k
words, three-same FP 0x4e ≈11.5k, SIMD ld/st ≈8.7k, scalar FP ≈4.1k,
STLUR ≈1k.

Tooling added: `tools/re/macho/bootstop_probe.py` (segment-aware VA→file
probe for boot-stop forensics), `kc dump` (decompressed Mach-O to disk),
SP-change tracking + nzcv in the boot-real trace.

**Session C second half (2026-10-29, three-same FP + unscaled AR):** the
three-same FP family landed — 24 ops across fadd/fsub/fabd/faddp/fmul/
fmulx/fdiv/fcmeq/fcmge/fcmgt/facge/facgt/fmax/fmin/fmaxnm/fminnm/fmaxp/
fminp/fmaxnmp/fminnmp/fmla/fmls/frecps/frsqrts. The field map was pinned
by keystone round-trips and is NOT the textbook layout: width = bit22
(0=S-lanes, 1=D-lanes), opcode-pair half = bit23 (FADD/FSUB share opcode
0x35 across bit23), bit10=1 keeps the crypto-3 siblings (bit10=0) out,
element width ≠ bits[23:22] (fadd .2d = size bits 01, fsub .4s = 10).
Integer three-same gained MLA/MLS (opcode 100101, U arm). FP exec is
per-lane f32/f64 with IEEE maxNum/minNum NaN rules; pairwise ops fold
pair(vn) then pair(vm). **REAL-DATA BUG #13:** BRAAZ/BLRAAZ (0xD6-space
A-key Z-forms, ~428 words in xnu indirect tail calls) — the session-A PAC
campaign pinned only the 0xD7 B-key arm; census masks
(0xFFFFFC1F, 0xD61F_081F/0xD63F_081F) landed with goldens. **REAL-DATA
BUG #14:** STLUR/LDAPUR/LDAPR (v8.1 unscaled release/acquire, ~1.1k words)
— stlur/ldapur 0xFFEFFC00 arms, ldapr (W/X, NO imm9 field — bits 23:12 are
a fixed pattern, size from bit30) mapped onto the LdSt9 Unscaled path
(release/acquire ordering is a no-op in this single-threaded model).
FCVTZS/FCVTZU fixed-point vector (opcode 11111 — real word 0x4F70FC00)
added to VShiftImm. **Measured: decode 98.89% → 99.03%
(7,889,208/7,966,342), exec probe 98.9% → 99.1%** (unknown 77,134, ~46k
literal-pool runs). `cargo test --workspace`: 100 passed / 0 failed.
boot-first re-run after the families landed: **9 insns retired, stop
Halted** (unchanged — the M2 stop is the zeroed GOT entry, not ISA).
Remaining honest gap to the 99.3% M1 acceptance: indexed-multiply family
(bit10=0: smull/umlal/sqdmull/fmul/fmla/fcmla-by-element ≈4.5k words),
SIMD ld/st multiple + register-offset ≈9.7k, scalar FP remainder
(fcmp/fcsel/fmov-imm/scvtf-scalar ≈4.1k), EXT/DUP-gpr ≈3.4k,
2-reg-misc narrowing (xtn/sqxtn/fcvtl/fcvtn/addp-scalar) ≈3k.

**Sessions D+E (2026-10-29, M1 gate CLEARED — 99.03% → 99.31% decode /
99.3% exec):** the five remaining families landed with capstone-oracle
field maps (pin_m1d3.py 62-combo brute force; hand-derived rows corrected:
the M bit is an INDEX bit for .h-lane indexed ops and the rm is 4 bits
there; FCMLA/SQRDMLAH own opcode4 0xC/0xD with U=1; FMLAL/FMLSL own 0000/
0100 with size=10). Landed: SIMD ld/st register-offset (opc<0>=L, opc<1>=Q,
S=size10/D=size11), multiple + single structures (de-interleave exec),
indexed FP/INT/FP16FML, scalar FP (fcmp-e bit4/fccmp/fcsel/fmov-imm
VFP-ExpandImm/FCVT{N,A,P,M,Z}S/U plain+fixed/SCVTF/UCVTF/FMOV gpr↔fp/
ADDP-scalar — the scalar pairwise class reuses the H type slot for D),
2-reg-misc (18 op families incl. fcvtn/fcvtl narrowing/widening + vector
fcvtzs/scvtf/ucvtf + across-lane addv/saddlv/uaddlv/sadalp/uadalp),
permute/ext/dup/ins/umov/smov/tbl/tbx, SHA1/SHA256 crypto (sha256h/h2
2-round semantics textbook-verified: both vectors written back, H uses
W[0..1], H2 W[2..3]), PMULL .1q, SIMD LDR literal + LDRSW literal +
PRFM-literal, FMOV vector .2d/.4s immediate. **REAL-DATA BUG #15:** the
reduce guard's bits20:17==1000 slot swallowed three-same Vm=16/17 insns
(fadd v0.4s,v0.4s,v16.4s = 0x4E30D400; ~1.5k words). **REAL-DATA BUG #16:**
FCVTL silently decoded as AESIMC (same opcode bits 15:10=011110; the AES
guard lacked the size==00 requirement). **REAL-DATA BUG #17:** ADC/ADCS/
SBC/SBCS decoded as CSEL/CSINC (0x1A group; the divider is bit23: ADC
family bit23=0 + opcode 000000, CSEL family bit23=1) — found by keystone
cross-check 0x1A020020 vs 0x1A820020. Goldens: 5 new gap_* families +
the 100-row generated capstone-named table (goldens_m1.rs).
**Measured: decode 99.31% (7,911,692/7,966,342), exec probe 99.3%
(UnknownInsn 136); unknown 54,650 of which 36,792 are ≥16-word
literal-pool runs (data).** `cargo test --workspace` 288 passed / 0 failed.
boot-first: 9 insns retired, stop Halted (M2 zeroed-GOT stop — not ISA).

### Layer 2.11d — session F: the M2 gate cleared the honest way (census → rewire → measure)

**The sandbox reset a third time mid-session** (repo + ~/.config + /tmp
wiped at ~16:0x). The S3 vault paid off exactly as designed: the
vault-index subagent had uploaded a fresh bundle from HEAD 9130a73 at
15:37, and recovery was `git clone` from
`research/ios-rust-repo-backup.bundle` + rewritten s3.env — back to a
verified-clean 9130a73 in minutes. (Also lost and re-pulled: fixtures
BuildManifest + DeviceTree via `ipsw_range.py`.) A census note records the
incident (`tools/re/notes/m2-chained-fixups-census.md`).

**M2 census — the BOOT-PLAN premise was wrong, and the bytes said so.**
`tools/re/extraction/m2_fixup_census.py` (re-runnable) proves the real
18C66 `kernelcache.release.iphone12b` carries **no fixup metadata at all**:
25 load commands, no LC_DYLD_CHAINED_FIXUPS / LC_DYLD_INFO, no fileset
entries, zero-size `__PRELINK_*`. What actually ships: `__TEXT,
__thread_starts` (u32 range list the kernel itself walks at boot — that
loop already runs correctly in-emulator), `__DATA_CONST,__auth_ptr`
(544/544 entries ship NON-zero, pre-signed PAC slots holding preferred-base
offsets — valid at our slide-0 handoff), and a mostly-zero `__DATA` the
kernel fills itself. The "un-rebased chained-fixup pointer" story is
retired; the real stop is **DeviceTree-dependent CPU enumeration**.

**Named-stop root cause (static RE + live trace agree).** The 8.14M stop
`ldr w9,[x0,#4]` with `x0=[x20+8]=NULL` @ 0x…81377b4: six BL callers, the
live `lr` lands on 0x…7b8cc0c — code that parses boot-arg `"cpus"` and
looks up DeviceTree **`"/cpus"`**, then fills a stack struct from globals
`x[0x…7744988]` (DT ptr) / `w[0x…7744998]` (DT flag) — **both ship 0x0**
in `__DATA_CONST,__const` — guarded by the memory-init gate
`bl 0x…8136f10; tbnz w0,#0 → skip stores` (store sites 0x…7b80d24 /
0x…7b81fd8 / 0x…7b83fa0). The live trace's `x9="LSSealio"` decodes the old
"LSSeaico" mystery: it's the AppleSPU ALS **Sealion** driver string, not a
pointer. Next evidence step: a live trace of the gate/store sites.

**REAL-DATA BUG #18 — MAIR_EL1 write dropped.** The M3 groundwork inventory
(`tools/re/notes/m3-mmu-groundwork.md`, regenerated after the reset from
the subagent report) found the MAIR write arm was `=> {}` while the read
arm read the never-filled store — every `mrs mair_el1` returned 0. Fixed:
write arm round-trips through `sysreg_store` AND feeds
`Mmu::set_mair(v)`; new `Mmu::attr_byte(attrindx)` decodes AttrIndx → MAIR
byte (DDI0487). Goldens: `gap_mair_roundtrip`, `gap_mair_mmu_attr_byte`.
`cargo test --workspace`: **290 passed / 0 failed** (288 + 2).

**boot-first rewired to the real handoff (the actual M2 unlock).** The old
lane executed `__TEXT_EXEC.__text[0]` with no x0/boot_args and a 20k cap —
"9 insns, Halted" was a harness artifact, not a kernel wall. It now runs
`boot_real::run` (boot_args at physBase, LC_UNIXTHREAD entry, MMU off,
12M budget). **Measured (debug build, IOS_RUST_DRAM_MB=1024):
8,135,842 real instructions retired** (gate ≥10,000 CLEARED), SHA-384
component verification ✅, MMU 460 walks / 0 faults, stop
`TranslationFault(load, invalid descriptor) va=0x4 pc=0xfffffff0081377b4 ·
clean: true` — the new named M2 stop. BOOT-PLAN M2 marked [x] with the
corrected mechanism and this run as evidence. parity.json notes updated to
match (decoder 99.31%, interpreter stop wording, boot-first lane 90%).

Tooling added: `tools/re/extraction/m2_fixup_census.py` (byte census +
empirical layout validation), notes trio
(`m2-chained-fixups-census.md`, `m3-mmu-groundwork.md`,
`s3-vault-manifest.md`). Vault: `s3://ios-research-vault/INDEX.md` now at
the bucket root for instant discovery.

### Layer 2.11e — session G: M3 gate cleared the honest way (walker goldens → bug #19 → measured 8.11M MMU-live insns)

**2026-10-30, Job 482743 work block.** The first open milestone was M3
(MMU/TLB). Session F had already wired a real 4K/16K stage-1 walker; the
audit (task 2-b, `tools/re/reports/m3_mmu_audit.md`) ranked 9 gaps and
provided the minimal work plan. Session G executed steps 1–5 of that plan
plus the honesty cleanup:

**REAL-DATA BUG #19 — TTBR masked to granule alignment truncates
truncated start tables.** The walker computed the start-level table base
as `ttbr & !page_mask & 0xFFFF_FFFF_F000`. Per DDI0487 the START-level
table may be truncated (xnu's 8-entry L1' bootstrap table is exactly
that), needing only 8-byte alignment; granule-masking silently walked
table 0 for any legitimately-placed truncated table. Found by the NEW
walker goldens (16K L1-start shape with L1' at 0x2000), NOT by the real
run — the kernel's tables happen to be granule-aligned, so the measured
boot was never affected (insns retired byte-identical before/after:
8,135,842). Descriptor-encoded next-level table addresses KEEP the
granule mask (their low bits are reserved by the encoding — arch-required
alignment for full tables). The bug class the audit predicted (G6: "zero
walker unit tests — any refactor can regress the walker unguarded")
caught itself one session later.

**M3 acceptance, measured** (`boot-first fixtures /tmp/bootfirst`,
debug build, IOS_RUST_DRAM_MB=1024, log `/tmp/bootfirst-m3.log`):
guest writes TCR/TTBR/MAIR (all consumed), flips SCTLR.M at insn
25,033, and **8,110,809 of 8,135,842 retired insns run with translated
fetch/load/store** (gate ≥ 1,000,000 — CLEARED). 460 walks / 9,125,225
TLB hits / hit-rate 100.0% / 1 walk fault (load — the known DT stop).
Leaf histogram L0 0 · L1 0 · **L2 459** · L3 0 — every bootstrap
translation terminates at an L2 32 MiB block descriptor, exactly the
start.s shape. TCR ground truth now live in the report:
`granule 16K t0sz 25 t1sz 25 ttbr0 0x801704000 ttbr1 0x801708000
tbi0 1 tbi1 0` — matches the statically-extracted
0x0008_0022_6519_A519.

**New instrumentation (report-only, zero behavior change):**
`mmu_live_from` captured at the SCTLR.M 0→1 edge → `MMU live: N of M
insns` line + the M3 verdict bullet in `print_report`; per-kind walk
fault tally (fetch/load/store); leaf-level histogram; MAIR attr
classification (device = byte bits[7:4]==0) with page + access counters
and device→RAM / normal→MMIO misroute tallies (`ram_top` = DRAM window
END — the first run mislabeled 459 kernel physmap PAs as normal→MMIO
because ram_top was the SIZE, not window end; fixed same session, now
0/0); `Bus` unmapped silent-zero reads / dropped writes surfaced (0/0 on
the real run).

**ESR/FAR synthesis (M4 groundwork, no vectoring yet):** every stage-1
translation fault now records FAR_EL1 = fault VA and synthesizes ESR_EL1
(EC 0b100100 instruction abort / 0b100101 data abort + WnR, IL=1, DFSC
translation-fault 0b0001LL / address-size 0b010LL from the walk chain
level). Live at the terminal stop: FAR_EL1=0x4, ESR_EL1=0x96000006
(data abort, DFSC 0b110 = translation fault L2) — agrees with the dumped
descriptor chain (L1 valid → L2 invalid). Guest-writable for M4
vectoring tests.

**Loud-fail hardening:** 64K granule / reserved TG encodings / TG0≠TG1
mixes set `config_fault` and fault on first walk (64K previously
silently walked as 4K); T0SZ/T1SZ=0 no longer remapped to 16; TBI0/TBI1
decoded, masking flag-gated (`honor_tbi`, default off — identical to the
measured baseline). **Honesty cleanup:** the dead `isa::SystemRegTable`
(128 lines, zero callers) removed; its SCTLR reset-value doc-vs-code
drift documented in place (live interpreter intentionally starts 0;
changing it mid-campaign would perturb the measured baseline).

**PARITY 2.11c reconciliation:** "MMU … 0 walk faults" was misleading —
the terminal DT stop IS a walk fault (per-kind tally: fetch 0 / load 1 /
store 0). The 2.11c run and the 2.11e run agree on 8,135,842 retired;
the earlier PARITY/BOOT-PLAN number drift (8,136,610 vs 8,135,842) is
resolved in favor of the re-measured 8,135,842.

`cargo test --workspace`: **298 passed / 0 failed** (290 + 8 net new
mmu goldens; report fields + isa cleanup produced no regressions).
BOOT-PLAN M3 marked [x] with this run as evidence; permission/AF/XN
enforcement stays an honest, tracked limit gated on M4 vectoring.

### 2.12 — Session H (2026-10-30): M4 vectoring live + four real-data bugs #20-#24

* **BUG #20 (boot_args DeviceTreeP @+0x28/+0x30 → must be +0x60/+0x68):**
  the M2-era builder put the DT pointer inside Boot_Video; the kernel
  reads deviceTreeP/deviceTreeLength at +0x60/+0x68 (PE_init_platform,
  pe_init.c:390; kernel-side `ldr x9,[x19,#0x60]` @0x…81399c8). This —
  not the "0x…b83f54 gate" — is why DT globals shipped zero since M2.
  Fixed (+revision=2), golden-pinned.
* **BUG #21 (ADT reg parsed big-endian):** real Apple ADT is LE;
  `/arm-io/aic` reg = 0x3b100000/0x8000 LE u64 pairs; all 59 modeled
  windows attached at garbage bases (aic@0x103B, pmgr@0x3B — measured by
  the M5 MMIO census, notes/m5-device-census.md). LE format rule pinned
  by real bytes (len%16==0 → u64 pairs; %16==8 → u32; ==4 → bare u32) +
  arm-io `ranges` translation (child <0x1_00000000 → +0x2_00000000;
  0x6_.. identity — decoded from the real ranges property).
* **BUG #22 (hardcoded staging layout):** DT blob sat exactly AT
  topOfKernelData (0x8_0400_0000) while end_kern of the 45.7 MB image is
  0x803BAD000 — outside the [end_kern, topOfKernelData) physmap region
  arm_vm_init maps; the kernel's PE_slide_devicetree landed head on the
  region start and SecureDT panicked "Device tree pointer outside of
  device tree region" (0x…73adec0) inside DTGetProperty("name","arm-io").
  Layout now computed from real sizes; deviceTreeP = blob bootstrap-KVA
  (PA + virtBase − physBase — the identity arm_vm_physmap_slide
  subtracts, verified against arm_vm_init.c:1471-1474).
* **BUG #23 (DT boot-cpu state):** the real n104ap blob ships all 6
  /cpus nodes state="waiting"; iBoot marks the boot core "running"
  before the jump (ml_is_boot_cpu, machine_routines.c:924). Harness now
  patches cpu0 "waiting\0"→"running\0" in-place (8 bytes, nothing else).
* **BUG #24 (CCMP/CCMN decode field swap):** decode read cond@3:0 /
  nzcv@15:12; keystone 4-sample pin: cond is ALWAYS 15:12, nzcv ALWAYS
  3:0, both forms. The real DT-walk `cmp x12,x8; ccmp x13,x8,#0,ls;
  b.lo` branched on correct registers and panicked the boot. Fixed +
  register-form VALUE semantics + 4 goldens; old row FA430822 was
  self-consistent with the swap (capstone: `ccmp x1, #3, #2, eq`).

* **Measured (IOS_RUST_DRAM_MB=1024):** boot-first 8,135,842 →
  **10,921,780 insns**; 22,946 walks / 14,568,119 TLB hits (99.8%);
  **21,270 data-aborts vectored to the kernel's own handler**
  (exc 21270 sync · FIQ 0 · IRQ 0 · WFI 0); terminal stop
  `UnknownInsn 0x0 @ 0xfffffff00816c458` — stop-pc re-walk: stale TLB
  entry → PA 0x80216c458 (correct text PA) reads ZERO; the kernel
  zeroed its own text page during the abort-driven remap storm (open RE
  target, next block). M4 acceptance (WFI-and-resume ≥10M): NOT cleared.
* **M4 infra (M4-B research landed, notes/m4-aic-timer-re.md):** sync
  abort vectoring (VBAR+0x200, ESR/FAR/ELR/SPSR, budget 100k), timer-FIQ
  delivery path, AIC IRQ line, WFI ns-fast-forward, cpu_data[0] scan,
  IOS_RUST_WATCH watchpoint diagnostics. Spec corrections: timer =
  FIQ via CNTV_CTL ISTATUS (NOT IRQ 29 — BOOT-PLAN corrected); CNTFRQ
  never read (24 MHz default); VBAR_EL1 = 0xfffffff008165000;
  machine_idle @0x81699a0; AIC v1 map per pexpert AIC.h.
* `cargo test --workspace`: **394 passed / 0 failed** (IOS_RUST_DRAM_MB=
  768 on the 3 GiB host — the 4 GiB default window OOMs there; knob is
  the honest workaround, unchanged behavior on 4+ GiB hosts).

### 2.12b — Session I (2026-10-30): the text-zeroing root cause + TPIDR seeding + bugs #25/#26

* **Session-H stop ROOT-CAUSED (notes/m4-text-zeroing-re.md, capstone + live
  reproduction): NOT a remap storm, NOT a stale TLB.** The kernel's own
  exception machinery ate its text by STACK OVERFLOW: the DT-pointer panic
  (the same "Device tree pointer outside" string, firing at insn 8,135,397
  since session H) hit `panic_impl`'s percpu deref with TPIDR_EL1=0
  (far=0x4f0 @0x…7a585d0) → the unhandled-exception reporter
  (@0x…81607b8: mrs esr/far → stp x29,x30 → `bl 0x…816c458` — the exact
  session-H stop pc) → the register-dump formatter refaulted
  (`ldr x11,[x10,#0x100]` @0x…816c38c) → 21,270 cycles × 0x4F0 stack
  descent (0x350 iframe + saves + 0x170 formatter frame, never popped)
  walked SP 0x9b0fff0 → through __DATA → PPLTEXT gap → __TEXT_EXEC,
  zeroing ~24 MB — terminal `UnknownInsn 0x0` on fetch of zeroed text.
  Rejected hypotheses (with evidence): PPL stack table 0x98a4180 (read
  only from __PPLTEXT trampoline), poisoned-x6 arithmetic (store log
  proves continuous descent). Doc corrections: session-H "remap storm /
  stale TLB" wording retired; the real VBAR_EL1 vector table is
  0xfffffff008160000 (the 0x…8165000 stub table is `b .` slots).
* **TPIDR_EL1/cpu_data[0] — the honest seed landed:** the kernel's own
  `cpu_data_init` stores intstack_top (0x98e4658) at cpu_data[0]+0x4f8 ⇒
  base 0x9a4aac8 — `discover_cpu_data0` (interp.rs, the guest-bytes
  fingerprint scan) existed but had ZERO call sites (dead code from the
  M4-B timeout). Now called lazily at the first `mrs tpidr_el1` while 0;
  measured live: `cpu_data[0] @ KVA 0xfffffff009a4aac8 · tpidr
  0xfffffff009a4aac8` (+0x4f8 = 0x98e4658, depth 1). The percpu abort
  storm is gone: `panic_impl`'s percpu deref now reads the real cpu_data.
* **Undefined instructions now VECTOR (hardware fidelity):** the kernel
  ships deliberate `0xE7FFDEFF` markers (the ARM GDB trap, 2 file sites
  in the panic path, capstone-verified as undecodable A64). Real
  hardware raises EC=UNCATEGORIZED (ESR 0x0200_0000: EC=0, IL=1, ISS=0 —
  the ISS==0 the vendored xnu sleh.c:694 asserts), and the kernel's
  handle_uncategorized routes it to DebuggerCall/EXC_BAD_INSTRUCTION.
  Model: undecodable word + live VBAR + budget → VBAR+0x200 with that
  ESR; pre-VBAR boot keeps the terminal UnknownInsn stop. 4 goldens
  (vectoring, pre-VBAR terminal, tpidr discovery, recursion latch).
* **Guardrails (named stops instead of silent corruption):**
  `StopReason::ExceptionRecursion` latches at ≥96 IDENTICAL (kind, esr,
  far, elr) re-entries (the measured storm cycled 21,270 times) and at
  any exception entry with SP below the real __TEXT_EXEC base. Measured
  catching at 96 cycles (~12.6k insns) where session H burned 21,270.
* **BUG #25 (DT placeholder lengths):** the IPSW blob ships 87 properties
  whose length word has bit31 SET (regulatory-model-number, serial-number,
  mac-address-*, *-color … — all identity/metadata; data = SysCfg
  REFERENCES like b"syscfg/SrNm/0x20,zeroes/"). iBoot resolves them from
  the SysCfg partition before the kernel sees the tree; the raw kernel DT
  walker (0x…8136fd4) adds the RAW length and its own bounds check
  panicked — THE panic that fired at insn 8,135,397 in every recent run.
  Fix: iBoot-equivalent-without-SysCfg pass on the staged copy
  (`dt_clear_placeholder_flags` — walk consumes the blob EXACTLY, 87
  cleared). Honest limit: the kernel now reads each placeholder's own
  reference BYTES as the value (nothing invented; no SysCfg device
  exists yet).
* **BUG #26 (__DATA BSS not zero-filled):** the harness flat-wrote the
  whole kernel FILE; __DATA's BSS tail (vmsize − filesize = 737,280 B)
  received the NEXT file bytes — the embedded IOCatalogue personalities
  plist text (b"pple.iokit.IOUSBHostFami…") — so the kernel's cursor
  global at BSS 0x…9adf638 read plist ASCII as a POINTER
  (far = 0x696d614674736f48 = "HostFami", measured @ insn 8,148,893
  after bug #25 fell). Fix: iBoot-equivalent per-segment BSS zero-fill
  after staging.
* **Measured (IOS_RUST_DRAM_MB=1024):** boot-first panic-point 8,135,842
  → 8,149,172 (post-#25) → 8,162,237 (87 flags cleared) → **8,194,993
  insns**, `panic() calls: none`, stop =
  `ExceptionRecursion(identical-exception-loop) elr=0x…816c38c far=0x100
  cycles=96` — the formatter refault loop now entered WITHOUT a panic
  via a garbage array-base write: `str w19,[x9]` @0x…7b8cd70, x9 =
  madd(x19,x25,[x24+0x14]) = 0xfffe00ee488b0058 (array object base
  garbage — NEXT BLOCK RE target: the constructor of that object; first
  abort of the run at insn 8,181,649, esr 0x96000050 write + L1
  translation fault). M4 acceptance (WFI-and-resume ≥10M): NOT cleared —
  8.19M < 10M and the stop is not a WFI park.
* AIC v1 (AIC.h map), ADT LE reg + irq_line wiring from the M4-B/M5
  census work committed pre-session (uncommitted-from-timeout batch
  landed here tested: AicTimebase page, t8030 attach classification,
  machine.rs aic-v1 parity 72%).
* `cargo test --workspace`: **403 passed / 0 failed** (IOS_RUST_DRAM_MB=
  768 on the 3 GiB host, honest workaround unchanged).
* **S3 snapshot TAKEN (session I closeout):** the vault had been stale
  at ≤ 1f9ec59 (sessions 6fffd65/8f6c345 unbacked — the mid-session
  credential scare was a transient `ls` miss; ~/.config/ios-rust/s3.env
  is intact). `tools/s3_backup.py snapshot ios-research-vault` uploaded
  390 source files + the full-history git bundle
  (s3://ios-research-vault/research/ios-rust-export/ + ios-rust-repo-backup.bundle)
  through this commit. Pre-existing gap unchanged: /home/z/work/
  ios-re-toolkit + ios-research/research-docs remain missing since the
  earlier sandbox reset (SKIP lines in the snapshot log).

### 2.12c — Session J (2026-10-30): bug #27 BFM family — boot 8.19M → 2,000,000,000 CLEAN insns

* **REAL-DATA BUG #27 (BFM/bfxil width formula):** the interpreter's
  `BfmKind::Bfm` executed `width = bits − imms − 1` with a rotate model —
  correct for NOTHING in the family. The arm_vm_init packed-pointer
  rebase decoder (`lsl x14,x13,#13 → sbfx x15,x13,#0,#43 → bfxil
  x14,x15,#0,#56 → add x14,x22,x14 → add x14,x14,x11(=0x0FF8FFC000)`,
  walker @0x…7b802c0, store @0x…7b80340) decoded the shipped entry
  0x0017fff007724458 into 0xfffe00ee488b0058 instead of
  0xfffffff007724458 (arithmetically proven delta) and STORED it into
  the DT-registry array base (object 0x…772478c field +0x14) — the
  array-push `str w19,[x9]` @0x…7b8cd70 (session I's stop) then faulted
  on its own garbage base. Found via the session-I-planned
  `IOS_RUST_WATCH_VA` store-watch: EXACTLY ONE corrupting write, at
  insn 107,008 — not 8.18M; the value was written once by the kernel's
  own rebase walker very early and used much later.
* **Fix (keystone/capstone truth table, ARM DDI 0487 semantics):**
  imms ≥ immr → extract src[imms:immr], insert at the LSB, all other dst
  bits preserved (bfxil family — capstone renders raw `bfm #4,#10` as
  `bfxil #4,#7`); imms < immr → wrap insert at lsb = bits − immr (bfi
  family). Two siblings fixed on the same evidence: **ubfiz** (Ubfm s<r
  branch had NO field mask — high garbage leaked into the field; for the
  LSL alias the mask is provably a no-op) and **sbfiz** (Sbfm s<r branch
  used a rotate model that picks up the wrapped high bits the alias
  discards — now sign-extend-then-shift). 6 goldens including the
  verbatim decode pipeline pinning x14 = 0xfffffff007724458.
* **Staged layout end_kern = the kernel's own VA span (bug #22
  follow-up):** end_kern = round_16K(max(vmaddr+vmsize)) =
  0xFFFFFFF0_09C60000 (the kernel's own `end_kern` writer @0x…7b83758 —
  RE-confirmed), NOT round_page(file bytes) — the VA span ends 0xB3000
  above the file-backed end, so the file-size staging put the DT blob
  BELOW end_kern and the physmap tail entry e[DT].len wrapped negative.
  All staging rounding is 16K (ARM64 xnu page size): dt_pa 0x803C60000 ·
  boot_args 0x803C98000 · topOfKernelData 0x803C9C000. Measured: the
  rebase now lands deviceTreeP on the REAL blob — SecureDTInit's node
  table builds with real 0x9c6xxxx KVAs (stack-write log).
* **Measured (IOS_RUST_DRAM_MB=1024, release build):** boot-first
  8,194,993 → 48,000,000 (budget stop, clean) → **2,000,000,000 insns
  retired · stop=Budget · clean · panic() 0 · sync aborts 0 · exceptions
  0 · bus unmapped 0/0** — the real kernel runs 2 GIGA instructions
  without a single fault. M4 gate: the **≥10M clause cleared 244×**;
  the WFI-and-resume clause NOT yet exercised (0 WFI in 2G insns).
* **NEW STOP CLASS (bug #28, next block's RE target):** the 2G budget
  stop is a diverging **Euclid GCD loop** @0x…7b92d68-78
  (`mov x11,x12; udiv x12,x10,x12; msub x12,x12,x11,x10; mov x10,x11;
  cbnz x12`), called from arm_vm_init (lr 0x…7b80a30): the operand pair
  is (24,000,000 — the timebase — and 2⁶⁴−24,000,000, i.e. a
  SIGNED-NEGATIVE value read as unsigned). Unsigned-udiv Euclid on a
  negative operand never terminates (the residue stays wrapped). An
  upstream clock-frequency derivation yields the wrapped value —
  candidate link to bug #25's unresolved placeholders (clock fields
  reading reference bytes). RE next: gcd args' provenance at the
  0x…7b80a30 call site.
* `cargo test --workspace`: **406 passed / 0 failed** (IOS_RUST_DRAM_MB=
  768; +3 goldens over session I's 403). Report improvement: the
  cpu_data[0] line now prints tpidr_el1 even when the scan never ran
  (the kernel sets TPIDR itself — 0 aborts through 2G insns).

### 2.12d — Session K (2026-10-30): bugs #28+#29+#30+#31 — four engine-semantics bugs in one block

* **REAL-DATA BUG #28 (MSUB subtract operand order) — the gcd loop
  RESOLVED:** the interpreter computed `Xn·Xm − Xa` where the ARM spec
  (C6.2.349) says `MSUB Xd,Xn,Xm,Xa → Xd = Xa − Xn·Xm`. MADD hid the flip
  for every other site (addition commutes); the kernel's Euclid remainder
  step `mov x11,x12; udiv x12,x10,x12; msub x12,x12,x11,x10` (verbatim
  words 0xAA0C03EB/0x9ACC094C/0x9B0BA98C @0x…7b92d68-70, keystone
  round-trip) requires `r = a − q·b ∈ [0,b)`; the flipped form returned
  `2⁶⁴−(a mod b)` — "the residue stays wrapped", exactly session J's
  observation. The helper @0x…7b92d20 is xnu's timebase-ratio
  computation: `{clock=24e6 (pexpert default), divisor=1}` →
  gcd(1e9, 24e6)=8e6 → ratio 125/3, Hz 24e6, kHz 24000 stored to
  0x…98e4658. Two latent W-form defects fixed on the same path: the
  addend was not masked to 32 bits and the result not truncated/
  zero-extended; `Insn::MaddW` (umsubl/smsubl) had the same flipped
  subtract. 6 goldens incl. the verbatim kernel sequence (1e9,24e6 →
  16e6).
* **REAL-DATA BUG #29 (MUL = MADD with Ra=31 → XZR, never SP):** with
  the gcd fixed the boot advanced to `vm_mem_bootstrap` and panicked
  **"Section __BOOTDATA,__init_entry_set has invalid size"** (insn
  8,255,200, lr 0x…7a8cf18, fmt @0x…735c26a). The check is a static
  divide-by-6 multiply-magic idiom on the section size 0x2640
  (`mul x9,x8,x9; ror x9,x9,#3; cmp; b.hs` @0x…7a8ce6c-84 — 0x2640 IS
  divisible by 6, real HW passes). Our MADD read the addend with the SP
  rule: every `mul` computed product + SP (SP was the boot stack inside
  __BOOTDATA!) → rotated product huge → b.hs → panic. Keystone proof:
  `mul x9,x8,x9` ≡ `madd x9,x8,x9,xzr` = 0x9B097D09, and the `sp`
  spellings DO NOT ASSEMBLE (`madd x0,x1,x2,sp`, `madd sp,x1,x2,x3`,
  `umaddl sp,w1,w2,sp` all KS-FAIL) — dp3 Rd/Ra are XZR-only. Fixed
  Ra=31 read (ZR) + Rd=31 discard (the old set_rsp(31) wrote SP).
* **REAL-DATA BUG #30 (authenticated branches must strip to CANONICAL):**
  next stop: fetch abort at **0x402fff007a8d060** (ESR 0x92000010) — the
  model pac() tag 0x402f at bits 63:48 of the callback pointer
  `pacia x16,x17(0xe4fe)` @0x…7a8cea0, dispatched by `blraa x27, x26`
  (0xD73F0B7A verbatim @0x…7f2f658, capstone) which our BrAuth jumped
  RAW. Fix: `crypto::canonical()` (sign-extend bit 47 → kernel VAs
  restore the 0xFFFF top), applied to aut(), RetA and BrAuth; plus pac()
  now signs the 48-bit VA only (aut's re-derivation never matched
  kernel pointers before). Goldens: the verbatim blraa word, retab,
  pac→aut round-trip.
* **REAL-DATA BUG #31 (add/sub register forms: Rn=31 reads SP):** next
  the exception-stack GUARD in the vector page
  (`cmp sp,x18; b.gt .; sub x18,#0x4000; cmp sp,x18; b.lt .`
  @0x…8160400, x18 = *([tpidr+0x4f8]+0x28) = 0x…9b18000) spun for the
  rest of a 2G run: `cmp sp, x18` (0xEB3263FF = the add/sub EXTENDED
  form, option LSL#0 — capstone) read Rn=31 as ZR → compared 0 vs the
  bound → nzcv=0000 → b.gt taken forever. ARM rule: in add/sub register
  forms (shifted AND extended, S=0 AND S=1) **Rn=31 is SP**; only Rd
  differs (S=0 → SP, S=1 → ZR). Fixed CmpReg/CmnReg/CmpImm/CmnImm/
  AddSubReg/AddSubExt (`a = rsp(rn)` always) + the immediate setflags
  path now discards Rd=31 (the bug #10 class in `cmp sp,#imm`).
  Goldens: verbatim guard prologue, in-window fall-through, shifted and
  immediate SP compares, `add sp,sp,x18`.
* **Measured (release build, IOS_RUST_DRAM_MB=1024):** boot 8.19M →
  panic-free through `vm_mem_bootstrap` callbacks (`__init_entry_set`
  constructors dispatched via pacia'd pointers + blraa), the one
  delivered exception = a physmap load translation fault (FAR
  0xffffffe013611fb0, ESR 0x96000005) which the kernel HANDLES
  (exception delivered 1, panic 0, bus unmapped 0/0). New diagnostics:
  `IOS_RUST_STOP_PC_RANGE=lo,hi` (stop on pc entering a range — catches
  entry paths instead of spin-filled rings), `IOS_RUST_TRACE_DEEP`
  (2048-deep trace ring + report), guard-chain dump in the cpu_data
  report.
* **NEW STOP CLASS (bug #32, next block's RE target):** after the
  handled physmap abort the kernel's exception-return ERETs to a
  CORRUPTED ELR — **0x00FFFFF00815F200** (bits 63:56 = 0x00, bits
  55:48 = 0xFF) instead of 0xFFFFFFF00815F200 — lands on
  `b 0x…81601d8` → `b guard` → spins. Some instruction in the C sleh
  path still mis-models a top-half operation (0x00FF/0xFFFF pattern —
  candidate: a BFM/extr/ror-family or MOVK-width bug). Trace-capture
  tooling is in place; RE next: the sleh dispatcher's return-value
  computation for the handled-abort path.
* `cargo test --workspace`: **425 passed / 0 failed** (+19 over session
  J's 406). RE notes: `tools/re/notes/m4-gcd-clock-re.md` (+ companion
  script `tools/re/reports/m4_gcd_clock.py`).

### 2.12e — Session N (2026-10-30): M5 census + B1 bus rule + PMGR 44-window + dockchannel/dapf

* **First live device census at the session-M frontier (M5 task 1):** the real
  18C66 boot path touches exactly **17 device-MMIO accesses through 48M insns**,
  all named after this session: dockchannel-uart w1 FIFO page 0x23D10C000
  (8 hits — previously the tree's ONLY UNMAPPED window), uart0 console init
  0x235200000 (9). A 400M-insn extension (`IOS_RUST_BOOT_FIRST_MAX_INSN`, new
  env knob, default unchanged) measured **0 further device touches** — the
  48M→400M stretch loops inside M4's open percpu wall (FAR 0x10c handled
  abort, panic 0, bus unmapped 0/0, WFI 0). Verdict: M5 device modeling is
  AHEAD of the boot path; the next ledger move is M4's bug #33 GXF-write half.
* **B1 bus rule** (vm-core `Bus::find`): overlapping windows resolve
  smallest-matching-wins, tie → last attached — the real ADT nests device
  pages inside larger windows and the old lowest-base-first rule shadowed
  them forever (pmgr w22 ⊃ dockchannel+pmp, mca-switch ⊃ mca0/1, SEPROM ⊃
  dart-sep).
* **PMGR 44-window** (`apple-soc/src/pmgr.rs` rewritten): PmgrCore +
  44 PmgrWindow boxes, concatenated linear offsets (the measured
  AppleT8030PMGR addressing), APSC 0xE2020/0xE2588 PS-mirror reads
  (default 0xFF ACTIVE), gate reads 0x80000+id*0x18 (stride-unconfirmed,
  degrades to always-powered), ADT clock-gates seeding, scratch elsewhere.
* **dockchannel-uart** (`apple-soc/src/dockchannel.rs`): replaced the
  s3c-uart mis-model with a 2-window shared-core scratch shim + dedicated TX
  sink (never the console). Reads echo stored config — the census PROVED
  write-then-readback touching before the spec's RAZ assumption was written.
* **dapf** (`apple-soc/src/dapf.rs`): dapf-disp0/dapf-aop out of the
  adp-v4/aop mis-models; TCR store/bypass, rest RAZ. Per-window exact sizes
  replace the blanket 0x1000 rounding; dead dart-ans arm deleted; new
  `ios-rust adt windows|find` diagnostic subcommand.
* Modeled windows: 59 → **103** (44 pmgr + dockchannel×2 + dapf×2); census
  at the current frontier: **17/17 named, 0 UNMAPPED, 0/0 unmapped counters**.
  Honest: M5 acceptance (NVMe rootfs bytes) still untested — ANS/SART/SMC
  sit behind the M4 wall; specs staged in m5-attach-spec §5.4-5.6.
* `cargo test --workspace`: **434 passed / 0 failed**. Docs: BOOT-PLAN M5
  session-N block.

### 2.13 — Session O (2026-10-30): REAL-DATA BUG #39 — the CCMP/SBCS decoder collision that WAS the percpu wall

* **The wall, finally named and killed.** Session M's "kernel-HANDLED load abort
  FAR 0x10c @ELR 0x…7b1e150 + the 48M→400M spin" is now fully explained end to
  end: (a) new first-abort FP-chain diagnostic (guest-read walk of the x29
  chain at vector entry, report-only) named the path:
  `vm_map_store_entry_unlink(map, entry)` ← `vm_map_store_coalesce` ←
  lookup-and-coalesce ← `vm_map_wire`-ish page-wiring loop ← kernel_map-views
  table load ← zone-bootstrap zinit callbacks ← `kernel_bootstrap` stage
  walker — the classic waitq/zone early-bootstrap vm_map churn; (b) the
  unlink got `map=NULL` because the coalesce fn's X0 was zeroed MID-FUNCTION;
  (c) per-instruction PC watches pinned the zeroing to the instruction at
  0x…7b0b598; (d) capstone vs engine decode of the verbatim word
  **0xFA4E0160 = `ccmp x11, x14, #0, eq`**: our ADC/ADCS/SBC/SBCS arm
  checked bit23 but NOT bit22 — and with cond=eq (bits[15:12]=0000),
  bits[11:10]=00 and nzcv=0, the CCMP word ALSO fits the SBCS shape
  (bits[15:10]=000000, Rd-slot=nzcv=0) → decoded as `sbcs x0, x11, x14` →
  **X0 = 0 mid-function** → unlink(NULL) → the FAR 0x10c abort → the
  exception-prologue stack-guard self-spin at 0x…8160410 that burned the
  budget. Capstone cross-check (keystone set re-run): CCMP family has
  bits[28:21]=110100**1**0 (bit22=1); ADC family 110100**00**.
* **Fix (a13-cpu/src/decode.rs):** the ADC arm now requires bits[23:21]==000
  (bit22+bit21 added); the CSEL arm pins bit21==0; the CCMP arm pins
  bit22==1 && bit21==0. The invalid-encoding word 0xFA8E2C00 now decodes to
  None — capstone-confirmed invalid.
* **Measured frontier move:** 48M run went from "1 kernel-HANDLED abort +
  48M 'clean'" to **0 sync aborts, 0 panics, 48M clean**; the 400M extension
  no longer loops — the kernel now runs into **its OWN panic at insn
  22,505,463**: `kernel_memory_allocate() failed to alloc global_waitqs`
  (fmt 0x…735e028 read from the image; whsize 0x4000; the panic wrapper at
  0x…987b99c called from 0x…7ab6f30). The waitq-bootstrap allocation inside
  kernel_map fails → next block's RE target is the vm_map_find_space /
  hole-state modeling in kernel_map. Panic count at 400M: 1 (the
  global_waitqs one); the post-panic spin (0x…8160410 prologue guard) is the
  panic path's own exception loop, no longer a silent wall.
* **New diagnostics (kept, env-gated, report-only):** first-abort FP chain +
  per-frame saved-x19/x20 window in the boot-real report (M5-O); nothing in
  the hot loop changed semantics.
* **Goldens (+3, goldens_m4):** `gap39_ccmp_reg_eq_decodes_as_ccmp`,
  `gap39_adc_family_keystones_unchanged` (1A020020/3A020020/5A020020/
  BA020020/DA020020), `gap39_kernel_ccmp_never_writes_gprs` (both nzcv
  outcomes leave X0..X30 frozen).
* `cargo test --workspace`: **437 passed / 0 failed**. Docs: BOOT-PLAN M5
  session-O block; tools/re/notes/m5-session-O-percpu-wall.md.

### 2.14 — Session P (2026-10-30): THREE real-data bugs — the waitqs wall was OUR W-form arithmetic, the DT lock-regs stub, and PSTATE.PAN — boot frontier 22.5M-panic → 155M FIPS POST

**Method note:** every bug below carries its measured number from the live
boot (release build, IOS_RUST_DRAM_MB=1024, panic wrapper probe 0x…987b99c
+ capstone cross-check of verbatim kernel bytes; oracle scripts in
tools/re/reports/m5p_*.py).

* **REAL-DATA BUG #40 — W-form add/sub + logical-register upper-half leak
  (the global_waitqs wall root).** waitq_bootstrp's whsize arithmetic
  (verbatim words 0x128004E9 `mov w9,#-0x28`, 0x1B097D08 `mul w8,w8,w9`,
  0x12124508 `and w8,w8,#0xffffc000`, **0x4B0803F3 `neg w19,w8`**,
  0x…7ab6d68..0x…7ab6d74) ran the 64-bit SUB 0 − 0x00000000FFFFC000 =
  **x19 = 0xffffffff00004000** with CLEAN inputs (W-form must zero-extend:
  x19 = 0x4000). That size to kernel_memory_allocate trips vm_kern.c's
  wired-extent check (map_size > MAX(1<<31, sane_size/64)) →
  KERN_RESOURCE_SHORTAGE → the kernel's OWN panic "kernel_memory_allocate()
  failed to alloc global_waitqs" at insn 22,505,463. The same class leaked
  in AddImm/SubImm (operand read + result), AddSubReg (Rn read + result;
  Rm was already masked via shift()), and LogicReg (ORR/EOR/BIC/EON via
  unmasked Rn — AND was safe by accident: result ⊆ masked Rm). Bug #38
  fixed only the IMMEDIATE logical forms.
  *Fix:* mask operands & zero-extend results in all four arms
  (a13-cpu/src/interp.rs). *Goldens (+4):* gap40_neg_wform_zero_extends
  (verbatim 0x4B0803F3), gap40_waitq_whsize_chain_verbatim (the 4-insn
  chain, x8=256 → x19=0x4000), gap40_addsub_imm_wform_masks_operand_and_
  result, gap40_logic_reg_wform_zero_extends.
* **REAL-DATA BUG #41 — /chosen/lock-regs aperture stub (iBoot job).** With
  waitqs fixed the boot advanced 182,713 insns to the kernel's OWN panic
  "lock-regs: cannot find required property 'aperture-count'" at insn
  22,688,176 (fmt 0x…736724f, x1='aperture-count' 0x…7367220). RE: the
  parser (0x…7b7c390, caller 0x…7b7c0a0) requires /chosen/lock-regs/amcc:
  aperture-count(<17,u32), aperture-size(u32≠0), plane-count(<17),
  plane-stride, aperture-phys-addr(count×8, ≤0x80), cache-status-reg-
  offset/mask/value; amcc-ctrr-a: page-size-shift + lower-limit/upper-
  limit/lock/enable/disable-reg-offset/mask/value. The IPSW EDT ships the
  node stub-EMPTY (name + AAPL,phandle only — `ios-rust adt dump`, new
  diagnostic subcommand). *Fix (iBoot-equivalent, honest):*
  dt_populate_amcc_lockregs stages 1×16KB aperture @ DRAM midpoint
  (RAM-backed, self-consistent), page-size-shift 14 (T8030 16K pages), reg
  locks 0 (the kernel's consistency check trivially passes at count=1);
  22 props staged. Real iBoot AMCC geometry stays a documented gap.
* **REAL-DATA BUG #42 — PSTATE.PAN unsupported (+ the SPSel mask
  misdecode).** machine_switch_context's helper (0x…7b91904) does
  `mrs x8, pan` (0xD5384268) then `cbz → panic "context switch with PAN
  disabled"` at insn 23,684,722 — the scheduler was RUNNING, our PSTATE had
  no PAN. 95 `msr pan, #0/#1` sites (0xD500409F/0xD500419F) were dropped,
  AND the SPSel-immediate mask (0xFFFFC01F, no op2 pin) silently decoded
  PAN words as SPSel. *Fix:* MsrPan/MrsPan insns, `pan` bit tracked, SPSR
  bit 23 saved on exception entry + restored on ERET; SPSel arm pins op2==5.
  Access GATING (PAN=1 blocking user-page accesses) is NOT enforced —
  honest limit. *Goldens (+3):* gap42_pan_decode_from_kernel_bytes,
  gap42_pan_msr_mrs_roundtrip, gap42_pan_spsr_save_restore.
* **Measured frontier move:** 22.5M waitqs-panic → 48M CLEAN budget stop
  (0 panics, 0 sync aborts) → 400M: the kernel runs zone/scheduler
  bring-up, lock-regs, and corecrypto_kext_start and reaches **its own FIPS
  Kernel POST Failed (%d) at insn 155,032,147** (err −1075 = 0xfffffbcd
  via the 0x…82e2b58 → 0x…82e8670 landing).
* **Bug #43 (OPEN, next block):** the failure decomposes to
  fipspost_post (0x…829fb3c) → fipspost_post_hmac (0x…82a4ce0) vector 0:
  the 20-byte HMAC-SHA1 KAT memcmp (0x…7b85714 at 0x…82a4e00, len 0x14)
  compares computed 491327a2e130799174899c2f7a9cbef2002b9571 vs expected
  886eae70f36bd3805eeb1274b3248fccf5e15b80 (stop-memdump diagnostic,
  IOS_RUST_STOP_PC_RANGE=0x…82a4e00 IOS_RUST_STOP_DUMP_MEM=1). The SHA1
  crypto-instruction VALUE semantics (sha1c/p/m 4-round-group + Vn
  writeback, sha1su0/su1 schedule) were never oracle-verified — goldens
  are decode-level only (crates/a13-cpu/src/crypto.rs has no SHA1 reference
  unlike AES/SHA512). Next: reconstruct the pipeline against a real oracle
  and re-verify the KAT.
* **New diagnostics (env-gated, report-only):** `ios-rust adt dump`
  (full node/property tree), MMIO log now records the VALUE per access
  (console-reconstruction aid), stop-memdump (x0/x1/x2 0x40-byte guest
  dumps at IOS_RUST_STOP_PC_RANGE hits).
* `cargo test --workspace`: **444 passed / 0 failed** (+7 gap40/gap42
  goldens; DRAM_MB=768 documented). Docs: BOOT-PLAN M5 session-P block;
  tools/re/notes/m5-session-P-blocks.md.

### 2.15 — Session Q (2026-10-30): BUG #43 CLOSED — the SHA crypto VALUE semantics rebuilt against three independent oracles

The session-P "next block" is done: every ARMv8 SHA crypto instruction was
rebuilt from ground truth and verified three independent ways — **QEMU
`target/arm/tcg/crypto_helper.c` (verbatim port)**, the **ARM A64 ISA
pseudocode** (DDI 0602 SHA1C's 160-bit `<y,x> = ROL(…, 32)` fold; SHA256H2's
operand swap `SHA256hash(V[n], V[d], …, FALSE)`), and **end-to-end digest
reproduction** (tools/re/oracle/derive_sha1_arm.py v2: the instruction
models reproduce `hashlib.sha1` and `hashlib.sha256` exactly under the real
Linux/OpenSSL caller choreography, verified 4/4 vectors each) — plus the
Linux `sha1-ce-core.S`/`sha2-ce-core.S` asm as the usage reference.

What was actually wrong (all of it "decode-verified, never value-verified"
since session D):

* **sha1c/p/m:** ran ONE round off Vm lane 0 with a `ror(a,2)` fold and
  packed the result one lane up. Reality: FOUR rounds consuming Vm lanes
  0..3, E arrives as the SCALAR `Vn.S[0]` (Vn is never written back), the
  round is `T = f(B,C,D) + ROTL(A,5) + E + W`, and the state rotates
  `(A,B,C,D,E) → (T, A, ROR(B,2), C, D)`. The discarded 5th word is exactly
  `sha1h(state-as-it-entered-the-group)` — which is how the kernel's
  sha1h ping-pong maintains E across groups.
* **sha1su1:** was a 3-term XOR with rotations; reality is 2-term ROL(1)
  where lane 3 folds in the ALREADY-UPDATED lane 0 (W[t] feeds W[t+3]).
* **sha1su0:** was per-lane XOR with a rotated Vn; reality works on 64-bit
  halves (`new_lo = hi(d)^lo(d)^lo(m)`, `new_hi = lo(n)^hi(d)^hi(m)`).
* **sha256h/h2:** ran TWO rounds on half of Vm and wrote BOTH Vd and Vn.
  Reality: each runs FOUR rounds on all of Vm and writes ONLY Vd; h2
  rebuilds the new e..h as `orig_abcd.lane[3-i] + T1_i` from the ORIGINAL
  a..d — which is why the kernel does `mov dg2v.16b, dg0v.16b` before the
  pair (confirmed by executing the Linux choreography through our engine).
* **sha256su0:** missed the wraparound `d3 += s0(m0)` term entirely.
* **sha256su1:** wrong operand lanes and no sequential terms (lane 2 uses
  the NEW lane 0, lane 3 the NEW lane 1).
* **sha1h:** left stale upper lanes; a scalar S-register write
  zero-extends.

Tests: the interpreter now computes the **real SHA-1("abc") digest
(a9993e36…d89d) end-to-end through actual sha1c/p/m/h + su0/su1 instruction
words** (20 four-round groups, K pre-added via vector ADD, Linux-style E
ping-pong, rotating su0/su1 schedule), a two-group sha256h/h2 pipeline
golden, and ten per-instruction value goldens.
`cargo test --workspace`: **448 passed / 0 failed** (+4).

Session-R next block: re-run the real boot (release build,
IOS_RUST_DRAM_MB=1024) — with #43 closed the kernel's FIPS POST HMAC-SHA1
KAT vector 0 should now match `886eae70…` and the frontier moves past
155,032,147; re-census MMIO at the new frontier (PMGR/AIC/WDT/SART/ANS
touches are expected once the scheduler actually runs).

### Session Q addendum — first live-CI exposure of the real-bytes fixtures gate

With GitHub push restored, the `fixtures` workflow ran for the first time
since the vault-only era (run 41149530459, 2026-10-31): the fetch job
pulled real T8030 IPSW ranges + a LIVE TSS ticket from Apple successfully,
and the suite ran against the real bytes.

* **Bug #44 (OPEN, upstream data drift):** `authinstall` real-TSS gate
  failed at real_tss.rs:77 — the live `ApImg4Ticket` DER (10619 B,
  @ServerVersion 2.1.0, magic "IM4M" present in the bytes) now parses with
  **member[0] tag 0x16 (PrintableString)** where `im4m::parse` requires
  OCTET STRING "IM4M" (0x04). Either Apple's TSS envelope changed or the
  captured member is nested differently. Fix belongs to the next session:
  re-derive the envelope from the captured fixture (the run artifact holds
  `real-tss-A17Pro.im4m`, 14509 B), then adjust the DER walk + goldens.
  Not related to the SHA fix (authinstall untouched by session Q).
* Everything else in the real-bytes run passed up to that test; the
  plain `ci` workflow is green on main at e979193.

### Session R (2026-10-31) — the re-run that was never done: TWO more engine bugs, FIPS POST frontier moves twice

The session-Q closeout said "re-run the real boot" — this session did, on
freshly fetched **18C66 (iOS 14.3) fixtures** (the boot's actual pinned
build; fetch_fixtures.py's 13.7 URL serves the *test-suite* fixtures — the
13.7 EDT ships no /chosen/lock-regs at all, which is what the earlier
"lock-regs node not found" stop actually was; `boot-real` now honors its
[fixtures-dir] CLI arg instead of silently ignoring it).

* **REAL-DATA BUG #46 (fixed):** `ld1/st1` multiple-structures used the
  LD4-interleaved layout for ALL op4 values. op4 {2,6,7,A} are LD1/ST1 —
  each register copies one CONTIGUOUS structure. The wrong layout was
  lossless across st1/ld1 spill round-trips (why 155M insns of kernel NEON
  survived) but corrupted every layout consumer: the kernel's SHA-1 vng
  `ld1 {v0..v3}, [x2], #64` fed the schedule v0=W[0,16,32,48]… and the
  FIPS POST HMAC-SHA1 KAT computed 6c829016… instead of 886eae70….
  Isolated by a per-insn step dump; fixed; repro
  `tests/fips_hmac_kat.rs` runs the kernel's OWN SHA-1 vng compress bytes
  (0x82c16f0..0x82c1b64) with the real KAT key/message — all 4 inner + 2
  outer chaining states now match the reference.
* **REAL-DATA BUG #47 (fixed):** AESE/AESD ran keyless — the interpreter
  read the state from Vn (the round key!) and passed key=0, dropping the
  `EOR Vn` that is part of the instruction (ARM DDI 0487 / QEMU
  crypto_aese). Every kernel AES round ran keyless → the AES-XTS early
  PRNG emitted ONE constant 16-byte block → read_random's stuck-output
  health test (cc_constant_time_equal at 0x82d48cc) → CCERR_OUT_OF_ENTROPY
  (−10) → "corecrypto kext RNG initialization failure". Fixed; FIPS-197
  C.1 verified three ways (unit test with the ARM-feed schedule — middle
  round keys pre-InvMixColumns'd — the new engine test
  `tests/aes_vaes_kat.rs` through real AESE/AESMC/EOR words, and the
  parity aes_exec golden on a zero key).
* **BUG #45 (fixed):** a dead experimental mask in LdStMult
  (`0xFu128 << r*64 << …`) overflow-panicked debug builds on every 4-reg
  LD1 — removed.
* **Frontier (measured):** FIPS POST HMAC-SHA1 vector 0 now MATCHES
  (stop-memdump at the memcmp: computed == expected 886eae70…), the RNG
  init passes, and the boot advances to insn **155,053,017** where
  fipspost_post returns −1075 for a LATER vector: **HMAC-SHA-512**.
* **BUG #48 (OPEN):** the 18C66 kernel has NO vng SHA-512 (10
  sha512-family words in the whole image → portable C), which computes
  4d14f3ea1ae4df05… vs expected 5705bfd5854b7cc3…b8c3. All RE data
  gathered: key 110 B @0x73c34bc, msg 128 B @0x73c352b, expected digest
  @0x73c35ac (python hmac reproduces the tag), sha512 di struct
  @0x77c2ed0 (0x40 B: {out=64, state=64, block=128, 11, ?, IV@0x7051cf8,
  init≈0x82e3774, final≈0x82de00c — PAC'd in running memory), K tables
  @0x7051690/0x7052640 with NO direct ADRP (chained-fixup GOT), and the
  memcmp fail branch at 0x82a4e2c catches the vector with
  IOS_RUST_STOP_PC_RANGE. Next: locate the portable-C compress (GOT walk
  or cchmac-call repro like fips_hmac_kat.rs), run it with the extracted
  key/msg, and bisect the first wrong instruction — the same
  decode-verified-but-never-value-verified class as #43/#46/#47.
* Diagnostics: stop-memdump extended (sp/sp+0x20 frame dump + x19 at
  0x80 B), per-insn step-dump test (ignored) kept as a tool.
* `cargo test --workspace`: **451 passed / 0 failed** (+1 AES KAT, +2
  SHA-1 KAT repro, +1 step-dump ignored tool).

### Session R part 3 (2026-10-31, same session) — #48 closed as REAL-DATA BUG #49; POST now passes every HMAC vector

* **#49 (fixed):** SIMD EXT built `(Rm.low8 : Rn.low8)` — operands
  swapped and only 8 bytes of each operand; every `.16b` EXT with index
  ≥ 8 zeroed its high half. The kernel's SHA-512 schedule
  `ext v18.16b, v4.16b, v5.16b, #8` read (W8, 0) instead of (W9, W10).
  Fixed to `result.B[i] = (Vn:Vm).B[i+imm4]` (Vn first, full width).
  Repro chain: fips_sha512_kat.rs (the kernel's own NEON-generic
  SHA-512 compress, 0x82e67f0..0x82e7c84, K @0x7052640) + step dump +
  fips_ext_micro (which also caught the byte-offset slip in the first
  fix attempt).
* AES-128 decrypt through real AESD/AESIMC/EOR words verified (FIPS-197
  C.1 inverse; plain rk_r decrypt feed — asymmetry with encrypt's
  aesimc(rk_r) documented in the test).
* **Frontier: 155,673,736** — fipspost_post −4075 (test 4, ≈ aes_ecb);
  the KAT memcmp loop completes with zero failures (all HMAC vectors
  pass: SHA-1, SHA-256, SHA-512, …). BUG #50 OPEN — the AES round
  instructions are verified; the miss is in the ECB glue / key-schedule
  expansion / KAT plumbing. Engine smoke frontier now three walls past
  session Q.
* `cargo test --workspace`: **455 passed / 0 failed**.
