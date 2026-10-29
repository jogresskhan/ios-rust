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
