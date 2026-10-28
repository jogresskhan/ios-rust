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

## Layer 3 — CPU execution (the big one)

| item | % | note |
|---|---|---|
| TCG-in-Rust AArch64 exec loop | **0** | contract defined (`virt::CpuBackend`); biggest ledger item |
| instruction decode: AES/PMULL, CRC32, LSE | 0 | first targets (restore path uses them) |
| FP16 / DOTPROD / RDM / FCMA / JSCVT | 0 | |
| PAC / BTI / AMUv1 / TLBI-range / FCADD | 0 | guest kernels run PAC-off variants in the lane |
| SEP real-firmware core + SEP-SIM | 0 | Inferno's superpower; port after CPU exec |
| PMGR / AOP / SMC / AES engine / PCIe / USB-OTG / touch / audio | 0 | next device wave |

## Layer 4 — the flow

| gate | status |
|---|---|
| G1 restore-ramdisk boot (C engine lane) | ✅ proven (run #74) |
| G2 ASR/invert stage | ⛔ frontier (diag refocused, 2156ae0) — host ASR stack now in-tree (`asr.rs`) to drive it from Rust |
| G3 install → launchd on restored APFS | pending G2 |
| G4 homescreen via ios-rust engine | pending G3 + CPU exec |


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
