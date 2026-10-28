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
| G2 ASR/invert stage | ⛔ frontier (diag refocused, 2156ae0) |
| G3 install → launchd on restored APFS | pending G2 |
| G4 homescreen via ios-rust engine | pending G3 + CPU exec |

**Workspace model parity (average of ledger rows, honest): ~56%** — up from 0
at workspace creation; every row above carries its gate so "100%" is a checklist,
not a slogan. Update this file with every verdict (same discipline as the
ios-sweet-rust ledger).
