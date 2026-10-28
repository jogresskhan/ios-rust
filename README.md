# ios-rust

**One Rust workspace. One binary. The QEMU-binary replacement for the T8030
iPhone boot/restore flow — with an honest 100%-parity ledger.**

```
SoC:     Apple T8030 (A13 Bionic)          machine:  apple-t8030
CPU:     apple-a13 (Lightning×2 + Thunder×4, ARMv8.4-A, AArch64-only)
Goal:    1 IPSW → launch GUI emulator → restore → install → boot homescreen
Status:  foundation live (libqemuutil port, SoC/devices/IPSW/vault) — CPU
         execution (TCG-in-Rust) is the largest open ledger item, reported
         honestly instead of faked.
```

## The single binary

```bash
ios-rust run -M apple-t8030 -kernel kernelcache.im4p -dtb adt.img4 \
             -serial file:console.log -drive file=rootfs.dmg,format=raw
ios-rust restore <ipsw>      # IM4P/BuildManifest parse + ramdisk variant matrix
ios-rust boot <ipsw>         # fetch → restore → install → homescreen ladder
ios-rust parity              # live parity ledger (% per component)
ios-rust vault list|get|put|usage   # research-S3 integration
ios-rust selftest            # release invariants
```

`run` accepts the qemu-system-a64 flag subset the restore lanes actually use
(`-M`, `-cpu`, `-kernel`, `-dtb`, `-append`, `-serial`, `-drive`, `-nographic`;
unknown flags are accepted-and-ignored so existing lane scripts keep working).

## Workspace layout

| crate | replaces / implements | state |
|---|---|---|
| `qemu-util` | **libqemuutil** (bitops.h, iov.c, fifo8.c, qemu/queue.h, error.c) | ported + tested |
| `soc-t8030` | SoC definition: T8030, apple-a13, ARMv8.4-A instruction table, memmap landmarks | defined + tested |
| `devices` | Inferno/QEMU device objects in Rust: AIC v2, DART (4-level PTE walker), ADP v4 DisplayPipe (frame contract), Synopsys MIPI-DSI (real GEN_HDR layout + FIFO), ANS2/NVMe queue skeleton, UART console, WDT | structural ports + tests |
| `virt` | the machine + QEMU-flag-compatible CLI + exec-loop contract (`CpuBackend`) | CLI/bus real; TCG stub honest |
| `ipsw` | IM4P containers, BuildManifest.plist reader, **the 8-variant ramdisk bisection as library code** (incl. run #74 verdicts), ranged HTTP fetch | working + tested |
| `vault` | client for the research S3 vault (`research-vault-rs` service): list/get(sha256-verified)/put/usage | working |
| `ios-rust` | **the one binary** wiring all of the above | built |

## CPU instruction parity (named, as required)

T8030 = A13 Bionic, ARMv8.4-A. The virtual CPU must cover (tracked per-group
in `soc_t8030::CPU_INSTRUCTIONS`): **LSE atomics, RDM, FCMA, JSCVT, FP16,
ASIMD RDM, DOTPROD (SDOT/UDOT), SHA512, SHA3, SM3/SM4, AES/PMULL, CRC32,
PAC (v8.3 pointer auth), BTI, CSV2/CSV3, AMUv1, MPAM id regs, TLBI RANGE,
DGH/DOT, FCADD**. None are decoded by the Rust backend yet (0% each, honest);
the C engine (ChefKiss Inferno QEMU fork) remains the executor meanwhile.

## The goal ladder (IPSW → homescreen)

1. **G1 restore-ramdisk boot** — proven in the C-engine lane (run #74: stock
   ramdisk passes `verify_storage_for_update` and pushes the full 5 GB rootfs).
2. **G2 ASR/invert stage** — current frontier (v1-full/v5-convert die at
   `0x065B asr_and_invert_image`; diag refocused, one dispatch from verdict).
3. **G3 install → launchd** — pending G2.
4. **G4 SpringBoard/homescreen** — pending G3; the ios-sweet path already
   proves CPU-rendered home screens at 20–30 fps on real hardware.

`ios-rust boot` reports each gate's honest state instead of pretending.

## Research S3 integration

Env: `RV_URL` + `RV_TOKEN` (the `research-vault-rs` service; bucket
`ios-research-vault` @ iDrive e2). `ios-rust vault get` verifies sha256 against
the bucket manifest; every verdict artifact from the lanes is push-able with
`vault put`. Snapshot archives of this repo are uploaded under
`research/repos__ios-rust.tar.gz` in the same bucket.

## Relationship to ios-sweet-rust

`ios-sweet-rust` is the toolkit/lanes monorepo (workbench + QEMU-overlay lane
+ docs); **ios-rust** is the Rust-engine spin-off that will eventually replace
the QEMU binary those lanes invoke. ios-sweet-rust carries a pointer doc
(`docs/IOS-RUST-SPINOFF.md`) and its ledger/CI can check this repo's verdicts
as they land.

## License

GPL-2.0-or-later (matches QEMU-base provenance; see PARITY.md for per-module
provenance: ChefKiss Inferno AGPL/GPL notes, qemu-sweet GPLv2+, Asahi GPL-2.0,
applesmc LGPL-2.1 — mixed-provenance modules are marked in source comments).
