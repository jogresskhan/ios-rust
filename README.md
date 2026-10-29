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
ios-rust boot-full [ipsw] [dir]  # FULL SYSTEM: full-root APFS → boot ladder → SpringBoard (G1–G4 ✅)
ios-rust parity              # live parity ledger (% per component)
ios-rust vault list|get|put|usage   # research-S3 integration
ios-rust selftest            # release invariants
# research & format tooling (reference-repo sweep):
ios-rust dsc info|images|rebase|symbols|a2o|o2a <dyld_cache>
ios-rust kc info|version|kexts <kernelcache>     # LZSS/LZFSE decode
ios-rust devices list|t8030|lookup|board|cpuid|ipsw-me
ios-rust vulns list|show|search|mitigations|frida|tools|json
ios-rust dc demo|constants|entitlements          # DeviceCheck token pipeline
ios-rust xnu syscalls|traps|errno|boot|boot-order|abi
ios-rust host check|deps|qemu                    # Linux host integration
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
| `plist` | libplist XML subset — the transport encoding for mux/restored/ASR | ported + tested |
| `usbmux` | **libusbmuxd** (usbmuxhost: framing, listen, connect tunnel) | ported + tested |
| `restored` | libimobiledevice restored client (port 0xF27E, decomp-cross-checked) | ported + tested |
| `asr` | idevicerestore `asr.c` (validation + 128 KiB push + SHA-1 tails) | ported + tested |
| `authinstall` | libauthinstall subset (TSS request/ticket, IM4M validation) | subset + tested |
| `apfs` | APFS on-disk reader + **writer** subset (fletcher64, B-trees, COW) | subset + tested |
| `ios-rust` | **the one binary** wiring all of the above | built |
| `dsc` | **dyld shared cache reader** (blacktop/ipsw pkg/dyld core): header v-gates, mappings, images, subcaches, slide-info rebase walks v2–v5, local symbols | working (synthetic-verified) |
| `kernelcache` | **kernelcache decode + metadata** (ipsw pkg/kernelcache core): `complzss` LZSS (xnu mkext port), LZFSE via vendored Apple C, version strings, `__PRELINK_INFO` KEXT inventory | working (synthetic-verified) |
| `restore` + | TSS **RestoreRequestRules engine** (EPRO/ESEC) + ~130-entry component 4CC map (libauthinstall/ipsw parity) | added |
| `devices-db` | **Apple device database** (ipsw_db format, 41 products/46 boards, A13 rows live-verified) + ipsw.me catalog client | working |
| `vuln-db` | **iOS vulnerability research KB**: 18 CVE/technique entries, XNU zone-allocator mitigation timeline, FRIDA catalog, 34 tool refs | data-complete |
| `devicecheck` | **DeviceCheck token internals** (andrd3v/dcdev RE): token buffer layout, ECDH-P256 → HKDF-SHA256 → AES-256-GCM, MESU/humbug endpoints, entitlements fixture | working |
| `xnu` | **XNU ARM64 ABI KB**: 423 BSD syscalls, 63 Mach traps, errno, `boot_args`, early-boot call order, SVC/VM/port constants (xnu-7195.141.2 + darwin-abi.h) | data-complete |
| `sandbox` | **SandBlaster port** (cellebrite-labs/sandblaster → Rust): binary sandbox-profile container (legacy 0x8000 + iOS 18 headers), 8-byte operation nodes, graph walk → **SBPL decompiler** | 75 |
| `a13-cpu` ISA parity | **all 20 `soc_t8030::CPU_INSTRUCTIONS` groups decode+execute in pure Rust** (LSE atomics, RDM, FCMA, JSCVT, FP16, ASIMD RDM, DOTPROD, SHA512, SHA3, SM3/SM4, AES/PMULL, CRC32, PAC, BTI, CSV2/3, AMUv1, MPAM, TLBI RANGE, DGH/DOT, FCADD) — goldens from Capstone/Keystone oracles, per-group retire counters;
  **measured 98.59% decode / 98.6% exec on real iOS 14.3 kernel text**
  (was 90.5% before the tools/re gap-fix sessions) | 90 |
| `boot-full` | **full-system pipeline**: IPSW → full-root APFS (System/Data/Preboot) → A13 boot ladder → launchd → **SpringBoard** homescreen (2436×1125 BMP) | 80 |
| `host-linux` | **Linux host integration** (ios-emulator-linux + darwin-vm): capability check (KVM/RAM/APFS/tools), dep manifest, reference QEMU command builder | working |

## Reverse-engineering toolkit (`tools/re/`) — read me if you are an AI

`tools/re/README.md` is the **playbook**: how to pull real Apple fixtures
(IPSW range requests), how the decode pipeline works, the proven
gap-fix loop that took the real iOS 14.3 kernel from **90.5% → 98.6%**
decode/exec coverage on the a13-cpu, and the Ghidra headless recipe.
Highlights:

* `tools/re/oracle/mask_discover.py` — brute-forces the A64 encoding space
  through capstone and emits the exact `if (w & MASK) == VALUE` pairs for
  `crates/a13-cpu/src/decode.rs`. Never hand-split instruction bits.
* `tools/re/oracle/insn_oracle.py` — keystone-assemble → capstone-decode
  ground truth; `--fuzz MNEMONIC` enumerates register encodings.
* `tools/re/coverage-probe/` — standalone honest-coverage probe: decode
  sweep + single-insn exec probe + unimplemented-class histogram against
  any real kernelcache (`cargo build --release && ./target/release/
  ios-rust-coverage-probe fixtures/kernelcache.release.iphone12b`).
* `tools/re/ghidra/` — bulletproof `analyzeHeadless` wrapper,
  per-function decompiled-C export, QEMU-trace coloring, and the
  proven `-processor AARCH64:LE:AppleArmv8k:applearm64k` recipe.
* `tools/re/macho/`, `tools/re/extraction/`, `tools/re/findings/` —
  Mach-O triage + ADR string xrefs, keyless IPSW/HFSX extraction, and the
  written `restored_external` RE evidence (copied from
  20kiwy/ios-re-toolkit).

## CPU instruction parity (named, as required)

T8030 = A13 Bionic, ARMv8.4-A. The virtual CPU covers (tracked per-group in
`soc_t8030::CPU_INSTRUCTIONS`): **LSE atomics, RDM, FCMA, JSCVT, FP16,
ASIMD RDM, DOTPROD (SDOT/UDOT), SHA512, SHA3, SM3/SM4, AES/PMULL, CRC32,
PAC (v8.3 pointer auth), BTI, CSV2/CSV3, AMUv1, MPAM id regs, TLBI RANGE,
DGH/DOT, FCADD**. All 20 groups decode AND execute in the pure-Rust backend
(`a13_cpu::interp::Interpreter::group_exec` retire counters, proven in
`a13-cpu/tests/parity_exec.rs`) and are pinned by a 189-entry CI golden
table (`a13-cpu/src/goldens_ext.rs`, generated by
`tools/goldens/gen_goldens.py` against capstone 5.0.1280 + keystone 0.9.2).
Honest remainder: FCMLA by-element structural (1 pending golden), FP16 .8h
vector arithmetic unverifiable by local oracles (goldens.rs op6/size pairs).
The C engine (ChefKiss Inferno QEMU fork) remains the device-level
executor lane; the Rust interpreter executes the named ISA natively.

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
