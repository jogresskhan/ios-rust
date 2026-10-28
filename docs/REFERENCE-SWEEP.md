# REFERENCE-REPO SWEEP — what was ported, from where, and what's next

(October 2026 sweep. Every claim below is checked against the referenced
source; the honest-gaps are listed per repo.)

## 1. blacktop/ipsw (Go) — the format-tooling mother lode

Study scope: `pkg/dyld` (~9.6k lines, in-repo since go-dyld was dropped),
`pkg/kernelcache`, `pkg/info` + `pkg/tss` + `pkg/img4`, `internal/download`.

**Ported into the workspace:**

| ipsw source | → ios-rust | notes |
|---|---|---|
| `pkg/dyld/types.go` CacheHeader (0x248 exact offsets, version gates `MappingOffset >= …`) | `crates/dsc/src/header.rs` | layout-verified field-by-field against the Go struct |
| `pkg/dyld/file.go:440-497` mapping parsing + flag→segment-name derivation (`__TEXT_STUBS`, `__AUTH_CONST`, …) | `crates/dsc/src/mapping.rs` | byte sizes: plain 32 B, with-slide 56 B |
| `pkg/dyld/types.go:332/898` image info (old + dyld4) + text info | `crates/dsc/src/image.rs` | `ImagesOffsetOld > 0` gate |
| `pkg/dyld/types.go:1223` subcache entries v1/v2 + naming rules (`file.go:236-274`: `.development` strip, `FileSuffix`, `.{i}`) | `crates/dsc/src/subcache.rs` | member UUID cross-check on open |
| `pkg/dyld/file.go:1138 parseSlideInfo` — rebase walkers v2 (u64 delta chains), **v3** (A13 iOS 13/14: `AuthValueAdd`, SignExtend51), v4 (u32 chains, small-neg/positive rules), v5 (34-bit runtime offsets + high8) | `crates/dsc/src/slide.rs` | bit-exact (verified against Go + dyld_cache_format.h); v1 = parsed, walk honestly skipped |
| `pkg/dyld` local symbols (`CacheLocalSymbolsInfo`, Entry64, nlist_64) | `crates/dsc/src/localsyms.rs` | `.symbols` member handled |
| `pkg/kernelcache/kernelcache.go DecompressData` | `crates/kernelcache/src/compress.rs` | LZFSE → vendored Apple C FFI (`restore::lzfse`); LZSS → own port; fat → thin |
| blacktop/lzss `Header` + xnu `libkern/mkext.c` `decompress_lzss` | `crates/kernelcache/src/lzss.rs` | **0x180 stream offset** (24-byte BE fields + 360-byte Padding; magic `"comp"+"lzss"` = `complzss`) — the earlier "complzzss 28-byte" folklore is wrong, verified against blacktop/lzss source |
| `pkg/kernelcache/kernelcache.go:500 GetVersion` | `crates/kernelcache/src/version.rs` | Darwin/LLVM line parsing, fileset-aware scan |
| `pkg/kernelcache/kext.go` prelink info | `crates/kernelcache/src/prelink.rs` | over `restore::plist_lite` |
| `pkg/info/data/ipsw_db.json` format + query helpers | `crates/devices-db/src/db.rs` | 41 products / 46 boards, A13 rows verified against live api.ipsw.me (A13 CPID = **0x8030**, boards D421AP/D431AP/D79AP/N104AP) |
| `internal/download/ipsw_me.go` | `crates/devices-db/src/ipsw_me.rs` | v4 endpoints, blocking wrappers |
| `pkg/tss/tss.go:122 applyRestoreRequestRules` + `pkg/img4/img4.go ComponentFourCCs` (~130 entries) | `crates/restore/src/tss_rules.rs` | condition→parameter mapping verbatim (unknown condition ⇒ rule unfulfilled) |

**Honest gaps (not ported):** PrebuiltLoaderSet/launch-closure parsing
(`prebuilt*.go`, `closure.go`), patch-info v1–v4 walkers, ObjC optimization
hash tables, stub islands, A2S address→symbol file, KEXT extraction with
chained fixups, pbzx/OTA/AEA.

## 2. andrd3v/dcdev — DeviceCheck token RE

Study scope: README (729-line devicecheckd RE), the stripped arm64e binaries,
`com_apple_MobileAsset_DeviceCheck.xml`.

**Ported into `crates/devicecheck`:**

* token payload buffer (offsets +65 ts / +73 certLen / +77 appLen / +81 data)
  and token buffer (+0 type, +1 GCM tag, +5 static pk, +85 ephemeral pk,
  +150 payloadLen, +154 ct) — README-literal, the two write-overlaps
  (u32-version↔tag, tag↔static-pk) documented rather than "fixed";
* crypto pipeline: `aks_ref_key_create(keybag,11,4,0,0)` → ECDH-P256 →
  HKDF-SHA256 (44 bytes → 32 key + 12 IV) → AES-256-GCM (no AAD, 16-byte
  tag) — implemented with p256/hkdf/aes-gcm;
* constants: fallback P-256 server pubkey (0xDC50 in DeviceCheckInternal),
  MESU asset URL + keys, `com.apple.twobit.fetcherror` codes (-3100/-3101/
  -3200), humbug BAA `https://humb.apple.com/humbug/baa` + UA + `x-jmet-
  deviceid`, keychain `2bit-identity` naming, XPC selectors;
* `devicecheckd` entitlements plist (verbatim fixture) + client allowlist.

**Honest gaps:** the aks ref-key shared-secret `+2` offset is internally
inconsistent in the README (treated as the raw 32-byte x-coordinate); no
XPC transport / keychain shim yet.

## 3. arlinux-xnu — Darwin userspace ABI + XNU-7195 reference

Study scope: `src/darwin-abi.h` (distilled ARM64 wire ABI), vendored
xnu-7195.141.2 (`pexpert`, `osfmk/kern/startup.c`, `bsd/kern/syscalls.master`).

**Ported into `crates/xnu` (std-only, data-complete):**

* 423-entry BSD syscall table + 63 Mach traps (negative-x16 form) + errno +
  kern-return tables — every `darwin-abi.h` entry cross-checked present;
* `boot_args` (repr(C), 736 = 0x2E0 asserted) + 34 known boot-arg names +
  the STARTUP_SUB_* phases + the 48-step ARM64 early-boot call order
  (`start.s → arm_init → … → machine_lockdown → launchd`);
* ~200 ABI constants (SVC encoding, platform syscall, VM flags, mach_msg2
  routing hints, MIG subroutine IDs, ulock ops, workqueue flags, commpage).

**Caveat recorded in-tree:** darwin-abi.h swaps 520/521 vs syscalls.master
(table follows syscalls.master, discrepancy flagged).

## 4. IdanBanani/iOS-Vulnerability-Research + ansjdnakjdnajkd/iOS

**Ported into `crates/vuln-db`:** 18 CVE/technique entries (2015→2021: zone
heap era, MIG/XPC, IOKit drivers, cfprefsd logic bugs), the XNU
zone-allocator hardening timeline (iOS 5→10) with defeat techniques, a
FRIDA/r2frida technique catalog, 34 pentest-tool references. All entries
carry sources; advisory-vs-real component attributions noted
(ProvInfoIOKit ≠ "IOKit", cfprefsd ≠ "Foundation").

## 5. Legasitech/ios-emulator-linux (+ upstream jprx/darwin-vm scripts)

**Ported into `crates/host-linux`:** capability check (KVM open, arch,
RAM, df-free, `apfs` in /proc/filesystems, tool PATH scan), the apt dep
manifest (base + WSL extras), install recipes (blacktop/ipsw release
asset — not the pip shim, ldid with the `-Cadhoc` flags=0x2 TXM/AMFI
requirement, linux-apfs-rw module, qemu-sptm configure line), and the
reference `-M darwin` QEMU argv builder (bootkc/dtree/tc/ramdisk/sptm/txm,
`rd=md0 serial=3 -v -noprogress wdt=-1 wlan-olyhal-abort`, qemuports
2100-2103) + the firmware file contract.

## Verification method

No real firmware is vendored in this repo, so format work is verified with
synthetic fixtures (built to the byte layouts above):

* `dsc`: a generated `dyld_v1 arm64` cache (3 mappings, slide-v3 chain of
  2 pointers, 3 images, 2 local symbols) — info/images/rebase/symbols/a2o
  all assert-correct (`/tmp/dsctest/test_cache` recipe reproducible);
* `kernelcache`: a generated `complzss` container (0x180 header + literal
  LZSS stream wrapping a minimal Mach-O with `__TEXT.__const`) — decode +
  version parse assert-correct (`test_kernelcache`);
* `devicecheck`: GCM decrypt of `parse_token` ciphertext equals
  `build_payload` output (round-trip);
* `devices-db`: live api.ipsw.me cross-check for the A13 family.

Flipping each remaining gate = run the same checks against real firmware
dumps (see PARITY.md Layer 2.7).
