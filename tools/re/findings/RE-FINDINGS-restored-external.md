# RE findings — restore-ramdisk userland (`restored_external`), 2026-10-28

Binary source: official Apple CDN IPSW
`iPhone11,8,iPhone12,1_14.0_18A5351d_Restore.ipsw` (iOS 14.0b5, 18A5351d),
member `038-44135-124.dmg` (restore ramdisk) — extracted keylessly, decoded
without hdiutil, and **verified page-for-page against the embedded ad-hoc
code signature** (CodeDirectory, 203 slots: **202/202 code pages match**;
the last slot covers the signature blob itself).

Tooling: `tools/extract-ramdisk-userland.py` (stdlib-only; replaces the
failed `im4p payload -> mountable HFS image` CI step of
`re-restore-ramdisk` run 40601600493 — the payload is a RAW HFSX volume,
no LZFSE, and binaries are decmpfs-compressed in resource forks).

## Binary facts (`restored_external`, 841,152 B)

* arm64 (not arm64e) MH_EXECUTE, LC_DYLD_CHAINED_FIXUPS, PAC instructions
  (`pacibsp`/`retab`/`pacia`) compiled in, 46 load commands.
* Links the full restore stack: `libauthinstall` (AP tickets), `APFS`,
  `MediaKit`, `libamsupport` (ASR), `libimg4`, `libMobileGestalt`,
  `libFDR`, `libTiSerialFlasher`, `libBBUpdaterDynamic`, `libSMC`,
  `libReverseProxyDevice` and — notably — **`IOMobileFramebuffer`**
  (the restore engine itself is a display-framework client).
* 955 imports; local symbols stripped. Addressing style: PC-relative
  **`adr`** for strings (7,793 ADRs — *not* adrp+add; this is why naive
  adrp xref scans come up empty) + literal-pool `ldr` for constants.

## The failure path (matches run 40592337155 serial exactly)

```
main (0x10000d360)
  └─ engine loop (0x10000d7xx-0x10000e00)
       ├─ 0x10000dd0c  adr → "waiting for host to trigger start of restore
       │                [timeout of 120 seconds]"        ← our serial line
       ├─ deadline = mach_absolute_time() + N           (0x10000dc98-daac)
       ├─ kevent(kq, NULL, 0, &ev, 1, timeout)          (0x10000ddbc)
       ├─ ret <= 0 and errno != EINTR
       │    └─ 0x10000dfa0 adr → "error waiting for events: %s"   ← our line
       │         → w20 = 1 → checkpoint(4, w20, "handle_new_connections")
       │           (0x10000dfe0 → the 0x0104 CHECKPOINT in the serial log)
       │         → restore-outcome = initial_engine_failure_no_return
       │         → cleanup (SMC writes) → monitor reboots to recovery
       └─ event path: 0x10000df14 → kAMFDRSealingMapTag… (engine proceeds)
```

## What the emulator must deliver (measured contract)

1. The guest's `restored_external` registers a **kqueue** on the usbmux
   connection fds and blocks in `kevent` with a 120 s budget. The host must
   send data that produces a **read-event wake on that kqueue** — the serial
   shows the mux TCP bytes arriving (`IN 40137->62078 1:293(292)`) yet the
   kevent never fires ⇒ the emulated USB IN-completion path does not
   propagate to the guest's socket layer as a readable event (consistent
   with the repo's documented "110 s IN-transfer stall" + "kqueue
   registration race" forensics, runs #57–#67).
2. `verify_storage_for_update` (0x100011318 ref) is reached only after the
   initial engine handshake completes — fixing (1) unblocks it.
3. `IOMobileFramebuffer` linked into `restored_external` means the restore
   UI progress bar goes through IOMFB — relevant to the M3a DisplayPipe
   track (R2 IOMFB/DCP shim) later.

## Working extraction (this commit)

`tools/extract-ramdisk-userland.py` — pure stdlib, HTTP-range IPSW reader +
zip64 + DER IM4P + raw-HFSX walker + decmpfs chunk decoder. Produces
`restored_external` (841,152 B), `restored_update` (823,936 B), `asr`
(360,576 B), `keystorectl` (801,920 B), `configdarwinbootargs` (36,400 B)
from both ramdisks without downloading the 6 GB image. Signature-verified
output. The Ghidra-decompile CI step can consume these directly
(arm64 Mach-O, no DSC loader needed for these standalone binaries).
