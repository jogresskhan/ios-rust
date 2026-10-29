# re-restored: Ghidra decompilation of the restore-stack userland (restored_external / ASR)

Provenance: CI run [40609705374](https://github.com/20kiwy/ios-sweet-rust/actions/runs/40609705374)
(workflow `re-restore-ramdisk`, dispatched after commits af5ae0db5d/e2808d214d), artifact
`re-restored-decomp` (2748 decompiled functions + the raw arm64 Mach-O binaries).
Pipeline: `tools/extract-ramdisk-userland.py` (keyless HTTP-range IPSW -> raw HFSX catalog
walk -> decmpfs decode, page-verified against embedded ad-hoc signatures) -> Ghidra 11.3.1
headless -> `tools/ExportDecompiled.java` per-function C export.

## Why this binary matters

The Inferno lane dies in the restore ramdisk: the engine child of `restored_external`
times out waiting for the host connection, writes
`restore-outcome=initial_engine_failure_no_return` into NVRAM and reboots
(the reboot loop). The decompilation pins the exact code path that produces
that string, so the emulator-side fix can be verified against a precise
contract instead of guesswork.

## What entry() (0x10000d360) actually does

`restored_external` is two processes in one binary:

1. **Monitor (no args).** `checkpoint_monitor_init()` -> creates the read/write
   ramdisk (`0x1180 create_ramdisk`) -> `fork()`. The child `execl`s itself with
   `-server`; the parent `waitpid()`s. If the child exits non-zero the monitor
   calls `_checkpoint_monitor_engine_failure(4, status)`, which stamps the
   `[REBOOT]` variant of the outcome string, syncs `/mnt5`, unmounts/ejects the
   ramdisk (`0x1183/0x1181/0x1182`) and reboots.
2. **Engine (`-server`).** `_checkpoint_engine_init(1,4,0)` then
   `_checkpoint_engine_perform()` runs the startup stage list, each with a
   checkpoint id: `umask` (0x400), `setvbuf` (0x402), `kernel_logger_thread`
   (0x403), `update_root_mount` (0x404), `disable_watchdog` (0x405),
   `set_progress_0` (0x406), `start_gasgauge_thread` (0x407),
   `listen_for_log_client` (0x408), `create_listen_socket` (0x40d),
   `enable_usb` (0x40e). Port **0xF27E = 62078** is hardcoded in `entry()` for
   the listener. Then:

   - reads NVRAM `restored-host-timeout` (default **120 s**, `0` = no timeout —
     this is an NVRAM escape hatch worth using while debugging the emulator);
   - creates a semaphore(50), a result `pipe()`, a `kqueue()`, and registers
     **EVFILT_READ (EV_ADD)** on both the listening socket and the pipe read end;
   - loops on `kevent(kq, NULL, 0, &ev, 1, &remaining_timeout)`:
     - event on the listener -> `accept()`, `SO_NOSIGPIPE`, `dispatch_async` of
       the connection handler (`FUN_10000e984`);
     - event on the pipe -> child exit status -> clean finish;
     - `kevent()` returning `<= 0` falls through to
       `ramrod_log_msg("error waiting for events: %s")` (on timeout the `%s` is
       a *stale* errno, which is why the serial prints `timed out`), then either
       retries (EINTR / monitor flag `DAT_1000ba160`) or exits the loop.

## The exact reboot-loop path (matches observed serial bit-for-bit)

```
kevent() returns 0 after 120 s
  -> "error waiting for events: timed out"            (serial, 00:14:52)
  -> result = 1
  -> _checkpoint_engine_notice(4, 1, "handle_new_connections")   = MAIN:[0x0104]
  -> _checkpoint_engine_finished_result(1)
       -> state 0xd log, "engine process terminating"
  -> child exit status 1
  -> parent waitpid -> _checkpoint_monitor_engine_failure(4, 1)
       -> outcome table @ DAT_100070a78[outcome] -> "[REBOOT]" string
  -> NVRAM restore-outcome = initial_engine_failure_no_return    (serial)
  -> sync /mnt5, unmount, eject, reboot -> the loop
```

`initial_engine_no_return -> initial_engine_failure_no_return` therefore means
exactly: **the initial engine (`handle_new_connections`) finished with FAILURE:1
because `kevent()` never delivered the listener event within the 120 s window.**

## Correlation with the G4 probe (run 40604541385)

The same boot's evidence (`gui-realboot-g2-evidence`) shows:

- Host side: `usb: response id mismatch (got 31 want 42) — 68 bytes stashed`,
  repeated `packet id=N parked (ASYNC)` / `IN poll parked past its timeout`,
  and at ~134 s `mux: TCP RST: 'sessionUpcall connection closed'` — *after* the
  engine died, i.e. a consequence (listener closed), not the cause.
- Guest side: `IN 40137->62078 0:0(0) S` (host SYN arrived at the guest mux),
  `IN 40137->62078 1:291(290) A` + `Copying 290 byte mbuf` (payload queued),
  `create_listen_socket` (0x040D) ended clean, **no** `unable to create kqueue`
  / `could not add listen sock to kqueue` errors — registration succeeded.
- Kernel probe (`g4-loopback-trace.log`): `filt_soread` *can* fire and deliver
  (`[FILT_SOREAD] hint=1` -> `[KQ_SCAN_DELIVER]` -> `[KEVENT] fd=8 nev=1`),
  `[SOWAKEUP]` fires for ordinary sockets.
- G3 verdict: `connections=1 reached=['desc','mux','tcp'] missing=['restored']`.

## Remaining discriminator: H1 vs H2

The mux-virtual TCP data lands in the guest kernel, and the loopback TCP
connection to the listener stays up until the engine dies. What is *not* proven
yet is whether the loopback handshake ever **completed**:

- **H1 — listener wakeup broken:** the TCP handshake completes (`sonewconn` ->
  new conn queued on `so_comp` -> `sorwakeup(listener)`), but the wakeup chain
  never marks the *listening* socket EVFILT_READ-ready in the emulated kernel
  (data-path sockets demonstrably work, listeners are a different filter path).
- **H2 — handshake never completes:** the mux's `socconnect()` to
  127.0.0.1:62078 sits in SYN_SENT (guest loopback TCP delivery broken, e.g.
  `lo0` not configured on the ramdisk); the connection only *looks* open
  because the mux session parks.

Cheapest discriminating probes for the next `gui-realboot` iteration:

1. gdb breakpoints on `sonewconn`, `soisconnected`, `sorwakeup` (watch for the
   listener `so` — the one whose `so_qlen` changes), and `tcp_output` filtered
   on destination 127.0.0.1. H1 = `sonewconn` + `sorwakeup(listener)` fire but
   no kevent; H2 = no `sonewconn` at all.
2. A tiny userland probe in the ramdisk that `socket/bind 127.0.0.1/listen`
   then `connect`+`accept` on loopback and reports which step fails — same
   shape as the existing G4 EVFILT_READ probe.
3. While debugging, set NVRAM `restored-host-timeout=0` (no timeout) so the
   engine window doesn't kill the session at 120 s mid-investigation.

Once the listener wakes, `accept()` -> `FUN_10000e984` speaks the restored
protocol and the run should leave `handle_new_connections` with SUCCESS,
ending the reboot loop at its first gate.
