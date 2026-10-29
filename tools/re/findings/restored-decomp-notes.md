# Decompiled `restored` map — entry / monitor / engine / checkpoints

Source: Ghidra headless export, CI run 40609705374 (2,748 functions from
restored_external 841,152 B, asr 360,576 B, restored_update 823,936 B,
keystorectl 801,920 B, configdarwinbootargs 36,400 B). Static anchors
cross-checked with `ios/macho/adr_string_scan.py`.

## Process model

`entry` (0x10000d360) does NOT run the engine inline. It:

1. parses the launch mode (`-server` vs monitor default),
2. installs a `umask..enable_usb` stage list (stages 0x400..0x40e),
3. `fork()`s; the child `execl`s itself with `-server`,
4. the monitor stays behind as checkpoint bookkeeper (notify port, verdicts).

The hardcoded usbmux port is **0xF27E = 62078**. The engine registers a
`kqueue` with `EVFILT_READ` on the listener socket + the result pipe and
waits with a deadline from NVRAM `restored-host-timeout` (default 120 s;
`0` disables the timeout — useful while debugging).

## The failure chain (matches serial of every failed run)

```
engine: waiting for host to trigger start of restore [timeout of 120 seconds]
        xref @ 0x10000dd0c
host:   SYN + first mux bytes arrive (seen in guest mbufs)
kqueue: kevent() returns -1 / times out  ← never woken (H1/H2, see below)
        xref @ 0x10000dfa0  ("error waiting for events: %s\n")
engine: notice(4,1,"handle_new_connections")  ← checkpoint 0x0104
monitor:_checkpoint_monitor_engine_failure → FINISHED FAILURE:1
        → [REBOOT] → restore-outcome = initial_engine_failure_no_return
```

## Checkpoint chassis (statically linked, symbols intact)

Functions found in the export:
`_checkpoint_monitor_engine_failure`, `_checkpoint_engine_finished_result`,
`_final_result` — the monitor reads engine results from a pipe and converts
them to restore-outcome verdicts. Failure 4,1 = "initial engine failure, no
return" (engine never reached its first checkpoint).

## NVRAM knobs worth knowing

| var | default | effect |
|---|---|---|
| `restored-host-timeout` | 120 | engine wait deadline; 0 = wait forever |
| `restored-host-timeout` seen in `configdarwinbootargs` leg | — | set before boot to keep the engine alive while iterating |

## Where to poke next (in decompiled C)

1. The function containing xref 0x10000dfa0 = `handle_new_connections` —
   read its kqueue setup: which fds, which filters, and what it does on
   EVFILT_READ.
2. Grep `sonewconn`-adjacent behavior on the host side is kernel work —
   the userland side only cares that accept() fires.
3. `restore-outcome` string (0x1000725fc) → verdict-plist writer; all
   failure paths funnel through it.
