# M5-C — measured device-access census on the real boot path (up to the current stop)

Task M5-C (RE + light instrumentation). Question: **which unmodeled devices does the
real 18C66 boot path actually touch, ranked by MMIO hits, before the
TranslationFault stop** — to rank the M5 peripheral work. Companion tools:
`tools/re/reports/m5_mmio_census.py` (this file's tables are its output).
See also `m5-adt-census.md` (static ADT census) and `m5-peripheral-specs.md`.

**Headline (measured, twice, two DRAM sizes): the real boot path touches ZERO
peripheral MMIO before the stop.** Every load/store/fetch of all 8,135,778
insns (8,135,842 at 1024 MiB DRAM) lands in DRAM. No unknown-device abort, no
silent-zero, no UART byte. The stop (TranslationFault va=0x4 @
0xfffffff0081377b4, kernel /cpus DT enumeration, DT globals zero) is a
**DeviceTree-content problem, not a device-model problem** — and the runtime
attach map (captured live) proves all 59 "modeled" peripherals sit at garbage
bases behind the `reg_entries` endianness bug.

## 0. Method

1. Grep for an existing env-gated MMIO/access log: none existed (`IOS_RUST_*`
   knobs were only `IOS_RUST_DRAM_MB`, `IOS_RUST_FIXTURES`, `IOS_RUST_IM4P`;
   no `RUST_LOG` handling anywhere). So one was added (§1).
2. Device-model landscape (read, not changed):
   - `crates/vm-core/src/bus.rs` — flat physical bus. `Bus::find` = first
     region containing addr; a miss is **not an abort**: reads return
     silent-zero, writes drop (counted in `unmapped_reads/writes`, surfaced in
     the boot report as "bus unmapped (silent-zero reads / dropped writes)").
   - `crates/apple-soc/src/t8030.rs` — `attach_from_adt` walks `/arm-io`
     children, `classify()` string-matches compatible/node names onto Rust
     models; matched → `bus.attach(base, size.max(0x1000))` at the ADT `reg`
     base; unmatched → `unimplemented_devices` list (never attached, so any
     kernel access to those windows is a bus miss).
   - `crates/vm-core/src/framebuffer.rs` is a sink, not a bus device;
     `crates/devices/` models feed the `soc-t8030` qemu-compat crate, not the
     vm-core boot path. RAM-backed regions: srom/sram/seprom/dram/boot-pause
     (+ nvram, not attached on this path).
3. Ran `boot-first` (the real-kernel harness, `IOS_RUST_DRAM_MB=768`) with the
   log on, post-processed with `m5_mmio_census.py`, and cross-checked every
   claim three ways: the new per-access log, the pre-existing
   `bus_unmapped_reads/writes` counters, and the MMU's `attr_device_pages`
   counter (0 device pages ever mapped → device accesses impossible).

## 1. Instrumentation added (flag-gated, default byte-identical)

* **`crates/vm-core/src/bus.rs`** — `IOS_RUST_MMIO_LOG=<path>`:
  - `#map,<device>,<base>,<size>` line on every `Bus::attach` (RAM regions too);
  - one append-only line per **non-RAM** bus access at the `Bus::read`/
    `Bus::write` dispatch point: `<addr hex>,<size bytes>,<r|w>,<device|UNMAPPED>`;
  - RAM-backed regions are excluded per-access (the 8M-insn boot would
    otherwise emit ~25M DRAM fetch/load/store lines for zero census value);
  - implementation: `OnceLock<Option<Mutex<File>>>`, env read once, one
    `is_some()` gate on the hot path, `pub fn mmio_log_line()` for annotations.
* **`crates/apple-soc/src/t8030.rs`** — `#unimpl,<node>,<base>,<size>,<compat>`
  (and `#unimpl-class,…`) lines in `attach_from_adt` for every /arm-io child
  that gets no Rust model, so UNMAPPED hits can be named later.
* **`tools/re/reports/m5_mmio_census.py`** (stdlib-only, re-runnable) — parses
  the log, resolves windows against `#map` lines + the committed LE-validated
  ADT table (`m5-adt-census-raw/armio_table.md`) + `FALLBACK_MAP` parsed from
  t8030.rs, and prints the ranked census / attach-map audit / named-question
  block.
* Not instrumented: `read_raw`/`write_raw` (bulk DMA/image-load path; no MMIO
  semantics), and **first-touch instruction VA is not captured** — PC does not
  reach the bus dispatch (`MemAccess` carries no PC); threading it through the
  trait would be a semantic change, skipped per task ("or skip if not"). If
  needed later, the cheapest hook is `Interpreter`'s trace ring at stop time.

Validation (positive control): `ios-rust boot` ("engine smoke") with the flag
on logs exactly the 4 expected UART writes — `0x235200020,4,w,s3c-uart` ×4
(the "IOS\n" banner; census ranks it, offset 0x20 ×4). Pipeline proven
end-to-end. Unit tests: `cargo test -p vm-core -p apple-soc` → 89 passed.

## 2. Ranked census table (boot-first → stop, log `/tmp/m5/mmio-768.log`)

Log = 99 lines: 64 `#map` + 35 `#unimpl` + **0 access lines**. The ranked
census is therefore empty — reproduced verbatim from the tool:

| rank | window | base | hits | r | w | modeled? | first touch |
|---:|---|---|---:|---:|---:|---|---|
| — | *(no device-window or unmapped access on the whole boot path)* | | | | | | |

Corroboration from independent counters in the same run: `bus unmapped
(silent-zero reads / dropped writes): 0 / 0` · MAIR `device pages 0` ·
`misroute device→RAM 0 / normal→MMIO 0` · MMU 9,125,685 translated accesses,
hit-rate 100% — all of them normal (DRAM) pages.

Pipeline sanity (positive control, `ios-rust boot`): the ranked table does
populate when devices are touched — `s3c-uart @ 0x235200000, 4 hits, 0r/4w,
first touch line 15 @ 0x235200020` (UTXH 0x20 ×4).

### Runtime attach map — what `attach_from_adt` actually did (59 modeled + 35 unmodeled)

Every modeled window is attached at a **garbage base**: `AdtNode::reg_entries()`
(`crates/adt/src/node.rs`) decodes this fixture's little-endian reg pairs as
big-endian (REAL bug, already documented in `m5-adt-census.md` §0 — static
finding; this run is its dynamic confirmation). Per-model windows
`(count @ garbage bases)`:

```
dart:16  mca:7  smc:4  s3c-uart:4  i2c:4  aop:3  spmi-pmu:3  aic:2  gpio:2
spi:2  adp-v4:2  pmgr:1  apple-wdt:1  aes:1  sep-sim:1  ans2-nvme:1  sart:1
typec-otg:1  mipi-dsi:1  scaler:1  apcie:1          (= 59 windows)
```

Examples (garbage → real base from the ADT table): aic `0x103B` → 0x23B100000 ·
pmgr `0x3B` → 0x23B000000 · apple-wdt `0x2B3D` → 0x23D2B0000 · s3c-uart
`0x2035/0x2135/0x80123D/0xC02135` → uart0/4/7/dockchannel @ 0x2352xxxxx ·
ans2-nvme `0x4077` → ans @ 0x277400000 · apcie `0x10`+0x6000000 → 0x610000000.
The 35 unmodeled (`classify`-miss) nodes: aft, amc, ane, atc-phy, avd, ave,
bluetooth, dwi, error-handler, gfx-asc, isp, jpeg0, jpeg1, mcc,
mtrtempsensor6/7/8/11/13/14/15, nco, pmp, pwm, rsm, sgx, sio, sochot0,
tempsensor0/1/2/3/4/5, wlan (matches PARITY 2.11a's "35 named-unmatched";
the other 11 of 105 /arm-io children have no `reg` and are skipped).

## 3. First unmodeled blocker on the boot path

**None — no device window (modeled or unmodeled) is touched at all before the
stop**, so M5 device modeling alone cannot move the boot path forward. The
measured blocker order for the boot path is:

1. **`reg_entries` LE fix in `crates/adt/src/node.rs`** (the m5-adt-census
   "#1 M5 fix") — today all 59 modeled peripherals attach at bases in
   0x0–0x80AC3xx (some with huge sizes: apcie/dart windows are 96 MiB), i.e.
   none is addressable at its real MMIO window. Harmless this boot only
   because the kernel touches nothing; any post-fix driver code would hit
   silent zeros from the wrong devices. (Static cross-check: garbage bases
   cover part of upper DRAM at ≥1 GiB DRAM sizes — worth re-verifying after
   the fix, but at 768 MiB no shadowing occurs and no access was misrouted.)
2. **DT content behind the 0x…b83f54 gate** (M2/M3 finding; the stop itself:
   DT globals zero → null deref at 0xfffffff0081377b4 in the /cpus walk).
3. Only then the first real device touches (not yet reached; when M4/M5
   unblocks the path, re-run `m5_mmio_census.py` — the ranking regenerates
   automatically, including UNMAPPED-hit naming via the ADT table).

## 4. Pre-stop touch map (named questions from the mission)

| device | bus accesses before stop | note |
|---|---:|---|
| UART (s3c-uart/uart*) | **0** | "UART output: (none yet)" — banner never starts |
| PMGR / pstate | **0** | no clock/power touch; kernel never reconfigs clocks pre-stop |
| AIC | **0** | no IRQ controller touch; also no AIC doorbell/timer MMIO |
| WDT | 0 | |
| ANS/NVMe | 0 | NVMe path not reached (M5 rootfs-bytes gate untested by this run) |
| *any* window or unmapped address | **0** | 0/0 silent-zero/dropped counters |

Timing note for M4/M5 ordering: pre-stop the kernel *does* use the **generic
timer via sysregs** (17 read / 23 write unknown-sysreg events incl.
`s3_0_c14_c1_0` = CNTV_CTL-ish and the `s3_4_c15_*` boot-stage polls — see the
boot report's unknown-sysreg list), so M4's AIC/timer work matters **after**
the DT fix unblocks further execution, not before. All bus traffic
pre-stop is RAM: the census tool must be re-run (not extrapolated) once the
path extends.

## 5. Behavior-drift check

Same binary before/after instrumentation, `env -u IOS_RUST_MMIO_LOG`:

| run | DRAM_MB | MMIO_LOG | insns retired | MMU live | stop |
|---|---:|---|---:|---:|---|
| pre-instrumentation baseline | 768 | — | 8,135,778 | 8,110,809 | TranslationFault va=0x4 @ 0xfffffff0081377b4 |
| post, flag OFF | 768 | — | **8,135,778** | 8,110,809 | identical |
| post, flag ON | 768 | /tmp/m5/mmio-768.log | **8,135,778** | 8,110,809 | identical |
| pre-instrumentation baseline | 1024 | — | 8,135,842 | 8,110,809 | identical |
| post, flag OFF | 1024 | — | **8,135,842** | 8,110,809 | identical |
| post, flag ON | 1024 | /tmp/m5/mmio-1024.log | **8,135,842** | 8,110,809 | identical |

Zero drift. Stronger: the **entire stdout** of the flag-OFF 768 run is
byte-identical to the pre-instrumentation baseline (`diff` clean).

Endianness of the ledger number: **8,135,842 is the 1 GiB-DRAM count** (the
pre-MMU bootstrap loop scales with bootargs memSize: 25,033 pre-MMU insns at
1024 vs 24,969 at 768; MMU-live and the MMU-on path are identical — 9,125,685
translated accesses at both sizes). The task's "8,135,842 with DRAM_MB=768"
conflates the two; both configurations reproduce exactly on this tree.

## 6. Reproduce / re-run (after M4 or any boot-path extension)

```bash
export PATH=$HOME/.cargo/bin:$PATH; cd /home/z/my-project/download/ios-rust
cargo build
IOS_RUST_DRAM_MB=768 IOS_RUST_MMIO_LOG=/tmp/m5/mmio-768.log \
  ./target/debug/ios-rust boot-first fixtures /tmp/bootfirst > /tmp/m5/run-768-log.txt
python3 tools/re/reports/m5_mmio_census.py --log /tmp/m5/mmio-768.log --out /tmp/m5/census-768.md
# drift check: same without IOS_RUST_MMIO_LOG → insns must match the table above
```

Raw evidence (session /tmp, not committed): `/tmp/m5/mmio-768.log`,
`/tmp/m5/mmio-1024.log`, `/tmp/m5/mmio-positive.log`, `/tmp/m5/census-768.md`,
run transcripts `/tmp/m5/run-*.txt`, pre-instrumentation baseline
`/tmp/m5-baseline-run.txt`.

Changes left in tree (uncommitted, per task): `crates/vm-core/src/bus.rs`
(env-gated log + attach/access lines), `crates/apple-soc/src/t8030.rs`
(`#unimpl` annotations), `tools/re/reports/m5_mmio_census.py`. No Rust
semantics changed; default path byte-identical (§5).
