# M5 attach spec — exact node→device mapping for T8030 / n104ap (18C66)

Task 2-c, RESEARCH ONLY (this note is the only file written; zero Rust edits).
Consolidates + cross-checks: `m5-peripheral-queue.md` (measured drivers),
`m5-adt-census.md` (+ `m5-adt-census-raw/`), `m5-device-census.md`,
`m5-peripheral-specs.md`, `m4-aic-timer-re.md`, and the **current** Rust code
(`crates/apple-soc/src/t8030.rs` `classify()`/`FALLBACK_MAP`/`attach_from_adt`,
`crates/apple-soc/src/*.rs` models, `crates/vm-core/src/bus.rs`,
`crates/virt/src/machine.rs`).

Ground truth used for every base/size/IRQ/clock-gate below:
**`/home/z/tmp-re/armio_rows.json`** (105 rows, parsed from the real flat ADT
`/tmp/adt-n104ap.bin`, 220,204 B, LE `(u64,u64)` reg pairs). I re-parsed the raw
ADT directly this session to get the **full multi-window reg lists** (the JSON
`base`/`size` fields are reg[0] only), the per-node `interrupt-parent` phandles,
the 44-window PMGR map, `/defaults/pmap-io-ranges`, and the pmgr `ps-regs`/
`devices` props. Everything below is re-derived from those bytes, not copied
from the older notes; every disagreement is flagged in §8.

---

## 0. Preconditions the spec depends on (verified in the current tree)

| # | fact | status in tree |
|---|------|----------------|
| P1 | `AdtNode::reg_entries()` decodes `(u64 LE, u64 LE)` first with sanity check, BE fallback (`crates/adt/src/node.rs:226`) | **FIXED** (the m5-adt-census "#1 M5 fix" has landed; garbage-base attach is gone) |
| P2 | `FALLBACK_MAP` bases (`t8030.rs:67-80`) | **ALREADY CORRECTED** — aic 0x23B100000/0x8000, aic-timebase 0x23B108000/0x1000, uart0 0x235200000/0x4000, wdt 0x23D2B0000/0x4000, ans2-nvme 0x277400000/0xC000, adp-v4 0x230000000/0x2FC000, mipi-dsi 0x230400000/0xC0000, sart 0x27AC50000/0x8000, pmgr 0x23B000000/0x100000, gpio 0x23C100000/0x100000, smc 0x23E400000/0x20000 — all match armio_rows.json. The "base drift" defect (a) in the older notes is **stale**. |
| P3 | `classify()` special-cases `aic-timebase` **before** `aic` (`t8030.rs:296`) | defect (d) is **half-fixed**: it is no longer a second `Aic`, but the `AicTimebase` register set is wrong (§5.3) |
| P4 | `FALLBACK_MAP` has **no** `dart-ans` entry; only a dead `"dart-ans"` match arm remains in `attach_fallback` (`t8030.rs:135`, unreachable) | defect (g) = delete dead code only |
| P5 | `attach_from_adt` uses `reg.first()` only + `size.max(0x1000)`; nothing reads `clock-gates`/`interrupts`/`interrupt-parent` | defects (e) — this spec defines both (§4, §6) |
| P6 | `Bus::find` = **first region containing addr, regions sorted by base** (`bus.rs:112-119`) | **must change** — see B1; today the lowest base silently shadows smaller nested windows |
| P7 | `virt/src/machine.rs::attach_devices` uses symbolic bases ("re-verify per LANDMARKS") | that is the *other* machine (soc-t8030 demo board, not the boot path). The boot path is `apple-soc` `T8030Machine::attach_from_adt` — this spec targets that one. |

**B1 — required bus rule (implementable, one line):** resolve overlapping
windows by **smallest matching region wins; tie → last attached**. Rationale:
the real ADT nests device pages inside larger windows (measured overlaps:
`mca-switch [238400000+18000]` ⊃ `mca0/mca1 [2384xxxxx+4000]` and
`[238300000+30000]` ⊃ `mca0 [238300000+4000] [238304000+4000]`;
pmgr window22 `[23D100000+80000]` ⊃ `dockchannel-uart [23D10C000+1000]
[23D128000+10000]` and `pmp [23D100000+14000] [23D128000+30000]`;
pmgr window0 ⊃ `error-handler [23B000000+A1000]`, `isp [23B080000+D000]`,
`ane [23B080000+80000]`, `ave [23B088000+4000]`, `mca-switch [23B0400B4+18]`,
`disp0 [23B0B8000+1000]`; pmgr window1 `[23D200000+100000]` ⊃ `aes
[23D2D0000+4000]`, `aop [23D2A8000+8]`, `wdt reg[1] [23D2B8020+4]`;
pmgr windows 24/25 and 38/39/40 and 41/42/43 overlap each other; the fixed
**SEPROM Ram `0x240000000+0x2000000`** ⊃ `dart-sep [2412C0000+4000]` and
`error-handler [241400000+4000] [241440000+14000]` — also verify SEPROM size
against `t8030.c`; with B1 the MMIO devices win regardless). Without B1,
pmgr/mca-switch/SEPROM shadow real devices forever. The AIC page pair is
*adjacent*, not overlapping (aic win0 ends at 0x23B108000 where aic-timebase
begins), and `aic reg[1] == aic-timebase reg[0]` is resolved by never
attaching aic's second window (§2 row 1).

---

## 1. Legend + inventory

- **Target model** values: `KEEP` = current model+base correct (no change);
  `KEEP-W` = keep model, change window/attach policy; `SWAP` = different model;
  `NEW` = new shim (spec in §5); `SKIP` = stays in `unimplemented_devices`
  (bus-miss = silent-zero = RAZ; per §6 skip-list that is acceptable).
- "w#" = reg window index in the node's `reg` property (arm-io-relative +
  0x200000000 for windows < 0x400000000; the second /arm-io range maps
  0x600000000→0x600000000 identically — ranges prop = `{0,0,0, 2,0,1,
  0,6,0, 6,0,2}` = child 0..4G → +0x2_00000000, child 0x600000000.. → identity).
- Row numbers cite `/home/z/tmp-re/armio_rows.json` (JSON order = ADT child
  order). IRQ numbers are the raw `interrupts` u32s; decode rules in §6.
- 105 children = 94 reg-bearing (13 zero-size rows = 11 no-reg + wlan/bluetooth
  whose `reg` is the single u64 0xF, not a base/size pair) = 77 rows with IRQs.

---

## 2. Corrected node→device mapping (all 105 /arm-io children)

| JSON# | node | reg windows (abs base+size) | IRQs | cg/pg | target | Δ vs current classify() |
|---:|------|-----------------------------|------|-------|--------|--------------------------|
| 1 | aic | w0 `23B100000+8000`; w1 `23B108000+1000` (=aic-timebase page, **do not attach**) | — (it is the interrupt controller) | — | **KEEP** `Aic` @ w0 only, `Aic` boot state: all masked (`masked=[!0]`), `Cap0`=N_IRQS | none (window policy already w0-only) |
| 2 | aic-timebase | `23B108000+1000` (device_type="timer", phandle 0x1B) | — | — | **KEEP-W** `AicTimebase`, register set extended per §5.3 | reg set fix (was MainTim-only) |
| 3 | pmgr | **44 windows — full table in §4** | — | cg=[197,198,199,200] | **KEEP-W** → ONE shared-core device on all 44 windows (§4) | attach policy change: 1 window → 44 windows, APSC + gate semantics |
| 4 | nco | `23B044000+14000` | — | — | SKIP | none |
| 5 | wdt | w0 `23D2B0000+4000`; w1 `23D2B8020+4` (skip — inside pmgr AON scratch) | 237, 0 (wire **237** only) | — (clock-ids=[4]) | **KEEP-W** `AppleWdt` with corrected register map (§5.7) | register map fix |
| 6 | gpio | `23C100000+100000` | 131,132,133,134,135,136,137 (aic) | — | **KEEP** `Gpio`; interrupt fan-in shim (§6.4) | IRQ wiring (new) |
| 7 | mcc | `200100000+80000`, `200000000+100000`, `200200000+100000` | — | — | SKIP (RAZ-with-log; early-ish) | none |
| 8 | error-handler | 17 windows: `200100000+60000`, `200000000+1000`, `20001C000+C000`, `200004000+12400`, `200040000+1000`, `20005C000+C000`, `200044000+12400`, `200080000+1000`, `20009C000+C000`, `200084000+12400`, `2000C0000+1000`, `2000DC000+C000`, `2000C4000+12400`, `241440000+14000`, `241400000+4000`, `23B000000+A1000`, `200200000+100000` | 141,185,145,148,151,154 | — | SKIP (RAZ-with-log) | none |
| 9 | dwi | `23B200000+4000` | 4 | 50 | SKIP (RAZ-with-log; gate 50 known) | none |
| 10 | pwm | `23500C000+1000` | 456 | 64 | SKIP | none |
| 11 | aes | w0 `235008000+4000`; w1 `23D2D0000+4000` (skip — pmgr AON) | 455 | 85 | **KEEP** `AesEngine` @ w0 | none |
| 12 | aop | w0 `24A400000+20000`; w1 `24A050000+4000`; w2 `24AE00000+1E0000`; w3 `23D2A8000+8` (skip — pmgr AON) | 210,209,212,211 | — | **KEEP** `Aop` @ w0 | none |
| 13 | dart-aop | `24AC00000+4000` | 224 | — | **KEEP** `Dart` | none |
| 14 | dapf-aop | `24AC04000+1000` | — | — | **SWAP→NEW** `dapf` shim (§5.2) | was `aop` — wrong model |
| 15 | aop-gpio | `24A820000+4000` | 196,197,198,199,200,201,202 (aic) | — | **KEEP** `Aop` stub (really a GPIOIC behind AOP — revisit M7) | none |
| 16 | nub-gpio | `23D1F0000+4000` | 233,234,235,226,227,228,229 | — | **KEEP** `Gpio` | none |
| 17 | smc-gpio | `23E820000+4000` | 261,262,263,264,265,266,267 | — | **KEEP** `Smc` family shim | none |
| 18 | pmp | 38 windows: `23BC00000+60000`, `23B850000+200000`, `23B500000+60000`, `200020000+4000`, `200060000+4000`, `2000A0000+4000`, `2000E0000+4000`, `200154000+4000`, `200204000+4000`, `200244000+4000`, `200284000+4000`, `2002C4000+4000`, 5× `200000000+0` (zero-size, skip), `204D14000+4000`, `210058000+4000`, `210158000+4000`, `210258000+4000`, `210358000+4000`, `210E20000+60000`, `210E48000+4000`, `211058000+4000`, `211158000+4000`, 2× `200000000+0`, `211E20000+60000`, `211E48000+4000`, `23D100000+14000`, `23D128000+30000`, `23D180000+4000`, `26B854000+4000`, `26B8F0000+4000`, `200170000+4000`, `23500C000+4000`, `23C100000+4000` | 359,358,361,360 | cg=pg=[123,124] | SKIP (RAZ-with-log; B1 makes its pmgr-nested windows visible when needed) | none |
| 19 | dart-pmp | `23B300000+4000` | 362 | — | **KEEP** `Dart` | none |
| 20 | sep | `242400000+10000` | 181,180,183,182 | 134/134 | **KEEP** `SepSim` | none |
| 21 | dart-sep | `2412C0000+4000` | 186 | — | **KEEP** `Dart` (needs B1: inside SEPROM Ram span) | none |
| 22 | sio | `236400000+20000`, `236050000+4000` | 485,484,487,486 | 227/62 | SKIP (RAZ-with-log) | none |
| 23 | dart-sio | `235004000+4000` | 482 | 176/176 | **KEEP** `Dart` | none |
| 24 | ans | w0 `277400000+C000` (ASC/RTKit side); w1 `277050000+4000` (admin, skip); w2 `27AD20044+4` (lock reg, skip); w3 **`27ACC0000+60000` = NVMe BAR** (BOOT_STATUS 0x1300, doorbells, eMVN pages +0x28000/+0x34000); w4 `279000000+18000`; w5 `27AB90000+8000`; w6 `27AD47C00+400`; w7 `27AD60000+8000`; w8 `27AD70000+8000` (w1,w2,w4-w8 skip) | 417,416,419,418,**422**(nvme-interrupt-idx=4) | 128/128 | **KEEP-W** `Ans2Nvme` **dual attach**: w0 ASC shim + w3 NVMe BAR, one shared state (§5.5) | was attached at w0 only — BOOT_STATUS/doorbells live at w3 |
| 25 | sart-ans | `27AC50000+8000` (sart-version=1) | — | — | **KEEP-W** `Sart` rewritten to **v1 layout** (§5.4) | register semantics rewrite |
| 26 | smc | w0 `23E400000+20000`; w1 `23E050000+4000` (skip) | 271,270,273,272 | — | **KEEP** `Smc` for now; **NEW** endpoint model at rank 5 (§5.6) | transport fix deferred to rank 5 |
| 27 | rsm | `23D325000+1000`, `23D003100+8` | 157 | 22 | SKIP | none |
| 28 | dart-rsm | `23D328000+4000` | 160 | — | **KEEP** `Dart` | none |
| 29 | dockchannel-uart | w0 `23D128000+10000`; w1 `23D10C000+1000` (device_type="dockchannel", enable-sw-drain=1, max-aop-clk=0x112A8800, no compatible, no IRQ) | — | — | **SWAP→NEW** `dockchannel` RAZ/sink shim (§5.1); both windows | was `s3c-uart` — wrong protocol |
| 30 | uart0 | `235200000+4000` (boot-console) | 435 | 76 | **KEEP** `S3cUart` → console sink | IRQ wiring (new) |
| 31 | uart4 | `235210000+4000` | 439 | 80 | **KEEP** `S3cUart` (own sink, not console) | IRQ wiring |
| 32 | uart7 | `23521C000+4000` | 442 | 83 | **KEEP** `S3cUart` | IRQ wiring |
| 33 | spi1 | `235104000+4000` | 445 | 71 | **KEEP** `Spi` | IRQ wiring |
| 34 | spi3 | `23510C000+4000` | 447 | 73,216 | **KEEP** `Spi` | IRQ wiring |
| 35-38 | i2c0-i2c3 | `235010000/235014000/235018000/23501C000` +`1000` | 457,458,459,460 | 65,66,67,68 | **KEEP** `I2c` | IRQ wiring |
| 39-40 | smc-i2c0/1 | `23ED04000+1000`, `23ED08000+1000` | 256,257 | 32,33 | **KEEP** `Smc` family shim | none |
| 41-43 | spmi0-2 | `23D180700+100`, `23D184700+100`, `23D188700+100` (+ 3 aux windows each: `+D00+100`, `+E00+64`, `+014+4`) | spmi0: 192,239,196-205,208-214,216-223; spmi1: 192,244,…(24); spmi2: 192,249,…(27); **interrupt-parent = themselves** | — | **KEEP** `SpmiPmu` @ w0 | none |
| 44 | atc-phy | `239000000+4`, `239000060+20` | — | 102 | SKIP | none |
| 45 | usb-drd | `239010000+10000`, `239020000+10000`, `23901C000+1800` | 497,498,499,500 | 103,245 | **KEEP** `TypecOtg` @ w0 | none |
| 46 | dart-usb | `239024000+4000`, `239028000+4000` | 501 | 177/177 | **KEEP** `Dart` @ w0 | none |
| 47 | mipi-dsim | w0 `230400000+C0000`; w1 `2304C0000+10000` (skip) | 322,328 | 113/113 | **KEEP** `MipiDsi` @ w0 | none |
| 48 | disp0 | w0 `230000000+2FC000`; w1 `230708000+1000` **= dapf-disp0 page — EXCLUDE from adp-v4**; w2 `230721000+1000`; w3 `23B0B8000+1000`; w4 `23BC04840+1000`; w5 `23BC2C000+1000` | 317,323,314,315,316,318,313,324,325 | 160-163/160-163 | **KEEP-W** `AdpV4` @ w0 (others skip; w1 owned by row 49) | window trim (reg[1] would collide with the dapf shim — identical window in both nodes) |
| 49 | dapf-disp0 | `230708000+1000` | — | — | **SWAP→NEW** `dapf` shim (§5.2) | was `adp-v4` — wrong model |
| 50 | dart-disp0 | `230704000+4000`, `230700000+4000` | 319 | 179/179 | **KEEP** `Dart` @ w0 | none |
| 51 | scaler0 | `263000000+20000`, `263210000+4000` | 429,431 | 240,122,217 | **KEEP** `Scaler` @ w0 | none |
| 52 | dart-scaler | `263200000+4000` | 430 | 182/182 | **KEEP** `Dart` | none |
| 53 | jpeg0 | `265000000+4000` | 423 | 224,195,206 | SKIP | none |
| 54 | dart-jpeg0 | `265004000+4000` | 424 | 180/180 | **KEEP** `Dart` | none |
| 55 | jpeg1 | `265008000+4000` | 426 | 225,195,206 | SKIP | none |
| 56 | dart-jpeg1 | `26500C000+4000` | 427 | 181/181 | **KEEP** `Dart` | none |
| 57 | isp | `22A000000+1F09000`, `23B080000+D000`, `23C260000+4000`, `23C280000+4000` | 173,174,175,176 | 229,56-59 | SKIP | none |
| 58 | dart-isp | `22BAC8000+4000`, `22BAD0000+4000`, `22BAD8000+4000`, `22BACC000+4000`, `22BAD4000+4000` | 178 | 183/183 | **KEEP** `Dart` @ w0 | none |
| 59 | ave | `267100000+300000`, `267800000+45C000`, `267050000+1000`, `23B088000+4000` | 394,388,387,390,389 | 9 ids | SKIP | none |
| 60 | dart-ave | `267030000+4000`, `267040000+4000`, `267020000+4000` | 391 | 184/184 | **KEEP** `Dart` @ w0 | none |
| 61 | avd | `268000000+2000000` | 375,376 | 231,196,207 | SKIP | none |
| 62 | dart-avd | `269010000+4000` | 382 | 185/185 | **KEEP** `Dart` | none |
| 63 | ane | `26A000000+1F00000`, `23B080000+80000` | 293 | 243/243 | SKIP | none |
| 64 | dart-ane | `26B800000+4000`, `26B810000+4000`, `26B820000+4000` | 294 | 178/178 | **KEEP** `Dart` @ w0 | none |
| 65 | sgx | `204000000+100000`, `204D00000+20000` | 397,398,399,400,412,414 | 208,210 | SKIP | none |
| 66 | gfx-asc | `206400000+20000`, `206050000+8` | 409,408,411,410 | 209/209 | SKIP | none |
| 67 | mapper-gfx-asc | no reg | — | — | SKIP | none |
| 68 | mca-switch | `238400000+18000`, `238300000+30000`, `23B0400B4+18`, `238500000+4` | — | 88-93 | **KEEP** `Mca` @ w0 (needs B1 vs rows 69-70) | none |
| 69-74 | mca0-mca5 | `238400000/238404000/238408000/23840C000/238410000/238414000` `+4000` + 2 aux windows each in `2383xxxxx+4000` | 448,449,450,451,452,453 | — | **KEEP** `Mca` @ w0 (B1 required — mca-switch shadows mca0/mca1 today) | none |
| 75-76 | alc0/alc2 | no reg | — | — | SKIP | none |
| 77 | apcie | 22 windows: w0 `610000000+1000000`; `600000000+4000`; `600080000+90000`; `6000C0000+18000`; `60C000000+8000`; `23D2BC000+1000`; `601000000+8000`; `601010000+1000`; `600088000+4000`; `6000C4000+8000`; `602000000+8000`; `602010000+1000`; `60008C000+4000`; `6000C8000+8000`; `603000000+8000`; `603010000+1000`; `600090000+4000`; `6000CC000+8000`; `604000000+8000`; `604010000+1000`; `600094000+4000`; `6000D0000+8000` | 532,535,538,541 | 125,126,128,60 | **KEEP** `Apcie` @ w0; **NEW**: dapf shims at `601008000+4000` / `602008000+4000` (NOT apcie windows — §8 conflict #3) | +2 NEW shims |
| 78 | dart-apcie2 | `603008000+4000` | 539 | — | **KEEP** `Dart` | none |
| 79 | dart-apcie3 | `604008000+4000` | 542 | — | **KEEP** `Dart` | none |
| 80 | amc | `200000000+1000` | — | — | SKIP | none |
| 81 | sochot0 | `23B0C4000+1000`, `23B2E4000+11000`, `211ED2000+B0000`, `23D2BC000+4000`, `210ED2000+1000` | — | — | SKIP | none |
| 82-94 | tempsensor0-5, mtrtempsensor6/7/8/11/13/14/15 (13 rows) | `23B2C4000+34000` ×3, `211ED0000+10000` ×2, `210ED0000+10000`, `23B281000+8000`, `23B289000+8000`, `23B299000+8000`, `211EE1000+16000` ×2, `23B2E0000+8000` ×2 | 8,10,12,78,80,45,26,16,14,89,89 (mtr14/15 have none) | — | SKIP (safe-skip list) | none |
| 95-98 | dietempctl0, vtempctl0, smctempsensor0, cpu-debug-interface | no reg | — | — | SKIP | none |
| 99 | aft | `200144000+4000` | — | — | SKIP | none |
| 100-103 | aod2, pearl-sep, haptics-support-interface, audio-resource-manager | no reg (pearl-sep has cg=[246,215,216,218] but no reg) | — | — | SKIP | none |
| 104 | wlan | `reg = 0xF` (single u64, not a pair — must NOT attach; `reg_entries` returns 0 pairs so `attach_from_adt` skips ✓) | — | — | SKIP | none |
| 105 | bluetooth | `reg = 0xF` (same) | 108, 0x02000002 (**gpio-parented**, 2 cells) | — | SKIP | none |

**Tally:** of 94 reg-bearing rows — 59 attach today; after this spec:
**10 rows change attach behavior materially** (rows 2, 3, 5, 24, 25, 29, 48, 49,
14, 77) + 1 dead-code deletion (P4) + IRQ/clock-gate wiring newly covers the 73
aic-parented rows (§6). 35 remain SKIP, 11 no-reg skip. No node keeps a wrong
base: every base above is byte-verified against armio_rows.json / the raw ADT.

### classify() patch list (exact, in current first-match order)

```rust
// t8030.rs classify() — insert before m("aic"):
if node_name.contains("dapf") || compat_all.iter().any(|c| c.starts_with("dapf")) {
    return Some("dapf");                    // NEW shim (§5.2) — fixes rows 14, 49
}
// insert before m("uart")||m("s3c"):
if node_name.contains("dockchannel") {      // row 29: no compatible; name is the only key
    return Some("dockchannel");             // NEW shim (§5.1)
}
// keep m("aic") AFTER the existing timebase arm (row 2).
// m("disp")||m("adp")||m("dpa") now matches ONLY row 48 (dapf intercepted above).
// delete the unreachable "dart-ans" arm in attach_fallback (P4).
```
Attach-site changes: `pmgr` → 44-window shared-core (§4); `ans2-nvme` → dual
window attach (§5.5); `disp0`/`adp-v4` → skip reg[1]; `apcie` → + 2 DISD dapf
shims; drop `size.max(0x1000)` rounding in favor of per-window exact sizes with
a floor of 0x1000 only for zero-size windows (keeps `200000000+0` pmp rows
harmless); apply B1.

---

## 3. (reserved — see §2 for the mapping table)

---

## 4. PMGR — one device, 44 windows (armio_rows.json row 3)

### 4.1 Window table (from the raw ADT `reg` prop; `lin` = byte offset in the
CONCATENATED map — AppleT8030PMGR addresses registers by this LINEAR offset
through the vtable-slot helper, measured in m5-peripheral-queue §2.1)

| win | abs base | size | lin off | lin end | note |
|---:|----------|-----:|--------:|--------:|------|
| 0 | 0x23B000000 | 0x100000 | 0x0 | 0x100000 | main pmgr-reg: APSC 0xE2020/0xE2588, ps-regs +0x80000 |
| 1 | 0x23D200000 | 0x100000 | 0x100000 | 0x200000 | AON (fuses; Rust consts 0x3D280088/0x3D2BC0xx/0x3D2E8000 live here) |
| 2 | 0x23D004000 | 0x1000 | 0x200000 | 0x201000 | |
| 3 | 0x210E20000 | 0x15000 | 0x201000 | 0x216000 | |
| 4 | 0x210F00000 | 0x50000 | 0x216000 | 0x266000 | |
| 5 | 0x210E40000 | 0x10000 | 0x266000 | 0x276000 | |
| 6 | 0x210E50000 | 0x1000 | 0x276000 | 0x277000 | |
| 7 | 0x210E70000 | 0x90000 | 0x277000 | 0x307000 | |
| 8 | 0x210050000 | 0x10000 | 0x307000 | 0x317000 | cpufreq cluster E0 |
| 9 | 0x210150000 | 0x10000 | 0x317000 | 0x327000 | cpufreq cluster E1 |
| 10 | 0x210250000 | 0x10000 | 0x327000 | 0x337000 | cpufreq cluster E2 |
| 11 | 0x210350000 | 0x10000 | 0x337000 | 0x347000 | cpufreq cluster E3 |
| 12 | 0x211E20000 | 0x15000 | 0x347000 | 0x35C000 | mirrored set (P-cluster side) |
| 13 | 0x211F00000 | 0x50000 | 0x35C000 | 0x3AC000 | |
| 14 | 0x211E40000 | 0x10000 | 0x3AC000 | 0x3BC000 | |
| 15 | 0x211E50000 | 0x1000 | 0x3BC000 | 0x3BD000 | |
| 16 | 0x211E70000 | 0x90000 | 0x3BD000 | 0x44D000 | |
| 17 | 0x211050000 | 0x10000 | 0x44D000 | 0x45D000 | |
| 18 | 0x211150000 | 0x10000 | 0x45D000 | 0x46D000 | |
| 19 | 0x23BC1C000 | 0x40000 | 0x46D000 | 0x4AD000 | |
| 20 | 0x23B280000 | 0x40000 | 0x4AD000 | 0x4ED000 | (temp-sensor block under it: rows 88-90) |
| 21 | 0x23D180000 | 0x2000 | 0x4ED000 | 0x4EF000 | spmi0/1/2 live at 0x23D180700/…4700/…8700 (B1 lets spmi win) |
| 22 | 0x23D100000 | 0x80000 | 0x4EF000 | 0x56F000 | ⊃ dockchannel-uart + pmp AON windows (B1) |
| 23 | 0x23B204000 | 0x10000 | | | |
| 24 | 0x26B8EC000 | 0x10000 | | | GPU (overlaps win25 — B1) |
| 25 | 0x26B8F4000 | 0x10000 | | | GPU |
| 26-37 | 0x262000000, 0x264000000, 0x266000000, 0x268000000, 0x26A000000, 0x22A000000, 0x231000000, 0x205000000, 0x60C000000, 0x234000000, 0x200148000, 0x279000000 | +0xD000 each | | | media vnom pages |
| 38 | 0x225000000 | 0x15000 | | | cpupm (overlaps 39/40 — B1) |
| 39 | 0x225004000 | 0x4000 | | | cpupm |
| 40 | 0x225008000 | 0x4000 | | | cpupm |
| 41 | 0x226000000 | 0x15000 | | | cpupm (overlaps 42/43 — B1) |
| 42 | 0x226004000 | 0x4000 | | | cpupm |
| 43 | 0x226008000 | 0x4000 | | | cpupm |

Total concatenated span = **0x675000** (6,770,688 B). Exact per-window `lin`
offsets for wins 23-43 are computed by summation at attach time (the generator
in this session's transcript emits all 44); wins 0-22 are shown with explicit
values because the measured APSC offsets and the ps-regs window live there.

### 4.2 Implementation shape (Rust-visible)

```rust
struct PmgrCore {                       // one Arc<Mutex<PmgrCore>>
    scratch: BTreeMap<u64, u32>,        // linear-offset → last written word
    apsc: [u32; 2],                     // last TARGET written to 0xE2020 / 0xE2588 (default 0xF)
    gates: BTreeMap<u32, u32>,          // gate id → last TARGET (default 0xF)
    gate_names: BTreeMap<u32, &'static str>, // parsed from the ADT `devices` prop
    unknown_reads: u64, unknown_writes: u64,
}
struct PmgrWindow { core: Arc<Mutex<PmgrCore>>, lin: u64 }  // 44 of these
impl Device for PmgrWindow {            // name() == "pmgr"
    fn read(&mut self, off, _)  { self.core.lock().read(self.lin + off) }
    fn write(&mut self, off, _, v) { self.core.lock().write(self.lin + off, v) }
}
// attach: for w in PMGR_WINDOWS { bus.attach(w.base, w.size, Box::new(PmgrWindow{..})) }
```
The old `Pmgr` (`ps` BTreeMap keyed by `off & !0xF`, 0x34000 cap, synthetic
0x1000 strides) is **replaced wholesale** — none of its offsets match the real
map (m5-adt-census §4: "matches none of the real ids").

### 4.3 APSC polls (measured, m5-peripheral-queue §2.1)

- `_waitAPSCPending` (fn 0xfffffff008b74ee0) polls linear offsets **0xE2020**
  and **0xE2588** (0xE2588 − 0x568 = 0xE2020; w1 = 0/1 = cluster select) — both
  < 0x100000 ⇒ inside window 0 ⇒ abs **0x23B0E2020 / 0x23B0E2588**.
- Semantics: these are CPU-cluster pstate (APSC) control/status registers in
  the Linux/m1n1 PS-register format (m5-peripheral-specs §8): bits 3:0 =
  PS_TARGET (R/W), bits 7:4 = PS_ACTUAL (RO), bit 28 = AUTO_ENABLE, bit 10 =
  DEV_DISABLE, bits 9/8 = WAS_CLKGATED/WAS_PWRGATED (RO sticky), bit 31 RESET.
- **Read answer:** `((target & 0xF) << 4) | (target & 0xF) | (word & 0x1000_0000)`
  where `target` = last low nibble written to that offset (default **0xF**).
  Power-on default read = **0x000000FF** (PS_ACTUAL=0xF "ACTIVE", PS_TARGET=0xF,
  AUTO_ENABLE clear, WAS_*/DEV_DISABLE clear). Rationale: the poll converges
  when PS_ACTUAL == PS_TARGET; mirroring the written target into ACTUAL makes
  every poll converge on the first read (m5-peripheral-specs §8: "emulator must
  mirror writes into ACTUAL immediately") and 0xFF is the correct idle answer
  for a cluster that never left ACTIVE. If a stricter driver check on
  AUTO_ENABLE ever shows up, OR in bit 28 (fallback value 0x100000FF).
- **Write:** store the whole word; the low nibble becomes TARGET (and hence
  ACTUAL on the next read). No delay, no staging.

### 4.4 Gate table (ps-regs window)

- `ps-regs` prop = 120 B = 30×u32; record 0 = `{1, 0x80000, 0xFF800}` — the
  psreg **window offset is 0x80000** inside the main window (matches the Rust
  `PMGR_PSREG_BASE` rename target; ADT-confirmed).
- `devices` prop = 8448 B = **352 records × 24 B** (pairs of 12-B rows); gate id
  = config word0 >> 24. Full id→name map: `m5-adt-census.md` §4 +
  `tools/re/notes/m5-adt-census-raw/pmgr_devices.txt`. Boot-critical ids:
  AIC=49 (always-on, referenced by no node), UART0=76, ANS→128 ("APCIE_ST"),
  darts SIO/USB/ANE/DISP0/JPG0/JPG1/MSR/ISP/VENC/AVD = 176-185, DISP0 = 160-163,
  MIPI_DSI=113, AES=85, SIO=62/227, PMP=123/124, APCIE=125/126/128, PCIE_REF=60,
  GFX=208/209/210, DWI=50, I2C0-3=65-68, PWM0=64, SPI1=71/SPI3=73, SEP=134.
- **Gate read:** offset `0x80000 + id*0x18` → same PS-format mirror as APSC
  (default target 0xF ⇒ reads 0xFF = on). **Stride 0x18 is UNCONFIRMED**
  (m5-peripheral-queue §7.2) — mitigation: treat any read in
  `[0x80000, 0x80000 + 247*0x18)` as a gate PS read with
  `id = (off-0x80000)/0x18`; the mirror semantics are stride-independent as
  long as the driver's own math lands in that span, so a wrong stride degrades
  to "always powered", never to a hang.
- `clock-gates` from each node (column in §2) feeds
  `PmgrCore::gates.insert(id, 0xF)` at attach (defect (e) fix, §6.5).
- Everything else in all 44 windows: **scratch R/W** — store on write, read
  returns the stored word, never-written reads return 0, both counted
  (`unknown_reads/writes`). No offset is rejected; no access can stall.

---

## 5. New-shim specs

### 5.1 dockchannel-uart (row 29) — replaces the second S3cUart

- ADT: no compatible, `device_type="dockchannel"`, reg w0 `23D128000+10000`,
  w1 `23D10C000+1000`, no IRQs, no cg, `enable-sw-drain=1`,
  `max-aop-clk=0x112A8800`. It is the AOP-side dock/debug serial channel; the
  kernel's boot console is uart0 (`boot-console` prop, row 30). No kext-name
  string for it was mined in our notes (honest limit) — classification keys on
  the node name only.
- Why not S3cUart: a dockchannel driver polling S3C `UTRSTAT`(0x10)=0x6 /
  writing `UTXH`(0x20) is protocol-wrong, and worse, `S3cUart::UTXH` writes
  into the **console sink**, corrupting the boot log with dockchannel bytes.
- **Boot-minimal model** (new `DockChannel` device, both windows share state):
  - reads: RAZ — return 0 for every offset; count `unknown_reads`.
  - writes: drop (count `unknown_writes`); optionally push `(val & 0xFF)` into
    a dedicated `Arc<Mutex<Vec<u8>>>` dockchannel sink (NOT the console sink)
    so a later session can mine dockchannel debug output. No FIFO, no IRQ, no
    clock gating. Nothing in the measured pre-stop boot path touches it
    (m5-device-census: 0 touches), so RAZ is sufficient for M5 boot; the sink
    is the only affordance worth adding.

### 5.2 dapf — DART address filter (rows 14 `dapf-aop`, 49 `dapf-disp0`, + the
two ownerless apcie DISD pages)

- `compatible="dapf,t8020"`, 1 window `0x1000` each:
  dapf-disp0 `230708000+1000`, dapf-aop `24AC04000+1000`. A DAPF gates which
  PA ranges a DART stream may reach; it is a DART-family block (NOT a display
  pipe, NOT an ASC coprocessor — the current `adp-v4`/`aop` attaches are the
  defect). Note `disp0 reg[1] == dapf-disp0 reg[0]` (identical window declared
  by two nodes): the dapf shim owns it; `adp-v4` must exclude reg[1] (§2 row 48).
- Plus the two **DISD-tagged** pages from `/defaults/pmap-io-ranges`
  (`601008000+4000`, `602008000+4000`) — the apcie ports 0/1 SID filters. The
  task brief claims they are apcie reg windows: **they are not** (§8 #3); they
  have no /arm-io owner, but the kernel whitelists them, so attach the same
  shim there.
- **Boot-minimal model** (`Dapf` device, ~0x1000/0x4000 span):
  - `0x0` (TCR): store-on-write, read returns stored (default 0). TCR=0 means
    TRANSLATE_ENABLE(bit7)=0 ⇒ bypass ⇒ no faults — the boot-safe answer.
  - every other offset: RAZ (read 0, write drop, counted).
- Rationale: m5-device-census measured 0 touches pre-stop; DAPF pages are
  probe-late (disp0/aop iommu parents). If a post-stop run shows a driver
  writing TCR=translate-enabled and reading back, upgrade to the full DART
  shim; until then this cannot hang boot.

### 5.3 aic-timebase (row 2) — banked timebase page, not a second AIC

- What the kernel does with it (m4-aic-timer-re §4, measured): pexpert maps
  `gTimerBase` = the `device_type="timer"` node = `23B108000+1000`; a driver
  fn @0x834edac writes **[timerbase+0x2014 / +0x2018]** (the 64-bit banked
  counter, two 32-bit halves), plus `0x201C`, `0x2020`, `0x200C`, `0x2010` —
  i.e. the AIC per-CPU timer block (TmrCnt/TmrIntStat/TmrStateSet/TmrStateClr/
  IPIClr/TmrCfg offsets of the AIC.h map) re-based on the timebase page.
  FIQ delivery never goes through it (xnu samples CNTV_CTL ISTATUS directly).
- Current `AicTimebase` only answers 0x20/0x28 (MainTimLo/Hi) — extend:
  | offset | semantics |
  |---|---|
  | 0x20 / 0x28 | MainTimLo/Hi — RO mirror of the global 64-bit timebase (keep; pexpert AIC.h kAICMainTimLo) |
  | 0x2010 | TmrCfg — R/W scratch (bit0 En) |
  | 0x2014 | banked counter low 32 — R/W |
  | 0x2018 | banked counter high 32 — R/W (the measured 64-bit split) |
  | 0x201C / 0x2020 | TmrStateSet/Clr — R/W scratch |
  | 0x200C | IPIClr — W1C-style ack (scratch) |
  | everything else | RAZ |
- Counter source: free-running; drive from `Device::tick` at 24 MHz (the
  effective timebase frequency — m4-aic-timer-re §2) or alias CNTVCT. Boot
  only needs write-then-read-back equality, so a plain stored counter + tick
  increment satisfies the driver.

### 5.4 sart-ans (row 25) — SART v1 "Marconi" (m5-peripheral-queue §2.2)

Replaces the current `Sart` transactional model (CONFIG/INDEX/ADDR_LO/HI/SIZE/
FLAGS/STATUS at 0x400-0x41C — **wrong layout for T8030**; that is the stale
pre-2023 Asahi v1 recollection m5-peripheral-specs §4 warned about).

- Base `27AC50000+8000` (pmap-io-ranges record 30 tags it `1TRS` = SART v1 —
  independent confirmation).
- Register file = **16 entries × 8 bytes** (entry count from the provider ivar;
  16 = APPLE_SART_MAX_ENTRIES in Linux/m1n1 — flag: T8030-specific count
  unmeasured, 16 is the safe default):
  - `CONFIG(idx) @ base + 8*idx + 0` (32-bit)
  - `PADDR(idx)  @ base + 8*idx + 4` (32-bit)
- Value semantics the driver builds (fns 0xfffffff0085e8c30 / 0x85e8c68):
  - `PADDR = PA >> 12` (asserts PA 4K-aligned, PA < 0x1_FFFF_F000)
  - `CONFIG = (size >> 12) | flag`, flag = **0x100000** or **0x300000**
    (asserts size 4K-aligned, size < 0x7_FFFF_F001)
- Program loop: write PADDR then CONFIG per 16-byte region row; afterwards a
  **verify pass re-reads PADDR/CONFIG and compares — mismatch panics**
  (0x85e8b0c-0x85e8b44). Therefore the model MUST store and return exactly what
  was written, per index, with no translation/rounding.
- **Emulator semantics:** `regs: [u32; 32]` (16×{config,paddr}), power-on
  defaults **0** (all entries free — Linux treats flags==0 as free at probe).
  write(off, v): `regs[off/4] = v`. read(off): `regs[off/4]`. Offsets ≥ 0x80
  (rest of the 0x8000 window): RAZ counted. Optional host-side helper (not
  needed for boot): `allow(PA,len)` = ∃ idx: `regs[2i]>>0 & 0xFFFFF` size pages
  covering PA with flag bit 20 set.
- Keep the current `Sart::program()`/`translate()` host API out of the Device
  impl (or re-point it at the v1 array) so the ANS DMA path can consult it later.

### 5.5 ans / ans2-nvme BOOT_STATUS + window split (row 24)

- Measured (m5-peripheral-queue §2.3): `AppleANS2NVMeController` reads
  offset **0x1300** and compares against **0xDE71CE55**, retry budget
  **0x186A0** (100,000) iterations, 1 s poll cadence (Linux/m1n1 contract).
  The NVMe BAR is ans **reg[3] `27ACC0000+60000`** (pmap-io-ranges eMVN pages
  `27ACE8000+4000` = +0x28000 and `27ACF4000+4000` = +0x34000 sit inside it);
  reg[0] `277400000+C000` is the ASC/RTKit coprocessor side. Today the model
  is attached at reg[0] only ⇒ BOOT_STATUS/doorbell accesses at 0x27ACC0000
  would bus-miss.
- **Decision (honest model): return 0xDE71CE55 immediately from reset.** The
  ANS firmware is not emulated — there is nothing to "stage" against, and the
  thing that would gate it (RTKit HELLO/STARTEP) is itself a shim. This is what
  the current `Ans2Nvme` does (`NVME_APPLE_BOOT_STATUS` → `0xde71ce55`) and
  what the ChefKiss-Inferno lineage does. Do NOT add poll-count staging: the
  driver's 100k budget makes any staged answer pure risk. If a later RTKit
  shim requires the handshake before ANS probe, gate the 0xDE71CE55 read on
  `rtkit_start()` (`started` flag already exists) — one-line change, noted for
  the vault-mining follow-up; not for M5.
- **Attach:** two `Ans2Nvme`-family devices sharing one state `Arc`:
  w0 `277400000+C000` → ASC/RTKit shim side (mailbox regs per §5.6 ASC map;
  writes dropped/reads 0 until the RTKit model lands), w3 `27ACC0000+60000` →
  the existing NVMe model (its offsets 0x000-0x1300 CAP/VS/CC/CSTS/AQA/ASQ/ACQ/
  doorbells 0x1000/0x1004, 0x1210 MAX_PEND, 0x1300 BOOT_STATUS, 0x24908
  LINEAR_SQ_CTRL, NVMMU 0x28100-family are all already in `ans2_nvme.rs` and
  belong to THIS window). w1/w2/w4-w8: skip.
- Doorbell-style decision (t8015 0x1000-family vs t8103 0x2490C) stays open
  (queue §7.1) — both offsets already exist in the model; re-run the census
  when the path reaches ANS.

### 5.6 SMC endpoint — minimal boot model (row 26, rank 5)

Measured (m5-peripheral-queue §2.4): transport = RTKit-style endpoint/mailbox,
NOT the MMIO key/cmd handshake the current `Smc` models. Evidence: 8-byte
message buffer at ivar `self+0x102`, 4-bit rolling msg-id at `self+0x112`,
send/poll through the endpoint object at `[self+0xc0]`, poll budget 1,000,000 µs
in 1000-loop chunks, 24-byte result packet, result byte 0x70 = retry, id echo
compared at `self+0x103`. ADT: child `iop-smc-nub` compatible
`iop-nub,rtbuddy-v2`, `firmware-name="t8030smc"`, `region-base=0x3FF00000`
`region-size=0x80000`.

Minimal model (only when boot reaches rank 5 — do not spend it earlier):
1. ASC mailbox regs in the smc w0 window (m5-peripheral-specs §6 ASC map):
   CPU_CONTROL 0x44 (bit4 RUN, read-back set), A2I_CONTROL 0x110 / I2A_CONTROL
   0x114 (FULL=bit16, EMPTY=bit17 — advertise I2A EMPTY, A2I not-FULL),
   A2I_SEND 0x800/0x808, A2I_RECV 0x810/0x818, I2A_SEND 0x820/0x828, I2A_RECV
   0x830/0x838.
2. RTKit protocol on the mailbox (m1n1 rtkit.c): HELLO →
   reply (MINVER=11, MAXVER=12); EPMAP → bitmap with endpoint 0x20 (SMC) bit
   set; STARTEP(0x20) → ack; PWRSTATE → accept.
3. SMC messages on endpoint 0x20 (message word `MSG=7:0, ID=15:12, SIZE=23:16,
   WSIZE=31:24, DATA=63:32`): answer INITIALIZE(0x17) and READ_KEY(0x10) from a
   static key table (seed = current `Smc::new()` keys: RMde="AppleSE", MSLD=0;
   extend as xnu asks), result packet = 24 B with RESULT=0 and ID echo; key
   data via the shared buffer at 0x3FF00000+0x80000 (attach a Ram region there
   if not already).
4. Keep the legacy MMIO-key `Smc` code path behind the new one until this lands;
   it is harmless pre-probe.

### 5.7 wdt (row 5) — corrected register map

Current `AppleWdt` offsets (RST 0x0 "write 1 = kick", CTRL 0x8, CNT 0x10,
PERIOD 0x1C) collide with the real map (0x8 = WD0_BARK_TIME, 0x10 = WD1_CUR…).
Replace with the m1n1/Linux map (m5-peripheral-specs §7, kept for the emulator
by queue §2.5):

| offset | name | semantics |
|---|---|---|
| 0x00/0x10/0x20 | WDx_CUR_TIME | R/W free-running tick counter; **write 0 = kick** |
| 0x04/0x14/0x24 | WDx_BITE_TIME | reset threshold (ticks) |
| 0x08 | WD0_BARK_TIME | IRQ (bark) threshold — WD0 only |
| 0x0C/0x1C/0x2C | WDx_CTRL | bit0 IRQ_EN, bit1 IRQ_STATUS (W1C), bit2 RESET_EN |

Boot-critical behavior (queue §2.5): kernel disables with **CTRL=0** at
arm_init; reboot sequence = **BITE=0x100000, CUR=0, CTRL=4**; kick = CUR=0.
Emulator: counters tick but never bite unless the guest armed it
(BITE_TIME != 0 && CTRL bit2); if armed and it expires, raise
`reset_requested` (existing plumbing). IRQ 237 = bark line into AIC (§6).
reg[1] `23D2B8020+4`: skip (pmgr AON scratch answers under B1).

---

## 6. IRQ wiring spec

### 6.1 ADT decode (verified this session)

- `interrupt-parent` is a single LE u32 phandle. Global counts:
  **aic (phandle 0x1A) = 79 nodes** (73 /arm-io children + 6 /cpus children),
  gpio (0x23) = 4, spmi0/1/2 = 2/2/1 (self-referential; spmi are their own
  controllers). NOTE: the 90-node figure in m5-peripheral-queue §1 is wrong —
  see §8 #1.
- `aic` node: `#interrupt-cells = 1` ⇒ for aic-parented nodes, `interrupts` is
  a **flat array of u32 HW IRQ numbers, one cell each** (no flags cells).
- `gpio` node: `#interrupt-cells = 2` ⇒ gpio-parented nodes have (pin, flags)
  pairs — only `bluetooth` (interrupts = [108, 0x02000002]) at /arm-io level.
- Max aic-parented HW IRQ = **542** (dart-apcie3); 77 of 105 rows carry IRQs.
- Per-CPU timer/IPI (from /cpus, m5-adt-census §3): timer IRQs 60/63/66/69/94/97
  (E0-E3/P0-P1), IPI space 576+ (576/577 per cpu, stride 2);
  `aic target-destinations` = {60→1, 63→2, 66→4, 69→8, 94→16, 97→32, 414→512}.

### 6.2 Mechanism

Today `Aic` is moved into the bus as `Box<dyn Device>` and only the
`irq_line: Arc<AtomicBool>` crosses back to the CPU. For device→AIC asserts:

1. Hold the controller as `Arc<Mutex<Aic>>`; attach a thin facade device that
   forwards read/write to it (keeps `Bus` unchanged).
2. Give modeled devices an `AicHandle` (`Arc<Mutex<Aic>>` clone) at attach.
3. `Aic::assert_irq(n)` = `self.set_irq(n, true)` (the method already exists;
   add the alias named in the task). Level-drop via `set_irq(n, false)` after
   the model deasserts (or leave latched — IACK auto-masks, EOI re-unmasks,
   which matches the AIC protocol for edge-ish devices).
4. `N_IRQS = 1024` already covers 542 HW + IPI 576-587 + slack (queue's
   `Aic::new(640)` suggestion is subsumed).

### 6.3 Attach-time IRQ table (drive these from the §2 rows)

| device (row) | IRQs to wire |
|---|---|
| wdt (5) | 237 (bark; second cell `0` = placeholder, do not wire) |
| gpio (6) | 131-137 = its 7 group outputs INTO aic; gpio-parented pins (bluetooth 108) fan-in via a group — M5: register only |
| uart0/4/7 (30-32) | 435 / 439 / 442 (assert on RX-nonempty) |
| spi1/spi3 (33-34) | 445 / 447 |
| i2c0-3 (35-38) | 457-460 |
| aes (11) | 455 (op complete) |
| aop (12) | 210,209,212,211 |
| sep (20) | 181,180,183,182 |
| ans (24) | 422 = NVMe completion (nvme-interrupt-idx=4 → 5th entry); 417,416,419,418 = ASC/RTKit |
| smc (26) | 271,270,273,272 |
| mipi-dsim (47) | 322,328 |
| disp0 (48) | 317,323,314,315,316,318,313,324,325 |
| dart-* (all 16) | one IRQ each (see §2 rows) — assert on translation fault |
| usb-drd (45) | 497-500 |
| apcie (77) | 532,535,538,541 |
| scaler0 (51) | 429,431 |
| spmi0-2 (41-43) | own-controller lists (their children route through them; M5: register only) |
| cpus (§6.1) | timer FIQ path bypasses AIC (m4-aic-timer-re §2: FIQ = CNTV_CTL ISTATUS); AIC sees 60/63/66/69/94/97 only if the machine models AIC-timer delivery |

At attach time **nothing is asserted** — all lines idle-low; the table exists
so event-driven models (NVMe completion, UART RX, WDT bark) can assert. Boot
init state stays inside `Aic::new()` (all masked).

### 6.4 GPIO fan-in (rank 6)

`Gpio` becomes an interrupt-source shim: `#gpio-pins=212`,
`#gpio-int-groups=7`, IRQs 131-137 into AIC. Minimal: `set_pin(pin, level)` →
group = pin/212*7 mapping placeholder → `assert_irq(131 + group)`. Buttons/
backlight events arrive post-boot; boot needs only the probe to see a quiet
controller (RAZ semantics of the current `Gpio` suffice).

### 6.5 clock-gates wiring (defect (e))

For every §2 row with cg/pg: `attach_from_adt` reads `clock-gates` +
`power-gates` (LE u32 arrays) and calls `PmgrCore::gates.insert(id, 0xF)` (and
optionally a `powered_gates: BTreeSet<u32>` for the host side). Boot-critical
seeds even for unreferenced ids: aic=49, ans→128, uart0=76, darts 176-185,
disp0 160-163. The gate **registers** are answered by the PMGR device (§4.4);
this wiring only pre-powers them so any gate-check read returns ACTIVE.

---

## 7. Priority order (m5-peripheral-queue §5 first-touch ranking → work order)

| rank | work item | rows | why first |
|---:|---|---|---|
| 0 | B1 bus rule + classify() patch list + FALLBACK dead-arm deletion | §0/§2 | precondition; zero-risk |
| 1 | **PMGR one-device 44-window attach + APSC 0xE2020/0xE2588 mirror + gate reads 0x80000+id*0x18 + scratch** | 3 | predicted first heavy MMIO consumer (gates/pstates feed everything) |
| 2 | **AIC keep + aic-timebase banked block (§5.3) + IRQ wiring (§6)** | 1, 2, + 73 | AIC kext probe (mask-all init), timer IRQs 60/63/66/69/94/97, IPI 576+ |
| 3 | **WDT corrected map (§5.7)** | 5 | kernel watchdog init (CTRL=0) at arm_init time |
| 4 | **SART v1 rewrite (§5.4) → ANS dual-window + BOOT_STATUS (§5.5)** | 25, 24 | rootfs gate: RTKit boot → SART carve-outs → doorbells → 0x1300 poll |
| 5 | **SMC endpoint model (§5.6)** | 26 | SMC endpoint boot; charger/buttons idle until userland |
| 6 | **GPIO fan-in shim (§6.4)** | 6, 15, 16, 17 | interrupt fan-in; buttons/backlight events |
| 7 | **disp0 window trim + dapf shims + dockchannel shim (§5.1/§5.2)** | 48, 49, 14, 29, 77 | M6 GUI path; disp0/mipi 0x23000000/0x230400000 |
| — | SKIP rows stay SKIP (RAZ = bus-miss silent-zero) | 35 rows | measured 0 touches pre-stop; re-run `m5_mmio_census.py` after the path extends and promote any row that shows UNMAPPED hits |

Re-measure after each rank: `IOS_RUST_MMIO_LOG=… ./target/debug/ios-rust
boot-first …` + `tools/re/reports/m5_mmio_census.py` (m5-device-census §6) —
the ranking regenerates automatically.

---

## 8. Data conflicts found (notes vs bytes — bytes win)

1. **"aic referenced by 90 nodes"** (m5-peripheral-queue §1): actual global
   `interrupt-parent == aic` count is **79** (73 /arm-io children + 6 /cpus).
   77 /arm-io rows carry IRQs (that part was right).
2. **"max observed HW IRQ 541"** (m5-adt-census §2 / queue §1): actual **542**
   (dart-apcie3, row 79). `N_IRQS=1024` covers it either way.
3. **"apcie owns DSID pages 0x601008000/0x602008000"** (task brief item h;
   m5-peripheral-queue §2.7/§3): **false per the ADT.** apcie's per-port
   windows are `[601000000+8000]`/`[602000000+8000]` — they END exactly where
   the DISD pages begin (`601008000` is the first byte AFTER the window). The
   two pages have **no /arm-io owner** (dart-apcie2/3 own the 0x603008000/
   0x604008000 twins ✓). Spec outcome: attach dapf shims there explicitly (§5.2).
4. **pmap-io-ranges tag rendering** (queue §3): the real fourCC tags are
   `eICP` (0x620000000 PCIe fabric), `TRAD` (dart), `UMMS` (smmu/aux),
   `DISD` (dart SID filter), `eMVN` (nvme), `1TRS` (sart v1) — the note's
   "PCIe/DART/SMMU/DSID/NVMe/SRT1" strings were paraphrase. All 32
   base/size/flag records match exactly (flags 0x4007, PCIe 0x27); record 2 is
   dart-sio 0x235004000 as the note said.
5. **FALLBACK_MAP base drift (defect a)**: already fixed in the current tree
   (P2) — the defect lists in m5-adt-census §6 / m5-peripheral-queue §1 predate
   the fix. Remaining FALLBACK work is only the dead `dart-ans` arm (P4).
6. **aic-timebase as second Aic (defect d)**: classify() already routes it to
   `AicTimebase` (P3); the open half is its register set (§5.3).
7. **aic-version=2 (ADT) vs AIC v1 register map** (m5-peripheral-specs §1.1):
   the ADT prop `aic-version=2` + `compatible="aic,1"` coexist; the byte-verified
   register layout (pexpert AIC.h + kext at 0x988e000, m4-aic-timer-re §4) is
   the classic v1 block. Keep the v1 map in `aic.rs` (current behavior correct);
   note the prop so nobody "fixes" it to the post-A13 aic2 layout.
8. **wlan/bluetooth `reg`** = the single u64 0xF (JSON renders base
   0x20000000F/size 0) — not a base/size pair; `reg_entries` yields 0 pairs so
   they are skipped; the census table's "0x20000000F" is a rendering artifact,
   not a real window.
9. **spmi0/1/2 are their own interrupt-parent** (not aic) — relevant to §6
   decode; their IRQ lists are their own controller outputs.
10. **`/arm-io` node overlap census** (new, supports B1): pmgr windows ⊃
    error-handler/isp/ane/ave/disp0/mca-switch/aes/aop/wdt-reg1/dockchannel/pmp
    sub-windows; mca-switch ⊃ mca0/mca1; SEPROM Ram ⊃ dart-sep + error-handler
    windows; ans w4 overlaps pmgr win37; disp0 reg[1] == dapf-disp0 reg[0];
    `mcc [200200000+100000]` == error-handler reg[16]. None of these are
    addressable correctly without B1.

## 9. Open items carried forward (unchanged ownership)

1. PMGR gate stride 0x18 confirmation against the driver's psreg math (§4.4
   mitigation makes it non-blocking).
2. ANS2 doorbell decision t8015 vs t8103 (§5.5) — re-run census at rank 4.
3. AIC kext MASK_SET-all-ones loop byte-verify (m4-aic-timer-re §4).
4. Wire `pmap-io-ranges` (§8 #4 tags) as the window-validation table in the
   attach audit (`m5_mmio_census.py --adt` cross-check).
5. SEPROM size vs `t8030.c` (B1 note) — 0x240000000+0x2000000 swallows
   dart-sep/error-handler MMIO today.
