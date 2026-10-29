# M5 — ADT peripheral census: T8030 / n104ap (iPhone 11, iOS 14.2 build 18C66)

Sub-agent B (task 5-a), RE only. Fixture: `fixtures/DeviceTree.n104ap.im4p` (42,763 B).
Raw flat tree saved to **`/tmp/adt-n104ap.bin`** (220,204 B). Dumper: `adt_dump2.py`
(kept in the session workspace; reproduce with `liblzfse.decompress(im4p[0x33:0x33+0xA6CE])`
then flat-parse).

## 0. Container + format validation (all assumptions checked against bytes)

* ASN.1/IMG4: `30 82 A7 07` SEQ, `16 04 'IM4P'`, `16 04 'dtre'`, `16 1D "EmbeddedDeviceTrees-5772.62.1"`,
  `04 82 A6 CE` OCTET STRING → **LZFSE payload at file offset 0x33, len 0xA6CE**, magic `bvx2`.
  Decompresses to 220,204 B.
* Flat-tree framing per `crates/adt/src/node.rs::parse_flat` (LE `{u32 nprops, u32 nchildren}`,
  props `{char name[32]; LE u32 len (bit31 = placeholder); data[len] 4-aligned}`, children pre-order):
  parse consumes **exactly 220,204/220,204 bytes**, 293 nodes, 3,836 properties. Root name
  `device-tree` (from its `name` prop), children: chosen, options, cpus, aliases, memory, pram, vram,
  arm-io, buttons, port-lightning-1, port-inductive-1, backlight, baseband, sacm, defaults, product,
  amfm, filesystems, osenvironments. `/arm-io` has **105 children** (matches PARITY 2.11a's count).
* **ENDIANNESS FINDING (critical):** every multi-byte property value in this real Apple flat tree is
  **little-endian**. Decisive evidence: aic `#interrupt-cells = 01 00 00 00` (=1), `AAPL,phandle`
  values cross-resolve (uart0 `interrupt-parent = 0x1A` = aic phandle 0x1A), `#main-cpus = 6`,
  `reg` entries are **(u64 LE addr, u64 LE size)** pairs — uart0 decodes to 0x35200000+0x4000, i.e.
  0x235200000 after `/arm-io ranges` `0x0 → 0x200000000 (4 GiB)`, `0x600000000 → 0x600000000 (8 GiB)`
  — matching the known T8030 serial base. Consequence:
  **`AdtNode::reg_entries()` (BE-first heuristic in `crates/adt/src/node.rs`) MIS-DECODES every reg
  in this fixture.** E.g. aic reg bytes `00 00 10 3B …` BE-pair → (0x103B, 0x0): `attach_from_adt`
  would attach AIC at **0x103B/0x1000**, not 0x23B100000/0x8000. Same for all 94 reg-bearing nodes.
  The "59 modeled" count in PARITY 2.11a is a `classify()` string-match count and stays correct, but
  every runtime base from the real ADT is garbage until `reg_entries` is fixed (try `(u64 LE, u64 LE)`
  first; keep BE as fallback for synthetic trees built by `to_bytes`). **This is the #1 M5 fix.**
* `interrupts` = plain array of LE u32 AIC IRQ numbers (aic `#interrupt-cells = 1`). No
  `fixed-interrupts`, no `interrupt-cells` (only `#interrupt-cells`), no `io-calendar` property
  anywhere in the tree.

## 1. `/arm-io` child table (94 reg-bearing, sorted by absolute base; +0x200000000 offset applied)

`cg`/`pg` = clock-gates / power-gates (pmgr device ids, see §4); "Rust model" = what
`attach_from_adt`/`classify()` (t8030.rs, exact first-match order) attaches.

| # | name | base (abs) | size | #reg | compatible | IRQs | cg | pg | Rust model |
|---|------|-----------:|-----:|-----:|------------|------|----|----|------------|
| 1 | amc | 0x200000000 | 0x1000 | 1 | amctempsensor,t8030;s5l8960x | — | — | — | — |
| 2 | wlan | 0x20000000F | 0x0 | 0 | (none) | — | — | — | — |
| 3 | bluetooth | 0x20000000F | 0x0 | 0 | bluetooth,n88 | 108,0x02000002 | — | — | — |
| 4 | mcc | 0x200100000 | 0x80000 | 3 | mcc,t8030 | — | — | — | — |
| 5 | error-handler | 0x200100000 | 0x60000 | 17 | error-handler,t8030 | 141,185,145,148,151,154 | — | — | — |
| 6 | aft | 0x200144000 | 0x4000 | 1 | aft,t8030 | — | — | — | — |
| 7 | sgx | 0x204000000 | 0x100000 | 2 | gpu,t8030 | 397,398,399,400,412,414 | 208,210 | 208,210 | — |
| 8 | gfx-asc | 0x206400000 | 0x20000 | 2 | iop,ascwrap-v2 | 409,408,411,410 | 209 | 209 | — |
| 9 | tempsensor5 | 0x210ED0000 | 0x10000 | 1 | tempsensor,t8030 | 45 | — | — | — |
| 10 | tempsensor3 | 0x211ED0000 | 0x10000 | 1 | tempsensor,t8030 | 78 | — | — | — |
| 11 | tempsensor4 | 0x211ED0000 | 0x10000 | 1 | tempsensor,t8030 | 80 | — | — | — |
| 12 | mtrtempsensor11 | 0x211EE1000 | 0x16000 | 1 | tempsensor,t8020 | 89 | — | — | — |
| 13 | mtrtempsensor13 | 0x211EE1000 | 0x16000 | 1 | tempsensor,t8020 | 89 | — | — | — |
| 14 | isp | 0x22A000000 | 0x1F09000 | 4 | isp,t8030;s5l8960x | 173,174,175,176 | 229,56-59 | 229,56-59 | — |
| 15 | dart-isp | 0x22BAC8000 | 0x4000 | 5 | dart,t8020 | 178 | 183 | 183 | dart |
| 16 | disp0 | 0x230000000 | 0x2FC000 | 6 | disp0,t8030 | 317,323,314,315,316,318,313,324,325 | 160,161,162,163 | 160,161,162,163 | adp-v4 |
| 17 | mipi-dsim | 0x230400000 | 0xC0000 | 2 | mipi-dsim-1,synopsys | 322,328 | 113 | 113 | mipi-dsi |
| 18 | dart-disp0 | 0x230704000 | 0x4000 | 2 | dart,t8020 | 319 | 179 | 179 | dart |
| 19 | dapf-disp0 | 0x230708000 | 0x1000 | 1 | dapf,t8020 | — | — | — | adp-v4 |
| 20 | dart-sio | 0x235004000 | 0x4000 | 1 | dart,t8020 | 482 | 176 | 176 | dart |
| 21 | aes | 0x235008000 | 0x4000 | 2 | aes,s8000 | 455 | 85 | — | aes |
| 22 | pwm | 0x23500C000 | 0x1000 | 1 | pwm,t8030;s5l8920x | 456 | 64 | — | — |
| 23 | i2c0 | 0x235010000 | 0x1000 | 1 | i2c,t8030;s5l8940x;iic,soft | 457 | 65 | — | i2c |
| 24 | i2c1 | 0x235014000 | 0x1000 | 1 | i2c,t8030;s5l8940x;iic,soft | 458 | 66 | — | i2c |
| 25 | i2c2 | 0x235018000 | 0x1000 | 1 | i2c,t8030;s5l8940x;iic,soft | 459 | 67 | — | i2c |
| 26 | i2c3 | 0x23501C000 | 0x1000 | 1 | i2c,t8030;s5l8940x;iic,soft | 460 | 68 | — | i2c |
| 27 | spi1 | 0x235104000 | 0x4000 | 1 | spi-1,samsung | 445 | 71 | — | spi |
| 28 | spi3 | 0x23510C000 | 0x4000 | 1 | spi-1,samsung | 447 | 73,216 | — | spi |
| 29 | uart0 | 0x235200000 | 0x4000 | 1 | uart-1,samsung | 435 | 76 | — | s3c-uart |
| 30 | uart4 | 0x235210000 | 0x4000 | 1 | uart-1,samsung | 439 | 80 | — | s3c-uart |
| 31 | uart7 | 0x23521C000 | 0x4000 | 1 | uart-1,samsung | 442 | 83 | — | s3c-uart |
| 32 | sio | 0x236400000 | 0x20000 | 2 | iop,ascwrap-v2 | 485,484,487,486 | 227 | 62 | — |
| 33 | mca-switch | 0x238400000 | 0x18000 | 4 | mca-switch,t8030 | — | 88-93 | — | mca |
| 34-39 | mca0..mca5 | 0x238400000..0x238414000 | 0x4000 ea | 3 | mcaCluster,t8030 | 448..453 | — | — | mca |
| 40 | atc-phy | 0x239000000 | 0x4 | 2 | atc-phy,t8030;t8027 | — | 102 | — | — |
| 41 | usb-drd | 0x239010000 | 0x10000 | 3 | usb-drd,t8030;t8027 | 497,498,499,500 | 103,245 | — | typec-otg |
| 42 | dart-usb | 0x239024000 | 0x4000 | 2 | dart,t8020 | 501 | 177 | 177 | dart |
| 43 | pmgr | 0x23B000000 | 0x100000 | 44 | pmgr1,t8030 | — | 197-200 | — | pmgr |
| 44 | nco | 0x23B044000 | 0x14000 | 1 | nco,t8030;s5l8960x | — | — | — | — |
| 45 | sochot0 | 0x23B0C4000 | 0x1000 | 5 | sochot,s5l8955x | — | — | — | — |
| 46 | aic | 0x23B100000 | 0x8000 | 2 | aic,1 | — | — | — | aic |
| 47 | aic-timebase | 0x23B108000 | 0x1000 | 1 | (none) | — | — | — | aic |
| 48 | dwi | 0x23B200000 | 0x4000 | 1 | dwi,t8030;s8000 | 4 | 50 | — | — |
| 49-56 | mtrtempsensor6/7/8, tempsensor0/1/2, mtrtempsensor14/15 | 0x23B281000..0x23B2E0000 | 0x8000-0x34000 | 1 | tempsensor,t8020/t8030 | 26,16,14,8,10,12 | — | — | — |
| 57 | dart-pmp | 0x23B300000 | 0x4000 | 1 | dart,t8020 | 362 | — | — | dart |
| 58 | pmp | 0x23BC00000 | 0x60000 | 38 | iop,ascwrap-v2 | 359,358,361,360 | 123,124 | 123,124 | — |
| 59 | gpio | 0x23C100000 | 0x100000 | 1 | gpio,t8030;s5l8960x | 131-137 | — | — | gpio |
| 60 | dockchannel-uart | 0x23D128000 | 0x10000 | 2 | (none) | — | — | — | s3c-uart |
| 61 | spmi0 | 0x23D180700 | 0x100 | 4 | spmi,t8015 | 192,239,196-205,208-214,216-223 (27) | — | — | spmi-pmu |
| 62 | spmi1 | 0x23D184700 | 0x100 | 4 | spmi,t8015 | 192,244,196-205,208-214,216-223 (24) | — | — | spmi-pmu |
| 63 | spmi2 | 0x23D188700 | 0x100 | 4 | spmi,t8015 | 192,249,196-223 (27) | — | — | spmi-pmu |
| 64 | nub-gpio | 0x23D1F0000 | 0x4000 | 1 | gpio,t8015;s5l8960x | 233,234,235,226-229 | — | — | gpio |
| 65 | wdt | 0x23D2B0000 | 0x4000 | 2 | wdt,t8030;s5l8960x | 237,0 | — | — | apple-wdt |
| 66 | rsm | 0x23D325000 | 0x1000 | 2 | rsm,t8030 | 157 | 22 | — | — |
| 67 | dart-rsm | 0x23D328000 | 0x4000 | 1 | dart,t8020 | 160 | — | — | dart |
| 68 | smc | 0x23E400000 | 0x20000 | 2 | iop,ascwrap-v2 | 271,270,273,272 | — | — | smc |
| 69 | smc-gpio | 0x23E820000 | 0x4000 | 1 | gpio,t8015;s5l8960x | 261-267 | — | — | smc |
| 70 | smc-i2c0 | 0x23ED04000 | 0x1000 | 1 | i2c,t8030;s5l8940x;iic,soft | 256 | 32 | — | smc |
| 71 | smc-i2c1 | 0x23ED08000 | 0x1000 | 1 | i2c,t8030;s5l8940x;iic,soft | 257 | 33 | — | smc |
| 72 | dart-sep | 0x2412C0000 | 0x4000 | 1 | dart,t8020 | 186 | — | — | dart |
| 73 | sep | 0x242400000 | 0x10000 | 1 | iop,t8030;t8015 | 181,180,183,182 | 134 | 134 | sep-sim |
| 74 | aop | 0x24A400000 | 0x20000 | 4 | iop,ascwrap-v2 | 210,209,212,211 | — | — | aop |
| 75 | aop-gpio | 0x24A820000 | 0x4000 | 1 | gpio,t8030;s5l8960x | 196-202 | — | — | aop |
| 76 | dart-aop | 0x24AC00000 | 0x4000 | 1 | dart,t8020 | 224 | — | — | dart |
| 77 | dapf-aop | 0x24AC04000 | 0x1000 | 1 | dapf,t8020 | — | — | — | aop |
| 78 | scaler0 | 0x263000000 | 0x20000 | 2 | scaler,t8030;s5l8960x | 429,431 | 240,122,217 | 240,122,217 | scaler |
| 79 | dart-scaler | 0x263200000 | 0x4000 | 1 | dart,t8020 | 430 | 182 | 182 | dart |
| 80 | jpeg0 | 0x265000000 | 0x4000 | 1 | jpeg,t8030;s5l8920x | 423 | 224,195,206 | 224,195,206 | — |
| 81 | dart-jpeg0 | 0x265004000 | 0x4000 | 1 | dart,t8020 | 424 | 180 | 180 | dart |
| 82 | jpeg1 | 0x265008000 | 0x4000 | 1 | jpeg,t8030;s5l8920x | 426 | 225,195,206 | 225,195,206 | — |
| 83 | dart-jpeg1 | 0x26500C000 | 0x4000 | 1 | dart,t8020 | 427 | 181 | 181 | dart |
| 84 | dart-ave | 0x267030000 | 0x4000 | 3 | dart,t8020 | 391 | 184 | 184 | dart |
| 85 | ave | 0x267100000 | 0x300000 | 4 | ave,t8030 | 394,388,387,390,389 | 226,193,148-153,205 | = cg | — |
| 86 | avd | 0x268000000 | 0x2000000 | 1 | avd,t8030 | 375,376 | 231,196,207 | = cg | — |
| 87 | dart-avd | 0x269010000 | 0x4000 | 1 | dart,t8020 | 382 | 185 | 185 | dart |
| 88 | ane | 0x26A000000 | 0x1F00000 | 2 | ane,t8030 | 293 | 243 | 243 | — |
| 89 | dart-ane | 0x26B800000 | 0x4000 | 3 | dart,t8020 | 294 | 178 | 178 | dart |
| 90 | ans | 0x277400000 | 0xC000 | 9 | iop,ascwrap-v2 | 417,416,419,418,422 | 128 | 128 | ans2-nvme |
| 91 | sart-ans | 0x27AC50000 | 0x8000 | 1 | sart,t8030 | — | — | — | sart |
| 92 | dart-apcie2 | 0x603008000 | 0x4000 | 1 | dart,t8020 | 539 | — | — | dart |
| 93 | dart-apcie3 | 0x604008000 | 0x4000 | 1 | dart,t8020 | 542 | — | — | dart |
| 94 | apcie | 0x610000000 | 0x1000000 | 22 | apcie,t8030 | 532,535,538,541 | 125,126,128,60 | 125,126,128,60 | apcie |

Nodes with **no `reg`** (skipped silently by `attach_from_adt`'s `reg.first() else continue`):

| name | compatible |
|------|------------|
| mapper-gfx-asc | iommu-mapper,gfx |
| alc0 / alc2 | alc,t8030 |
| dietempctl0 | dietempctl,t8030 |
| vtempctl0 | vtempctl,t8030 |
| smctempsensor0 | smc-tempsensor |
| cpu-debug-interface | (none) |
| aod2 | aod,t8030;aod,s5l8960x |
| pearl-sep | biosensor,pearl |
| haptics-support-interface | haptics-support,leap |
| audio-resource-manager | audio,embedded-resource-manager |

**Tally: 105 children = 94 with reg = 59 classified to a Rust model + 35 `unimplemented_devices`
+ 11 skipped.** Note: there is **no `ans2` node and no `dart-ans`/`dart-ans2` on T8030** — the
ANS node is `ans` (role="ANS2"), it is DART-less (SART-only), so `FALLBACK_MAP`'s `dart-ans`
entry has no real counterpart.

## 2. AIC node (`/device-tree/arm-io/aic`) — definitive extract

```text
compatible      = "aic,1"
device_type     = "interrupt-controller"; interrupt-controller = "master"
#interrupt-cells= 1            #address-cells = 0        #main-cpus = 6
aic-version     = 2            #shared-timestamps = 16
AAPL,phandle    = 26           (referenced as interrupt-parent by 90 nodes)
reg             = [0x3B100000 + 0x8000] [0x3B108000 + 0x1000]   (arm-io-relative)
                  → abs 0x23B100000+0x8000 (AIC2 main) and 0x23B108000+0x1000 (= separate
                    /arm-io/aic-timebase node, device_type="timer", the "always-on" AIC page)
ipid-mask       = [15, 0×17]
target-destinations = [60,1, 63,2, 66,4, 69,8, 94,16, 97,32, 414,512]
```

No `fixed-interrupts` property exists anywhere in the tree. AIC2 (aic-version 2), IRQ space:
hardware IRQs 0..~541 observed, **IPIs at 576+** (see cpus below); max observed HW IRQ 541 < 576
(so `Aic::new(640)` covers it). Rust notes: `aic.rs` is a stub and gets attached twice (aic +
aic-timebase both classify as "aic").

## 3. CPU / timer interrupt bindings (`/device-tree/cpus`, 6 children)

Each cpu node: `interrupt-parent=[26]` (aic), `interrupts=[IPI, TIMER, IPI_other]` — 3 entries,
`#interrupt-cells=1`, plus `function-ipi_dispatch=[26, "IPI_", IPI]` fourcc bindings confirming
the first/third entries are AIC IPIs:

| cpu | core | compatible | reg(cpu#) | interrupts | enable_core mask | cluster |
|-----|------|------------|-----------|------------|------------------|---------|
| cpu0 | E0 | apple,thunder,ARM,v8 | 0 | **576, 60, 577** | 1 | E |
| cpu1 | E1 | apple,thunder,ARM,v8 | 1 | **578, 63, 579** | 2 | E |
| cpu2 | E2 | apple,thunder,ARM,v8 | 2 | **580, 66, 581** | 4 | E |
| cpu3 | E3 | apple,thunder,ARM,v8 | 3 | **582, 69, 583** | 8 | E |
| cpu4 | P0 | apple,lightning,ARM,v8 | 0x100 | **584, 94, 585** | 16 | P (cluster 1) |
| cpu5 | P1 | apple,lightning,ARM,v8 | 0x101 | **586, 97, 587** | 32 | P (cluster 1) |

**Answer to the 27/28/29/30 question: those GIC PPI numbers do not exist on T8030.** The per-CPU
generic-timer/FIQ line is the *middle* IRQ of each cpu node — **60/63/66/69 (E-cores),
94/97 (P-cores)** — and the aic `target-destinations` table maps exactly those IRQs to cpu masks
(60→1, 63→2, 66→4, 69→8, 94→16, 97→32). Timer delivery is AIC-routed (plus the separate
`aic-timebase` page at 0x23B108000); IPI space starts at 576 (576 = dispatch, +1 = dispatch_other,
per-cpu stride 2). The `no-aic-ipi-required` prop is present (empty). For M5: `Aic::new(640)` and
the per-cpu timer model should key off 60/63/66/69/94/97 + IPI base 576.

## 4. PMGR (`/device-tree/arm-io/pmgr`) — windows + full gate table

```text
compatible = "pmgr1,t8030"   device_type = "pmgr"   phandle = 28
reg (44 windows, arm-io-relative → abs = +0x200000000):
  0x23B000000+0x100000 (main pmgr-reg), 0x23D200000+0x100000 (AON: fuses/PMGR_AON — matches
  Rust consts 0x3D280088, 0x3D2BC0xx, 0x3D2E8000), 0x23D004000+0x1000,
  0x210E20000+0x15000, 0x210F00000+0x50000, 0x210E40000+0x10000, 0x210E50000+0x1000,
  0x210E70000+0x90000, cpufreq-cluster windows 0x210050000/0x210150000/0x210250000/
  0x210350000 (+0x10000 each), mirrored 0x211E20000..0x211150000 set,
  0x23BC1C000+0x40000, 0x23B280000+0x40000, 0x23D180000+0x2000 (spmi0/1/2 live at
  0x23D180700/…4700/…8700), 0x23D100000+0x80000, 0x23B204000+0x10000,
  GPU 0x26B8EC000+0x10000 & 0x26B8F4000+0x10000, ANE/media vnom pages 0x262000000, 0x264000000,
  0x266000000, 0x268000000, 0x26A000000, 0x22A000000, 0x231000000, 0x205000000, 0x260C00000,
  0x234000000, 0x200148000, 0x279000000 (+0xD000 each), cpupm 0x225000000+0x15000,
  0x225004000+0x4000, 0x225008000+0x4000, 0x226000000+0x15000, 0x226004000+0x4000,
  0x226008000+0x4000
clock-gates = [197,198,199,200] (= PMGR-SOC-VNOM/VMAX, PMGR-DCS-VNOM/VMAX)
ps-regs     = records with psreg window offset **0x80000** (matches Rust PSREG_BASE)
devices     = 8448 B = 352 records × 24 B  ← the real gate table
```

`devices` record layout (decoded + validated): pairs of 24 B rows — config row
`{LE u32 (gate_id<<24 | type), LE u32 parent_id, …}` then name row
`{u32, u32, char name[16]}`. **Gate id = config word0 >> 24.** Validated against node
`clock-gates` props: DWI=50 ✓, I2C0-3=65-68 ✓, PWM0=64 ✓, SPI1=71 ✓, SPI3=73 ✓,
UART0=76 ✓, UART4=80 ✓, UART7=83 ✓, AES=85 ✓, MIPI_DSI=113 ✓, SIO=62 ✓, SIO-CPU-V=227 ✓,
PMP=123 ✓, PMS_SRAM=124 ✓, APCIE=125 ✓, APCIE_GP=126 ✓, APCIE_ST=128 ✓, PCIE_REF=60 ✓,
GFX-SGX=208 ✓, GFX-ASC=209 ✓, GFX-BUSY=210 ✓, darts: SIO-DART=176, USB-DART=177, ANE-DART=178,
DISP0-DART=179, JPG0-DART=180, JPG1-DART=181, MSR-DART=182, ISP-DART=183, VENC-DART=184,
AVD-DART=185 ✓ all match node cg values. Full named map (id → name, gate row type byte in ()):

```text
1-4 ECPU0-3, 7-8 PCPU0-1, 0B ECPM, 0C PCPM, 0D CPU-BUSY, 0E ECPU, 0F PCPU, 10 DEBUG,
11-14 NUB_SPMI0-2/NUB_AON, 15 NUB_GPIO, 16-17 NUB_FABRIC/NUB_SRAM, 18 DEBUG_USB,
19-1D AOP_SCM/AOP_CPU/AOP_SRAM/AOP_LEAP_AOP/SMC_FABRIC, 1E SMC_AON, 1F SMC_CPU,
20 SMC-I2CM1, 21 AOP_FILTER, 22 AOP_BASE, 29(0x30) SBR, 31(49) AIC, 32(50) DWI,
33-35 SOC_SPMI0-2, 36 GPIO, 37 PMS, 38-3B ISPSENS0-3, 3C(60) PCIE_REF, 3D SIO_BUSIF,
3E(62) SIO, 3F SIO_CPU, 40(64) PWM0, 41-44(65-68) I2C0-3, 45 SPI_P, 46-48 SPI0-2,
49(73) SPI3, 4A(74) UART_P, 4B(75) UART_N, 4C(76) UART0, 4D-53(77-83) UART1-7, 54 UART8,
55(85) AES, 56 AUDIO_CPU, 57 AUDIO, 58-5D MCA0-5, 5E DPA, 5F SIO_LEAP, 60 MCC,
61-64 DCS0-3, 65(101) USB, 66 C0_USBCTL, 67(103) C0_USB31DRD, 68 C0_USB2DEV,
69 SMX, 6A IMX, 6B RMX, 6C MMX, 6E(110) DISP0_FE, 6F(111) DISP0_BE, 71(113) MIPI_DSI,
72 DP, 73-76 DISP0_GP0/GP1/PPP/HILO, 77 DISP0_DSC, 78 JPG, 79 MSR, 7A MSR_ASE_CORE,
7B(123) PMP, 7C(124) PMS_SRAM, 7D(125) APCIE, 7E(126) APCIE_GP, 7F(127) ANS2,
80(128) APCIE_ST, 81 GFX, 82 ISP_SYS, 83 VENC_SYS, 84 AVD_SYS, 85 ANE_SYS, 86(134) SEP,
87 SEP_EISP, 88 PMS_BUSIF, 89 SOC_DPE, 8A PMGR_SOC_OCLA, 8B I2C4, 8C ANE_SYS_CPU,
94 VENC_DMA, 95-98 VENC_PIPE4/5/ME0/ME1, 99 VENC-DUMMY,
A0-A3(160-163) DISP0-V/DISP-MIE-DPB/DISP-FB-ACTIVE/DISP-DCS-PG,
B0-B8(176-184) SIO-DART/USB-DART/ANE-DART/DISP0-DART/JPG0-DART/JPG1-DART/MSR-DART/ISP-DART/VENC-DART,
B9(185) AVD-DART, C0-C4 ISP/AVE/VDEC/JPG/AVD-SOC-VNOM, C5-C8(197-200) PMGR-SOC/DCS-VNOM/VMAX,
C9-CC CLPC-SOC/DCS-VNOM/VMAX, D0-D2(208-210) GFX-SGX/GFX-ASC/GFX-BUSY, D7-D9 SEP/MSR-SOC-V*, E0-E1 JPG0/1-V,
E2 VENC-SYS-V, E3(227) SIO-CPU-V, E5 ISP-SYS-V, E7 AVD-SYS-V, F0(240) MSR-V, F3 ANE-SYS-V,
F4(244) APCIE-V, F5(245) USB-AUDIO-V, F6(246) SEP-PEARL-V  (+VNOM/VMAX rows C1,C3,C10A0150-type dV/dt entries)
```

One ambiguity, stated honestly: strict config→name pairing gives ANS2=127 and APCIE_ST=128; the
`ans` node references **cg=pg=128** (its upstream internal-PCIe gate — ANS2 sits behind the APCIe
fabric on T8030, hence also `dart`-less). All 24 other cross-checks match exactly.

**Boot-critical gate map (M5):** uart0→76 "UART0" (+clock-ids [336,4]); aic→49 "AIC" (always-on,
not referenced by any node); ans→128 "APCIE_ST" clock+power (ANS2's own id 127 is firmware-
managed); dart-usb→177, dart-sio→176, dart-aop/rsm/sep/pmp have **no** cg (always-on DARTs);
sart-ans, wdt, smc, aop, gpio, apcie-main: **no clock-gates** (always-on domains; wdt has
`clock-ids=[4]` only). disp0→160-163, mipi→113, sgx→208+210, gfx-asc→209, aes→85, spmi: none.
The Rust `Pmgr::GATES` table (aic/uart0/wdt/… at synthetic 0x1000 psreg strides) matches **none**
of the real ids — psreg window base 0x80000 is right, per-gate stride (0x18 per M1-era convention,
max id 0xF6=246) is **unconfirmed** — flagged as M5 next action against XNU/Inferno t8030.c.

## 5. Full node dumps (condensed; raw values LE)

```text
== /arm-io/wdt ==   compatible="wdt,t8030,wdt,s5l8960x" (wdt-version=1, clock-ids=[4])
  reg=[0x3D2B0000+0x4000] [0x3D2B8020+0x4]   interrupts=[237, 0]   interrupt-parent=aic(26)
  function-panic_notify=[35,"$neM",162,256]  panic-save-flag-bit / panic_{flush,halt}_helper fourccs
  NOTE: FALLBACK_MAP's wdt 0x235290000 is WRONG vs this ADT (0x23D2B0000).
== /arm-io/smc ==   compatible="iop,ascwrap-v2" role="SMC" iop-version=1
  reg=[0x3E400000+0x20000] [0x3E050000+0x4000]   interrupts=[271,270,273,272]
  child iop-smc-nub: compatible="iop-nub,rtbuddy-v2", firmware-name="t8030smc",
    region-base=0x3FF00000 region-size=0x80000, no-shutdown, watchdog-enable, coredump-enable
  children: smc-pmu (interrupt-controller, event_name-gpio16="wifibt", gpio9="baseband",
    gpio13="charger", gpio12="codec", btn1="hold"), smc-charger, smc-ext-charger,
    portmicro (smc-ccg2, usbc-fw-personality="HPM,13"), smc-aop
== /arm-io/ans ==   role="ANS2" device_type="ans" compatible="iop,ascwrap-v2" iop-version=1
  reg=[0x277400000+0xC000 (ANS2 main) | 0x277050000+0x4000 (admin) | 0x27AD20044+0x4
       | 0x27ACC0000+0x60000 | 0x279000000+0x18000 | 0x27AB90000+0x8000 | 0x27AD47C00+0x400
       | 0x27AD60000+0x8000 | 0x27AD70000+0x8000]
  interrupts=[417,416,419,418,422] nvme-interrupt-idx=4 (→ IRQ 422)
  clock-gates=[128] power-gates=[128] clock-ids=[376,375,374] namespaces=[1,1,0,2,2,2048,3,3,32,
  4,4,2,5,5,2,6,6,1,7,8,256] iommu-parent="\" (none) auto-boot child iop-ans-nub: rtbuddy-v2
  NOTE: FALLBACK_MAP's ans2-nvme 0x27BCC4000+0x10000 is WRONG vs this ADT (0x277400000+0xC000).
== /arm-io/sart-ans ==  compatible="sart,t8030" sart-version=1 device_type="sart"
  reg=[0x27AC50000+0x8000]   (FALLBACK's 0x23321C000+0x4000 is WRONG)
== /arm-io/uart0 == compatible="uart-1,samsung" device_type="uart" uart-version=1
  reg=[0x235200000+0x4000] interrupts=[435] clock-gates=[76] clock-ids=[336,4]
  boot-console=<8B> no-flow-control=<8B> child debug-console
  (uart4 +0x210000 IRQ 439 cg 80, child stockholm; uart7 +0x21C000 IRQ 442 cg 83, child iap-uart-1)
== /arm-io/dockchannel-uart == no compatible, reg=[0x23D128000+0x10000] (+1 more window);
  classify() attaches it as a SECOND S3cUart (wrong protocol — dockchannel ≠ S3C UART).
== /arm-io/sgx == compatible="gpu,t8030" device_type="sgx"
  reg=[0x204000000+0x100000] [0x204D00000+0x20000] interrupts=[397,398,399,400,412,414]
  clock-gates=power-gates=[208,210] clock-ids=[315] metal-standard=256 opengl-standard=768
== /arm-io/disp0 == compatible="disp0,t8030" device_type="display-subsystem"
  reg=[0x230000000+0x2FC000] [0x230708000+0x1000] [0x230721000+0x1000] [0x23B0B8000+0x1000]
      [0x23BC04840+0x1000] [0x23BC2C000+0x1000]
  interrupts=[317,323,314,315,316,318,313,324,325] cg=pg=[160-163] clock-ids=[353,352]
  iommu-parent=[151,152] (=dart-disp0 mappers)
== /arm-io/mipi-dsim == compatible="mipi-dsim-1,synopsys" mipi-version=8 #lanes=2
  reg=[0x230400000+0xC0000] [0x2304C0000+0x10000] interrupts=[322,328] cg=pg=[113]
  clock-ids=[326] child lcd (panel node)
== /arm-io/aop == role="AOP" compatible="iop,ascwrap-v2"
  reg=[0x24A400000+0x20000] [0x24A050000+0x4000] [0x24AE00000+0x1E0000] [0x23D2A8000+0x8]
  interrupts=[210,209,212,211] child iop-aop-nub (rtbuddy, accel/gyro/compass/pressure/prox/
  audio-mca0-1/haptic/rose/smart-cover/smc-control sub-nubs)
== /arm-io/aes == compatible="aes,s8000" aes-version=3
  reg=[0x235008000+0x4000] [0x23D2D0000+0x4000] interrupts=[455] cg=[85]
== /arm-io/gpio == compatible="gpio,t8030,gpio,s5l8960x" interrupt-controller #interrupt-cells=2
  reg=[0x23C100000+0x100000] interrupts=[131-137] #gpio-pins=212 #gpio-int-groups=7 role="AP"
== /arm-io/spmi0 == compatible="spmi,t8015" interrupt-controller #interrupt-cells=1
  reg=[0x23D180700+0x100] [0x23D180D00+0x100] [0x23D180E00+0x64] [0x23D180014+0x4]
  interrupts=[192,239,196-223 (27 entries)] queue-depth=[256,256]
```

## 6. Rust cross-reference (`attach_from_adt` + `crates/devices`)

Faithful re-run of `classify()` (exact match order) over the 94 reg-bearing children:
**59 attach** (dart×16 — all 16 darts, incl. dart-aop/apcie2/3/scaler/jpeg; s3c-uart×4 (uart0/4/7 +
dockchannel-uart); smc×4 (smc, smc-gpio, smc-i2c0, smc-i2c1 — 3 of them are really GPIO/I2C behind
SMC); mca×7 (mca0-5 + mca-switch); i2c×4; spmi-pmu×3; gpio×2 (gpio, nub-gpio); aic×2 (aic +
aic-timebase as a second Aic); aop×3 (aop, aop-gpio, dapf-aop); adp-v4×2 (disp0, dapf-disp0 —
dapf is a DART address filter, wrong model); ans2-nvme, sart, apple-wdt, pmgr, sep-sim, aes,
mipi-dsi, typec-otg, apcie, scaler×1 each). **35 → `unimplemented_devices`, 11 skipped (no reg).**

Beyond bases, four systematic mismatches for M5: (a) reg endianness (§0); (b) FALLBACK_MAP base
drift — aic/uart0 correct, **wdt, dart-ans (nonexistent node), ans2-nvme, sart, pmgr (real main
window starts 0x23B000000, not 0x23B070000), gpio (0x23C100000 not 0x23D100000), adp-v4, mipi-dsi
all wrong vs the real tree**; (c) `size.max(0x1000)` rounding hides 0-size stubs; (d) Pmgr gate
model is synthetic (§4) and nothing reads `clock-gates`/`interrupts` from the ADT (grep confirms
zero uses in crates/devices).

## 7. Ranked unmodeled gap list (top 15 of 35; boot-relevance guess per line)

| # | node | base | size | compatible | boot relevance |
|---|------|------|------|------------|----------------|
| 1 | dwi | 0x23B200000 | 0x4000 | dwi,t8030;s8000 | **boot path** — clock/voltage debug IF XNU probes early (gate 50, IRQ 4) |
| 2 | mcc | 0x200100000 | 0x80000 | mcc,t8030 | **early** — memory/LLC controller; XNU touches early, 3 windows |
| 3 | error-handler | 0x200100000 | 0x60000 | error-handler,t8030 | **early** — fault/reg-dump router, 6 IRQs; silent-zero OK short-term |
| 4 | rsm | 0x23D325000 | 0x1000 | rsm,t8030 | **early-ish** — reset/sleep state machine (gate 22, IRQ 157) |
| 5 | atc-phy | 0x239000000 | 0x4 | atc-phy,t8030;t8027 | early-mid — USB-C PHY for USB boot/charging (gate 102) |
| 6 | sochot0 | 0x23B0C4000 | 0x1000 | sochot,s5l8955x | early-mid — thermal trip (5 windows) |
| 7 | sio | 0x236400000 | 0x20000 | iop,ascwrap-v2 | **early** — SIO coprocessor (leap/i2c/spi/pwm owner), 4 IRQs |
| 8 | pmp | 0x23BC00000 | 0x60000 | iop,ascwrap-v2 | early-mid — PMP coprocessor (38 windows, gates 123/124) |
| 9 | pwm | 0x23500C000 | 0x1000 | pwm,t8030;s5l8920x | late-mid (gate 64, IRQ 456) |
| 10 | nco | 0x23B044000 | 0x14000 | nco,t8030;s5l8960x | late-mid — clock NCO blocks |
| 11 | gfx-asc | 0x206400000 | 0x20000 | iop,ascwrap-v2 | late — GPU ASC (rtbuddy-style, gate 209, 4 IRQs) |
| 12 | sgx | 0x204000000 | 0x100000 | gpu,t8030 | late — GPU (2 windows, 6 IRQs, gates 208/210) |
| 13 | isp | 0x22A000000 | 0x1F09000 | isp,t8030;s5l8960x | late — camera (huge 31.7 MB window) |
| 14 | ave/avd/jpeg0/jpeg1 | 0x267100000… | 0x300000/0x2000000/0x4000×2 | ave/avd/jpeg,t8030 | late media codecs |
| 15 | ane | 0x26A000000 | 0x1F00000 | ane,t8030 | late — Neural Engine (gate 243) |

(Plus 12 temp sensors + wlan/bluetooth stubs + amc/aft = inert; ranked below all above. `aop` is
*modeled* but only as a structural stub — treat as maybe-early for real boot since it owns sensors
and the AOP GPIO/audio fabric.)

## 8. Next actions for M5

1. Fix `AdtNode::reg_entries` to decode `(u64 LE, u64 LE)` pairs first (keep BE fallback for
   synthesized trees); add a golden test against this fixture (aic@0x23B100000, uart0@0x235200000,
   ans@0x277400000, sart@0x27AC50000, wdt@0x23D2B0000). No Rust edits made here (research-only).
2. Rewrite `FALLBACK_MAP` from §1/§5 (drop `dart-ans`; ans2 main = 0x277400000+0xC000,
   admin = 0x277050000; wdt = 0x23D2B0000; sart = 0x27AC50000; pmgr = 0x23B000000+0x100000;
   gpio = 0x23C100000; disp0 = 0x230000000+0x2FC000; mipi = 0x230400000).
3. Wire AIC IRQ model: #interrupt-cells=1, per-cpu timer IRQs 60/63/66/69/94/97, IPI base 576
   (576/577 per cpu), max HW IRQ 541; add `aic-timebase` page 0x23B108000.
4. Feed `Pmgr` the real gate table (id→name map §4; psreg window 0x80000; confirm 0x18 stride
   against XNU `AppleT8030PMGR`/Inferno t8030.c when the reference clone is fetched).
5. Model or RAZ-map the top-7 gap rows (dwi, mcc, error-handler, rsm, atc-phy, sochot0, sio) —
   uart/aic/pmgr/ans/sart/dart/wdt/smc are already covered by models but now at correct bases.
