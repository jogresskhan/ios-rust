# M5 Peripheral Register Specs (T8030 / A13 / iPhone 11 / iOS 14.2 18C66)

Authoritative sources fetched this session (see inventory at the end). Every table row cites
`file:line`. Anything not provable from a fetched source is marked **T8030-UNCERTAIN** — do not
"fix" these by invention; validate against the xnu build under emulation instead.

Primary citations:
- `[AIC]`   refs/linux/irqchip/irq-apple-aic.c (Linux master, GPL-2.0)
- `[AICB]`  refs/linux/irqchip/apple-aic.h (dt-bindings)
- `[XAIC]`  refs/xnu/AIC.h (xnu-7195.121.3 = iOS 14.2-era pexpert header)
- `[XH13]`  refs/xnu/H13.h (T8030 = "H13" pexpert SoC header)
- `[DART]`  refs/linux/iommu/apple-dart.c
- `[DPT]`   refs/m1n1/dart8020.py, refs/m1n1/dart.c (m1n1, T8020-layout DART)
- `[SART]`  refs/linux/soc/sart.c
- `[MSART]` refs/m1n1/sart.c
- `[NVME]`  refs/linux/nvme/apple.c
- `[MNVME]` refs/m1n1/nvme.h / nvme.c (M1 cross-check)
- `[SMC]`   refs/linux/mfd/macsmc.c + macsmc.h
- `[MSMC]`  refs/m1n1/smc.c
- `[WDT]`   refs/linux/watchdog/apple_wdt.c
- `[MWDT]`  refs/m1n1/wdt.c
- `[PMGR]`  refs/linux/pmdomain/pmgr-pwrstate.c
- `[MPMGR]` refs/m1n1/pmgr.c
- `[RTK]`   refs/linux/soc/rtkit.c, refs/m1n1/rtkit.c
- `[ASC]`   refs/m1n1/asc.c
- `[DTS]`   refs/linux/dts-t8103.dtsi, dts-t8103-pmgr.dtsi (t8103-only — addresses, not T8030)

---

## 1. AIC — Apple Interrupt Controller

### 1.1 Version determination for T8030 (RESOLVED)

Linux `aic_info_match` `[AIC:309-331]`:

| compatible          | info struct            | version | fast IPI | local fast IPI |
|---------------------|------------------------|---------|----------|----------------|
| apple,t8103-aic (M1)| aic1_local_fipi_info   | **1**   | yes      | yes            |
| apple,t8015-aic(A10X)| aic1_fipi_info        | **1**   | yes      | no             |
| apple,aic (generic) | aic1_info              | **1**   | no       | no             |
| apple,aic2          | aic2_info              | 2       | yes      | yes            |
| apple,t8122-aic3    | aic3_info              | 3       | yes      | yes            |

Key fact: **the M1 (t8103) uses the classic AIC-v1 MMIO layout** (`AIC_EVENT` @0x2004 etc.).
"AIC v2" (`apple,aic2`) is a *later* register layout (die-multiplexed, IRQ_CFG-first, VERSION/INFO
regs at 0x0-0xc) and appears only on post-A13 SoC generations. T8030 (A13, 2019) predates AIC2 ⇒
**T8030 = AIC v1 register map** (`apple,aic` class). Confirmed by xnu: pexpert `AIC.h` for iOS 14
defines only the classic block + timebase `[XAIC:29-31]`, and `H13.h` (T8030's pexpert header)
sets `HAS_IPI 1` `[XH13:38]` ⇒ fast-IPI sysregs exist on A13.

- Fast IPI sysregs: "present and used (A11+)" `[AIC:241-242]` ⇒ T8030 has them. xnu
  `apple_arm64_regs.h` carries the same `IPI_RR` definitions `[refs/xnu/apple_arm64_regs.h:194-197]`.
- **T8030-UNCERTAIN:** local fast IPI (`SYS_IMP_APL_IPI_RR_LOCAL_EL1`) — Linux comment says "(M1+)"
  `[AIC:243-244]`. Model GLOBAL-only cross-CPU IPIs; accept writes to LOCAL as harmless.
- **T8030-UNCERTAIN:** `AIC_INFO.NR_IRQ` value on T8030 (read-only, 16:0 `[AIC:71-72]`). t8103
  reports 896; A13 likely ≤896. Emulator: return 0x380 (896) or 0x400; xnu sized from HW info.
- **T8030-UNCERTAIN:** AIC MMIO base address on T8030 (t8103 = 0x23b100000 `[DTS:707]`; T8030
  differs — take it from the emulator's DT/ADT).

### 1.2 AIC v1 register table (R=32-bit unless noted; all R/W via `base`)

Computation of the "array" area: v1 probe sets `start_off = AIC_TARGET_CPU (0x3000)`, then
`off += 4 * max_irq (0x400)` for the TARGET_CPU array, then four bit-per-IRQ arrays of
`(max_irq>>5)*4 = 0x80` bytes each, plus HW_STATE `[AIC:996-1009, 1033-1041]`. m1n1 hardcodes the
same offsets (SW_SET 0x4000 … MASK_CLR 0x4180) `[refs/m1n1/aic_regs.h:4-20]`.

| Offset  | Name          | R/W | Semantics (bits) |
|---------|---------------|-----|------------------|
| 0x0004  | AIC_INFO      | RO  | NR_IRQ = bits15:0 `[AIC:71-72]` |
| 0x0010  | AIC_CONFIG    | R/W | (v1: unused by driver) `[AIC:74]` |
| 0x2000  | AIC_WHOAMI    | RO  | current CPU index; Linux `WARN_ON(read != smp_processor_id())` `[AIC:76,894-900]` |
| 0x2004  | AIC_EVENT (IACK) | RO | IACK/auto-ack: read returns next event and **auto-masks+acks** it `[AIC:391-399,406-421]`. DIE=31:24, TYPE=23:16, NUM=15:0 `[AIC:78-80]`. TYPE: 0=FIQ(soft), 1=IRQ, 4=IPI `[AIC:82-84]`; IPI NUM: 1=OTHER, 2=SELF `[AIC:85-86]`. **0 = no event, terminates the dispatch loop** `[AIC:421]` |
| 0x2008  | AIC_IPI_SEND  | WO  | write BIT(cpu) to IPI that CPU `[AIC:88,93]` |
| 0x200C  | AIC_IPI_ACK   | WO  | ack IPIs: IPI_OTHER=BIT(0), IPI_SELF=BIT(31) `[AIC:89,95-96]` |
| 0x2024  | AIC_IPI_MASK_SET | WO | mask IPI sources (same bits) `[AIC:90]` |
| 0x2028  | AIC_IPI_MASK_CLR | WO | unmask IPI sources `[AIC:91]` |
| 0x3000+4n | AIC_TARGET_CPU[n] | R/W | affinity of IRQ n: BIT(cpu) `[AIC:98,445-462,1079-1081]`; driver inits all to `1` (CPU0) |
| 0x4000+4w | AIC_SW_SET[w]   | WO/RW | software-set IRQ bit (w = irq>>5, bit = irq&31) `[AIC:1033-1034]` |
| 0x4080+4w | AIC_SW_CLR[w]   | WO/RW | software-clear IRQ bit; driver writes 0xFFFFFFFF at init `[AIC:1035-1036,1077-1078]` |
| 0x4100+4w | AIC_MASK_SET[w] | WO/RW | mask IRQ; driver inits **all masked (U32_MAX)** `[AIC:1037-1038,1074-1076]` |
| 0x4180+4w | AIC_MASK_CLR[w] | WO/RW | unmask IRQ `[AIC:1039-1040]` |
| 0x4200+4w | AIC_HW_STATE[w] | RO  | hardware pending state of IRQs `[AIC:1041]` |
| 0x5008+cpu*0x80 | AIC_CPU_IPI_SET | WO | per-CPU IPI set (fallback alias of 0x2008) `[AIC:100-103]` |
| 0x500C+cpu*0x80 | AIC_CPU_IPI_CLR | WO | per-CPU IPI clear |
| 0x5024/0x5028+cpu*0x80 | AIC_CPU_IPI_MASK_SET/CLR | WO | per-CPU IPI mask |
| +0x1000+0x20/0x28 | AIC timebase | RO | 64-bit global timebase counter (kAICMainTimLo/Hi); DT node = AIC base+0x1000 `[XAIC:29-31]` |

`MASK_REG(x)=4*(x>>5)`, `MASK_BIT(x)=BIT(x&31)` `[AIC:163-164]`.

### 1.3 IACK/EOI protocol (emulator contract)

1. CPU takes IRQ exception → xnu reads `AIC_EVENT` until it returns 0 `[AIC:406-421]`.
2. Each read with TYPE=1 delivers that IRQ and **auto-masks it**; handler EOI = write
   `AIC_MASK_CLR[irq]` (driver re-unmasks at EOI unless masked) `[AIC:391-399]`.
3. TYPE=4/NUM=1 → IPI path: ack via `AIC_IPI_ACK=IPI_OTHER` (non-fast-IPI) or
   `IPI_SR_EL1.PENDING` write (fast-IPI), then vIPI processing, then `AIC_IPI_MASK_CLR=IPI_OTHER`
   `[AIC:812-836,907-913]`. Boot init on every CPU: `AIC_IPI_ACK = SELF|OTHER`, and with fast IPI
   `AIC_IPI_MASK_SET = SELF|OTHER` (both hard-wired IPIs masked at AIC level) `[AIC:894-914]`.
4. FIQs never go through AIC_EVENT; xnu samples sources directly (timers via `CNTP/CNTV_CTL`,
   fast-IPI via `IPI_SR_EL1`, PMU via `PMCR0.IACT`) `[AIC:557-613]`.

### 1.4 Fast-IPI IMP-DEF sysregs (A13 has them; T8030-UNCERTAIN whether xnu-7195 uses LOCAL)

| Sysreg (S<op0>,<op1>,<CRn>,<CRm>,<op2>) | enc | field |
|---|---|---|
| IPI_RR_LOCAL_EL1  | 3,5,15,0,0 | CPU 7:0; write = send IPI `[AIC:171-173]` |
| IPI_RR_GLOBAL_EL1 | 3,5,15,0,1 | CPU 7:0, CLUSTER 23:16, TYPE 29:28 (0=IMMEDIATE,1=RETRACT,2=DEFERRED,3=NOWAKE) `[AIC:172-180]` |
| IPI_SR_EL1        | 3,5,15,1,1 | bit0 PENDING (W1C) `[AIC:183-184,821-823]` |
| VM_TMR_FIQ_ENA_EL2| 3,5,15,1,3 | bit0 EN_V, bit1 EN_P (guest-timer FIQ enables, EL2 only) `[AIC:187-189]` |
| IPI_CR_EL1        | 3,5,15,3,1 | deferred-IPI countdown `[AIC:192]` |
| UPMCR0_EL1 / UPMSR_EL1 | 3,7,15,0,4 / 3,7,15,6,4 | uncore-PMC FIQ mode/active `[AIC:195-204]` |

## 2. Generic timer ↔ AIC (PPI conventions)

There are **no GIC-style PPI IRQ numbers** — the 4 architectural timers are **FIQ sources**
indexed in the AIC DT binding `[AICB:10-15]`, delivered via `AIC_EVENT` with TYPE=0 only in
software bookkeeping; the hardware path is direct FIQ `[AIC:557-598]`:

| FIQ index | binding name      | EL1-kernel meaning (xnu on iPhone runs EL1) |
|-----------|-------------------|---------------------------------------------|
| 0 | AIC_TMR_HV_PHYS    | CNTP (physical timer, EL0/EL1 regs) — `cntp_ctl_el0` firing check `[AIC:578-580,228-231]` |
| 1 | AIC_TMR_HV_VIRT    | CNTV (virtual timer) `[AIC:582-584]` |
| 2 | AIC_TMR_GUEST_PHYS | EL02 CNTP (only when kernel at EL2; EL1 maps 2→0) `[AIC:232,722-736]` |
| 3 | AIC_TMR_GUEST_VIRT | EL02 CNTV (EL1 maps 3→1) |
| 4 | AIC_CPU_PMU_E      | efficiency-core PMU (merged into 5) `[AIC:234,738-740]` |
| 5 | AIC_CPU_PMU_P      | performance-core PMU FIQ `[AIC:600-603]` |

Timer "firing" predicate used by Linux (emulator should mirror): `(CNTx_CTL & (ENABLE|IMASK|ISTATUS)) == (ENABLE|ISTATUS)` `[AIC:552-555]`. xnu masks timer FIQs at boot by setting IMASK in
CNTx_CTL until its scheduler is up `[AIC:867-869]`.

## 3. DART (T8030-era "DART1" = T8020 register layout)

Mainline model: `apple_dart_hw_t8103` uses `type = DART_T8020` — i.e. the "T8020 registers"
below are the pre-t8110 DART generation; T8030's DARTs are this class (A12X/A13 generation).
`oas=36, max_sid_count=16, ttbr_count=4, fmt=APPLE_DART` `[DART:1284-1302]`.

| Offset | Name | R/W | Semantics |
|--------|------|-----|-----------|
| 0x00  | DART_PARAMS1 | RO | PAGE_SHIFT = bits27:24 (pgsize = 1<<field) `[DART:44-45,1000-1001]`. Emulator: return 14 (16K pages) — **T8030-UNCERTAIN** but t8020-class uses 16K `[DPT:86-87]` |
| 0x04  | DART_PARAMS2 | RO | bit0 BYPASS_SUPPORT `[DART:47-48]` |
| 0x20  | STREAM_COMMAND | W/R | BUSY=bit2, INVALIDATE=bit20 `[DART:52-54]`; poll BUSY==0 after command (timeout 100 µs) `[DART:72,397-405]` |
| 0x34  | STREAM_SELECT | WO | sidmap word(s) selecting streams for the command `[DART:56,394-395]` |
| 0x40  | ERROR | R/W1C | FLAG=bit31, STREAM=27:24, CODE=11:0; codes: NO_TTBR=0, NO_PMD=1, NO_PTE=2, WRITE_FAULT=3, READ_FAULT=4 `[DART:58-67]` |
| 0x50/0x54 | ERROR_ADDR_LO/HI | RO | faulting IOVA `[DART:74-75]` |
| 0x60  | CONFIG | R/W | bit15 LOCK `[DART:69-70]` |
| 0x80  | STREAM_REMAP | R/W | (m1n1 only) `[refs/m1n1/dart.c:36]` |
| 0xFC  | STREAMS_ENABLE | R/W | per-stream enable bitmap `[DART:77]` |
| 0x100+4*sid | TCR(sid) | R/W | TRANSLATE_ENABLE=bit7, BYPASS_DART=bit8, BYPASS_DAPF=bit12 `[DART:79-82,149]` |
| 0x200+4*(4*sid+idx) | TTBR(sid,idx) | R/W | VALID=bit31, addr = value<<12 (shift 12, field shift 0) `[DART:84-88,151-153]` |

TLB invalidate protocol (per stream-map): write sidmap→0x34, write INVALIDATE→0x20, poll 0x20
BUSY→0 `[DART:391-405,461-465]`.

Page-table format (walker, from m1n1, T8020 class): 3 levels × 11 index bits, 16K granule;
64-bit PTE: `VALID=bit0`, `SP_PROT_DIS=bit1`, `OFFSET=bits39:14` (phys>>14), `SP_START=63:52`,
`SP_END=51:40` `[DPT:44-49,94,155-170]`. TTBR holds L1 table phys>>12.
**T8030-UNCERTAIN:** DART MMIO base addresses and per-device stream assignments (t8103 dts shows
e.g. sio_dart @0x235004000 `[DTS:496-497]`; T8030 map must come from its ADT). t8103 ias=32 bits
`[DART:1177-1180 area, probe: ias=32 for T8020/T6000 types]`.

## 4. SART (ANS DMA allow-list)

Compatibles: `apple,t8015-sart`→**v0**, `apple,t8103-sart`→v2, `apple,t6000-sart`→v3
`[SART:354-368]`. m1n1 picks version from ADT prop `sart-version`, defaulting **t8015 ⇒ v0**
`[MSART:210-218]`. All versions are **direct-indexed tables of 16 entries**
(`APPLE_SART_MAX_ENTRIES=16`) `[SART:26]`; there is no transaction/CTRL register in current
sources.

**T8030-UNCERTAIN:** SART version on T8030 (v0 like t8015, or v2 like t8103). Emulator should
implement both layouts below; identical offsets, different field widths.

SARTv0 (t8015-class) `[SART:29-38,86-117]`:

| Offset | Name | R/W | Semantics |
|--------|------|-----|-----------|
| 0x00+4*idx | CONFIG(idx) | R/W | FLAGS=bits28:24 (ALLOW value = 0xf), SIZE=bits18:0, size = SIZE<<12 (max 0x7FFFF<<12) |
| 0x40+4*idx | PADDR(idx) | R/W | phys addr = value<<12 |

SARTv2 (t8103) `[SART:41-50]`: same offsets; FLAGS=31:24 (ALLOW=0xff), SIZE=23:0.

Protocol implemented by consumers (the "4-step" dance is: pick free entry → write PADDR → write
CONFIG(flags|size) → transaction live; removal = write 0/0):
`apple_sart_add_allowed_region`: find free idx (flags==0; entries non-zero at probe are
bootloader-protected) → `set_entry(i, ALLOW, paddr, size)` = write PADDR then CONFIG
`[SART:271-302,98-108]`. `remove_allowed_region`: match (paddr,size), write 0,0 `[SART:305-338]`.
ANS2 NVMe uses exactly this for RTKit shared-memory buffers `[NVME:260-296]`.

**Note on the task's "SART_DATA/ADDR/INDEX/FLAGS/CTRL 4-step transactional protocol":** that is
the *pre-2023 Asahi SARTv1 driver interface*, which is **not present in current mainline** and
could not be fetched this session (GitHub rate-limited; no authenticated access). Treat the
direct-indexed v0/v2 tables above as authoritative; the transactional description is
**T8030-UNCERTAIN** and likely a stale recollection — do not model CTRL/START semantics without
an actual source.

## 5. ANS2 NVMe (rootfs read path)

Two MMIO regions: `reg[0] "nvme"` (NVMe+Apple regs) and `reg[1] "ans"` (coprocessor control)
`[NVME:1511-1520]`; t8103 dts: nvme @0x27bcc0000 (0x40000), ans @0x277400000 (0x4000)
`[DTS:1007-1011]` — **T8030-UNCERTAIN addresses**.

HW variants `[NVME:1722-1744]`: `t8015` (depth 16, no linear-SQ/NVMMU), `t8103` (depth 64,
linear-SQ+NVMMU), `t8132` (+IOQ regs). **No `t8030` compatible exists upstream.**
**T8030-UNCERTAIN:** A13 ANS2 class (iOS 14.2). Likely t8015-class (16-deep, no NVMMU TCBs) but
the emulator must support both; decide from which doorbell xnu writes (0x1000 vs 0x2490c).

### 5.1 Apple-specific registers (offsets in "nvme" region unless noted)

| Offset | Name | R/W | Semantics |
|--------|------|-----|-----------|
| (ans reg) 0x44 | ANS_COPROC_CPU_CONTROL | R/W | bit4 RUN — starts ANS firmware before RTKit boot `[NVME:39-40,1098-1101]` |
| 0x1000 | NVME_REG_DBS (SQ0 tail db) | WO | **t8015 admin-SQ doorbell** (standard NVMe doorbell stride base) `[NVME:1526-1536]` |
| 0x1004 | ANS_ACQ_DB | WO | admin CQ head doorbell (Apple-specific; *not* 0x1008) — host writes cq_head `[NVME:42,1526-1536,705-706]` |
| 0x1008 | (t8015) IO SQ0 tail doorbell | WO | `NVME_REG_DBS+8` `[NVME:1536]` |
| 0x100C | ANS_IOCQ_DB | WO | IO CQ head doorbell `[NVME:43]` |
| 0x1200/0x1208/0x1210 | T8132_IOQ_CMDS/CQES/SIZE | WO | only on t8132+ (`needs_ioq_register`) `[NVME:45-47,1205-1213]` |
| 0x1210 | T8103_MAX_PEND_CMDS_CTRL | WO | max pending cmds, `depth | depth<<16` (t8103) `[NVME:49,1141-1150]` |
| 0x1300 | ANS_BOOT_STATUS | RO | must read **0xDE71CE55** ("de-ti-ce-ss") after RTKit boot; 1 s poll `[NVME:51-52,1111-1118]` |
| 0x24908 | ANS_LINEAR_SQ_CTRL | R/W | bit0 EN — enables linear (tag-indexed) SQs `[NVME:54-55,1132-1138]` |
| 0x2490C | ANS_LINEAR_ASQ_DB | WO | admin SQ doorbell in linear mode: write **tag** (=tail index) `[NVME:57,366]` |
| 0x24910 | ANS_LINEAR_IOSQ_DB | WO | IO SQ doorbell (tag) `[NVME:58]` |
| 0x28100 | NVMMU_NUM_TCBS | WO | max queue depth−1 (shared by both queues) `[NVME:60,1152-1154]` |
| 0x28108/0x28110 | NVMMU_ASQ/IOSQ_TCB_BASE | WO | 64-bit TCB array base `[NVME:61-63,1164-1170]` |
| 0x28118 | NVMMU_TCB_INVAL | WO | write command_id (tag) to invalidate its TCB `[NVME:63,241-248]` |
| 0x28120 | NVMMU_TCB_STAT | RO | must read 0 after invalidate (else "TCB invalidation failed") `[NVME:64,241-248]`. **Discrepancy:** m1n1 has 0x29120 `[MNVME:55]` — implement both reads as 0 |

Standard NVMe regs overlaid (NVMe 1.0 BAR layout; from m1n1 mirrors of the driver's usage):
CAP=0x00, VS=0x08, CC=0x14, CSTS=0x1C, AQA=0x24, ASQ=0x28, ACQ=0x30 `[MNVME:18-34]`;
driver: `AQA=(depth-1)|(depth-1)<<16`, `ASQ/ACQ` 64-bit writes, `CAP` read, `nvme_enable_ctrl`
(CC.EN=1, poll CSTS.RDY) `[NVME:1157-1179]`.

### 5.2 Queue model & IRQ conventions

- One admin + one IO queue, **single shared interrupt** `[NVME:126-134,1594-1597]`; t8103 dts IRQ
  = `AIC_IRQ 590` `[DTS:1012]` (**T8030-UNCERTAIN number**).
- Admin depth 2 `[NVME:75]`; IO depth = hw max−1 tags, admin tags reserved at bottom
  `[NVME:1346-1352]`.
- Completion: CQE phase bit toggling, host writes new cq_head to ACQ_DB/IOCQ_DB `[NVME:633-706]`;
  with linear SQ, each completed tag must be NVMMU-invalidated before reuse `[NVME:645-648,241-248]`.
- t8015 submit: 64-byte sqes[tail] (`memcpy`), tail++ %depth, write tail→sq_db. **Note:**
  `APPLE_NVME_IOSQES 7` ⇒ **IO SQ entries are 128 bytes** on this controller (`sq_tail<<7`)
  `[NVME:78,319-327]` (admin stays 64B).
- t8103 submit: program TCB[tag] {opcode, dma_flags(bit0=FROM device/read, bit1=TO device/write),
  command_id, length, prp1, prp2} (128 B, incl. AES IV @80) `[NVME:108-124,333-368]`, copy 64-B
  cmd to sqes[tag], write tag→LINEAR_*_DB.
- Boot flow for emulator: set CSTS per state machine; BOOT_STATUS→0xDE71CE55 once
  CPU_CONTROL.RUN + RTKit boot done; respond to admin commands (Identify, CreateCQ/SQ,
  SetFeatures, SetQueueCount=1) so reset_work completes and IO reads issue.
- "Boot namespace": no register in Linux/m1n1 — it is an ANS-firmware namespace concept
  (Identify namespace list; xnu mounts from the boot NS). **T8030-UNCERTAIN**; implement as
  regular NVMe NSID 1 with real rootfs backing.

## 6. SMC (System Management Controller)

**Transport on M1+/mainline = ASC mailbox + RTKit endpoint 0x20** — NOT MMIO `[SMC:13,72-79]`
`[MSMC]`. The MMIO handshake (SMC_KEY/VAL/CMD/RES/FLAGS) in the task brief is **not in any
fetched source** ⇒ offsets **T8030-UNCERTAIN**; keep the emulator's existing offsets, validate
via xnu probe. The *protocol semantics* below are authoritative and transport-independent.

Firmware commands (identical in Linux and m1n1) `[SMC:15-22]` `[MSMC:8-15]`:

| Cmd | Name | Meaning |
|-----|------|---------|
| 0x10 | READ_KEY | read `size` bytes of key into shared buffer |
| 0x11 | WRITE_KEY | write wsize bytes |
| 0x12 | GET_KEY_BY_INDEX | arg=index → returns key FourCC |
| 0x13 | GET_KEY_INFO | returns type FourCC + size + flags |
| 0x17 | INITIALIZE | (boot) |
| 0x18 | NOTIFICATION | async event from SMC |
| 0x20 | RW_KEY | combined read/write |

Message word layout (64-bit): `MSG=7:0, ID=15:12, SIZE=23:16, WSIZE=31:24, DATA=63:32`
`[SMC:21-27]`. Result word: RESULT=7:0 (0=OK), ID=15:12 must match request ID, SIZE 31:16 (m1n1)
or 23:16 (linux `SMC_SIZE`), VALUE/DATA=63:32 `[SMC:21-27,92]` `[MSMC:16-20]` — **size-field
width T8030-UNCERTAIN (23:16 vs 31:16); Linux returns `FIELD_GET(SMC_SIZE, ret)` and 0 on
error** `[SMC:88-92]`.

Handshake loop (emulate exactly): `msg_id = (msg_id+1)&0xf` → send → wait up to **500 ms** →
check ID match → RESULT!=0 ⇒ error; key data moves via shared-memory (SRAM) buffer, not the
message word `[SMC:52-92,95-140]`. Key flags: READABLE=bit7, WRITABLE=bit6, FUNCTION=bit4
`[SMC.h:46-48]`; keys are FourCC u32 big-endian packed `[SMC.h:31-44]`.

ASC mailbox registers (if xnu probes the "smc"/"ans" ASC device) `[ASC:8-24]`:
CPU_CONTROL 0x44 (bit4 START), A2I_CONTROL 0x110 / I2A_CONTROL 0x114 (FULL=bit16, EMPTY=bit17),
A2I SEND0/1=0x800/0x808, RECV0/1=0x810/0x818; I2A SEND0/1=0x820/0x828, RECV0/1=0x830/0x838.
RTKit endpoints: MGMT=0, CRASHLOG=1, SYSLOG=2, DEBUG=3, IOREPORT=4, OSLOG=8; versions 11–12
`[RTK (m1n1):22-27,70-71]` `[RTK (linux):74-75]`. MGMT messages: HELLO (MINVER/MAXVER 15:0/31:16),
EPMAP (BASE 34:32, BITMAP 31:0, MORE=bit51), STARTEP (EP 39:32, FLAG bit1), PWRSTATE 15:0;
per-EP BUFFER_REQUEST (SIZE 51:44, IOVA 43:0) `[RTK (linux):41-59]`.

## 7. WDT (watchdog)

Map `[WDT:37-52]` (m1n1 cross-check `[MWDT:8-10]`):

| Offset | Name | R/W | Semantics |
|--------|------|-----|-----------|
| 0x00/0x10/0x20 | WDx_CUR_TIME | R/W | free-running tick counter; **write 0 = kick** `[WDT:27-35,86-93]` |
| 0x04/0x14/0x24 | WDx_BITE_TIME | R/W | reset threshold (ticks) `[WDT:38,43,47]` |
| 0x08 | WD0_BARK_TIME | R/W | IRQ (bark) threshold (WD0 only) `[WDT:39]` |
| 0x0C/0x1C/0x2C | WDx_CTRL | R/W | bit0 IRQ_EN, bit1 IRQ_STATUS (W1C), bit2 RESET_EN `[WDT:50-52]` |

Boot-critical behavior: xnu/bootloaders disable by `CTRL=0` `[MWDT:30]`; reboot =
`BITE=0x100000, CUR=0, CTRL=4` `[MWDT:56-58]`; Linux restart = `CTRL=RESET_EN; BITE=0; CUR=0`
→ immediate reset `[WDT:121-140]`. Emulator: keep counters ticking at clk rate but never bite
unless the guest asked (or bite→reset for correctness); **T8030-UNCERTAIN:** clock rate
(clk-driven `[WDT:172-177]`; 24 MHz typical on Apple blocks — verify). t8103 WDT base
0x23d2b0000 `[DTS:892-893]` (**T8030-UNCERTAIN**).

## 8. PMGR (power/clock management)

PMGR is syscon + children; each **power-state (PS) register** is 32-bit at its own offset
(t8103: ps_sbr@0x100, ps_aic@0x108, ps_dwi@0x110, … ps_ans2@0x3F0, ps_apcie_st@0x418 — 8-byte
spacing) `[DTS-t8103-pmgr:10-56,722-731,829-831]` (**offsets are per-SoC; T8030-UNCERTAIN**).

PS register bits `[PMGR:20-38]` (identical m1n1 `[MPMGR:9-17]`):

| Bits | Name | Semantics |
|------|------|-----------|
| 31 | RESET | hold device in reset (assert: set RESET+DEV_DISABLE; deassert: clear both) `[PMGR:116-150]` |
| 28 | AUTO_ENABLE | auto-on; "active" if TARGET==0xF && AUTO_ENABLE `[PMGR:92-104]` |
| 27:24 | PS_AUTO | |
| 19:16 | PS_MIN | |
| 11 | PARENT_OFF | RO status: parent off |
| 10 | DEV_DISABLE | quiesce flag |
| 9/8 | WAS_CLKGATED/WAS_PWRGATED | RO sticky flags |
| 7:4 | **PS_ACTUAL** | RO actual state — polls converge here |
| 3:0 | **PS_TARGET** | R/W target state |

State codes: `0xF=ACTIVE, 0x4=CLKGATE, 0x0=PWRGATE` `[PMGR:33-35]`. Set protocol: read, clear
`AUTO_ENABLE|WAS_*|PS_TARGET`, write new TARGET, poll until `PS_ACTUAL==target` (timeout 100 µs)
`[PMGR:52-90]` — **emulator must mirror writes into ACTUAL immediately (or after a few reads)**
so these polls don't stall the boot path. Gate-poll reads: answer `PS_ACTUAL=0xF` for devices
xnu expects powered (ANS/APCIE/SIO/AIC parents).

Clock-gate registers (per-device 1-bit enables in grouped gate regs) are ADT-indexed
(`clock-gates`, group+offset into ps-regs space; PMGR_FLAG_VIRTUAL=0x10 devices have no reg)
`[MPMGR:20,130-147,201-223]`. Mainline models no separate gate cells for t8103 — exact gate
offsets are DT/ADT data, **T8030-UNCERTAIN**; a R/W-scratch + bit0-enable behavior suffices for
gate-poll reads.

CPU pstate (cpufreq, optional): per-cluster CPUPM block — DVFS_CMD 0x20 (BUSY bit31, SET bit25,
PS1/PS2 fields), DVFS_STATUS 0x50 (CUR_PS/TGT_PS fields, layout varies per SoC incl. S5L8960X),
DVFS_PLL_STATUS 0xC0 `[refs/linux/cpufreq/apple-soc-cpufreq.c:25-56]`. **T8030-UNCERTAIN**
(A13 pstate field layout not in driver's variants).

---

## Source inventory (saved)

```
tools/re/refs/linux/irqchip/irq-apple-aic.c      # AIC v1/v2/v3
tools/re/refs/linux/irqchip/apple-aic.h          # FIQ index bindings
tools/re/refs/linux/iommu/apple-dart.c           # DART T8020/T6000/T8110
tools/re/refs/linux/nvme/apple.c                 # ANS2 NVMe
tools/re/refs/linux/watchdog/apple_wdt.c         # WDT
tools/re/refs/linux/soc/sart.c                   # SART v0/v2/v3
tools/re/refs/linux/soc/rtkit.c                  # RTKit protocol
tools/re/refs/linux/mfd/macsmc.c, macsmc.h       # SMC (RTKit transport)
tools/re/refs/linux/pmdomain/pmgr-pwrstate.c     # PMGR PS regs
tools/re/refs/linux/cpufreq/apple-soc-cpufreq.c  # DVFS/pstate
tools/re/refs/linux/dts-t8103.dtsi, dts-t8103-pmgr.dtsi
tools/re/refs/m1n1/  aic.c aic.h aic_regs.h dart.c dart.h dart8020.py dart8110.py
                     sart.c sart.h smc.c smc.h wdt.c wdt.h pmgr.c pmgr.h
                     nvme.c nvme.h asc.c asc.h rtkit.c rtkit.h
tools/re/refs/xnu/   AIC.h H13.h apple_arm64_common.h apple_arm64_regs.h sleh.c
                     (from apple-oss-distributions xnu-7195.121.3 tarball, /tmp/xnu-xnu-7195.121.3)
```

Not fetched (blocked): inferno-os `hw/intc/apple_aic.c` (task brief's guessed path — inferno-os
public repo has no such path); old Asahi transactional SARTv1 + pre-RTKit MMIO apple-smc.c
(GitHub raw/API rate-limited from this IP; codeload worked but no tag with those files could be
identified). drivers/mailbox/apple-mailbox.c 404'd on googlesource mirror; ASC mailbox covered by
m1n1 asc.c instead.
