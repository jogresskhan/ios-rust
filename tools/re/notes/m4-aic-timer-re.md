# M4-a RE notes — IRQ/AIC/timers + DT-gate (kernel 18C66, T8030/A13, iPhone 11)

Tooling: `tools/re/extraction/m4a_decompress.py` (IM4P+bvx2 LZFSE → `/tmp/kc18c66.macho`,
0x2BA8488 bytes, Mach-O 0xFEEDFACF), `m4a_common.py` (segment walk copied from
`m2_fixup_census.py`; capstone CS_ARCH_ARM64/CS_MODE_LITTLE_ENDIAN, detail on),
`m4a_xref.py` (raw ADRP prefilter + capstone confirm), `m4a_blscan.py` (BL target scan),
`m4a_memscan.py` (full linear disasm_lite with ADRP+ADD state → resolved VA hits).

## Segments (from decompressed Mach-O load commands)

| seg | vmaddr | vmsize | fileoff |
|---|---|---|---|
| __TEXT | 0xfffffff007004000 | 0x6e4000 | 0x0 |
| __DATA_CONST | 0xfffffff0076e8000 | 0x330000 | 0x6e4000 |
| __TEXT_EXEC | 0xfffffff007a18000 | 0x1e68000 | 0xa14000 |
| __PPLTEXT | 0xfffffff009880000 | 0x1c000 | 0x287c000 |
| __DATA | 0xfffffff0098ac000 | 0x254000 | 0x28a8000 |
| __BOOTDATA | 0xfffffff009b00000 | 0x20000 | 0x2a4c000 |

No LC_SYMTAB symbols (nsyms=0), no LC_DYLD_CHAINED_FIXUPS at top level. Everything below is
from capstone disassembly only.

## Task 1 — THE DT-GATE

### Globals (all ship ZERO in __DATA_CONST/__const, verified by file read)
| VA | role |
|---|---|
| 0xfffffff007744988 | DT base pointer (`x20` in iterators) |
| 0xfffffff007744990 | DT end (base+size) |
| 0xfffffff007744998 | DT valid flag (w32, = (base != 0)) |
| 0xfffffff0077449a0 | DT size |
| 0xfffffff007744ad0 | DT config struct: +0 = base, +0x10 = size |
| 0xfffffff007744ae0 | DT size copy |
| 0xfffffff007744a38 | dt_init once-guard (w32) |
| 0xfffffff007701cf8 | kernel_pmap pointer (ships fixup-encoded 0x00d7fff0098a4ac0) |

### Q1: what 0xfffffff008136f10 READS (full function, capstone)
```
0xfffffff008136f10: pacibsp
0xfffffff008136f14: stp x20, x19, [sp, #-0x20]!
0xfffffff008136f18: stp x29, x30, [sp, #0x10]
0xfffffff008136f1c: add x29, sp, #0x10
0xfffffff008136f20: adrp x20, #0xfffffff007004000      ; constant = kernel __TEXT vmaddr
0xfffffff008136f24: add x20, x20, #0
0xfffffff008136f28: mov x0, x20
0xfffffff008136f2c: bl #0xfffffff008169574             ; kvtophys_at(VA)
0xfffffff008136f30: mov x19, x0
0xfffffff008136f34: cbnz x0, #0xfffffff008136f58       ; nonzero PA → use it
0xfffffff008136f38: adrp x8, #0xfffffff007701000
0xfffffff008136f3c: ldr x0, [x8, #0xcf8]               ; kernel_pmap
0xfffffff008136f40: mov x1, x20
0xfffffff008136f44: bl #0xfffffff007b72f88             ; pmap software walk (returns ppnum)
0xfffffff008136f48: lsl x8, x0, #0xe                   ; <<14 = PA for 16K pages
0xfffffff008136f4c: bfi x20, x0, #0xe, #0x32
0xfffffff008136f50: cmp x8, #0
0xfffffff008136f54: csel x19, xzr, x20, eq             ; x19 = PA(kernel base) or 0
0xfffffff008136f58: adrp x8, #0xfffffff007744000
0xfffffff008136f5c: ldr x20, [x8, #0x988]              ; DT base global
0xfffffff008136f60: mov x0, x20
0xfffffff008136f64: bl #0xfffffff008169574             ; kvtophys_at(DT base VA)
0xfffffff008136f68: cbnz x0, #0xfffffff008136f8c
0xfffffff008136f6c: adrp x8, #0xfffffff007701000
0xfffffff008136f70: ldr x0, [x8, #0xcf8]               ; kernel_pmap
0xfffffff008136f74: mov x1, x20
0xfffffff008136f78: bl #0xfffffff007b72f88
0xfffffff008136f7c: lsl x8, x0, #0xe
0xfffffff008136f80: bfi x20, x0, #0xe, #0x32
0xfffffff008136f84: cmp x8, #0
0xfffffff008136f88: csel x0, xzr, x20, eq
0xfffffff008136f8c: cmp x0, x19
0xfffffff008136f90: cset w0, lo                        ; w0 = PA(DT) < PA(kernbase)
0xfffffff008136f94: ldp x29, x30, [sp, #0x10]
0xfffffff008136f98: ldp x20, x19, [sp], #0x20
0xfffffff008136f9c: retab
```
Reads, exhaustively:
1. **`at s1e1r, x0` + `mrs x1, par_el1`** inside callee 0xfffffff008169574 (= `kvtophys_at`):
   ```
   0xfffffff008169574: mrs x2, daif
   0xfffffff008169578: msr daifset, #3
   0xfffffff00816957c: at s1e1r, x0
   0xfffffff008169580: isb
   0xfffffff008169584: mrs x1, par_el1
   0xfffffff008169588: msr daif, x2
   0xfffffff00816958c: tbnz w1, #0, #0xfffffff00816959c   ; PAR.F=1 → fail path
   0xfffffff008169590: bfxil x1, x0, #0, #0xc             ; PA page | VA low 12 bits
   0xfffffff008169594: and x0, x1, #0xffffffffffff        ; 48-bit PA
   0xfffffff008169598: ret
   0xfffffff00816959c: mov x0, #0                          ; fail → 0
   0xfffffff0081695a0: ret
   ```
   → needs PAR_EL1 semantics (F bit, PA field) + AT S1E1R + DAIF save/restore.
2. **Memory loads**: `[0xfffffff007744988]` (DT base VA), `[0xfffffff007701cf8]` (kernel_pmap).
3. Fallback callee 0xfffffff007b72f88 = `pmap_find_phys(kernel_pmap, va)` → ppnum:
   - range check `[pmap+0x10] <= va < [pmap+0x18]` (fail → 0)
   - PAC-auth of root table ptr `[pmap+0]` with modifier 0xb2b7<<48 (`autda`/`xpacd`/`brk #0xc472`)
   - 3-level walk, 16K granule: L0 idx = ubfx(va,#0x24,#3), L1 idx = ubfx(va,#0x19,#0xb),
     L2 idx = ubfx(va,#0xe,#0xb); valid bit0 / block bit1 checks; `bl 0xfffffff007b818a0`
     (phys→virt of table pages) between levels; final merge via level mask table at
     0xfffffff0070097e8 + 0x38*level, field+8 (init values: lvl1 mask 0x7fffffffffff,
     lvl2 0xfffffffff, lvl3 0x1ffffff — i.e. 2^47/2^36/2^25 block coverages).
4. NO MMIO loads, NO boot_args field reads, NO other sysregs (only daif, par_el1).

### Q2: what makes bit0 = 1
`cset w0, lo` after `cmp x0, x19` → **w0 = (PA(DT-global-value) < PA(0xFFFFFFF007004000))**, unsigned,
where each operand is 0 when translation fails. Consequence: if the DT global is 0 (never
initialized), PA(DT)=0, and the gate returns 1 iff kvtophys(kernel text base) != 0 — i.e. the
gate returns 1 (skip) in exactly the emulator state (text mapped, VA 0 unmapped).

### Q3: the gated store block in arm_vm_init (function 0xfffffff007b82e34, call site 0xfffffff007b83f54)
```
0xfffffff007b83f54: bl #0xfffffff008136f10
0xfffffff007b83f58: ldr w8, [x21, #0x160]
0xfffffff007b83f5c: tbnz w0, #0, #0xfffffff007b83fc8      ; gate==1 → skip stores
0xfffffff007b83f60: sub w9, w8, #1
0xfffffff007b83f64: add x10, sp, #0x50
0xfffffff007b83f68: umaddl x9, w9, w19, x10                ; &region_list[n-1], stride 0x18
0xfffffff007b83f6c: ldr x9, [x9, #8]                       ; region base
0xfffffff007b83f70: adrp x10, #0xfffffff007702000
0xfffffff007b83f74: ldr x10, [x10, #0x568]                 ; global A
0xfffffff007b83f78: adrp x11, #0xfffffff007744000
0xfffffff007b83f7c: add x11, x11, #0xad0
0xfffffff007b83f80: sub x9, x9, x10                        ; delta = region - globalA
0xfffffff007b83f84: ldr x10, [x11]                         ; [0x744ad0]
0xfffffff007b83f88: add x9, x10, x9
0xfffffff007b83f8c: str x9, [x11]                          ; [0x744ad0] += delta
0xfffffff007b83f90: ldr x10, [x11, #0x10]                  ; size
0xfffffff007b83f94: cmn x9, x10
0xfffffff007b83f98: b.hs #0xfffffff007b84850               ; overflow → panic
0xfffffff007b83f9c: adrp x11, #0xfffffff007744000          ; (no add — plain page)
0xfffffff007b83fa0: str x9, [x11, #0x988]                  ; [0x744988] = base
0xfffffff007b83fa8: str x10, [x11, #0x9a0]                 ; [0x7449a0] = size
0xfffffff007b83fac: add x10, x10, x9
0xfffffff007b83fb4: str x10, [x11, #0x990]                 ; [0x744990] = base+size
0xfffffff007b83fb8: cmp x9, #0
0xfffffff007b83fbc: cset w9, ne
0xfffffff007b83fc0: adrp x10, #0xfffffff007744000
0xfffffff007b83fc4: str w9, [x10, #0x998]                  ; [0x744998] = (base != 0)
```
So the gate only decides an **arm_vm_init rebase** of already-set DT globals.

### Who actually populates the DT globals (the real init path)
`dt_init` @ **0xfffffff00813995c** (ungated!):
```
0xfffffff00813998c: adrp x8, #0xfffffff007744000
0xfffffff008139990: ldr w8, [x8, #0xa38]          ; once-guard
0xfffffff008139994: cbz w8, #0xfffffff0081399b0
   ; guard==0 branch: guard=1; copy config (x1) fields into 0x744a38-struct:
   ;   [0x744ad0] = [config+0x60]  (str x9,[x8,#0x98] @0x81399c8)
   ;   [0x744ae0] = [config+0x68]  (str x9,[x8,#0xa8] @0x81399d0)
0xfffffff008139a28: (always) x8=[0x744ad0], x9=[0x744ae0]
0xfffffff008139a3c: b.hs panic                    ; cmn overflow → "DeviceTree overflow: %p, size %#zx"
                                                    ;   (string 0xfffffff0073ade9b)
0xfffffff008139a44: str x8, [x21, #0x988]         ; DT base
0xfffffff008139a4c: str x9, [x10, #0x9a0]         ; DT size
0xfffffff008139a58: str x9, [x22, #0x990]         ; DT end
0xfffffff008139a68: str w8, [x20, #0x998]         ; DT flag = (base != 0)
```
dt_init callers (BL scan): 0xfffffff007b808f8 (mode=0, config = memmove'd 0x2e0-byte boot
config at 0xfffffff007702128, copied by 0xfffffff00987c290=memmove from arm_init's arg in fn
0xfffffff007b80288), 0xfffffff007b80c78 (mode=1, config 0xfffffff009a4ae60), 0xfffffff007b816d4.
Other writers of DT globals: rebaser 0xfffffff0081398e4 (no BL callers), clearer
0xfffffff0080326a8 (str xzr×3+wzr — teardown), writer 0xfffffff008136eb0 ("DeviceTree overflow"
panic string, no BL callers).

### Q4 — VERDICT for the emulator
The crash (TranslationFault va=0x4 at pc=0xfffffff0081377b4, lr=0xfffffff007b8cc10) is the DT
iterator `DTIteratorNext` @0xfffffff008137790 doing `ldr x0,[x20,#8]` (=NULL) then
`ldr w9,[x0,#4]`. Its caller DTIteratorCreate @0xfffffff007b8cbc0 reads flag
`ldr w8,[0x744998]; cbz → skip init` but still calls the iterator with a zeroed object:
```
0xfffffff007b8cbc8: ldr w8, [x19, #0x998]
0xfffffff007b8cbcc: cbz w8, #0xfffffff007b8cbec   ; flag==0 → leave iterator zeroed
...
0xfffffff007b8cc0c: bl #0xfffffff008137790        ; → NULL+4 fault
```
Fix hierarchy for the emulator:
1. **Primary**: feed DeviceTree base/size through the boot config (0x2e0-byte struct → memmove
   to 0xfffffff007702128; fields **+0x60 = DT base VA, +0x68 = DT size**) so ungated
   `dt_init` @0xfffffff00813995c writes 0x744988/0x990/0x998/0x9a0 + 0x744ad0/0xae0.
   Implementing the gate correctly does NOT populate them — the only gated block is a rebase.
2. **kvtophys (0xfffffff008169574) must work** (AT S1E1R → PAR_EL1 F-bit + PA, DAIF masking):
   it is used 50× across the kernel and inside the gate.
3. The gate 0x8136f10 needs nothing special: with DT global populated, it compares
   PA(DT-VA) vs PA(kernel-base) and returns 1 (=skip rebase) in the normal case — the
   hardware-typical outcome, harmless to replicate exactly.

# PASS 2 (resumed session) — source cross-check + sysreg/WFI/VBAR/AIC byte evidence

Source tree `/tmp/xnu-xnu-7195.121.3` (exact 14.2-era drop) now grounds the earlier disassembly.
New scans: `m4a_sysreg_scan2.py` (encoding-normalized), byte-exact sysreg imm-scan (op0=3 bases:
MRS=0xD5380000|op1<<16|CRn<<12|CRm<<8|op2<<5|Rt, MSR=0xD5180000|…) — capstone 5 emits some sysregs
as raw `s3_x_c..` names, so byte-scan is the complete enumeration. Artifacts:
`/tmp/sysreg_hits.json`, `/tmp/aic_early_init.txt`, `/tmp/aic_ppl*.txt`, `m4_sysreg_table.out`.

## 1. DT-gate — SOURCE-IDENTIFIED

**0xfffffff008136f10 = `SecureDTIsLockedDown()`** (pexpert/gen/device_tree.c):
```c
addr64_t exec_header_phys = kvtophys((vm_offset_t)&_mh_execute_header);   // = 0xfffffff007004000
if (kvtophys((vm_offset_t)DTRootNode) < exec_header_phys) { assert(kvtophys(DTEnd) < ...); return true; }
return false;
```
Matches the disassembly exactly (`cset w0, lo` after `cmp PA(DT), PA(kernbase)`; kvtophys = the
`at s1e1r`+PAR_EL1 callee 0x8169574; `_mh_execute_header` = kernel __TEXT vmaddr, hence the
`adrp x20, 0xfffffff007004000`). Both call sites in osfmk/arm64/arm_vm_init.c:
- line 1203: `if (SecureDTIsLockedDown()) { segEXTRADATA = PE_state.deviceTreeHead; segSizeEXTRADATA = PE_state.deviceTreeSize; }`
- line 1472: `if (!SecureDTIsLockedDown()) PE_slide_devicetree(temp_ptov_table[i].va - end_kern);`
  ← the disassembled gated block @0xfffffff007b83f54.

**The skipped stores = `PE_slide_devicetree`** (pexpert/arm/pe_init.c:372):
`PE_state.deviceTreeHead += slide; SecureDTInit(head, size)` → SecureDTInit writes
DTRootNode(0x744988)/DTEnd(0x744990)/DTInitialized w32(0x744998)/DTSize(0x7449a0) + the head copy
(0x744ad0) — byte-identical to the dumped str block. `SecureDTInit` = dt_init @0x813995c ✓
(panic string "DeviceTree overflow: %p, size %#zx" at device_tree.c:238).

**Why bit0=1 in the emulator:** DTRootNode global is 0 (nothing populated it) → kvtophys(0)
fails → returns 0 → `0 < PA(kernel text)` → true. Same value real hardware takes when the DT
lives in EXTRADATA (before the kernel — the normal prelinked-IPSW case). The gate is **benign**;
the crash (DTIteratorCreate → `ldr x0,[x20,#8]` NULL @0x81377b4) is purely because
`PE_init_platform` (pe_init.c:393-395) reads **`boot_args->deviceTreeP` (+0x60) /
`deviceTreeLength` (+0x68)** and the emulator passes zeros. boot_args layout (boot.h):
Revision@0, Version@2, virtBase@0x8, physBase@0x10, memSize@0x18, topOfKernelData@0x20,
Video@0x28 (6×u64), machineType@0x58, **deviceTreeP@0x60, deviceTreeLength@0x68**,
CommandLine[608]@0x70, **bootFlags@0x2D0** (kBootFlagsDarkBoot=bit0), memSizeActual@0x2D8.
The gate itself reads NO boot_args field (verified). bootFlags@0x2d0 IS kernel-read but at
0x8168110/0x8168238 (`ldr x26,[x20,#0x2d0]` in the early CPU-start paths), unrelated to the gate.

## 2. Generic timer — sysregs, frequency, FIQ path

Byte-exact sysreg census (whole kernel, all +Rt forms):
| reg | enc | n | sites |
|---|---|---|---|
| MSR VBAR_EL1 | 0xD518C000| 4 | 0x81680fc, 0x8168224, 0x81684cc, 0x9899678(PPL) |
| MRS CNTFRQ_EL1 | 0xD538E000 | **0** | — kernel never reads CNTFRQ |
| MRS/MSR CNTKCTL_EL1 | 0xD538E100 / 0xD518E100 | 3/3 | 0x7b8160c/18, 0x7b8ed1c/28, 0x7b8ee14/24 |
| MRS CNTVCT_EL0 | 0xD53BE040 | 804 | monotonic everywhere (first 0x7a20afc) |
| MRS CNTPCT_EL0 | 0xD53BE020 | **0** | — |
| MSR CNTV_CTL_EL0 | 0xD51BE320 | 5 | 0x7b80ccc, 0x7b816f8, 0x7b81784, 0x7b8188c, 0x7b8ecec |
| MSR CNTP_CTL_EL0 | 0xD51BE220 | 5 | same sites (paired) |
| MSR CNTV_TVAL_EL0 | 0xD51BE300 | 6 | 0x7b7ff94, 0x7b8e7ec, 0x7b930cc, 0x7b93208, 0x7b93298, 0x7b93354 |
| MRS CNTV_CTL/TVAL | 0xD53BE320/300 | 3/1 | 0x7b8a688, 0x7b8e86c(ml_get_timer_pending), 0x7b9318c / 0x7b8e864 |
| CNTV/CNTP_CVAL | 0xD5(1/3)BE240/340 | **0** | deadline uses TVAL, not CVAL |
| CNTHCTL_EL2 / CNTVOFF_EL2 | — | 0 | no EL2 timer config (EL1 boots directly) |

Canonical init pair (arm_init @0x7b80ccc; per-CPU @0x7b816f8/0x7b81784/0x7b8188c; re-enable
helper @0x7b8ece4): `mov w8,#1; msr cntv_ctl_el0,x8` (virtual timer ENABLE, unmasked) +
`mov w8,#2; msr cntp_ctl_el0,x8` (physical timer DISABLE+IMASK). Deadline = 32-bit
`msr cntv_tval_el0, w0` @0x7b8e7ec (`rtclock` arm path; `cpu_decrementer=-1` first). Absolute
time = `isb; mrs cntvct_el0` + epoch at cpu_data+0x4f8→+0x58 (@0x7b8e800). CNTKCTL @0x7b8ed1c:
`mrs/orr (field<<4)/orr #0xF/msr` — EL0 PCTEN/VCTEN/PTEN/VTEN = 0xF (userland readouts).

**Frequency:** pe_identify_machine.c: `t8030-io` is not in the hardcoded list → `use_dt=1` →
defaults `gPEClockFrequencyInfo.timebase_frequency_hz = 24000000`, bus 100MHz, cpu 400MHz,
overridden by `/cpus` children with state=="running" + timebase/bus/cpu-frequency props —
**the n104ap ADT cpu nodes have none of those props** (verified in ADT census) →
**timebase = 24 MHz** is the effective value. CNTFRQ itself is never read → emulator may set
CNTFRQ=24 MHz for fidelity but boot does not depend on it; CNTVCT ticking does.

**FIQ path (sleh.c ground truth, sleh_fiq @1783):** order = (1) `gFastIPI` (default 1,
machine_routines.c:118): `MRS IPISR_EL1` bit0 → ack (`MSR IPISR_EL1`) + `cpu_signal_handler()`;
(2) MONOTONIC_FIQ `mt_pmi_pending` → mt_fiq; (3) `ml_get_timer_pending()` = **read CNTV_CTL_EL0,
test ISTATUS (bit2)** (machine_routines.c:2038) → `cdp->cpu_decrementer = -1; rtclock_intr(TRUE)`.
No AIC IACK in the FIQ path at all. Device IRQs: `sleh_irq` (1752) → `PE_handle_ext_interrupt()`
(USE_APPLEARMSMP=1, board_config.h:242) — implemented by the AIC kext below. AIC IACK vec types
(pexpert AIC.h): ext=1, IPI=4, timer=7.

## 3. WFI + VBAR

- VBAR_EL1: early = **0xfffffff008165000** (`adrp x0,#0x81650000; add #0; msr vbar_el1` @0x81680fc
  right after `msr sctlr_el1`+isb on the boot CPU, and again @0x8168224 on secondaries after
  `msr oslar_el1,xzr; msr daifset,#0xf`). Post-relocation = **0xfffffff00815f000 + slide**
  (`adrp x0,#0x815f000; add x0,x0,x22; sub x0,x0,x23; msr vbar_el1` @0x81684cc). PPL table =
  0xfffffff009898000 (@0x9899678, with entry ptr 0x9898c8c written to S3_6_C15_C8_1 — the PPL
  interrupt vector config reg).
- WFI: only **2 sites** in the whole kernel. Idle = fn @0x81699a0 (`machine_idle`): sets Apple
  WFI-gate sysregs `S3_5_C15_C5_0 |= 0xA00000` and `S3_5_C15_C6_0 |= 0x400000000 |0x10000 |0x6000
  |0x60000 |0x6000000 |0x100000000` (mask/clear idempotent bit fiddling), then
  `dsb sy; isb; wfi; b .-4` loop @0x8169a10. **No DAIF change inside the idle loop** — interrupts
  are already unmasked: the timer-enable path @0x7b81880 does `isb; msr daifclr,#4` (unmask FIQ)
  immediately before `cntv_ctl=1/cntp_ctl=2`. Second WFI @0x8169a3c = AP-spin wait
  (`wfi; cbz x30,…`) in the cpu-start path. Emulator: idle = WFI trap with FIQ/IRQ unmasked,
  wake = deliver FIQ (timer) / IRQ via vbar table at 0x8165000.

## 4. AIC boot-time writes

xnu public source contains **no AIC driver body** — only `pexpert/pexpert/arm/AIC.h` (+arm64 twin),
whose offset table **exactly matches the v1 layout** from the sibling note: AicRev 0x0000, Cap0
0x0004, Cap1 0x0008, Rst 0x000C, GlbCfg 0x0010, MainTim 0x0020/0x0028, WhoAmI 0x2000, Iack 0x2004
(vec type ext=1/IPI=4/timer=7), IPISet 0x2008, IPIClr 0x200C (self bit31), TmrCfg 0x2010
(En=1, FSL: PTI=0/SGTI=1/ETI=2 <<4), TmrCnt 0x2014, TmrIntStat 0x2018 (Pct=1), TmrStateSet/Clr
0x201C/0x2020, TgtDst(n)=0x3000+4n, SwGenSet/Clr=0x4000/0x4080+4n, IntMaskSet/Clr=0x4100/0x4180+4n,
HwIntMon=0x4200+4n, per-CPU alias 0x5000+0x80n (+WhoAmI/Iack/IPISet/IPIClr/TmrCfg/TmrCnt/
TmrIntStat/TmrStateSet/TmrStateClr at +0x00..0x20).

**pexpert boot-time AIC writes on T8030: NONE.** pe_arm_init_interrupts →
pe_arm_map_interrupt_controller maps gPicBase from the DT "interrupt-controller"/"master" reg
(soc_phys 0x200000000 + 0x3B100000 → 0x23B100000) and gTimerBase from device_type="timer"
(= aic-timebase, 0x23B108000) — ADT-confirmed. pe_arm_init_timer: for arm64 `tbd_funcs =
&empty_funcs` (the T8002 branch that writes TmrCnt/TmrCfg/TmrIntStat is #ifdef'd out);
`ml_init_timebase` (arm64, machine_routines.c:859) only stores the funcs pointer. So the
"mask-all at boot" work belongs to kext **com.apple.driver.AppleInterruptController** (name found
in __PRELINK_INFO @ fileoff 0x2b490cc), whose code lives at **0xfffffff00988e000-0x98910000**
(PPL-adjacent text). Byte-verified MMIO ops there: `ldr/str w, [x19, #0x2008/0x200C/0x2004/
0x2010/0x2014/0x2018/0x201C/0x2020]` with x19 = mapped AIC base (e.g. IPI ack path
@0x988ef9c-0x988efc4: ldr 0x200C / ldr 0x2008 / str; handler table stride 0x28; mask bitmap
writes `str wzr,[x9, w?, uxtw]` @0x988ec98/0x988efe0). The 0x4100/0x4180/0x3000 windows exceed
imm12 range → accessed via computed bases (add #0x4000-class), not byte-pinned: **the exact
MASK_SET-all-ones loop is NOT yet byte-verified** — flagged honestly; the header + kext identity
is the source ground truth, emulator can implement MASK_SET/MASK_CLR/TGT_DST per the table.
Separate timebase-page user: fn @0x834edac writes `[timerbase+0x2014/0x2018]` (64-bit counter
split), `0x201C`, `0x2020`, `0x200C`, `0x2010` — the aic-timebase banked-timer block (device_type
= "timer"), i.e. AIC.MainTim read/write via the +0x23B108000 page.

**Emulator takeaways (AIC v1 @0x23B100000+0x8000):** WHOAMI/IACK/IPI(0x2000-0x200C) + banked
timer (0x2010-0x2020) + TgtDst(0x3000) + SwGen(0x4000/0x4080) + Mask(0x4100/0x4180) + HwIntMon
(0x4200) + per-CPU alias(0x5000+0x80n) are the only windows xnu touches; FIQ timer path bypasses
AIC (CNTV_CTL ISTATUS); fast IPI uses IPISR_EL1 sysreg, not AIC 0x2008 (both exist on this SoC).
