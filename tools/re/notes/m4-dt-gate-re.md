# M4-A RE notes — the DT-gate caller chain and the boot_args DeviceTree-field mismatch

Task: RESEARCH ONLY. Kernel = real iOS 14.3 (18C66) T8030 kernelcache `/tmp/kc18c66.macho`
(decompressed, `__TEXT` vm 0xfffffff007004000 @ file 0). Stop under investigation:
TranslationFault(load, invalid descriptor) va=0x4, pc=0xfffffff0081377b4, after
8,135,842 retired insns (`/tmp/bf-m4-baseline.log`).

Tools (all capstone-derived, no hand bit-splitting):
* `tools/re/reports/m4_dt_caller_chain.py` — full-function disassembly, pacibsp
  back-scan, BL scans (`m4a_blscan`), streaming ADRP+xref scan, file-byte reads
  (output archived at `/tmp/m4_dt_caller_chain.out`).
* `tools/re/reports/m4_dt_fixture_cpus.py` — IM4P→LZFSE decode of the DeviceTree
  fixture (liblzfse) + flat-tree parse + `/cpus` dump (output at `/tmp/m4_dt_cpus.out`).
* `tools/re/reports/m4_stop_context.py` — segment map + stop-site windows (M3-era helper).
* xnu source cross-reference: `/tmp/xnu-xnu-7195.121.3` (xnu-7195.121.3 = the exact
  Darwin-20 lineage of build 18C66) — used ONLY to name functions; every xnu-side
  claim below is anchored in disassembly of the real binary, not the source.

---

## 1. Evidence — the stop, register-exact

The faulting function is **SecureDTIterateEntries @ 0xfffffff008137790** (pexpert
`pexpert/gen/device_tree.c` iterator-next; prior notes called it "DTIteratorNext").
Full capstone function (ends `retab` at 0xfffffff00813781c):

```
0xfffffff008137790: pacibsp
0xfffffff008137794: sub  sp, sp, #0x30
0xfffffff008137798: stp  x20, x19, [sp, #0x10]
0xfffffff00813779c: stp  x29, x30, [sp, #0x20]
0xfffffff0081377a0: add  x29, sp, #0x20
0xfffffff0081377a4: mov  x19, x1          ; out: DTEntry *nextEntry
0xfffffff0081377a8: mov  x20, x0          ; iter
0xfffffff0081377ac: ldr  x8, [x0, #0x20]  ; iter->currentIndex
0xfffffff0081377b0: ldr  x0, [x0, #8]     ; iter->currentScope   → NULL
0xfffffff0081377b4: ldr  w9, [x0, #4]     ; currentScope->nChildren  ← FAULT va=0x4
0xfffffff0081377b8: cmp  x8, x9
0xfffffff0081377bc: b.hs 0xfffffff0081377d8      ; index >= nChildren → kIterationDone
0xfffffff0081377c0: add  x9, x8, #1
0xfffffff0081377c4: str  x9, [x20, #0x20]
0xfffffff0081377c8: cbz  x8, 0xfffffff0081377e4  ; first child path (bl 0x81373cc GetFirstChild)
0xfffffff0081377cc: ldr  x0, [x20, #0x10]        ; iter->currentEntry
0xfffffff0081377d0: bl   0xfffffff0081375ec      ; GetNextChild
…
0xfffffff0081377e8: str  x0, [x20, #0x10]
0xfffffff0081377ec: adrp x8, #0xfffffff007744000 ; region check vs DTRoot/DTEnd
0xfffffff0081377f0: ldr  x9, [x8, #0x988]         ; DTRootNode
0xfffffff0081377f8: ldr  x10, [x8, #0x990]        ; DTEnd
0xfffffff0081377fc: cmp  x9, x0
0xfffffff008137800: ccmp x10, x0, #0, ls
0xfffffff008137804: b.lo 0xfffffff008137820      ; outside region → panic
0xfffffff008137808: str  x0, [x19]
0xfffffff00813780c: mov  w0, #1                  ; kSuccess
0xfffffff008137810: ldp  x29, x30, [sp, #0x20] …
0xfffffff00813781c: retab
```

[E1] Iterator layout recovered from the code: `{+0x0 outerScope, +0x8 currentScope,
+0x10 currentEntry, +0x18 savedScope, +0x20 currentIndex}` — matches
`OpaqueDTEntryIterator` in `pexpert/pexpert/device_tree.h`.
[E2] Register state at stop cross-checks perfectly (`/tmp/bf-m4-baseline.log`):
x20=0xFFFFFFF009B0FEC0 = iter (caller's sp+0x50), x19=x1=0xFFFFFFF009B0FEF0 =
&child (caller's sp+0x80), x0=0 = the loaded `currentScope`, fault va=0x4 =
`[NULL+4]` = nChildren of a NULL node, x29=0x…9B0FE60 = sp+0x20, sp=0x…9B0FE40 =
caller_sp−0x30, x30=0xFFFFFFF007B8CC10 = return of the bl below. Nothing else in
the dump contradicts this frame.
[E3] The DT globals the iterator depends on all ship ZERO in the file (read from
`/tmp/kc18c66.macho` by the report script):

| VA | meaning (source name) | file bytes |
|---|---|---|
| 0xfffffff007744988 | DTRootNode | 0 |
| 0xfffffff007744990 | DTEnd | 0 |
| 0xfffffff007744998 | DTInitialized (w32) | 0 |
| 0xfffffff0077449a0 | DTSize | 0 |
| 0xfffffff007744ad0 | PE_state.deviceTreeHead | 0 |
| 0xfffffff007744ae0 | PE_state.deviceTreeSize | 0 |
| 0xfffffff007744a38 | PE_state (initialized once-guard) | 0 |

---

## 2. Caller chain (x30-derived, every level BL-verified)

**L0 — SecureDTIterateEntries @ 0xfffffff008137790** (the faulting fn, §1).

**L1 — ml_parse_cpu_topology @ 0xfffffff007b8cb58** (osfmk/arm64/machine_routines.c).
Function start found by pacibsp-back-scan; 384+ insns. Boot-log trace + static disasm:
```
0xfffffff007b8cb90: mov  w8, #6 ; str w8,[sp,#0x4c]        ; cpu_boot_arg = MAX_CPUS(6)
0xfffffff007b8cb98: adrp x0, 0x73a8000 + 0x785             ; "cpus"
0xfffffff007b8cba0: add  x1, sp, #0x4c ; w2=4 ; w3=0
0xfffffff007b8cbac: bl   0xfffffff0081379b4                ; PE_parse_boot_argn("cpus",…)
0xfffffff007b8cbb0: adrp x1, 0x73ad000 + 0xff6             ; "/cpus"
0xfffffff007b8cbbc: mov  x0, #0 ; x2 = &entry
0xfffffff007b8cbc0: bl   0xfffffff008137198                ; SecureDTLookupEntry(NULL,"/cpus",&entry)
0xfffffff007b8cbc8: ldr  w8, [x19, #0x998]                 ; DTInitialized   [E3: 0]
0xfffffff007b8cbcc: cbz  w8, 0xfffffff007b8cbec            ; ==0 → skip iterator init (inlined
                                                            ;  SecureDTInitEntryIterator)
0xfffffff007b8cbd0: ldur x8, [x29, #-0x78]                 ; (DT-initialized path) startEntry
0xfffffff007b8cbe0: stp  x8, x8, [sp, #0x50]               ; iter->outer/currentScope = entry
0xfffffff007b8cbe4: stp  xzr, xzr, [sp, #0x60]             ; currentEntry=NULL, savedScope=NULL
0xfffffff007b8cbe8: str  xzr, [sp, #0x70]                  ; currentIndex=0
0xfffffff007b8cbec: …                                      ; (flag==0 falls here, iterator untouched)
0xfffffff007b8cc04: add  x0, sp, #0x50                     ; iter (zeroed at fn top: stp q0,q0,[sp,#0x50])
0xfffffff007b8cc08: add  x1, sp, #0x80                     ; &child
0xfffffff007b8cc0c: bl   0xfffffff008137790                ; ← the faulting call, return = x30 at stop
0xfffffff007b8ccd8: bl   0xfffffff008137790                ; loop back-edge (while-loop iteration)
```
[E4] So with `DTInitialized == 0`: `SecureDTLookupEntry` returns kError (unchecked —
`assert()` is compiled out in this release kernel, proven by our run falling
through), the iterator is left ZEROED (it was zero-filled at the top of the
function), and the while-loop calls SecureDTIterateEntries anyway → NULL scope →
`[0+4]` fault. This is exactly the source semantics of
`ml_parse_cpu_topology` minus compiled-out asserts.
[E5] Property strings read per-iteration (resolved cstrings): "name"(0x73adffc),
"state" vs "running"(0x73ae002), "die-id"(0x7368c6d), "reg"(0x73ae29d),
"l2-access-penalty"(0x7368c98), "l2-cache-size"(0x7368caa), "l2-cache-id"(0x7368cb8),
"l3-cache-size"(0x7368cc4), "l3-cache-id"(0x7368cd2), "die-cluster-id"(0x7368d4c),
"cluster-core-id"(0x7368d5b) — i.e. the /cpus child-walk of §5.

**L2 — arm_init @ 0xfffffff007b80288** (osfmk/arm/arm_init.c). Exactly ONE direct
BL to L1 in all of __TEXT_EXEC: call site 0xfffffff007b80968. arm_init receives the
boot_args pointer in x0 (stashed `mov x19, x0` at 0x…b802a0) — same pointer
`start` passes on (osfmk/arm64/start.s:503-504 "Return to arm_init()", x0 = boot args).
arm_init has **no direct BL/B callers** in __TEXT_EXEC → entered via the
`start.s` sequence (boot log entry 0xfffffff0081644e8 → `ret` into arm_init).

**L3 — `start` / start_first_cpu** — kernel entry 0xfffffff0081644e8
(LC_UNIXTHREAD, matches boot log); also reads boot_args+0x2d0 (bootFlags) per the
measured handoff contract in `crates/ios-rust/src/boot_real.rs` doc comment.

Chain: `start` → **arm_init(boot_args)** → **ml_parse_cpu_topology** →
[SecureDTLookupEntry + INLINED SecureDTInitEntryIterator] → **SecureDTIterateEntries** → fault.

---

## 3. The "gate" at 0xfffffff007b83f54 — it guards a REBASE, not the population

The enclosing function (pacibsp back-scan) starts at **0xfffffff007b82e34** =
`arm_vm_init` (osfmk/arm64/arm_vm_init.c). At the call site:

```
0xfffffff007b83f54: bl   0xfffffff008136f10        ; SecureDTIsLockedDown()
0xfffffff007b83f58: ldr  w8, [x21, #0x160]         ; physmap region count n
0xfffffff007b83f5c: tbnz w0, #0, 0xfffffff007b83fc8 ; ★ THE ONLY skip branch
0xfffffff007b83f60: …   region_list[n-1].base − [0x7702568] delta math …
0xfffffff007b83f80: sub  x9, x9, x10
0xfffffff007b83f88: add  x9, x10, x9               ; head += delta
0xfffffff007b83f8c: str  x9, [x11]                 ; PE_state.deviceTreeHead (0x744ad0) += delta
0xfffffff007b83f94: cmn  x9, x10
0xfffffff007b83f98: b.hs 0xfffffff007b84850        ; (overflow → panic "DeviceTree overflow", not a skip)
0xfffffff007b83fa0: str  x9,  [x11, #0x988]        ; DTRootNode  ← the store block
0xfffffff007b83fa8: str  x10, [x11, #0x9a0]        ; DTSize
0xfffffff007b83fb4: str  x10, [x11, #0x990]        ; DTEnd
0xfffffff007b83fbc: cset w9, ne
0xfffffff007b83fc4: str  w9, [x10, #0x998]         ; DTInitialized = (base != 0)
0xfffffff007b83fc8: …                              ; arm_vm_init continues
```

[E6] **Exactly one conditional branch skips the 0x…7b83fa0 store block**:
`tbnz w0, #0, 0xfffffff007b83fc8` @ 0xfffffff007b83f5c. The `b.hs 0x…b84850`
@ 0x…b83f98 is the overflow-panic edge. (Full window printed by the report script.)

[E7] The gate callee **0xfffffff008136f10 = SecureDTIsLockedDown**
(pexpert/gen/device_tree.c; `KERNEL_INTEGRITY_KTRR/CTRR` build):
```
x19 = kvtophys_at(0xfffffff007004000)   ; &_mh_execute_header (kernel text VA)
      (callee 0xfffffff008169574: at s1e1r, x0; mrs par_el1; F-bit→0; PA|va[11:0])
x20 = [0xfffffff007744988]              ; DTRootNode
x0  = kvtophys_at(x20)                  ; PA of the DT root (0 if unmapped)
cset w0, lo   after  cmp x0, x19        ; w0 = PA(DTRoot) < PA(kernel_text)
```
Gate = 1 (locked down) ⇔ **the DT root's physical address is BELOW the kernel
text base** (DT shipped inside EXTRADATA/CTRR region ahead of the kernel). On a
real device the iBoot-placed DT sits after the kernel load area → PA(DT) >
PA(kernel) → gate=0 → the rebase (PE_slide_devicetree inlined) executes.

[E8] **Consequence (the honest verdict on the gate):** with our zeroed globals,
gate = (kvtophys(0)=0 < 0x801004000) = 1 → rebase skipped — which is also the
harmless outcome, because there is nothing to rebase. **Fixing the gate does NOT
populate the DT globals.** The gated block only re-slides values that PE_init_platform
already installed. (Also confirmed by xref scan: PE_state.deviceTreeHead has only 4
ADRP refs in __TEXT_EXEC: 0x7b81fa8, 0x7b83f7c (this block), 0x81398f8 (slide helper),
0x8139a2c (the populate path, §4).)

## 4. Who ACTUALLY populates the DT globals — reads boot_args+0x60/+0x68

**PE_init_platform @ 0xfffffff00813995c** (pexpert/arm/pe_init.c; x0=vm_initialized,
x1=boot_args*). The prior note called this "dt_init"; the video-field writes identify
it beyond doubt:
```
0xfffffff008139990: ldr  w8, [0x744a38]            ; PE_state.initialized
0xfffffff0081399b0: (first-boot path) [0x744a38]=1
0xfffffff0081399c0: str  x19, [x8, #0xa0]          ; PE_state.bootArgs = boot_args_ptr (0x744ad8)
0xfffffff0081399c4: ldr  x9, [x19, #0x60]          ; ★ boot_args->deviceTreeP
0xfffffff0081399c8: str  x9, [x8, #0x98]           ; PE_state.deviceTreeHead (0x744ad0)
0xfffffff0081399cc: ldr  w9, [x19, #0x68]          ; ★ boot_args->deviceTreeLength
0xfffffff0081399d0: str  x9, [x8, #0xa8]           ; PE_state.deviceTreeSize (0x744ae0)
0xfffffff0081399d4: ldr  x9, [x19, #0x28]          ; boot_args->Video.v_baseAddr  ★ +0x28 is VIDEO
0xfffffff0081399dc: ldur q0, [x19, #0x38]           ; Video.v_rowBytes/.v_width
0xfffffff0081399e4: ldr  x9, [x19, #0x48]           ; .v_height ; +0x50 .v_depth (rotate/scale)
0xfffffff0081399a8: bl   0xfffffff007b8f660         ; strlcpy(PE video pixelFormat,"BBBB…RRRR",0x40)
0xfffffff008139a28: (SecureDTInit inlined:)

0xfffffff008139a2c: x9 = 0xfffffff007744ad0
0xfffffff008139a30: x8 = [x9]                       ; head
0xfffffff008139a34: x9 = [x9, #0x10]                ; size
0xfffffff008139a38: cmn x8, x9 ; b.hs 0x…9d2c       ; panic "DeviceTree overflow: %p, size %#zx"
                                                    ;   (string @0x73ade9b, verified)
0xfffffff008139a44: str  x8, [0x744988]             ; DTRootNode
0xfffffff008139a4c: str  x9, [0x7449a0]             ; DTSize
0xfffffff008139a58: str  (x8+x9) [0x744990]         ; DTEnd
0xfffffff008139a68: str  w8=(x8!=0) [0x744998]      ; DTInitialized
```
[E9] **There is NO condition on the population itself** — PE_init_platform
unconditionally copies boot_args+0x60/+0x68 → PE_state → DT globals on the first
(!vm_initialized) call. The DT globals are zero **if and only if boot_args+0x60
was zero**. (Condition disguised in the source: `PE_state.initialized` once-guard.)
[E10] Callers (BL-scan): 0xfffffff007b808f8 (arm_init, `mov w0,#0; mov x1,x20`
@0x…b808f0-f4 — vm_initialized=FALSE, x1 = the boot_args COPY), 0xfffffff007b80c78
(second arm_init call, vm_initialized=TRUE), 0xfffffff007b816d4 (fn 0x7b815b0, the
re-init/slide phase).
[E11] The boot_args copy: arm_init memmoves 0x2E0 bytes → **0xfffffff007702128**
(`add x20, x20, #0x128; mov x0,x20; mov x1,x19; mov w2,#0x2e0; bl 0xfffffff00987c290`
@0x…b807f0-f4, size literally `#0x2e0` = 736 = sizeof(boot_args)); the copy pointer is
stored to global [0x7702408]. 0x2E0 = the exact struct size in §5. The copy target
ships zero in the file (report script §5) — it is filled at boot from OUR boot_args.

## 5. boot_args mismatch — THE root cause

Real arm64 `boot_args` (xnu-7195.121.3 `pexpert/pexpert/arm64/boot.h`, LP64; the
project's own faithful port `crates/xnu/src/boot.rs::BootArgs` with
`const _: () = assert!(size_of::<BootArgs>() == 736)` agrees):

| off | field | our boot_real.rs writes | kernel reads it as |
|---|---|---|---|
| 0x00/0x02 | Revision / Version | 0 / 2 | — |
| 0x08/0x10/0x18/0x20 | virtBase/physBase/memSize/topOfKernelData | ✓ correct | ✓ (start) |
| **0x28** | **Video.v_baseAddr** | **DT_PA 0x804000000 ✗** | Video base (PE_init_platform 0x…99d4) |
| **0x30** | **Video.v_display** | **dt_len 220204 ✗** | Video display (0x…9a08) |
| 0x38–0x50 | Video rowBytes/width/height/depth | 0 | Video (0x…99dc–0x…9a08) |
| 0x58 | machineType (+pad) | 0 | — |
| **0x60** | **deviceTreeP** | **0 ← THE BUG** | DT base (0x…99c4) |
| **0x68** | **deviceTreeLength** | **0 ← THE BUG** | DT length (0x…99cc) |
| 0x6c | CommandLine[608] | 0 | PE_boot_args |
| 0x2d0 | bootFlags | 0 | start (measured handoff field) |
| 0x2d8 | memSizeActual | 0 | — |

`crates/ios-rust/src/boot_real.rs::build_boot_args` (lines 156–171) does:
```rust
put(&mut ba, 0x28, dt_pa);                    // ← writes Video.v_baseAddr
ba[0x30..0x34].copy_from_slice(&dt_len…);     // ← writes Video.v_display
// device_tree_p (+0x60) / device_tree_length (+0x68) left ZERO
```
The doc comment above it even states the wrong offsets
("DeviceTreeP@0x28, DeviceTreeLen@0x30"). `crates/xnu/src/boot.rs` documents the
correct offsets (`device_tree_p` offset 96 = 0x60, `device_tree_length` offset
104 = 0x68, `video` offset 40 = 0x28, 48 bytes) — boot_real.rs simply never used it.

[E12] **Causal chain, end to end:** boot_args.devTree at wrong offset →
PE_state.deviceTreeHead/Size = 0 (0x…99c4-0x…99d0) → DTRootNode/DTEnd/DTSize/
DTInitialized = 0 (0x…9a44-0x…9a68) → arm_init → ml_parse_cpu_topology:
SecureDTLookupEntry kError (assert out), iterator left zeroed (0x…cbcc cbz) →
SecureDTIterateEntries loads currentScope=0 → `ldr w9,[x0,#4]` → TranslationFault
va=0x4 at pc=0xfffffff0081377b4. Every step evidence-backed above.
(E13) Cosmetic side-effect of the same bug: the kernel reads our DT_PA as
Video.v_baseAddr and dt_len as v_display; harmless today, wrong by construction.

## 6. /cpus contents of the real DeviceTree (what the enumerator will iterate)

Fixture `fixtures/DeviceTree.n104ap.im4p` → IM4P(`dtre`, "EmbeddedDeviceTrees-5772.62.1")
→ LZFSE bvx2 (payload 0xA6CE B @ DER offset 0x33) → 220,204 B flat tree;
sha256 = b9562f91b8eb2b0d2008d920e77abb99f2a08ffa4d7f5118bfe7fe68c8c6c9e4 ==
`/tmp/adt-n104ap.bin` (report script verifies). Root `device-tree`, 19 children
(chosen, options, cpus, aliases, memory, pram, vram, arm-io, …). `/cpus`
(#address-cells=1, #size-cells=0, phandle 14) has **6 children**:

| node | reg(LE) | compatible | state | interrupts (IPI, timer, IPI_other) | cluster-type | enable_core mask |
|---|---|---|---|---|---|---|
| cpu0 | 0 | apple,thunder,ARM,v8 | waiting | 576, 60, 577 | E | 1 |
| cpu1 | 1 | apple,thunder,ARM,v8 | waiting | 578, 63, 579 | E | 2 |
| cpu2 | 2 | apple,thunder,ARM,v8 | waiting | 580, 66, 581 | E | 4 |
| cpu3 | 3 | apple,thunder,ARM,v8 | waiting | 582, 69, 583 | E | 8 |
| cpu4 | 0x100 | apple,lightning,ARM,v8 | waiting | 584, 94, 585 | P (cluster-id 1) | 16 |
| cpu5 | 0x101 | apple,lightning,ARM,v8 | waiting | 586, 97, 587 | P (cluster-id 1) | 32 |

Per node also: cpu-id, reg-private, coresight-reg, cpu-impl-reg, cpu-uttdbg-reg,
acc-impl-reg, cpm-impl-reg (reg ranges, LE u64 addr/size), l2-cache-size
(4 MiB E / 8 MiB P), l2-cache-id, interrupt-parent=26 (aic), function-*
fourcc bindings, no-aic-ipi-required. **No timebase-frequency / fixed-frequency /
bus-frequency property exists anywhere in the tree** (only root `clock-frequency` = 0);
timer info lives in the AIC IRQ numbers above (agrees with notes/m5-adt-census.md §3).
[E14] `ml_is_boot_cpu` (machine_routines.c:924) panics if a cpu node lacks "state"
(all have it) and boot_cpu is the node whose state == "running" — **all six ship
"waiting"**: the IPSW blob is iBoot's pre-patch template. With asserts compiled out,
the enumerator will iterate all 6, find no boot_cpu, and the next honest stop is the
`topology_info.boot_cpu->cpu_id` load (TPIDRRO_EL0 setup, machine_routines.c:1114).

## 7. Minimal, honest change list for the emulator (data supply only)

1. **boot_real.rs `build_boot_args`: move the DeviceTree fields to +0x60/+0x68**
   (deviceTreeP=0x804000000, deviceTreeLength=220204=0x35C3C) and stop writing
   +0x28/+0x30 (Video) — or construct `xnu::boot::BootArgs` (already has the
   asserted-correct layout) and serialize it. This alone unblocks the exact stop:
   DT globals become non-zero via PE_init_platform 0x…99c4-0x…99d0 + SecureDTInit
   0x…9a44-0x…9a68; the iterator gets a real scope; `/cpus` enumeration runs.
2. **boot_args Revision**: write 2 (kBootArgsRevision2), not 0 — matches the
   0x2E0/Version-2 layout the kernel expects; low risk, one line.
3. **iBoot-equivalent DT staging (needed for the NEXT stop, not this one):**
   when staging DeviceTree.n104ap, set the boot CPU's `state` property to
   "running" (real iBoot patches the handed-over tree; the IPSW template ships
   all-"waiting", §6). Without it, expect an honest stop at the boot_cpu NULL
   deref in ml_parse_cpu_topology (E14). Choose the boot cpu consistent with the
   handoff (cpu0) — do NOT add/remove nodes.
4. **Do NOT touch the gate**: SecureDTIsLockedDown + the 0x…b83f5c tbnz rebase must
   keep running as-is. After fix 1 the gate computes
   PA(0x804000000) < PA(0x801004000) = false → rebase executes (hardware-typical
   path). Watch-item: the rebase adds `region_list[n-1].base − [0x7702568]` to
   PE_state.deviceTreeHead — if those vm_reloc globals aren't consistent in the
   emulator the DT pointer shifts; verify with a mem-probe at the new stop.
5. **kvtophys_at must keep working** (AT S1E1R → PAR_EL1, 0x…8169574) — already
   exercised by the gate and 50+ sites; no change, just re-verify post-fix.
6. Nothing else: no synthetic DT parsing, no skipping of SecureDT* functions — the
   enumerator consumes the real blob at the real VA once the boot_args data is right.

Reproduce/verify after the fix: `cargo run … boot-real` → expect the stop to move
from 0xfffffff0081377b4 (DT iterate, va=0x4) into the /cpus topology walk (or the
E14 boot_cpu deref), with DT globals [0x744988]=0x804000000, [0x744998]=1 visible
in the mem probe.

— Script outputs archived: `/tmp/m4_dt_caller_chain.out`, `/tmp/m4_dt_cpus.out`;
scripts committed under `tools/re/reports/` (m4_dt_caller_chain.py,
m4_dt_fixture_cpus.py). No Rust code touched (research-only task M4-A).
