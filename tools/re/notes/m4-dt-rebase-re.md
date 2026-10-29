# M4 RE — Bug #25: the arm_vm_init DT-globals rebase (`PE_slide_devicetree`) corrupts the DT head

Task 2-a (RETRY), RESEARCH ONLY — no Rust semantics touched. Kernel = real 18C66
`/tmp/kc18c66.macho`. Capstone evidence: `tools/re/reports/m4_dt_rebase.py` →
`/tmp/m4_dt_rebase.out` (windows A/B/C + end_kern-writer + DT-global writer census +
python arithmetic; raw-ADRP prefilter because the full `adrp_add_scan` census OOM-kills
this sandbox). Live cross-checks: `/tmp/bf-text-zero.log` (session H: panic at insn
8,135,397, x1=0x80000011, x2=0), `/tmp/bf-bug25.log` (current build, storm starts
insn 8,148,893 @0x8138ad8, far=ASCII "HostImag"). Source ground truth: vendored
`/tmp/xnu-xnu-7195.121.3` (arm_vm_init.c, pe_init.c, kernel_mach_header.c).

## VERDICT

**The rebase itself is straight-line and benign; the corruption is a STAGING bug. The
emulator puts the DeviceTree blob 0xB3000 bytes BELOW the kernel's own `end_kern`
(getlastaddr), i.e. inside the kernel image's VA extent — so (1) the kernel's physmap
entry for the DT region has a NEGATIVE length that wraps to ~2^64 and its mapping
pass tramples memory, and (2) the rebase translates the DT head onto a VALID mapping
of the WRONG region (the `__PRELINK_INFO` physmap entry), so SecureDT parses
non-DT bytes.** Fix = stage the blob above the kernel's own end_kern (§FIX SPEC);
one constant in `StagedLayout::compute` (`image_bytes` → VA image end), no kernel
or interpreter semantics change.

## Window A — the rebase site 0x7b83f54 (out: §A1–A3)

```
0x7b83f44: bl 0x7b825d0            ; arm_vm_page_granular_prot for e[DT] (args in x0..x6)
0x7b83f48: ldr w8,[x21,#0x160]     ; w8 = ptov_index  (GLOBAL u32 @0x7702160, x21=adrp 0x7702000)
0x7b83f50: str w8,[x21,#0x160]     ; ptov_index++ (entry e[DT] just appended)
0x7b83f54: bl 0x8136f10            ; SecureDTIsLockedDown() -> w0
0x7b83f5c: tbnz w0,#0,0x7b83fc8    ; locked-down -> skip whole block
0x7b83f60: sub w9,w8,#1
0x7b83f64: add x10,sp,#0x50        ; temp_ptov_table base = STACK LOCAL sp+0x50
0x7b83f68: umaddl x9,w9,w19,x10    ; &e[ptov_index-1], stride w19 = 0x18
0x7b83f6c: ldr x9,[x9,#8]          ; e[n-1].va        (+0 = .pa, +8 = .va, +0x10 = .len)
0x7b83f74: ldr x10,[0x7702568]     ; end_kern (the ONLY other operand)
0x7b83f80: sub x9,x9,x10           ; slide = e[DT].va - end_kern
0x7b83f8c: str x9,[0x744ad0]       ; PE_state.deviceTreeHead += slide
0x7b83f90: ldr x10,[0x744ae0]      ; PE_state.deviceTreeLength
0x7b83f98: b.hs 0x7b84850          ; cmn overflow -> "DeviceTree overflow" panic
0x7b83fa0: str x9,[0x744988]       ; DTRootNode = head
0x7b83fa8: str x10,[0x7449a0]      ; DTSize
0x7b83fb4: str x10+x9,[0x744990]   ; DTEnd = head + size
0x7b83fc4: str w9,[0x744998]       ; DTInitialized = (head != 0)
```
This is xnu `arm_vm_physmap_init` (arm_vm_init.c:1471-1474, inlined into arm_vm_init
@0x7b82e34): `arm_vm_physmap_slide(temp_ptov_table, end_kern, (topOfKernelData -
gPhysBase + gVirtBase) - end_kern, AP_RWNA, 0)` then
`PE_slide_devicetree(temp_ptov_table[ptov_index-1].va - end_kern)` (pe_init.c:
`PE_state.deviceTreeHead += slide; SecureDTInit(head, length)` — the SecureDTInit is
the inlined store block above). **x1 of the later panic is a DT node pointer, and
x2 is [0x744990] read fresh at the assert (§E2) — not a saved value.**

## Window B — where region_list ("temp_ptov_table") is built (out: §B1, §A1)

- Array: `ptov_table_entry temp_ptov_table[8]`, **stack local at sp+0x50** inside
  arm_vm_init (frame `sub sp,#0x180`); record layout = arm_vm_init.c:344-348
  `{pmap_paddr_t pa @+0; vm_map_address_t va @+8; vm_size_t len @+0x10}`, stride
  0x18 (w19=0x18, set at 0x7b83f20). Count = `ptov_index` — **global u32 @0x7702160**
  (`[x21+0x160]`), NOT a boot_args/pmap field. NOT boot-args phys regions: entries
  are appended by (mostly inlined) `arm_vm_physmap_slide` fills.
- Fill (source lines 1437-1478, keep_linkedit=TRUE for this fileset kernel so the
  LINKEDIT pair is skipped): e[0]=gVirtBase region (len = segLOWEST−gVirtBase = **0**
  with the emulator's virtBase=link-base contract), e[1]=segKLDDATAB (+0x4000),
  e[2]=segBOOTDATAB (+0x20000), e[3]=segPRELINKINFOB (+0x118000), e[4]=**DT region**,
  e[5]=remainder. So Σ(len0..len3) = **0x13C000**.
- e[i].va = physmap_base (i=0) else prev.va+prev.len; e[i].pa = orig_va − gVirtBase +
  gPhysBase; e[i].len = round_page(len) — the e[4] fill is inlined at 0x7b83ea0-0x7b83f44
  (reads [x25+0x20]=args->topOfKernelData, [0x7702568]=end_kern, [0x7702450]=gPhysBase,
  [0x7702458]=gVirtBase; x25 = boot_args ptr).
- `physmap_base` (source 1747/1754/1757) = ROUND_TWIG(phystokv(topOfKernelData) +
  (early_random() & 0x3FFFFFFF & ~0x3FFF)) — RANDOM up to 1 GB, ROUND_TWIG = 2 MB.
- Final table → qsort by len desc → global `ptov_table` (phystokv/ml_static_vtop LUT).

## Window C — [0x7702568] and the DT globals (out: §C1-C5, §D, §E)

- **[0x7702568] = `end_kern`** (arm_vm_init.c:309, SECURITY_READ_ONLY_LATE). Writer
  census (raw-ADRP scan, 962 ADRPs into the two watched pages, __TEXT_EXEC+__TEXT+
  __PPLTEXT): exactly **4 refs** in the whole image —
  `0x7b82574 ldr` (out-of-line slide copy), `0x7b83758 str` (**the writer**),
  `0x7b83ea4 ldr` (e[4] len), `0x7b83f74 ldr` (rebase subtrahend).
  Writer (0x7b83734-0x7b83758): `x = [0x7724058] (segHIGHESTKC); cbz x9 → getlastaddr
  path; [0x7702568] = round_page(x)`. segHIGHESTKC ships 0 (file read, §[0]) and has no
  store in arm_vm_init ⇒ **end_kern = round_page(getlastaddr())**.
  `getlastaddr()` (kernel_mach_header.c:52) = max(vmaddr+vmsize) over the top-level
  Mach-O's LC_SEGMENT_64s = **0xFFFFFFF009C5C488** (__LINKEDIT end) ⇒
  **end_kern = 0xFFFFFFF009C60000** (16K round).
- DT globals: writers = dt_init @0x813995c (the honest initializer, ungated), the
  rebase block §A, a guarded zeroing teardown @0x80326a8 (`cbz w19` skip; zeroes
  0x744988/9a0/990/998 — kext-teardown path, not early boot), out-of-line PE_slide
  @0x8136eb0 (no BL callers). Readers = the assert pair §E.
- Assert (panic "Device tree pointer outside of device tree region: pointer %p,
  DTEnd %lx", string @0x73adec0): SecureDTLookupEntry @0x8137198 and
  SecureDTIterateEntries @0x8137790 both check `ptr ∈ [DTRootNode[0x744988],
  DTEnd[0x744990]]`; the panic site 0x8137820 does `ldr x8,[0x744990]; stp x0,x8,[sp]`
  — **x2 is [0x744990] at panic time** (session H: 0).

## Arithmetic (out: §F, python-exact)

Session H observed: head_before = 0xFFFFFFF009BAD000 (live store @0x81399c8),
panic x1=0x80000011, x2=0. `0x80000011 − 0x9BAD000 = 0x76455011` as bare link-rel
values — but **no completed rebase+SecureDTInit can produce that pair**: (a) any
e[4].va is 16K-aligned and 0xFFFFFFF0_-prefixed, head' = head + (e[4].va − end_kern)
stays aligned/prefixed — 0x80000011 is neither; (b) SecureDTInit always writes
DTEnd = head + 0x35C2C ≠ 0. ⇒ the observed pair reflects globals stomped around the
rebase (below), not the rebase's own arithmetic.

With the CURRENT emulator staging (boot_real.rs `StagedLayout::compute`, identical
`[stage]` line in both logs: end_kern_pa = dt_pa = 0x803BAD000 = page(LOAD_PA +
**file size** 45,778,056), ba_pa = 0x803BE3000, top = 0x803BE4000):

- kernel end_kern = **0xFFFFFFF009C60000** (PA 0x803C60000) — the VA image end is
  0x2C58488 above the load base, i.e. **0xB0000 more than the file size**
  (vmsize>filesize: __PRELINK_INFO/__DATA paddings).
- ⇒ staged blob KVA 0xFFFFFFF009BAD000 is **0xB3000 BELOW end_kern**, physically
  overwriting the loaded __LINKEDIT tail / __PRELINK_INFO overlap.
- `e[4].len = phystokv(top) − end_kern = 0xFFFFFFF009BE4000 − 0xFFFFFFF009C60000
  = −0x7C000` → round_page wraps to **0xFFFFFFFFFFF84000**; `adds len,#0x3FFF` does
  NOT carry (no panic at 0x7b8483c), so the kernel runs `arm_vm_page_granular_prot`
  over a ~2^64 range (asserts are compiled out in RELEASE) — page-table fills that
  wander far past the intended window (candidate mechanism for stomped globals,
  e.g. DTEnd found 0).
- rebase head' = head + (e[4].va − end_kern) = e[4].va − 0xB3000 = physmap_base +
  **0x89000** — that VA lies inside e[3]'s mapping (`__PRELINK_INFO`, AP_RONA,
  PA 0x803B20000 + 0x65000 = 0x803B85000). **The kernel then parses __PRELINK_INFO
  bytes as a device tree** — garbage nodes → the §E asserts / the ASCII-far aborts
  seen in bug25 (far="HostImag" at 0x8138ad8). The rebase is PA-faithful (PA(head')
  identity = blob PA only if head ≥ end_kern); here head < end_kern breaks it.

## FIX SPEC (concrete hex; change = `StagedLayout::compute` only)

Stage the blob ABOVE the kernel's own end_kern, using the VA image end
(`getlastaddr`) instead of the file size. With this exact binary:

| quantity | value |
|---|---|
| end_kern_pa (kernel-derived, unchanged) | **0x803C60000** (= 16K-round(PA(getlastaddr 0xFFFFFFF009C5C488))) |
| dt_pa (NEW) | **0x803C60000** |
| boot_args.deviceTreeP @+0x60 (NEW) | **0xFFFFFFF009C60000** (= LINK_BASE + dt_pa − LOAD_PA) |
| boot_args.deviceTreeLength @+0x68 (unchanged) | **0x35C2C** |
| ba_pa (NEW) | **0x803C98000** (16K-round(0x803C60000+0x35C2C)) |
| top_of_kernel_data @+0x20 (NEW) | **0x803C9C000** |
| (unchanged) virtBase@+0x8 = 0xFFFFFFF007004000, physBase@+0x10 = 0x801004000, memSize@+0x18 = 0x40000000 | |

Then, for EVERY physmap slide s ∈ [0,0x3FFFF000): end_kern = 0xFFFFFFF009C60000,
phystokv(top) = 0xFFFFFFF009C9C000, e[4].len = **0x3C000** (positive, no wrap),
e[4].va = ROUND_TWIG(0xFFFFFFF009C9C000 + s) + 0x13C000, head' = head + e[4].va −
end_kern = **e[4].va + 0** (blob sits exactly at the region start) ∈ [e[4].va,
e[4].va+0x3C000) — inside the physmap mapping the kernel just created; DTEnd' =
head' + 0x35C2C ≤ e[4].va + 0x3C000 ✓; SecureDTIsLockedDown: kvtophys(head') =
0x803C60000 > kvtophys(kernel) = 0x801004000 ⇒ gate = 0, rebase runs and lands the
head on the blob through the kernel's own mapping. No emulator MMU/pmap special-casing
needed — the kernel's own bootstrap tables (which the interpreter already executes,
468 walks in bug25) provide the translation.

Implementation note: compute the staged `end_kern_pa` from the already-parsed
LC_SEGMENT_64s as `max(vmaddr+vmsize)` mapped through `PA = vmaddr − LINK_BASE +
LOAD_PA` (== LOAD_PA + 0x2C5C488 for this image), NOT from `image_bytes`. Keep the
`page()` 4K rounding harmless by using 16K (0x3FFF mask) for dt_pa/ba_pa/top.

## xnu-7195.121.3 cross-check (PE_slide_devicetree semantics)

pexpert/arm/pe_init.c: `PE_slide_devicetree(slide)` = `PE_state.deviceTreeHead +=
slide; SecureDTInit(head, PE_state.deviceTreeLength)`. It is called ONLY from
arm_vm_init.c:1473 with `slide = temp_ptov_table[ptov_index-1].va - end_kern` — i.e.
**it slides only when SecureDTIsLockedDown() is false**, which happens exactly when
the DT lives ABOVE the kernel text in PA (kvtophys(DTRootNode) ≥ kvtophys(&_mh_execute_header),
device_tree.c SecureDTIsLockedDown) — the prelinked-kernelcache case, where the DT
blob sits in the [end_kern, topOfKernelData) "EXTRADATA" region and must be
re-translated from its bootstrap-map KVA to the randomized physmap aperture. When
the DT is BELOW the kernel (locked-down/extradata-before-text) it returns true and
the globals keep their PE_init_platform values. On real hardware the call is
therefore a no-op-or-correct translation; it only corrupts when the blob is staged
outside [end_kern, topOfKernelData) — precisely the emulator's bug.

## Provenance / next actions

- `python3 tools/re/reports/m4_dt_rebase.py > /tmp/m4_dt_rebase.out` (runs ~30 s;
  the old full-census variant OOM-kills — keep the raw-ADRP prefilter).
- Next (implementation task, not this one): the one-line staging change above +
  re-run boot-first; expect the DT walk to parse the REAL blob through the physmap
  window and the session-H panic/ASCII-far storm to disappear.
- Cheap confirmation dumps for the implementer (one boot with a store filter):
  `[0x7702568]` == 0xFFFFFFF009C60000 before 0x7b83f54; `[0x744ad0]` after the
  rebase == e[4].va (16K-aligned, 0xFFFFFFF0_-prefixed); `[0x744990]` == head+0x35C2C.
