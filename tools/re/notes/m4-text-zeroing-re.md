# M4 RE — root cause of the text-PA-reads-zero stop (PA 0x80216c458 / VA 0xfffffff00816c458)

Task 2-a, RESEARCH ONLY (no Rust semantics touched). Kernel = real 18C66 `/tmp/kc18c66.macho`
(45,778,056 B). Evidence: static capstone (`tools/re/reports/m4_text_zeroing.py` →
`/tmp/m4_text_zeroing.out`, re-runs of `m4b_percpu.py` + `m4b_sites.py`) + ONE live
reproduction (`IOS_RUST_DRAM_MB=1024 boot-first`, log `/tmp/bf-text-zero.log`: 10,921,780
insns · 21,270 vectored sync aborts · stop `UnknownInsn 0x0 @ 0xfffffff00816c458` — exact
session-H reproduction, 394-test tree untouched).

## VERDICT

**The kernel did not "remap" or "zero" its text via pmap. It ate its own text with the
exception machinery's own stack frames.** The storm is an **unbounded recursive exception
report loop that consumes 0x4F0 bytes of kernel stack per abort cycle and never unwinds**:

1. `panic("Device tree pointer outside of device tree region: pointer %p, DTEnd %lx\n", …)`
   @ insn 8,135,397 (string @0x73adec0; args x1=**0x80000011** (garbage DT head),
   x2=0 (DTEnd), x3=0x744a89) — see §3 for how DT globals got here (head was honestly
   0x9bad000/DTEnd 0x9be2c2c after PE_init_platform; the arm_vm_init
   `PE_slide_devicetree` rebase `head += region_list[n-1].base − [0x7702568]`
   (call site 0x7b83f54, m4-aic-timer-re.md §1) corrupted it afterwards).
2. Panic path derefs percpu: **elr 0x7a585d0 `ldr [tpidr=0 +0x4f0]`, far=0x4f0,
   ESR 0x96000006** @ insn 8,135,442 — TPIDR_EL1=0 (cpu_data[0] never discovered).
3. Vector → `br x22` dispatch (@0x81605d4; x9=15 slot) → **0x81607b8 = the
   unhandled-exception reporter**: `mrs esr/far; str [x0+0x120/0x118]; stp x29,x30,[sp,#-0x10]!`
   (@0x81607c8); `bl 0x816c458` (exception-report checker) → `bl 0x816c360` (the 0x170-frame
   register-dump formatter) → **formatter faults `ldr x11,[x10,#0x100]` @0x816c38c**
   (x1/x10 = NULL iframe chain — depends on tpidr) → abort → vector → reporter → formatter …
   **elr=0x816c38c, far=0x100, 131 insns/cycle, 21,270 cycles** (first 8 + last 24 aborts in
   the log are all this pair). The formatter never completes ⇒ **nothing ever pops**.
4. Per cycle the stack descends: vector iframe `sub sp,sp,#0x350` (@0x81601dc…0x8160290
   slots; saves `stp x2..x30,[x0,#0x18..0xf8]`, `stp q0..q3,[x0,#0x140..0x160]` —
   synthesized fresh GPR state = mostly **zeros**) + 0x10 push + 0x20 (0x816c458-fn) +
   0x170 formatter frame (spills q0..q21 = 0). **0x4F0/cycle × 21,141 cycles =
   0x9b0fff0 − 0x816c220 exactly** (the boot-stack-pointer log shows the continuum:
   0x9b0fda0 → 0x9b0f9a0 → 0x9b0f4b0 → 0x9b0efc0 → 0x9b0ead0 → … → 0x9b0d270, then on
   through __DATA (data_stores: iframes at 0x9affxxx…), the __PPLTEXT gap, and into
   __TEXT_EXEC down to the final sp=0xfffffff00816c220).
5. The descending canvas overwrites ~24 MB of __DATA/__PPLTEXT/__TEXT_EXEC with frame
   garbage and zeros (including the PPL vector table/trampoline page and the formatter
   itself). Terminal: the intact reporter `bl 0x81607d0` fetches its callee at 0x816c458
   — **zeroed by earlier cycles' frame saves** → `UnknownInsn 0x0`. The stop-pc walk
   (L1 0x801704000 → …) is **not stale-wrong**: VA−kernel_base = PA−0x801004000 ⇒
   PA 0x80216c458 is the CORRECT text PA; **the RAM content is zero because the guest
   stored zeros there**. Session-H's "stale TLB" and "abort-driven remap storm" wording
   is wrong (see §5).

## Hint adjudication (the three candidate SP sources)

* **PPL per-cpu stack table (0x98a4180, stride 0x180, sp@+0x10) — REJECTED.** Its only
  readers are in the __PPLTEXT trampoline (0x9899638–0x98996d4: `adrp x2,0x98a4000;
  add #0x180; madd cpu*0x180; ldr x1,[x1,#0x10]`), reached only via the
  `s3_6_c15_c8_1` PPL entry — never taken in this storm (all 21,270 aborts are EL1
  sync via VBAR 0x815f000/0x8165000). The table region sits in the file gap between
  __PPLTEXT end 0x989c000 and __DATA 0x98ac000 (no file backing; `u64va` → None) —
  it is runtime-allocated, and it got trashed by the overflow like everything else.
* **ORR/ADD of poisoned x6 (=0x0000fff008137198, top-16-zeroed &SecureDTLookupEntry) —
  REJECTED as the SP source.** The match `0xfffffff008137198 + 0x35088 =
  0xfffffff00816c220` is numerology: no `add …,#0x35088` exists near any `mov sp`
  site; the live store log proves sp **descended continuously** (0x4F0/cycle, §VERDICT 4),
  and 0x9b0fff0 − 21,141×0x4F0 = 0x816c220. The poison x6 is a **symptom** (one 48-bit
  truncation in the panic path, then saved into every iframe at `stp x6,x7,[x0,#0x38]`
  @0x8160424 — 21,273 identical stores into the descending canvas; first poison store
  actually pc=0x7b80340 → [0x7a0a320]=0xfff009812528 — worth one look later, not a cause).
* **Actual source: plain stack overflow by recursion.** The "last SP change pc=0x81607c8
  → sp=0x816c220" wording in m4-percpu-blocker.md misled: sp changes EVERY cycle (each
  0x81607c8 push); that line is just the final one. Register snapshot at stop (x19=
  0x816c720 = a text address saved from the previous cycle's frame; x29=0x816c220;
  lr=0x81607d4) confirms the frames are the exception machinery's own.

## Key bytes (file truth, all verified nonzero in the shipped image)

* 0x816c458 = `pacibsp` (word d503237f) — head of the exception-report fn called by
  `bl 0x81607d0`; zeroed at runtime.
* 0x816c38c = `ldr x11,[x10,#0x100]` — the deterministic refault point (far=0x100;
  early cycles far=0x2e656c7070612f6d "m/apple." = string bytes deref'd via the same
  NULL iframe chain, ESR 0x96000012 = alignment fault).
* 0x816c360 = the 0x170-frame formatter: `sub sp,sp,#0x170; stp x28,x27,[sp,#0x150]; …;
  stur q0..q21,[sp,#0x28..0xf8]; ldr esr [x1,#0x120]/far [x1+8,#0x110]; …; bl 0x987b99c`
  (0x987b99c = the noreturn console/panic printer — the honest exit the storm never reaches).
* Vector prologue save area = `sub sp,sp,#0x350` slots @0x8160070…0x8160290; ERET restores
  `mov sp,x1` (iframe-saved sp) — unreachable while the loop is closed inside the reporter.
* cpu_data fields in play: tpidr+0x4f0 (panic_impl deref), +0x4f8 (intstack_top — the
  per-cpu switch `msr tpidr_el1,x0; ldr x1,[x0,#0x4f8]; str x0,[x1,#0x30]` @0x81687a0/
  0x8168a1c/0x8168df8), +0x500 (exception depth), +0x450, +0x488/0x498.

## The real root-root cause + fix list (ranked: fidelity × likelihood)

1. **Seed TPIDR_EL1 / cpu_data[0] from the kernel's own evidence (THE fix).**
   cpu_data_init already ran: boot-stack log `pc=0x7b80844 → [0x9a4afc0] = 0x98e4658`
   (arm_init storing intstack_top=0x98e4658 into cpu_data+0x4f8) ⇒ **cpu_data[0] base =
   0x9a4aac8** (in __DATA 0x98ac000–0x9b00000; 8-aligned). The discovery helper
   `discover_cpu_data0` (interp.rs:423) would find exactly this base — its filters pass
   (istack 0xFFFF_FFF0_098E_4658 ∈ [0xFFFF_FFF0_0980_0000, 0xFFFF_FFF0_0A40_0000),
   8-aligned, steps by 8) — but it is **currently DEAD CODE: defined, zero call sites in
   the whole crates tree** (grep-verified) — hence "cpu_data[0]: never discovered".
   Fix: re-wire the scan (or seed TPIDR_EL1 from the `data_stores` fingerprint
   (pc,va,val) = the guest's own store) — honest either way, since the value is one the
   guest itself wrote. With tpidr valid, the panic path completes → formatter runs →
   noreturn printer 0x987b99c → **first real UART output** ("Device tree pointer outside
   of device tree region: pointer 0x…, DTEnd 0") — measurable milestone instead of a
   24 MB trash fire.
2. **Bug #25 (next real bug): the DT-globals rebase corrupts the DT pointer.**
   After PE_init_platform the globals are correct (DTRootNode=0x9bad000, DTEnd=0x9be2c2c
   via [0x744ad0]=0x9bad000 @0x81399c8); the arm_vm_init rebase
   (`[0x744988] += region_list[n-1].base − [0x7702568]`, site 0x7b83f54) then produced
   **head=0x80000011, DTEnd=0** → the panic. Actionable: dump the kernel's physmap
   region_list tail + [0x7702568] at rebase time and check against the emulator's
   staged layout (MMU L2 block leaves @0x801710018+ = 0x80000601/0x80200601/0x80400601/
   0x80600601/0x80800601 show the real physmap windows).
3. **Emulator guardrails (cheap, honest, prevents recurrence):** (a) stack-overflow
   tripwire — named stop when SP descends below the boot-stack floor − margin (i.e. into
   __TEXT_EXEC/__PPLTEXT); (b) exception-recursion detector — named stop after N
   consecutive identical (elr,far) abort pairs (the current 100k-insn sync budget never
   fires: 21,270 aborts × 131 insns ≈ 2.8M ≪ 100k-insn semantics mismatch — the budget
   counts insns but the loop looks "productive"). Both convert this class of failure
   into a one-cycle honest stop instead of 24 MB of silent corruption.
4. **Later, non-blocking:** the 48-bit truncation that poisons x6 (first store
   pc=0x7b80340 in arm_vm_init) — real kernel-visible artifact, chase after 1–3.
5. **Non-actions (explicitly closed):** do NOT model the PPL stack table (unreachable);
   do NOT chase a "stale TLB" (translation is correct; content is zero); do NOT add
   pmap/remap fixes (no pmap writes are involved).

## Doc corrections to carry into BOOT-PLAN/PARITY next session

* "the kernel zeroed its own text during the abort-driven remap storm" → **"unbounded
  recursive exception reporting consumed the kernel stack (0x4F0/cycle × 21,270 cycles,
  0x9b0fff0 → 0x816c220); the exception frames themselves zeroed __TEXT_EXEC"**.
* "stale TLB entry" → the walk is correct; the stop-pc PA bytes are zero because the
  guest's own frame stores wrote them.
* m4-percpu-blocker.md "last SP change" → sp changes every cycle; the line is the final
  push, not a one-time warp.

Provenance: probe `tools/re/reports/m4_text_zeroing.py` (new, research-only) →
`/tmp/m4_text_zeroing.out`; re-runs `/tmp/m4b_percpu_rerun.out` (OOM-killed at the
__TEXT censuses — reuse `/home/z/tmp-re/m4_sysreg_table.out` for those),
`/tmp/m4b_sites_run.out` (the 0x81687a0/0x8168a1c/0x8168df8 per-cpu switch windows);
live run `/tmp/bf-text-zero.log` (binary `/home/z/my-project/download/ios-rust/target/
debug/ios-rust`, session-H build, zero drift: 10,921,780 insns / 21,270 aborts / same stop).

## Session I addendum — the POST-#26 chain head (next block's target)

Measured (IOS_RUST_WATCH=0x…7b8cd70, insn 8,181,649 — the run's FIRST abort):

    [watch] insn=8181649 pc=0xfffffff007b8cd70 lr=…7b8cd2c x9=fffe00ee488b0058
            x19=0 x21=fffe00ee488b0058 x22=…7744000 x24=…772478c x25=0x88 sp=…9b0fe70

- aborting store: `str w19, [x9]` @0x…7b8cd70 — an array PUSH
  (x9 = madd(x19, x25, x21); x19=0 → x9 = the ARRAY BASE = [x24+0x14]).
- the array OBJECT sits at the STATIC address 0xfffffff00772478c;
  stride x25=0x88.
- shipped image bytes at [x24+0x14] (VA 0x…77247a0) = 0x0017fff007724458 —
  a MANGLED-TOP-BITS kernel pointer (0xFFFFFFF007724458 class — the same
  "48-bit" family as session H's 0x0000FFF008137198 = the panic call site).
- RUNTIME value read = 0xfffe00ee488b0058 ≠ shipped ⇒ something WROTE it
  during boot. NEXT PROBE (one run): IOS_RUST_WATCH_VA=0xfffffff0077247a0
  (+PA alias auto-added) → the corrupting store's pc + value.
- working hypothesis: __thread_starts / self-rebase fixup wrote a
  wrong-section value (the shipped 0x0017… top bits suggest the image
  ships fixup-encoded pointers, not plain ones — m2_fixup_census.md's
  "kernel self-rebases via __thread_starts" is the machinery; its writer
  for THIS slot is the question), or a PAC-keyed store path.

Note: the array-push code (0x…7b8cd30-70) runs INSIDE the DT/registry
lookup family (x1=0x…73ae00a/x20=0x…73adffc string literals — same page
as the DT strings), i.e. the IOCatalogue/DT init reached deeper than
every previous session. Progression this session: 8,135,842 → 8,149,172
(#25) → 8,162,237 (87 flags) → 8,194,993 (#26) → first abort 8,181,649
pre-loop; loop cut at 96 cycles by the guardrail.
