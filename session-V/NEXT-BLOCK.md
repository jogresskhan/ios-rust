# Session V continuation notes (bug #55 — the post-POST NULL call)

State: repo at (this commit) after #53 AND #54 CLOSED. Frontier
327,096,716 — the FIPS POST COMPLETES (zero panics; all 17 tests pass:
hmac … rsa_sig, ecdsa, ecdh, aes_ccm, aes_cmac, pbkdf, kdf_ctr, aes_gcm,
aes_xts, tdes_cbc, drbg_ctr, drbg_hmac). The boot then advances ~105M
insns into NEW territory (PMGR/IOKit/scheduling bring-up) and dies on a
call through a NULL pointer.

Workspace: /home/z/my-project/ios-rust-work/repo. RE tools:
/home/z/my-project/scripts/re/ (kc.py needs /tmp/kc18c66.macho —
REGENERATE via scripts/kcdump if /tmp was recycled).

## BUG #55 (OPEN): NULL-pointer call in the AST path @327,096,716

- Stop: ExceptionRecursion(stack-descended-into-text), elr=0x0,
  far=0xffffffe802d1bd80 (= the SP of the faulting context — a
  SECONDARY stack, not the boot stack 0x…fab940), SPSel=true,
  VBAR=0xfffffff00815f000, pc=0xfffffff00815f300 (the EL1 SPx sync
  vector), NO panic() call.
- The call site: lr = 0xfffffff007a8d828 — right after
  `bl 0xfffffff007b8ba64` (w0=1) at 0x7a8d824 — the AST take
  (0x7b8ba64 = ast_taken). The sequence around it (0x7a8d7f0..0x7a8d830):
  calls into 0x7e6cf7c, 0x7e684c8 (printf-ish, strings @0x735c56d/
  0x735c57c), 0x7ec3504, 0x81394b4, `mov w0,#0xe; bl 0x7a8cf1c`,
  `mov w0,#1; bl 0x7b8ba64` ← crash inside.
- Register clues at the stop: x16 = 0x32E5FFF00772EE58 (PAC'd →
  0x772EE58), x17 = 0xFFFFFFF00772EE00, x19 = 0x3c0, x22 = 0xFFFFFFFF,
  x20 = 0xfffffff009ab8be8 (the per-CPU base). The fault: a branch to 0
  — likely a call through a NULL fn ptr (an unregistered service —
  IOKit method table? PMGR hook? a kext's vtable slot that the
  emulator's device model never filled).
- SCOPED (session-V staged stops + the boot-V-3 trace ring): the AST
  fn 0x7b8ba64 runs with an AST PENDING → 0x7b8bab8 → the AST action
  0x7a4f61c → (x10 = [percpu+0x28] != 0 → clears bit 2 → ret) OR the
  tail call 0x7a80d6c — and BACK in the AST loop `b 0xbabc` → the
  flags byte [x8+0x4c] still has bit 2 → loop → the take path reaches
  `msr daifclr, #7` at 0x7b8ba90 — **THE TRACE ENDS AT THAT MSR**: the
  engine's post-insn IRQ/FIQ check fires IMMEDIATELY (run loop:
  timer_fiq_pending && DAIF.F clear → take_exception(0x300,"fiq")), the
  FIQ vector 0x815f300 pushes the frame at sp=0x…d1bd80 and the store
  FAULTS (far = the sp; L3 @0x80d82d550 = 0 — an invalid descriptor —
  NOTE: the very same page accepted the AST fn's own prologue pushes
  moments earlier!) → nested sync abort → recursion → the SP descends
  → the guardrail. x16 = 0x32E5FFF00772EE58 / x17 = 0x772EE00 held
  across (a GOT/di pair — probably unrelated leftovers).
- NEXT: (1) dump the page tables around VA 0x…2d1b000 at the FIQ
  moment (stop at 0x815f300, walk 0x2d1bd00-0x2d1be00) — did the
  kernel UNMAP/remap the thread stack mid-flight, or is the engine's
  walk stale? (2) check the engine's take_exception SP model — ARM
  banks SP per EL/SPSel; the single-bank `self.sp` model (see
  MsrSpsel) may corrupt the FIQ frame push; (3) check whether the FIQ
  should even be PENDING (the timer model — timer_fiq_pending may be
  stuck high); (4) the AST-loop `b 0xbabc` spinning on bit 2 — is the
  bit actually CLEARED by the 0x7a4f61c path (w9 &= ~4 → str) — if the
  engine's store is fine the loop should exit; single-step it.
- NOTE: this is the FIRST post-POST wall — the frontier moved past the
  crypto into kernel-services land. Expect kext/IOKit fidelity work
  (the BOOT-PLAN M5 clause ② path: kext → scheduler → NVMe read).

## Also open
- M4 WFI-resume ≥10M acceptance clause (BOOT-PLAN M4).
- M5 clause ②: NVMe returns real rootfs bytes from full-root.apfs —
  needs the current wall(s) passed first.
- The M5-BUGS-AND-GAPS.md table needs the #53/#54/#55 rows (standing
  order: keep the bug table + gap analysis current).

## Repro kit that worked this session (the campaign way)
1. Staged boot stops (IOS_RUST_STOP_PC_RANGE + MIN_INSN +
   STOP_DUMP_ADDRS; 0x200/dump cap — split wide windows).
2. Pure-leaf fn repros: fips_tdes_kat.rs / fips_modmul_kat.rs drive a
   single kernel fn from captured state (PagedRam: store() MUST
   auto-create pages).
3. Single-step micros with v-register dumps after each insn:
   neon_shift_micro.rs / des_repack_micro.rs — both caught their bug
   in <20 instructions.
4. python oracles: des_full_model.py (schedule+repack+block — note the
   model itself had 2 arithmetic slips; the ENGINE chain validated
   against pycryptodome is the authority), modmul_check.py,
   stack_decode.py (all in tools/re/oracle/).
