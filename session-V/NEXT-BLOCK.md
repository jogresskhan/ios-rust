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
- NEXT: (1) staged stop INSIDE 0x7b8ba64's callee chain (watchpoints on
  the bl targets — find the deepest call before pc→0); (2) read the
  call's target slot (x16/x17 pattern suggests a GOT/di dispatch —
  check [0x772EE00]/[0x772EE58] contents — is the SLOT zero? then find
  who should have registered it); (3) the M4-b "poison stores" and
  __DATA←stack diagnostics in boot-V-3.log may name the service.
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
