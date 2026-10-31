# Session V continuation notes (bug #54 — tdes_cbc)

State: repo at (this commit) after #53 CLOSED (the INS-general 32-bit
truncation). Frontier 221,859,723 — the POST's tdes_cbc panic.
Workspace: /home/z/my-project/ios-rust-work/repo. RE tools:
/home/z/my-project/scripts/re/ (kc.py needs /tmp/kc18c66.macho —
REGENERATE via scripts/kcdump if /tmp was recycled).

## BUG #54 (OPEN): fipspost_post_tdes_cbc — err −15000

The POST's test order (all measured this session): hmac ✓ integrity ✓
indicator ✓ aes_ecb ✓ aes_cbc ✓ rsa_sig ✓ ecdsa ✓ ecdh ✓ aes_ccm ✓
aes_cmac ✓ pbkdf ✓ kdf_ctr ✓ aes_gcm ✓ aes_xts ✓ **tdes_cbc ✗** then
drbg_ctr, drbg_hmac.

- Test fn 0x82a5184 (called from driver 0x82a0510); fail branch
  0x82a0540 (err w8 = −0x3a98 = −15000) → fail-exit 0x82a05e8 → the
  panic("FIPS Kernel POST Failed (%d)!") at 0x82e868c (insn
  221,859,613; panic-x1 = 0x3beb7400040004 = the driver's packed err).
- The test's own error codes (from the disasm): 0x31 (49) if the first
  helper 0x82aad50(?, 0x18, key@0x73c3725, iv@0x73c373e, 1, x5=?, out
  = sp+0x20) returns nonzero; 0x45 (69) if 0x7b85714(mode_str, sp+0x20,
  8) returns nonzero; more steps after 0x82a5220 (data @0x73c3763…).
- Staged stop recipe that pinned the fail branch (reuse for the step):
  IOS_RUST_STOP_PC_RANGE="0xfffffff0082a05e8,0xfffffff0082a05ec"
  IOS_RUST_STOP_PC_MIN_INSN=200000000 (32 s/boot, deterministic).
- TDES = 3DES (bit permutations, S-boxes) — likely suspects: NEON
  byte/lane ops in the des core (tbl/tbx? rev? eor?), the key schedule
  (pc1/pc2 permute), or the CBC chaining. NOTE the #53 fix touched
  INS-general only — but #49 (EXT) and #53 (INS) suggest auditing the
  OTHER neon lane ops in the des path (tbl/tbx index handling, BIC,
  ZIP…) against the des implementation.

## Repro kit that worked for #53 (the campaign way)
1. Staged boot stops (boot-V-*.log in ../session-V/) with
   IOS_RUST_STOP_DUMP_ADDRS (0x200/dump cap — split wide windows).
2. Minimal single-fn repro: tests/fips_modmul_kat.rs drives the modmul
   dispatcher directly from captured state (PagedRam: store() MUST
   auto-create pages or stack writes vanish silently — cost an hour).
3. Single-step micro: tests/neon_shift_micro.rs (cpu.step() + v-reg
   dumps after each insn) — caught the truncating `mov v3.d[1], x5`
   in 12 instructions.
4. python oracles: tools/re/oracle/modmul_check.py + stack_decode.py.

## Also open
- M4 WFI-resume ≥10M acceptance clause (BOOT-PLAN M4).
- After #54 (+ any drbg fallout): the POST may COMPLETE → then the M5
  census re-measure + NVMe rootfs clause (full-root.apfs), then M4's
  WFI clause, then M6 opens.
