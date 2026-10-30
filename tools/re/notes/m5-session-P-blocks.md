# M5 session P — three bugs in one block (2026-10-30)

Frontier: 22.5M (waitqs panic) → 155M (FIPS POST) in one session.

## Bug #40 — the waitqs wall was OUR W-form arithmetic
* measured: x19 = 0xffffffff00004000 at the KMA call (watch 0x…7ab6f30)
* verbatim chain: 0x128004E9/0x1B097D08/0x12124508/0x4B0803F3 at
  0x…7ab6d68..0x…7ab6d74 (waitq_bootstrp)
* root: AddImm/SubImm/AddSubReg non-setflags + LogicReg computed at
  64-bit width with no operand mask / result zero-extension
* fix: mask (a & b) and `& mask` the result when !is64
* goldens: gap40_* (4 tests, verbatim words)

## Bug #41 — the lock-regs aperture stub
* panic: "lock-regs: cannot find required property 'aperture-count'"
  (fmt 0x…736724f) at 22,688,176
* parser RE (0x…7b7c390): amcc needs aperture-count/size, plane-count/
  stride, aperture-phys-addr (count×8), cache-status-reg-*; ctrr-a needs
  page-size-shift + 5×(offset/mask[/value]) — all u32 size 4
* the EDT node is stub-empty (adt dump); iBoot populates at runtime
* fix: dt_populate_amcc_lockregs — 1 aperture @ dram_base+dram_size/2,
  16KB, page-size-shift 14, all reg locks 0; 22 props
* the kernel maps the aperture (bl 0x…7b848b4 prot 7) and samples
  [va+offset] per plane — count=1/plane=1 trivially consistent

## Bug #42 — PSTATE.PAN
* panic: "context switch with PAN disabled" at 23,684,722
  (mrs x8, pan @0x…7b91918, second site 0x…7b928f8)
* 95 msr pan,#0/#1 sites (0xD500409F/0xD500419F); the SPSel mask
  (0xD500401F family) swallowed them (op2 4 vs 5)
* fix: MsrPan/MrsPan + pan bit + SPSR bit23 save/restore; gating NOT
  enforced (documented honest limit)
* goldens: gap42_* (3 tests)

## Bug #43 (OPEN) — the FIPS HMAC-SHA1 KAT
* panic: "FIPS Kernel POST Failed (%d)!" err −1075 at 155,032,147
* chain: fipspost_post 0x…829fb3c → fipspost_post_hmac 0x…82a4ce0
  vector 0 → memcmp 0x…7b85714 @0x…82a4e00 fails (len 0x14, SHA-1)
* computed 491327a2e130799174899c2f7a9cbef2002b9571 vs expected
  886eae70f36bd3805eeb1274b3248fccf5e15b80 (stop-memdump)
* cause: sha1c/p/m are 4-round-group ops (Vd+Vn lane writeback) and
  sha1su0/su1 have precise sliding-window semantics — the engine's
  single-round/lane-0 model and guessed schedule XORs were never
  oracle-verified (goldens are decode-only)
* next: oracle-reconstruct the pipeline (tools/re/oracle/
  derive_sha1_arm.py first pass), fix the ops, re-run the KAT

## Diagnostics added this session
* `ios-rust adt dump` (full node/property tree)
* MMIO log value column (bus.rs read/write/UNMAPPED lines)
* IOS_RUST_STOP_DUMP_MEM stop-memdump (x0/x1/x2 0x40 B guest dumps)
* reports: tools/re/reports/m5p_waitqs_panic.py, m5p_waitqs_body.py
