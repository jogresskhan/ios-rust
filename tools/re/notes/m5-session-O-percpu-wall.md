# M5 session O — the percpu wall deconstructed (REAL-DATA BUG #39)

## The wall (as inherited from session M)

kernel-HANDLED sync abort: FAR 0x10c, ESR 0x96000005 (byte load),
ELR 0xfffffff007b1e150 = `ldrb w8, [x0, #0x10c]` with x0=NULL, at insn
21,713,122. Delivered once, then the exception-prologue stack-guard
self-spins at 0xfffffff008160410 (`b.lt #0x…8160410`, `0x5400000b`)
until budget — the 48M→400M stretch burned inside the spin.

## Method (reusable)

1. **First-abort FP chain** (new engine diagnostic, report-only): at the
   FIRST vectored data abort, walk the interrupted x29 chain via
   debug_walk + bus reads; also capture per-frame [fp-0x8..fp-0x28]
   (saved x19/x20 pairs). Wiring: interp.rs take_exception →
   boot_real.rs report ("M5-O first-abort FP chain").
2. Backtrace decode (nearest-pacibsp scan + BL/B target scan):
   `vm_map_store_entry_unlink` (0x…7b1e134 — SKIP_RB_TREE 0xBAADC0D1
   checks map+0x38, nentries-- at +0x30, first_free +0x100, hint +0xf0)
   ← coalesce (0x…7b0b510) ← lookup+coalesce (0x…7b19364) ←
   page-wiring fn (0x…7b01cb8, pmap_enter per page) ← views-table load
   (0x…7abf0c8: `ubfx x8, [obj+0x48], #0xb, #2; ldr x0, [0x…76fd2e8 +
   x8*8]` — the iOS-internal kernel_map[4] views) ← zone zinit
   callbacks ('zcc_magazine_zone') ← init-entry walker (0x…7a8cf1c,
   blraa over __init_entry_set) ← `kernel_bootstrap` (0x…7b015d4).
3. **PC watches** (`IOS_RUST_WATCH=pc,pc,…`): bisected X0
   0xfffffff06e2c5ec0 (coalesce entry) → 0 (unlink call site 0x…7b0b620)
   down to the single instruction at 0x…7b0b598.
4. **Capstone cross-check of the verbatim word**: 0xFA4E0160 =
   `ccmp x11, x14, #0, eq`. Engine decoded it as
   `Adc { rd: 0, rn: 11, rm: 14, subtract: true }` — SBCS x0, x11, x14.

## Root cause (bits, computed not guessed)

| word | bits[28:21] | b23 | b22 | b21 | bits[15:10] |
|---|---|---|---|---|---|
| ccmp x11,x14,#0,eq (0xFA4E0160) | 11010010 | 0 | **1** | 0 | 000000 |
| ccmp x13,x8,#0,ls (0xFA4891A0)  | 11010010 | 0 | **1** | 0 | 100100 |
| adc w0,w1,w2 (0x1A020020)       | 11010000 | 0 | 0 | 0 | 000000 |
| sbcs/adcs family                | 11010000 | 0 | 0 | 0 | 000000 |

With cond=eq ⇒ bits[15:12]=0000 and bits[11:10]=00 and nzcv=0 (⇒ the
Rd slot reads 0), the ccmp word ALSO fits the SBCS shape. The ADC arm
only checked bit23 ⇒ collision ⇒ `sbcs x0, x11, x14` executed and
ZEROED X0 (0x…6e2c5ec0 − 0x…6e2edec0-ish borrow chain → 0 measured).
Fix: ADC arm requires bits[23:21]==000; CSEL arm pins bit21==0; CCMP
arm pins bit22==1 && bit21==0.

## Where the boot stands after the fix (measured, release, DRAM 1024MB)

* 48M: **0 sync aborts, 0 panics**, budget stop clean.
* 400M: the kernel runs past the old wall into `kernel_bootstrap`'s
  zone/waitq phase and calls **its own panic** at insn 22,505,463:
  `"kernel_memory_allocate() failed to alloc global_waitqs" ", error: %d,
  whsize: 0x%x"` — fmt at 0xfffffff00735e028, panic wrapper
  0xfffffff00987b99c called from 0xfffffff007ab6f30, whsize 0x4000.
  x2 at the wrapper = 0xffffffff00004000 (kr/whsize packing — unpack in
  the next block).

## The kernel_map[4] views table (measured stores, this session)

* 0x…76fd2d8 = 2 (view count) @21,480,088 (pc 0x…7abe488)
* 0x…76fd2e0 = 0x16f18000 (budget) @21,480,151 (pc 0x…7abe49c)
* 0x…76fd2e8 = 0xfffffff06e2c5ec0 (view 0) @21,484,852 (pc 0x…7abe904)
* 0x…76fd2f0 = 0xfffffff06e2c5c90 (view 1) @21,490,901
* 0x…76fd2f8 = 0xfffffff06e2c5b78 (view 2) @21,494,604
* kernel_map global 0x…7700910 = 0xfffffff06e2c5da8 @21,371,346 (pc 0x…7b0174c)

## Next block (P)

1. Unpack the kr at the global_waitqs panic; RE kernel_memory_allocate →
   vm_map_find_space hole/first_free state in kernel_map.
2. Check why the 16 KB KMA_KOBJECT|KMA_PERMANENT allocation fails —
   candidates: hole-list enablement, first_free divergence after
   kmem_init's region reservations, page-shift handling in the views.
3. Re-run: expect the frontier past 22.5M into scheduler bring-up.
