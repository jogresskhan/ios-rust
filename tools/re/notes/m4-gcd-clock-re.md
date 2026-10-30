# M4 bug #28 — the diverging Euclid GCD loop (RESOLVED: engine MSUB operand order)

**Session K (2026-10-30). Companion script: `tools/re/reports/m4_gcd_clock.py`.**

## The stop

Session J: boot ran 8.19M → 48M → **2,000,000,000 clean insns** but never reached
WFI — the kernel spun forever in a Euclid GCD loop at `0x…7b92d68-78`
(`udiv x12,x10,x12; msub x12,x12,x11,x10; cbnz`), called from arm_vm_init
(lr 0x…7b80a30). The observed residue "stayed wrapped" (pair seen:
24,000,000 / 2⁶⁴−24,000,000).

## The helper (capstone, real bytes — helper start = pacibsp @0x…7b92d20)

```
helper(x0 = &{clock, divisor}):
  x9 = [x0+8]                 ; divisor
  if (x9-1) > 3 (unsigned)    → ESCAPE (panic, string 0x…73699eb → bl 0x…987b99c panic wrapper)
  x8 = [x0]                   ; clock
  if x8 < x9 (unsigned)       → ESCAPE
  w10 = 0x3b9aca00            ; 10⁹
  x9 = divisor * 10⁹
  x10 = max(x9, x8); x12 = min(x9, x8)
  cbz x12 → x11 = x10 ; else Euclid: x11=x12; x12=x10 mod x12; x10=x11; while x12≠0
  x9 = (divisor·10⁹)/gcd ; x8 = clock/gcd
  → store w9,w8 at [0x…98e4658+8]      ; numerator/denominator of the tick ratio
  x8 = clock/divisor
  x9 = (x8 & 0xffffffff) * 0x431bde83 >> 50   ; magic = divide by 1000
  → store w8,w9 at [0x…98e4658]        ; Hz, kHz
```

Call site (0x…7b80a2c): `adrp x8,0xfffffff009a8a000; ldr x8,[x8,#0x4d8]` (the
clock global — pexpert default 24 MHz per m4-aic-timer-re.md §2), `mov w9,#1`,
`stp x8,x9,[sp,#0x30]`, `bl 0x…7b92d20`. So `{clock=24e6, divisor=1}` →
x9 = 1e9, gcd(1e9, 24e6) = 8e6, ratio 125/3, Hz 24e6, kHz 24000.

## ROOT CAUSE — REAL-DATA BUG #28 is an ENGINE bug, not a kernel/data bug

Textbook Euclid terminates for ANY unsigned inputs. Our `Insn::Madd` subtract
branch computed **`Xn·Xm − Xa`** instead of the ARM-spec **`Xa − Xn·Xm`**.
MADD hid the flip for every other site (addition commutes). In the kernel's
remainder step `udiv q,a,b; msub r,q,b,a` the correct result is `a − q·b = a
mod b ∈ [0,b)`; ours returned `q·b − a = 2⁶⁴ − (a mod b)` — the wrapped
residue, exactly as observed. Simulation of the buggy loop from (1e9, 24e6)
cycles through 2⁶⁴−16e6, 2⁶⁴−24M, … forever — never zero.

Two latent W-form defects on the same code path (also fixed):
* W-form addend `c` was NOT masked to 32 bits (upper bits of Xa leak),
* W-form result was NOT truncated to 32 bits / zero-extended
  (kept the full 64-bit product).

Also fixed: `Insn::MaddW` (umsubl/smsubl) had the same flipped subtract.

## Evidence pins (keystone + real image)

* Real word @0xfffffff007b92d70 = `0x9B0BA98C` = keystone
  `msub x12, x12, x11, x10`; @…d6c = `0x9ACC094C` = `udiv x12, x10, x12`;
  @…d68 = `0xAA0C03EB` = `mov x11, x12`.
* Goldens (crates/a13-cpu/src/goldens_m4.rs): verbatim 3-insn kernel Euclid
  step (1e9,24e6 → 16e6), operand-order, W-form mask/zeroext, madd W
  truncation, umsubl order, umaddl regression.

## Fix

`crates/a13-cpu/src/interp.rs` `Insn::Madd` / `Insn::MaddW`:
`r = subtract ? c.wrapping_sub(prod) : prod.wrapping_add(c)`, W-form masks
`c` and truncates to 32 bits.

## Measured result

boot-first (debug, IOS_RUST_DRAM_MB=1024, 48M budget): stop=Budget ·
clean=true · panic 0 · aborts 0 · faults 0 · bus unmapped 0/0 — the gcd
loop completes and the kernel moves on (486 MMU walks, 100% TLB hit).
One delivered `undefined` exception at FAR=ELR=0x…7a584fc = the kernel's
deliberate 0xE7FFDEFF ARM-GDB trap marker (session-I model — correct).
2G run: /tmp/bf-bug28-2g.log.

---

# Session K continuation — bugs #29/#30/#31 fixed, #32 scoped (2026-10-30)

## #29 MUL = MADD Ra=31 (XZR), never SP
Panic: "Section __BOOTDATA,__init_entry_set has invalid size" @insn 8,255,200
(lr 0x…7a8cf18, fmt 0x…735c26a). The check @0x…7a8ce24 is STATIC:
size=0x2640 (section end 0x…9b02640 − seg start 0x…9b00000), the unsigned
div-by-6 idiom `mul x9,x8,x9; ror x9,#3; cmp x9,0x0AAAAAAAAAAAAAAB; b.hs`.
Keystone: `mul x9,x8,x9` ≡ `madd x9,x8,x9,xzr` = 0x9B097D09; `madd
x0,x1,x2,sp` / `madd sp,x1,x2,x3` / `umaddl sp,w1,w2,sp` DO NOT ASSEMBLE.
Fix: Insn::Madd/MaddW addend read via r() (ZR), Rd=31 discards.

## #30 PAC canonical strip
`blraa x27, x26` = 0xD73F0B7A (verbatim @0x…7f2f658) jumped RAW to the
pac()-tagged pointer (tag 0x402f). Fix: crypto::canonical() (sign-extend
bit 47); aut()/RetA/BrAuth all strip-and-restore; pac() now signs the
48-bit VA only.

## #31 add/sub register forms: Rn=31 reads SP (ALWAYS)
The vector-page stack guard `cmp sp,x18; b.gt .; sub x18,#0x4000; cmp
sp,x18; b.lt .` @0x…8160400 spun 2G insns: 0xEB3263FF (`cmp sp, x18`,
add/sub EXTENDED form, capstone) read Rn=31 as ZR → nzcv=0000 → b.gt
taken. ARM rule: Rn=31 is SP in both S=0/S=1; Rd=31 is SP (S=0) / ZR
(S=1). Fixed CmpReg/CmnReg/CmpImm/CmnImm/AddSubReg/AddSubExt + the imm
setflags Rd=31 discard.

## #32 (OPEN) — the corrupted-ELR ERET / boot-stack frame corruption
After the handled physmap load-abort (FAR 0xffffffe013611fb0, ESR
0x96000005 — the callback's `ldr w9,[x1]` @0x…7a8d064, x1 = physmap of PA
0x13611fb0), the kernel ERETs and later flow lands in the vector-page
stack guard and spins (pc 0x…8160410 now, flags correct post-#31).

MEASURED FACTS (deep-trace + guard-range stop, /tmp/bf-deep-guard.log):
1. The abort vectors correctly: VBAR+0x200 → save helper @0x…816041c →
   C sleh (0x…8137xxx region in the ring) → ERET path @0x…81609dc
   (msr elr_el1) / 0x…8160acc (eret).
2. The save helper writes the ENTIRE 0x350-byte frame (x2-x30 at
   [x0+0x18..0xf8], q0-q31 at [x0+0x140..0x340]) where x0 = the
   INCOMING sp — ON THE BOOT STACK (0x…9b0fe50). [sp+0x134] is ABOVE sp —
   into the interrupted call chain's LIVE frames (dispatcher/callback
   saved x30s). Same writes happen on real HW → the +0x200 stub MUST be
   entered with sp on the per-cpu EXCEPTION stack.
3. The exception-stack switch pattern exists in the vector page:
   `mrs x1,tpidr_el1; ldr x1,[x1,#0x4f8]; ldr x1,[x1,#0x10]; mov sp,x1`
   (@0x…8160180 and @0x…8160380 slots). The descriptor @0x…9a4ae60:
   [+0x10] = switch target (NOT YET DUMPED), [+0x20]/[+0x28] =
   0x…9b18000 (guard bound). [tpidr+0x498] (the OTHER switch field,
   used by the 0x…81603cc stub) = 0 in our memory.
4. Final jump: callback 2nd load @0x…7a8d064 → pc 0x…815f200 (in one
   capture printed as 0x00FF_FFF0_0815_F200 — top byte lost; in the
   deep capture as clean 0xFFFFFFF00815F200 — tag-vs-clean ambiguity)
   → `b 0x…81601d8` → `b guard`. NO second vectoring in the ring →
   consistent with a CORRUPTED x30 (frame overwrite) reached by `ret`,
   or a partially-stripped tag through a plain branch.

NEXT RE STEPS (concrete):
a. Dump [desc+0x10] (the switch target) at stop; check whether it
   equals 0x…9b18000 (the guard-pass window top).
b. Decide the vector-offset question: does THIS kernel expect
   current-EL-SPx sync (0x200) to arrive on the exc stack? Compare the
   +0x200 stub (no switch) against +0x000/+0x080 (SP0 entries — the
   `msr spsel,#0; sub sp,#0x350` @0x…8160198 block). If xnu's boot CPU
   runs SPSel=1 (SPx), the 0x200 stub without a switch means the
   kernel EXPECTS sp already on the exc stack — i.e. OUR engine should
   deliver sync-aborts with sp switched, OR the kernel's own earlier
   code should have been RUNNING on the exc stack (check: what sp does
   the real kernel use after cpu_data_init? the boot stack at 0x…9b0fe50
   vs exc top 0x…9b18000 — the kernel may switch to the intstack in
   machine_idle/sched path we haven't reached).
c. Verify the x30-corruption theory: read the boot-stack memory above
   0x…9b0fe50 for the dispatcher's saved x30 (0x…7f2f74c) before/after
   the exception — if the save helper overwrote it, the `ret` target
   explains the jump.
d. Tooling ready: IOS_RUST_STOP_PC_RANGE, IOS_RUST_TRACE_DEEP (2048),
   guard-chain dump in the report.

## #32 addendum (end of session K block)
Measured at stop: exc-stack descriptor @0x…9a4ae60 → [+0x10] (stub switch
target) = 0x…9b10000, [+0x20]/[+0x28] (guard bound) = 0x…9b18000 — the
guard window (0x…9b14000, 0x…9b18000] does NOT contain the switch target:
the guard belongs to a DIFFERENT (nested) stack level; the +0x200 stub is
simply not the right entry for a boot-stack sync abort, or the real boot
never takes this abort.
STRONG LEAD: the faulting FAR 0xffffffe013611fb0 decodes as
physmap(PA=0x13611fb0); the DRAM window here is 0x8_00000000..0x8_40000000
— the kernel almost certainly wanted PA 0x8_13611fb0 (physmap VA
0xffffffe0_81361fb0). The 0x8_00000000 bit was LOST = a 33rd-bit
truncation somewhere in the kvtophys/physmap computation — ANOTHER engine
mis-model (candidate: a W-form addsub/ext or a shift/extend site). Next
block: RE the instruction that computed x22=0xffffffe013611fb0 (the
callback's argument chain from 0x…7f2f730-48), find the truncation, fix +
golden. Then the physmap load stops aborting, the whole guard question
may go away, and the boot proceeds into the scheduler (WFI territory).
