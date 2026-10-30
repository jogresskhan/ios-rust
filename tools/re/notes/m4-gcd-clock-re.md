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
