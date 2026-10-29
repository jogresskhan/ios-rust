# M4-b — percpu blocker (TPIDR_EL1 / cpu_data[0]) — Task 4-b worklog

Baseline (session H, pre-work, measured `IOS_RUST_DRAM_MB=1024 boot-first fixtures /tmp/bootfirst`):

- 10,921,780 insns · 21,270 vectored sync aborts · stop `UnknownInsn 0x0 @ 0xfffffff00816c458`
- MMU live 10,896,747 insns; aborts all load-type (ESR 0x96000006/0x96000012), MMU leaf L2 1875
- 1 `panic()` @ insn 8135397: x0=0xfffffff0073adec0 x1=0x80000011 x2=0 x3=0xfffffff007744a89
- abort timeline:
  1. insn 8135442 elr=0xfffffff007a585d0 far=0x4f0 (panic_impl percpu deref, tpidr=0)
  2. ~elr=0xfffffff00816c38c far=0x2e656c7070612f6d ("m/apple.") — handler deref of string bytes
  3. steady loop: elr=0xfffffff00816c38c far=0x100 (tpidr=0 → NULL+0x100), ~131 insns/cycle, until budget
- POISON probe: 21,273 stores of `0x0000fff008137198` (top-16-zeroed 0xFFFFFFF008137198) at
  pc 0x…8160420/24/40 (vector prologue register save) → x6 truncated SOMEWHERE upstream, once,
  then preserved by every save/restore cycle (approach #5 lead).
- cpu_data[0]: heuristic scan never discovered (0x98AC000..0x9B00000 __DATA, [+0x4f8] stack-VA test)
- last SP change: pc=0xfffffff0081607c8 → sp=0xfffffff00816c220 (sp → text: the fatal save path)

## Worklog


## Closed (session I, 2026-10-30)

Root cause chain fully identified — see m4-text-zeroing-re.md and the
PARITY 2.12b entry: the "poisoned x6" and "last SP change" notes above
were red herrings (x6's value = the panic call site 0x…8137198 with
truncated top bits; SP changes EVERY storm cycle, not once). The stop =
recursive exception-report stack overflow; fixes: TPIDR discovery
re-wire (dead code), DT placeholder flags (bug #25), BSS zero-fill
(bug #26), undefined-insn vectoring, ExceptionRecursion guardrail.
Worklog continues in BOOT-PLAN M4 (session I evidence).
