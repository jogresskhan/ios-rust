# M2 census — what the real 18C66 kernelcache actually ships (2026-10-29)

**Supersedes the BOOT-PLAN M2 premise.** The plan said "parse
LC_DYLD_INFO/DYLD_CHAINED_FIXUPS and walk DYLD_CHAINED_PTR_64 with slide =
image_base − preferred_base". A byte-level census of the real
`kernelcache.release.iphone12b` (45,788,672 B, 18C66, n104ap) proves the
image carries **no fixup load commands at all**. Every claim below is
measured (`tools/re/extraction/m2_fixup_census.py`, re-runnable).

## 1. The image is an old-style bare kernel Mach-O

Top-level load commands (25 total, no fileset entries, no components):

| cmd | count | meaning |
|---|---|---|
| 0x19 LC_SEGMENT_64 | 18 | segments |
| 0x1b | 1 | UUID |
| 0x2 | 1 | SYMTAB |
| 0xb | 1 | DYSYMTAB |
| 0x5 | 1 | UNIXTHREAD (the real entry point) |
| 0x26 | 1 | FUNCTION_STARTS |
| 0x2a | 1 | DATA_IN_CODE |
| 0x32 | 1 | LINKER_OPTIMIZATION_HINT |

**Absent: LC_DYLD_CHAINED_FIXUPS (0x80000034), LC_DYLD_INFO (0x22 /
0x80000022), LC_DYLD_EXPORTS_TRIE (0x80000033), LC_FILESET_ENTRY.**
All `__PRELINK_*` / `__PLK_*` segments have vmsize = 0 — this is the bare
XNU kernel (kexts come from the aux collection / rootfs, not baked in).

## 2. Where the fixup data actually lives

* `__TEXT,__thread_starts` va `0xfffffff0076e7b8c`, size `0x36c` — u32
  (start,end) offset pairs (relative to link base `0xfffffff007004000`),
  ascending: (0,0x6e4000) (0x6e5100,0x6e5380) (0x6e8748,0x6f0000)
  (0x6f6580,0x720308) (0x780000,0xa10bd0) (0xa13770,0x1168dc8) … These are
  the ranges the **kernel itself** scans at boot for DYLD_CHAINED_PTR_64-style
  chained entries (`cmn w12,#1` end marker, `ldr x13,[x12]` chain walk,
  `ubfx/madd` next, `str` rebase — loop at 0x…7b802b8, already executed
  correctly by the emulator, PARITY 2.11c).
* `__DATA_CONST,__auth_ptr` va `0xfffffff0076e8000`, size `0x1100` —
  **544/544 entries ship NON-zero**, pattern `0x8010_<sig16>_<off32>` where
  off32 is an offset from the preferred kernel base (entry[1] = 0x80100000_00a14000;
  0xa14000 is exactly `__TEXT_EXEC` − link base). Pre-linked, PAC-signed
  GOT slots — valid as-is at slide 0 (which is what our handoff uses:
  `LOAD_PA = DRAM + (LINK_BASE & 0x1FFFFFF)`).
* `__DATA,__data` first 4 KB: 1023/1024 quads ZERO — __DATA ships empty and
  is filled by the kernel's own early boot.

## 3. What actually stops boot-real at 8,136,610 insns (NOT a rebase stop)

Named stop: `TranslationFault(load) va=0x4 @ 0xfffffff0081377b4` —
`ldr x0,[x20,#8]` → NULL → `ldr w9,[x0,#4]`. Static RE of the stop site
(`tools/re/extraction/m2_fixup_census.py` companion session, capstone):

* The faulting fn (0x…8137790) reads a caller-built struct:
  `+0x20` = count, `+0x8` = element pointer; the element pointer is NULL.
* Six BL callers; two build the struct on-stack and fill `+8` from
  **globals**: count `w[0xfffffff007744998]`, pointer `x[0xfffffff007744988]`
  (both in `__DATA_CONST,__const`, **both ship 0x0**), guarded by
  `PE_parse_boot_argn("cpus", …)` and a DT lookup of **`"/cpus"`**
  (strings at 0x…73a8785 / 0x…73adff6).
* The DT lookup fn (0x…8137198) hard-requires `w[0x…7744998] != 0`;
  the globals are stored only by early-boot memory-init
  (store sites 0x…7b80d24 / 0x…7b81fd8 / 0x…7b83fa0-84) **behind a gate**:
  `bl 0xfffffff008136f10; tbnz w0,#0 → skip stores` (16K-granule page-database
  ordering check).

**Conclusion:** the honest M2 story is a **DeviceTree-dependent early-boot
stop** (CPU enumeration), not missing load-time rebase. Next evidence step:
a live boot-real trace confirming whether the 0x…7b83fa0 store site executes
and what the gate returns in-emulator.

## 4. Harness facts corrected this session

* `boot-first` was NOT running the real handoff: it executed
  `__TEXT_EXEC.__text[0]` with no x0/boot_args and a 20k cap
  (hence "9 insns, stop Halted"). Fixed 2026-10-29: boot-first now runs
  `boot_real::run` (the measured real handoff contract) with a 12M budget.
* boot-real loads at the **preferred** VA layout (slide 0) — prelinked
  absolute pointers are valid as shipped; no iBoot-style rebase pass is
  needed for this handoff.

## 5. Main kernel component ranges (for stop forensics)

`__TEXT` 0xfffffff007004000+0x6e4000 (fo 0x0) · `__DATA_CONST`
0xfffffff0076e8000+0x330000 (fo 0x6e4000) · `__TEXT_EXEC`
0xfffffff007a18000+0x1e68000 (fo 0xa14000) · `__DATA`
0xfffffff0098ac000+0x254000 (fo 0x28a8000) · `__BOOTDATA`
0xfffffff009b00000+0x20000 (fo 0x2a4c000). Section file-offsets in section
headers carry flag bits in the high nibble (mask with 0xFFFFFFFF).

## Session incident (recorded for honesty)

The sandbox reset mid-session (repo + ~/.config + /tmp wiped; third reset
this campaign). Recovered from the S3 vault: bundle
`research/ios-rust-repo-backup.bundle` (HEAD 9130a73, uploaded 15:37 by the
vault-index subagent) + rewritten s3.env. Repo verified clean at 9130a73
after restore. **The vault-as-storage-of-record policy works.**
