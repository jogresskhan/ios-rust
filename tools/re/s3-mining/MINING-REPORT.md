# S3 VAULT MINING + SNAPSHOT REPORT — task 2-c (2026-10-29)

Agent scope: snapshot pipeline fix + fresh snapshot + vault mining for M2 (rebase/chained-fixups) and M3 (MMU/TLB). No Rust source touched, no git commit/push (GitHub forbidden; S3 is storage of record). Nothing deleted from the bucket.

---

## 1. Snapshot status: SUCCESS

| item | value |
|---|---|
| command | `source ~/.config/ios-rust/s3.env && python3 tools/s3_backup.py snapshot ios-research-vault` |
| exit code | 0 |
| duration | **261 s** (4m21s) under a 570 s wall-clock guard |
| HEAD captured | `b609f1844be65c692ccf28ac405bdbb696fdd281` — verified post-upload by GETting `research/ios-rust-export/.commit` and `MANIFEST.txt` from S3 (both show b609f18; subject = "M2 gate cleared the honest way…") |
| uploaded | 302 PUTs: 301 files → `research/ios-rust-export/` (48.2 MB tree incl. committed `full-root.apfs` 25.2 MB, 2 × 10.9 MB BMPs) + `research/ios-rust-repo-backup.bundle` 1.2 MB (full history, 75 commits) |
| skipped (expected) | `/home/z/work/ios-re-toolkit`, `/home/z/work/ios-research/research-docs` — dirs don't exist locally; **their vault copies are the only copies** |
| manifest id (this snapshot) | export `.commit` uploaded 2026-10-29 17:29:28Z, bundle 17:33:42Z |
| prior snapshot id | `b609f18-20261029T1705Z` (same commit; prior upload round 17:05:58Z) |
| working tree after | still clean of tracked changes; only new untracked files under `tools/re/s3-mining/` (this mining set). No commit made. |

No side-car script was needed for the snapshot itself — the tool completed on its own. `tools/re/s3-mining/mine_vault.py` is a read-only mining helper (downloads only), not a snapshot replacement.

## 2. Why the previous 120 s timeouts happened (evidence)

1. **Root cause is wall-clock throughput, not a hang.** `cmd_snapshot` → `upload_dir` does one sequential HTTP PUT per file (~300 requests; boto3 `max_concurrency=8` only parallelizes chunks of files ≥64 MB, and no file here is). Measured endpoint RTT ≈ 0.25–0.5 s/request (DNS 9 ms, TCP 252 ms, TLS 1.2 s; 621-key listing varied 1.4 s–23 s across runs). 300 × ~0.5 s ≈ 150–260 s → any 120 s guard kills it. The vault's own `INDEX.md` corroborates: "a full one took 2m22s" and the "15:13 round stopped right before its bundle step (likely killed by a 120s timeout)."
2. **Secondary latent risks in `tools/s3_backup.py`** (review of full file):
   - No `botocore.config.Config` at all → default 60 s connect/read timeouts × 5 retries; one stalled request can burn ~10 min inside a "stuck-looking" transfer.
   - Env-var mismatch: script reads `S3_ENDPOINT_URL`, the env file exports `S3_ENDPOINT`. Harmless today only because the hardcoded default equals the real endpoint.
   - `tarfile.extractall` DeprecationWarning (Python 3.14 filter change) on line 190.
   - `sync` compares size only; `research/ios-rust-export/` accumulates stale keys from older trees (524 keys in prefix now vs 301-file tree; the old 223→31 target/ fingerprint junk remains — no deletions allowed, and none made).
3. **Fix applied:** generous timeout (≥570 s wall clock). Measured full snapshot = 261 s → 600 s Bash timeout is the right standing rule (also already documented in `tools/re/notes/s3-vault-manifest.md`: "allow ≥600 s").

## 3. Bucket inventory headline

File: `tools/re/s3-mining/bucket-inventory.txt` (post-snapshot, 644 lines, full per-object listing) and `bucket-listing-preflight.txt` (pre-snapshot, 621 objects).

- Bucket `ios-research-vault` (IDrive e2, eu-central-1). Versioning: **OFF** → snapshots overwrite the same keys; there are no per-snapshot-ID keys.
- **621 objects, 1036.3 MB** total. 6 other buckets exist (`ios`, `knowlia`, `egregoria-maps`, …) — untouched.
- Prefixes: `research/diag` 1 obj 606.6 MB (unknown ramdisk zip) · `research/` root 22 objs 352 MB (12 upstream tarballs incl. **xnu 32.7 MB**, linux-sandcastle 117.7 MB, darling, asahi, m1n1, pongoOS + `repos__ios-sweet-rust.tar.gz` 110 MB, `repos__chefkiss-inferno` 62.2 MB, workspace tarball, T8030 frame) · `research/ios-rust-export/` 524 objs 77.1 MB · `research-docs` 10 md (ONLY copy) · `ios-re-toolkit` 50 keys incl. .git (ONLY copy) · `reports` 6 · `ledger/worklog.md` · `verdicts/ios-rust-latest.json` · root `INDEX.md` (2026-10-29 15:44) + `manifest.json` (2026-10-28 corpus sha256s).
- Snapshot rounds observed on the same keys: 2026-10-28 03:39 (HEAD aa877bf) → 2026-10-29 03:39 / 14:11 / 15:13 (killed at 120 s) / 15:35–15:37 (HEAD 9130a73, 2m22s) → **17:29–17:33 (HEAD b609f18, mine, 261 s)**.

## 4. What was downloaded (mining set)

`tools/re/s3-mining/b609f18-20261029T1705Z/` — **124 small text artifacts, 2.6 MB** + the 1.2 MB history bundle, mirrored by S3 key path:
- `research/ios-rust-export/` docs/*.md, parity.json, tools/** (small .md/.json/.py/.txt/.yml/.java/.sh/.toml), .commit, MANIFEST.txt — includes 31 stale `coverage-probe/target/*` fingerprint JSONs (junk, kept only as evidence of the stale-key issue).
- `research/research-docs/` 10 md (ONLY copy in existence): KPF-GAP-ANALYSIS, PLAN-ISO-BOOT, PROJECT-LANDSCAPE, IOS26-STATE, RESEARCH-ALL-LIBS, WIKI-SNAPSHOT-2026-10-25, devicetree-d22ap (148 KB), kc-kexts (66 KB), launchd-spawn-map, userspace-deps.
- `research/ledger/worklog.md` (38 KB), `research/reports/` 6 files (parity report 30 KB, parity-metrics.json 42 KB, CSV, plan, inventory), `research/verdicts/ios-rust-latest.json`, `research/INDEX-latest.md`, root `INDEX.md`, `manifest.json`.
- `research/ios-rust-repo-backup.bundle` → cloned to `…/repo-bundle-clone/` (75 commits verified, `git log` clean).
- Provenance: `MINED-MANIFEST.txt` (S3 key, size, last-modified per file); mining done BEFORE the fresh snapshot because versioning is OFF and the snapshot overwrites `research/ios-rust-export/*` + the bundle in place.
- NOT downloaded (per <2 MB text-only rule): the 606 MB diag zip, all tarballs. `manifest.json` has their sha256s.

## 5. Delta analysis (S3 vs local HEAD b609f18)

- **Repo export: byte-identical.** All 92 text files under `research/ios-rust-export/` (excluding stale target/ junk) compare equal to the local tree (`cmp -s` over every file: zero diffs). The prior snapshot was taken from the same commit the local repo has. **The repo itself lost nothing** — and the bundle (75 commits) contains **zero deleted .md/.json/.txt files** (`git log --diff-filter=D` empty).
- **No `m1close_full.json` anywhere** in bucket keys or git history; no per-snapshot oracle outputs exist outside the repo tree. The "older oracle outputs" live inside the repo's committed `tools/re/oracle/` (identical both sides).
- **The vault's unique value is the material OUTSIDE the repo** (research-docs / reports / toolkit / verdicts — several marked "ONLY COPY EXISTS HERE"). Delta verdicts per file class below.

### Findings for M2 (rebase / chained-fixups)

**F1 — the exact loader reference is named and validated (KPF-GAP-ANALYSIS.md §3.3):**
> "`extract_im4p_payload` (kernelcache/DeviceTree from IPSW containers, LZSS/LZFSE …), `macho_load_dtb` …, fileset handling (`macho_get_fileset_header(…, "com.apple.kernel")`), symbol processing (`macho_process_symbols` — release kernelcaches retain symbol tables), and the slide/rebase helper family. **This file is nearly directly reusable.**"
That is qemu-t8030's `hw/arm/xnu.c` (1,321 LoC) — the slide/rebase helper family is a working reference for exactly the M2 image-loading step, proven on real iOS 14.0b5 iPhone 11 caches (same SoC class T8030 as our 18C66).

**F2 — chained-fixups parsing already exists in a sibling repo whose tarball is in the vault (reports/iOS-Library-Parity-Report.md "fact table"):**
> "Mach-O / fileset / chained fixups / kext extraction | `macho.rs` 419 L · `kexts.rs` 361 L · `mkpayload.py` · `boot.c` | ✅"
and §B: "Mach-O fixups + fileset entries (`macho.rs`, `kexts.rs`)". `repos__ios-sweet-rust.tar.gz` (110 MB, sha256 in root `manifest.json`) holds that implementation — a ready-made cross-check for `m2_fixup_census.py` findings (18C66 = old-style bare kernel, no fixup LCs; kernel self-rebases via `__thread_starts`; `__auth_ptr` pre-signed slide-0).

**F3 — the canonical pre-M2 blocker list survives only in the vault verdict (verdicts/ios-rust-latest.json, aa877bf era):**
> "blockers": ["rebase/chained-fixups image loading", "MMU/TLB", "IRQ/AIC + 46 unmodeled peripherals", "userspace (DSC rebase + dyld)"]
Useful as the honest "M2 as originally scoped" record; note the M2 commit's census has since corrected the mechanism (no chained-fixup LCs on 18C66).

### Findings for M3 (MMU / TLB)

**F4 — a measured 16K-granule EL1 MMU bring-up recipe exists (reports/iOS-Library-Parity-Report.md §C on ios-sweet's shim):**
> "Shim (`shim/`, 1,481 LOC C+asm): **EL1 MMU (16K granule)**, PSCI CPU_ON for secondaries, JEDEC UFSHCI host driver …"
plus the DART walker: "**`sweet_dart.c` (854 LOC real 4-level DART PTE walker, W3 gate measured PASS 2026-10-24)**" and Inferno's "DART IOMMU ✅ `dart.c` 980 L + 9 stub instances … `nvme_mmu.c` 292 L", "A13 CPU features … **GXF** `a13_gxf.c` 640 L; AMX cpregs; PAC via QEMU TCG; **PPL patching works on Darwin 25**". All in the 62.2 MB `chefkiss-inferno` + 110 MB `ios-sweet-rust` tarballs (keys + sha256s in the vault).

**F5 — PPL/arm64e MMU ground truth for the current 18C66 target (KPF-GAP-ANALYSIS.md + PLAN-ISO-BOOT.md L0 measured table):**
> iPhone 11 iOS 14.0b5 (our kernel's family): "arm64e, **PACIBSP ×62,425, `__PPLTEXT` present**"; iPhone X 16.7.16: "arm64, PACIBSP ×0, `__PPLTEXT` absent". qemu-t8030's KPF "unconditionally dereferences the `__PPLTEXT` section, which does not exist on arm64 (no PPL on T8015)" → any ported loader/patcher needs the `has_ppl` gate. Current local stop is a TranslationFault inside kernel `/cpus` DT enumeration with DT globals zero behind the 0x…b83f54 gate — the 148 KB `devicetree-d22ap.md` dump is a T8015 (not T8030) DT, but its node inventory (`iommu-present`, `dart-options`, `smmu-options`, `iommu-mapper`, `bypass-address`, `dram-capacity`, `config-data`) is a concrete model of what the live DT must contain once globals ungate.

**F6 — older bug numbers / parity eras preserved (vault-only):** `verdicts/ios-rust-latest.json` (352/352 tests, 98.59% decode @ aa877bf, "boot not yet"), `INDEX-latest.md` (aa877bf-era index), `reports/parity-metrics.json` (milestones M0/M1 DONE, M2 RUNNING — *different* M-numbering: sibling campaign's library-parity milestones, not the repo's boot gates), `ledger/worklog.md` (session log incl. BL-1..BL-5 blocker root-causes, e.g. "verify_storage_for_update lives in Apple 'restored' NOT idevicerestore", "Dopamine 26.0-26.0.1 A12/A13 CONFIRMED").

## 6. Recommendations

1. **Standing rule:** snapshot with ≥600 s guard (measured 261 s); retry once on kill. Optionally patch `s3_backup.py` (small, non-source) later: read `S3_ENDPOINT` as fallback, add `Config(connect_timeout=10, read_timeout=60, retries={"max_attempts":3})` — do NOT change the packing format.
2. **Do not delete** `research/research-docs/` and `research/ios-re-toolkit/` from the bucket — they are the only copies (local dirs gone).
3. **Regenerate `research/verdicts/ios-rust-latest.json`** — still describes aa877bf (98.59%, boot-blocked); reality is b609f18 (M2 gate cleared, 290/0 tests, boot-first 8.14M insns). It lives outside the snapshot prefix, so it won't refresh itself.
4. **For M2 next session:** pull `research/repos__ios-sweet-rust.tar.gz` (macho.rs chained-fixups ref) and compare against `m2_fixup_census.py`; consult qemu-t8030 `xnu.c` slide/rebase helpers (upstream tarballs or public clones).
5. **For M3 next session:** mine the inferno/ios-sweet tarballs for `dart.c`/`sweet_dart.c`/`nvme_mmu.c` and the 16K-granule EL1 MMU shim; use the DT dump as the shape-checklist for `/cpus` + DART nodes feeding the 0x…b83f54 gate.
6. Stale-key hygiene (31 target/ fingerprints + a few old names) is documented in `INDEX.md`; leave in place, trust the bundle for faithful restore.

## 7. Artifacts produced by this task (all untracked, nothing committed)

```
tools/re/s3-mining/b609f18-20261029T1705Z/   # prior-snapshot mining set (124 files + bundle + repo-bundle-clone/ + MINED-MANIFEST.txt)
tools/re/s3-mining/mine_vault.py             # read-only miner (bucket -> local, <2MB text filter)
tools/re/s3-mining/bucket-inventory.txt      # post-snapshot full inventory (621 objs / 1036.3 MB)
tools/re/s3-mining/bucket-listing-preflight.txt  # pre-snapshot raw listing
tools/re/s3-mining/inventory-preflight.txt   # pre-snapshot summary + 25 newest
tools/re/s3-mining/snapshot-run.log          # the successful snapshot run (302 PUTs)
tools/re/s3-mining/MINING-REPORT.md          # this file
```
