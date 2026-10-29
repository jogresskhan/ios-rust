# S3 vault manifest — ios-research-vault (2026-10-29, session F)

> Regenerated (condensed) after the session-F sandbox reset. The full index
> lives IN the bucket: `s3://ios-research-vault/INDEX.md` (6,654 B, uploaded
> 2026-10-29T15:44Z) — pull that for the authoritative list.

## Vault shape (measured 2026-10-29)

* 616 objects / 1,086,570,221 B (~1.04 GB) recursive (18.6 s first listing).
* Largest: `research/diag/run40593862961-diag-ramdisk.zip` 606.6 MB
  (contents unknown, not pulled), `repos__ios-sweet-rust.tar.gz` 110 MB,
  `repos-upstream__linux-sandcastle.tar.gz` 117.7 MB.

## Storage-of-record keys (the ones that matter)

* `research/ios-rust-repo-backup.bundle` — git bundle, faithful checkout
  source. 1,190,506 B @ 2026-10-29T15:37:29Z, created from HEAD `9130a73`.
  **Restore:** `git clone <downloaded bundle> <dir>` (then
  `git fetch origin` inside if you need remote refs).
* `research/ios-rust-export/` — 297-file worktree export + `.commit` marker
  + MANIFEST. NOTE: contains 223 stale keys from older trees; `sync`
  compares size only — **prefer the bundle for a faithful restore**.
* `research/research-docs/` — 10 md (KPF-GAP-ANALYSIS, devicetree-d22ap,
  kc-kexts, launchd-spawn-map, …) — ONLY COPY EXISTS HERE.
* `research/ios-re-toolkit/` — ghidra/extraction/macho/QEMU toolkit repo
  incl. .git — ONLY COPY EXISTS HERE.
* `research/ledger/worklog.md`, `research/reports/` (plan + library-parity
  report/metrics/csv), `research/verdicts/ios-rust-latest.json` (98.59%
  decode verdict @ aa877bf — one era behind, regenerate when convenient),
  `manifest.json` (sha256 manifest of the 2026-10-28 corpus, 33 objects).

## How to use (session-standard)

```bash
source ~/.config/ios-rust/s3.env   # AWS creds + S3_ENDPOINT/REGION/BUCKET
python3 tools/s3_backup.py snapshot ios-research-vault   # full snapshot (slow endpoint: allow ≥600 s)
python3 tools/s3_backup.py get ios-research-vault <key> <dst>   # per-script usage
```

Warnings measured this session: endpoint is slow (one snapshot died at 120 s
timeout; a full one took 2m22s); 223 stale export keys linger (documented in
INDEX.md); INDEX-latest.md + verdicts JSON still describe aa877bf.

**Proven value:** this vault restored the campaign after the session-F reset
(repo + ~/.config + /tmp wiped; bundle clone back to 9130a73 in minutes).
