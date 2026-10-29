#!/usr/bin/env python3
"""mine_vault.py — one-off read-only miner for s3://ios-research-vault.

Pulls the PRIOR snapshot's small text artifacts (+ the full-history bundle)
BEFORE a fresh `s3_backup.py snapshot` overwrites the shared keys (bucket
versioning is OFF — snapshots overwrite in place, no snapshot-ID keys exist).

Downloaded into tools/re/s3-mining/<snapshot-id>/ mirroring the S3 key paths,
plus a MINED-MANIFEST.txt recording key/size/date for provenance.
"""
import os
import time
from pathlib import Path

import boto3
from botocore.config import Config

BUCKET = "ios-research-vault"
DEST = Path("/home/z/work/ios-rust/tools/re/s3-mining")
TEXT_EXTS = {".md", ".json", ".txt", ".py", ".csv", ".yml", ".yaml", ".java", ".sh", ".toml"}
MAX_BYTES = 2 * 1024 * 1024  # mission rule: skip anything >2MB

c = boto3.client(
    "s3",
    endpoint_url=os.environ.get("S3_ENDPOINT") or "https://s3.eu-central-1.idrivee2.com",
    region_name=os.environ.get("S3_REGION") or "eu-central-1",
    aws_access_key_id=os.environ["AWS_ACCESS_KEY_ID"],
    aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_KEY"],
    config=Config(connect_timeout=15, read_timeout=60, retries={"max_attempts": 3}),
)

print("listing bucket ...")
t0 = time.time()
objs = []
for page in c.get_paginator("list_objects_v2").paginate(Bucket=BUCKET, PaginationConfig={"PageSize": 1000}):
    objs.extend(page.get("Contents", []))
print("  %d objects in %.1fs" % (len(objs), time.time() - t0))
by_key = {o["Key"]: o for o in objs}


def fetch(key) -> bytes:
    return c.get_object(Bucket=BUCKET, Key=key)["Body"].read()


# --- identify the prior snapshot via its export markers ---------------------
commit = fetch("research/ios-rust-export/.commit").decode().strip()
prior_manifest = fetch("research/ios-rust-export/MANIFEST.txt").decode(errors="replace")
lm = by_key["research/ios-rust-export/.commit"]["LastModified"]
snap_id = "%s-%s" % (commit[:7], lm.strftime("%Y%m%dT%H%MZ"))
snap_dir = DEST / snap_id
snap_dir.mkdir(parents=True, exist_ok=True)
print("PRIOR SNAPSHOT id: %s (export .commit uploaded %s)" % (snap_id, lm.isoformat()))
print("PRIOR MANIFEST.txt:\n" + prior_manifest)
(snap_dir / "_prior-MANIFEST.txt").write_text(prior_manifest)


def want(key: str, size: int) -> bool:
    if key in ("INDEX.md", "manifest.json", "research/ios-rust-repo-backup.bundle"):
        return True
    if size > MAX_BYTES:
        return False
    if not any(key.lower().endswith(e) for e in TEXT_EXTS):
        return False
    if key.startswith("research/ios-rust-export/"):
        rel = key[len("research/ios-rust-export/"):]
        if rel in (".commit", "MANIFEST.txt", "parity.json", "README.md", "PARITY.md", "BOOT-PLAN.md"):
            return True
        return rel.startswith("docs/") or rel.startswith("tools/")  # docs/*.md, tools/** small text
    if key.startswith(("research/research-docs/", "research/ledger/", "research/reports/", "research/verdicts/")):
        return True
    if key.startswith("research/ios-re-toolkit/"):
        return "/.git/" not in key  # skip packfiles etc.
    return False


targets = [o for o in objs if want(o["Key"], o["Size"])]
total = sum(o["Size"] for o in targets)
print("downloading %d artifacts (%.1f MB) -> %s" % (len(targets), total / 1048576, snap_dir))
t0 = time.time()
lines = []
for i, o in enumerate(sorted(targets, key=lambda x: x["Key"]), 1):
    dst = snap_dir / o["Key"]
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(fetch(o["Key"]))
    lines.append("%s\t%d\t%s" % (o["Key"], o["Size"], o["LastModified"].isoformat()))
    if i % 25 == 0:
        print("  %3d/%d  %.0fs elapsed" % (i, len(targets), time.time() - t0))
(snap_dir / "MINED-MANIFEST.txt").write_text("\n".join(lines) + "\n")
print("DONE: %d artifacts, %.1f MB, %.0fs -> %s" % (len(targets), total / 1048576, time.time() - t0, snap_dir))
