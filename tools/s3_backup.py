#!/usr/bin/env python3
"""s3_backup.py — local-first backup of the ios-rust project to S3 (IDrive e2).

GitHub push is blocked (account suspended) — this script is the remote-storage
replacement. It works with any S3-compatible endpoint (IDrive e2, AWS, Wasabi,
Backblaze B2 S3, MinIO …).

Configuration comes from the environment (see ~/.config/ios-rust/s3.env):

    export S3_ENDPOINT_URL=https://s3.eu-central-1.idrivee2.com
    export S3_REGION=eu-central-1
    export AWS_ACCESS_KEY_ID=...
    export AWS_SECRET_ACCESS_KEY=...

Usage:
    source ~/.config/ios-rust/s3.env
    python3 tools/s3_backup.py buckets
    python3 tools/s3_backup.py create <bucket>
    python3 tools/s3_backup.py ls <bucket>[/prefix]
    python3 tools/s3_backup.py put  <local-file-or-dir> <bucket/key>
    python3 tools/s3_backup.py get  <bucket/key> <local-dest>
    python3 tools/s3_backup.py sync <local-dir> <bucket/prefix>   # upload, skip identical
    python3 tools/s3_backup.py snapshot                            # the curated project set

`snapshot` uploads the canonical backup set:
    ios-rust/        full committed source tree (git archive of HEAD)
    git bundle       full history (ios-rust-repo-backup.bundle)
    ios-research/    research pipeline + research-docs
    ios-re-toolkit/  standalone RE toolkit repo copy
Requires: boto3 (pip3 install boto3). Large files use multipart automatically.
"""

import hashlib
import io
import os
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

try:
    import boto3
    from boto3.s3.transfer import TransferConfig
except ImportError:
    sys.exit("boto3 missing: pip3 install boto3")

ENDPOINT = os.environ.get("S3_ENDPOINT_URL", "https://s3.eu-central-1.idrivee2.com")
REGION = os.environ.get("S3_REGION", "eu-central-1")
GB = 1024 ** 3
CFG = TransferConfig(multipart_threshold=64 * 1024 * 1024, multipart_chunksize=16 * 1024 * 1024,
                     max_concurrency=8)

# Curated backup set (repo-local paths are absolute at call time)
EXPORT_DIR = "/home/z/my-project/download/ios-rust"
BUNDLE_PATH = "/home/z/my-project/download/ios-rust-repo-backup.bundle"
REPO_DIR = "/home/z/work/ios-rust"
SNAPSHOT_SET = [
    (EXPORT_DIR, "research/ios-rust-export/"),  # full export of HEAD (re-archived below)
    (BUNDLE_PATH, "research/ios-rust-repo-backup.bundle"),
]


def client():
    return boto3.client(
        "s3",
        endpoint_url=ENDPOINT,
        region_name=REGION,
        aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY"),
    )


def split_target(target):
    bucket, _, prefix = target.partition("/")
    return bucket, prefix.strip("/")


def md5_file(path, chunk=1024 * 1024):
    h = hashlib.md5()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(chunk), b""):
            h.update(b)
    return h.hexdigest()


def upload_file(c, local, bucket, key):
    size = os.path.getsize(local)
    print(f"  put {local}  ({size / MB:.1f} MB)" if (MB := 1024 * 1024) else "")
    c.upload_file(str(local), bucket, key, Config=CFG)


def upload_dir(c, local_dir, bucket, prefix):
    base = Path(local_dir)
    n = 0
    for p in sorted(base.rglob("*")):
        if p.is_file():
            key = f"{prefix}/{p.relative_to(base)}"
            upload_file(c, p, bucket, key)
            n += 1
    print(f"  = {n} files -> s3://{bucket}/{prefix}/")


def cmd_buckets(c, _):
    for b in c.list_buckets().get("Buckets", []):
        print(b["Name"])


def cmd_create(c, args):
    bucket = args[0]
    kwargs = {"CreateBucketConfiguration": {"LocationConstraint": REGION}} if REGION not in ("us-east-1", "") else {}
    c.create_bucket(Bucket=bucket, **kwargs)
    print(f"created s3://{bucket}")


def cmd_ls(c, args):
    bucket, prefix = split_target(args[0])
    kw = {"Bucket": bucket, "Prefix": prefix}
    total = 0
    while True:
        r = c.list_objects_v2(**kw)
        for o in r.get("Contents", []):
            total += o["Size"]
            print(f"{o['Size']:>12}  s3://{bucket}/{o['Key']}")
        if not r.get("IsTruncated"):
            break
        kw["ContinuationToken"] = r["NextContinuationToken"]
    print(f"-- {total / (1024 * 1024):.1f} MB total")


def cmd_put(c, args):
    local, target = args
    bucket, key = split_target(target)
    p = Path(local)
    if p.is_dir():
        upload_dir(c, p, bucket, key.rstrip("/"))
    else:
        upload_file(c, p, bucket, key)


def cmd_get(c, args):
    key, dest = args
    bucket, key = split_target(key)
    c.download_file(bucket, key, dest, Config=CFG)
    print(f"got s3://{bucket}/{key} -> {dest}")


def cmd_sync(c, args):
    local_dir, target = args
    bucket, prefix = split_target(target)
    have = {}
    kw = {"Bucket": bucket, "Prefix": prefix}
    while True:
        r = c.list_objects_v2(**kw)
        for o in r.get("Contents", []):
            have[o["Key"]] = o["Size"]
        if not r.get("IsTruncated"):
            break
        kw["ContinuationToken"] = r["NextContinuationToken"]
    base = Path(local_dir)
    sent = skipped = 0
    for p in sorted(base.rglob("*")):
        if not p.is_file():
            continue
        key = f"{prefix}/{p.relative_to(base)}"
        if have.get(key) == p.stat().st_size:
            skipped += 1
            continue
        upload_file(c, p, bucket, key)
        sent += 1
    print(f"sync done: {sent} uploaded, {skipped} skipped (identical)")


def cmd_snapshot(c, args):
    bucket = args[0] if args else "ios-rust"
    repo = Path(REPO_DIR)
    export = Path(EXPORT_DIR)
    if repo.exists():
        head = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                              capture_output=True, text=True).stdout.strip()
        subj = subprocess.run(["git", "-C", str(repo), "log", "-1", "--format=%s"],
                              capture_output=True, text=True).stdout.strip()
        # 1. re-archive the committed tree of HEAD (always current, never stale)
        if export.exists():
            shutil.rmtree(export)
        export.mkdir(parents=True)
        archive = subprocess.run(["git", "-C", str(repo), "archive", "HEAD"],
                                 capture_output=True, check=True).stdout
        with tarfile.open(fileobj=io.BytesIO(archive)) as tf:
            tf.extractall(export)
        (export / ".commit").write_text(head + "\n")
        (export / "MANIFEST.txt").write_text(
            "ios-rust full source export — generated by tools/s3_backup.py snapshot\n"
            f"HEAD: {head}\nsubject: {subj}\n"
            "files: committed tree of HEAD (+ .commit, MANIFEST.txt); fixtures NOT included\n"
            "history: git clone <this bucket>/ios-rust-repo-backup.bundle ios-rust\n")
        print(f"HEAD = {head} — export re-archived from git archive")
        # 2. refresh the full-history bundle
        subprocess.run(["git", "-C", str(repo), "bundle", "create", str(BUNDLE_PATH), "--all"], check=True)
        print(f"bundle refreshed: {Path(BUNDLE_PATH).stat().st_size / (1024 * 1024):.1f} MB")
    for local, key in SNAPSHOT_SET:
        p = Path(local)
        if p.is_dir():
            upload_dir(c, p, bucket, key.rstrip("/"))
        elif p.exists():
            upload_file(c, p, bucket, key)
        else:
            print(f"  SKIP (missing) {local}")
    # 3. research + toolkit trees (under research/ to match the bucket INDEX)
    for extra, prefix in [("/home/z/work/ios-re-toolkit", "research/ios-re-toolkit"),
                          ("/home/z/work/ios-research/research-docs", "research/research-docs")]:
        if Path(extra).exists():
            upload_dir(c, extra, bucket, prefix)
        else:
            print(f"  SKIP (missing) {extra}")


CMDS = {
    "buckets": (cmd_buckets, 0),
    "create": (cmd_create, 1),
    "ls": (cmd_ls, 1),
    "put": (cmd_put, 2),
    "get": (cmd_get, 2),
    "sync": (cmd_sync, 2),
    "snapshot": (cmd_snapshot, 0),
}


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in CMDS:
        print(__doc__)
        sys.exit(1)
    fn, nargs = CMDS[sys.argv[1]]
    args = sys.argv[2:]
    if len(args) < nargs:
        print(__doc__)
        sys.exit(f"need {nargs} args for {sys.argv[1]}")
    fn(client(), args)


if __name__ == "__main__":
    main()
