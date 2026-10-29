#!/usr/bin/env bash
# ghidra-headless.sh — bulletproof wrapper for Ghidra headless decompilation.
#
# Battle scars from ios-sweet-rust CI (re-restore-ramdisk, runs 40608042694 /
# 40608877380 / 40609705374, 2026-10-28):
#   * the 'ghidra' Homebrew cask VANISHED on macos-26 → pin a verified release
#     URL and fall back to the GitHub releases API
#   * analyzeHeadless does NOT create the project directory → we mkdir it
#   * runners with setup-java need GHIDRA_JAVA_HOME honored
#   * a "successful" run can export 0 functions (false green) → hard-fail
#
# Usage:
#   ghidra-headless.sh BIN [BIN...] OUTDIR
#     BIN   : arm64 Mach-O files to decompile
#     OUTDIR: per-function C files land as OUTDIR/<binname>/<func>.c
#
# Env:
#   GHIDRA_VERSION   (default 11.3.1)
#   ANALYSIS_TIMEOUT (per file, seconds; default 900)
set -uo pipefail

GHIDRA_VERSION="${GHIDRA_VERSION:-11.3.1}"
ANALYSIS_TIMEOUT="${ANALYSIS_TIMEOUT:-900}"
TMP="${RUNNER_TEMP:-/tmp}"

die() { echo "FATAL: $*" >&2; exit 1; }
[ $# -ge 2 ] || die "usage: ghidra-headless.sh BIN [BIN...] OUTDIR"
OUTDIR="${@: -1}"; BINS=("${@:1:$#-1}")
mkdir -p "$OUTDIR" || die "cannot create $OUTDIR"

# ---------- locate / install Ghidra ----------
GHIDRA="$(find /opt/homebrew/Caskroom/ghidra /usr/local/Caskroom/ghidra /opt/ghidra -name analyzeHeadless 2>/dev/null | head -1 || true)"
if [ -z "$GHIDRA" ]; then
  echo "[ghidra] not found — installing ${GHIDRA_VERSION}"
  URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_20250716.zip"
  if ! curl -sfIL "$URL" >/dev/null 2>&1; then
    echo "[ghidra] pinned URL failed, asking releases API for latest"
    URL=$(curl -s https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest \
      | python3 -c "import json,sys; [print(a['browser_download_url']) for a in json.load(sys.stdin)['assets'] if a['name'].endswith('_PUBLIC.zip')]" | head -1)
    [ -n "$URL" ] || die "no Ghidra release zip found"
  fi
  curl -sL "$URL" -o "$TMP/ghidra.zip" || die "download failed"
  SIZE=$(stat -f%z "$TMP/ghidra.zip" 2>/dev/null || stat -c%s "$TMP/ghidra.zip")
  [ "$SIZE" -gt 300000000 ] || die "ghidra.zip too small ($SIZE B) — download broken"
  unzip -q "$TMP/ghidra.zip" -d "$TMP/gh"
  GHIDRA=$(find "$TMP/gh" -name analyzeHeadless | head -1)
fi
echo "[ghidra] using: $GHIDRA"

# ---------- Java ----------
if [ -n "${GHIDRA_JAVA_HOME:-}" ]; then
  export JAVA_HOME="$GHIDRA_JAVA_HOME"
  export PATH="$JAVA_HOME/bin:$PATH"
fi
java -version 2>&1 | head -1 || die "Java not available (Ghidra needs 21+)"

# ---------- project dir ----------
PROJDIR="$TMP/ghproj-$$"
mkdir -p "$PROJDIR" || die "cannot create project dir (analyzeHeadless will NOT create it)"

# ---------- decompile each binary ----------
SCRIPTDIR="$(cd "$(dirname "$0")" && pwd)"
fail=0
for B in "${BINS[@]}"; do
  [ -f "$B" ] || { echo "[skip] $B not a file"; continue; }
  N=$(basename "$B")
  echo "=== decompiling $N ==="
  "$GHIDRA" "$PROJDIR" "proj-$N" -import "$B" -overwrite \
    -analysisTimeoutPerFile "$ANALYSIS_TIMEOUT" \
    -scriptPath "$SCRIPTDIR" \
    -postScript ExportDecompiled.java "$OUTDIR/$N" \
    > "$TMP/ghidra-$N.log" 2>&1 \
    || echo "[warn] ghidra nonzero exit for $N (log: $TMP/ghidra-$N.log)"
  tail -5 "$TMP/ghidra-$N.log" || true
  CNT=$(find "$OUTDIR/$N" -name "*.c" 2>/dev/null | wc -l | tr -d ' ')
  echo "[result] $N: $CNT functions decompiled"
  [ "$CNT" -eq 0 ] && fail=1
done

[ "$fail" -eq 0 ] || die "at least one binary decompiled to 0 functions (false-success guard)"
echo "[done] all outputs in $OUTDIR"
