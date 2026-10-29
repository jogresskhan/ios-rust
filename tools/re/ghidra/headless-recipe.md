# Ghidra headless decompilation — the exact working recipe

Proven in CI: `re-restore-ramdisk` run 40609705374 (macOS runner, Ghidra 11.3.1)
— 2,748 functions decompiled from `restored_external` / `asr` / `keystorectl`
/ `restored_update` / `configdarwinbootargs` with zero interaction.

## 1. Install (macOS runner)

The `ghidra` Homebrew cask disappeared on `macos-26` — do NOT use brew.
Pin a verified release URL and check the zip size before trusting it
(a truncated 302-followed download once produced a "successful" run with
0 decompiled functions):

```bash
GHIDRA_URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.3.1_build/ghidra_11.3.1_PUBLIC_20250219.zip"
curl -L "$GHIDRA_URL" -o ghidra.zip
unzip -q ghidra.zip -d "$RUNNER_TEMP/ghidra"
```

Java: Ghidra 11.3.x needs JDK 21+. On GitHub Actions use `actions/setup-java`
and point Ghidra at it:

```yaml
- uses: actions/setup-java@v4
  with: { distribution: temurin, java-version: '21' }
- run: echo "GHIDRA_JAVA_HOME=$JAVA_HOME" >> "$GITHUB_ENV"
```

## 2. Analyze + export decompiled C

`analyzeHeadless` does NOT create the project directory — mkdir it yourself.
Hard-fail when 0 functions come back (that is the false-success signature):

```bash
mkdir -p "$RUNNER_TEMP/ghproj"
"$GHIDRA/analyzeHeadless" "$RUNNER_TEMP/ghproj" proj \
  -import "$BIN" \
  -processor AARCH64:LE:AppleArmv8k:applearm64k \
  -scriptPath tools \
  -postScript ExportDecompiled.java "$OUTDIR" \
  -deleteProject
# sanity gate:
test "$(ls -1 "$OUTDIR"/*.c 2>/dev/null | wc -l)" -gt 0 || { echo "0 functions"; exit 1; }
```

Notes learned the hard way:
* `-processor` matters for Apple kernel/userland Mach-O; without it the
  auto-detect occasionally lands on a generic ARM variant and PA-BI/PAC
  instructions (`pacibsp`, `retab`, `pacia`) confuse the disassembler.
* iOS restore-ramdisk binaries have **local symbols stripped** but keep
  imports; function names in the export come mostly from the entry chain,
  so grep decompiled C by string constants, not by function name.
* The `-deleteProject` flag keeps runners from ballooning; the analysis
  is cheap to redo.

## 3. Where to look in restored_external (the failure path)

Known-good anchors (verified by `ios/macho/adr_string_scan.py` and the
decompiled export from run 40609705374):

| anchor | address | meaning |
|---|---|---|
| `entry` | `0x10000d360` | Mach-O entry; forks monitor/(-server) engine split |
| `waiting for host to trigger start of restore [no timeout]` | xref `0x10000dd0c` | engine wait loop entered |
| `error waiting for events: %s\n` | xref `0x10000dfa0` | kevent returned non-zero → engine failure |
| `restore-outcome` | string `0x1000725fc` | plist key for the failure verdict |
| `handle_new_connections` | checkpoint notice | the 0x0104 checkpoint chassis |

Search the exported C for `error waiting for events` and walk outward —
that function is `handle_new_connections`; its timeout branch is the
`initial_engine_failure_no_return` reboot loop.

## 4. Trace coloring (QEMU execution traces)

`TraceColor.java` colors the address space of a Ghidra program from a QEMU
execution trace — same idea as AlephSecurity's `ColorAddress.java` from
xnu-qemu-arm64-tools, but it accepts BOTH the aleph format and a plain
one-hex-address-per-line format:

```bash
"$GHIDRA/analyzeHeadless" "$RUNNER_TEMP/ghproj" proj \
  -process restored_external -noanalysis \
  -scriptPath tools -postScript TraceColor.java "$TRACE.txt" "$OUT.png.html"
```

Point the Inferno emulator's `-d exec` tracing at it and you get a heat-map
of which decompiled functions the real kernel/restored actually executed —
the fastest way to bridge static decompilation and dynamic QEMU evidence.
