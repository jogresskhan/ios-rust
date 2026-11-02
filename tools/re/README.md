# ios-rust RE toolkit — the reverse-engineering playbook

**Read this first (any human or AI session).** This directory is the
self-contained reverse-engineering stack for the ios-rust project: how we
pull Apple binaries apart, how we decode them, how we find and fix the
a13-cpu gaps, and how we decompile with Ghidra. Everything here was used to
take the real iOS 14.3 (18C66) T8030 kernel from **90.5% → 98.6%**
decode/exec coverage in one session (PARITY.md Layer 2.11a) — the loop
below is proven, not aspirational.

Golden rules:

* **Never hand-split instruction bits.** Derive encodings with the oracle
  (`oracle/`) — capstone/keystone are ground truth. Every hand-derived
  field guess in the 2026-10 sessions was wrong at least once.
* **Real bytes only.** Fix bugs found by real fixtures (`fixtures/`),
  then record the finding in PARITY.md ("real-data bug #N").
* **Re-measure after every change** with the coverage probe, and commit
  scripts + findings so the next session inherits them.

## 0. Environment setup (one time)

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
pip3 install capstone keystone-engine          # the decode oracle
# Ghidra (JDK 21+ required; java -version to check):
mkdir -p ~/ghidra && cd ~/ghidra
curl -sL -o ghidra.zip https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.3.1_build/ghidra_11.3.1_PUBLIC_20250219.zip
unzip -q ghidra.zip && rm ghidra.zip
# sanity: ~/ghidra/ghidra_*/support/analyzeHeadless exists
```

Verify: `python3 -c "import capstone, keystone; print('oracle ok')"`.

## 1. Real fixtures — Apple CDN, range requests only

Never download a 5+ GB IPSW. Stream members over HTTP Range:

```bash
# iOS 14.3 (18C66) T8030 (iPhone 11) — the session-2026-10-A fixture set:
python3 tools/re/extraction/ipsw_range.py \
  "https://updates.cdn-apple.com/2020WinterFCS/fullrestores/001-87267/C892DBD9-83E0-4538-95A8-5E9E45C4F095/iPhone11,8,iPhone12,1_14.3_18C66_Restore.ipsw" \
  fixtures "kernelcache.release.iphone12b$" "DeviceTree.n104ap" "BuildManifest"
# NOTE: the combined IPSW also ships kernelcache.release.iphone11b (A12/XR)
# and kernelcache.research.iphone12b — the "$" anchor picks the A13 release
# cache. Fixtures land in ./fixtures/ (gitignored) and boot-full auto-finds
# them, or set IOS_RUST_FIXTURES=$PWD/fixtures.
```

Quick triage of what you pulled:

```bash
ios-rust kc info fixtures/kernelcache.release.iphone12b   # LZFSE decode, version, kexts
ios-rust devices ipsw-me iPhone12,1                        # which builds exist
python3 tools/re/macho/macho_inspect.py <bin> --verify     # Mach-O triage + codesign check
```

## 2. How we decode (the pipeline, end to end)

```
IPSW (zip)  --range-req-->  kernelcache.release.iphone12b (IM4P, LZFSE)
   --img4::im4p::Im4p::parse-->  DER unwrap   (iOS 14-era containers are DER)
   --kernelcache::decompress--> 45.7 MB Mach-O kernel collection
   --kernelcache::sections-->   segment/section map (__TEXT_EXEC.__text …)
   --a13_cpu::decode(pc, w)-->  Insn — the pure-Rust A13 decoder (the thing
                                 we measure and fix)
   --a13_cpu::interp-->         execution (the emulator)
```

Honest-coverage measurement (run after EVERY decoder change):

```bash
cd tools/re/coverage-probe && cargo build --release
./target/release/ios-rust-coverage-probe ../../fixtures/kernelcache.release.iphone12b
# decode sweep: 7854241/7966342 decodable = 98.59%  (the headline number)
# exec probe:   single-insn execution of 20k sampled real instructions
./target/release/hist ../../fixtures/kernelcache.release.iphone12b
# histogram of unimplemented classes by top-8-bit bucket — the worklist
./target/release/dbg 0x2a0b014a 0xd65f0bff      # what does OUR decoder say?
python3 -c "import capstone; ..."               # what does the oracle say?
```

`unknown words` split into (a) literal pools / jump tables (runs ≥ 16 words
— data, not instructions), and (b) genuinely unimplemented instruction
classes. Fix (b) top-down by real-byte count.

## 3. The gap-fix loop (how the 90.5 → 98.6 session worked)

1. **Find the biggest unknown class** — `hist` bucket counts, then
   capstone-decode 2–3 example words per bucket to name the mnemonic:

   ```python
   import capstone
   md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
   for w in [0xd73f0909, 0xd4388e20, 0xf85f82c1]:
       i = next(md.disasm(w.to_bytes(4, 'little'), 0)); print(i.mnemonic, i.op_str)
   ```

2. **Derive exact masks with the mask tool** (brute-force the encoding
   space through capstone, intersect fixed bits):

   ```bash
   python3 tools/re/oracle/mask_discover.py --words 0xd65f0bff,0xd65f0fff
   python3 tools/re/oracle/mask_discover.py --range 0xd6000000:0xd8000000 \
       --want braa,brab,blraa,blrab,drps
   # → "braa if (w & 0xFFFFFC00) == 0xD71F0800" — paste into decode.rs
   ```

   Gotchas learned the hard way: a 4-aligned scan misses encodings whose
   low bits are part of the opcode (RETAA = 0xd65f0bff is NOT 4-aligned —
   use `--range` with step=1 via the module import); SIMD single-LS width
   rule is `load = opc&1`, `16B iff opc bit1 && size==0 else 1<<size`.

3. **Assemble ground truth with keystone** (`oracle/insn_oracle.py
   --fuzz RETAA BLRAA …`). Keystone's ARM64 does NOT know all pointer-auth
   mnemonics (`retaa` fails) — for those, hand-encode a candidate and
   verify with capstone *disassembly* instead.

4. **Implement** in `crates/a13-cpu/src/decode.rs` (+ `interp.rs` exec),
   add the keystone/capstone words as `gap_*` golden tests (see the
   existing `gap_pac_branch_family`, `gap_pairs_gpr_and_simd`, … tests —
   test expectations come from capstone output, never from mental
   bit-splitting).

5. **Re-measure** (`coverage-probe`), update PARITY.md + parity.json,
   commit. Never claim a percentage you did not just measure.

Closed this way in 2026-10 (real-14.3 counts): PAC-branch family
`RETAA/RETAB/BRAA/BRAB/BLRAA/BLRAB` (~212k words), exception class
`BRK/DCPS1-3/DRPS` (~170k), pre/post-index + unscaled GPR load/store
incl. `LDTR/STTR`, signed loads `LDRSB/SH/SW` (~190k), STP/LDP fixes +
SIMD pairs S/D/Q + `LDPSW` (~40k), SIMD single LS 9-bit/unsigned
(~15k), register-offset load/store with extend/shift (~20k),
add/sub-extended register (~10k), `LSLV/LSRV/ASRV/RORV` (~5k), and the
MOV-alias fall-through decoder bug (`orr w10,w10,w11` decoded as None).
Remaining honest gaps: SIMD three-same arithmetic (`0x4e`), SIMD
bitwise/shift immediate (`0x6f/0x4f`), scalar FP (`0x1e`), plus ~51k
words of literal pools (data).

## 4. Ghidra headless decompilation

Full recipe + battle scars: `tools/re/ghidra/headless-recipe.md`.
Proven working in THIS sandbox (2026-10 session):

```bash
# Ghidra 11.3.1 unzipped at ~/ghidra/ghidra_11.3.1_PUBLIC (450 MB zip, size-gated).
# Headless needs a FULL JDK (javac) — the sandbox JRE is not enough:
mkdir -p ~/jdk && cd ~/jdk
curl -sL -o jdk.tar.gz "https://api.adoptium.net/v3/binary/latest/21/ga/linux/x64/jdk/hotspot/normal/eclipse"
tar xzf jdk.tar.gz && export JAVA_HOME=~/jdk/jdk-21.0.13+9

# Stock language id is AARCH64:LE:64:v8A (NOT ...:ARMv8ARdefault and NOT
# Aleph's AppleArmv8k — that one needs the xnu-qemu-arm64-tools extension,
# https://github.com/alephsecurity/xnu-qemu-arm64-tools, which the
# ios-re-toolkit CI installs; stock v8A decompiles fine, PAC insns may
# land as unnamed aliases).
GHIDRA=~/ghidra/ghidra_11.3.1_PUBLIC/support/analyzeHeadless
mkdir -p /tmp/ghproj
"$GHIDRA" /tmp/ghproj proj -import <binary> \
  -processor AARCH64:LE:64:v8A \
  -scriptPath tools/re/ghidra -postScript ExportDecompiled.java /tmp/dec \
  -deleteProject
test "$(ls /tmp/dec/*.c | wc -l)" -gt 0   # 0 functions = false success
```

* Use Aleph's `AARCH64:LE:AppleArmv8k:applearm64k` when the extension is
  installed — it decodes `pacibsp`/`retab`/`pacia` by name (the exact
  instruction families a13-cpu implements).
* Use `TraceColor.java` to paint a QEMU/Inferno execution trace onto the
  decompiled program — bridges dynamic evidence and static C.
* Restore-ramdisk binaries are local-symbol-stripped: grep the decompiled C
  by string constants, not function names (`adr_string_scan.py` finds the
  ADR-style xrefs Apple's single-`adr` codegen produces).

## 5. Tool map

| path | what |
|---|---|
| `oracle/insn_oracle.py` | keystone assemble → capstone decode; `--fuzz` enumerates register encodings of a mnemonic |
| `oracle/mask_discover.py` | brute-force encoding space → fixed-bit mask/value pairs for decode.rs |
| `coverage-probe/` | standalone cargo bin: decode sweep + exec probe + class histogram + word dbg against the real kernelcache |
| `ghidra/ghidra-headless.sh` | bulletproof analyzeHeadless wrapper (pin-URL, size gate, false-green check) |
| `ghidra/ExportDecompiled.java` | per-function decompiled-C export |
| `ghidra/TraceColor.java` | color a program from an execution trace |
| `ghidra/headless-recipe.md` | the proven CI recipe + restored_external anchors |
| `macho/macho_inspect.py` | Mach-O triage, chained-fixups imports, codesign page-hash verify |
| `macho/adr_string_scan.py` | string → ADR/ADRP xref → function map (restored decoder) |
| `extraction/ipsw_range.py` | stream IPSW members over HTTP Range |
| `extraction/extract-ramdisk-userland.py` | restore-ramdisk IPSW → valid arm64 Mach-O binaries, keylessly |
| `extraction/hfsx_extract.py` / `hfsx_mem.py` | HFSX/HFS+ volume reader (catalog B-tree walk, decmpfs) |
| `codesign-verify.py` | standalone ad-hoc CodeDirectory verifier |
| `findings/` | written evidence: restored_external failure path + decomp notes |

Provenance: `ghidra/`, `macho/`, `extraction/`, `codesign-verify.py`,
`findings/` are copied from 20kiwy/ios-re-toolkit (the campaign's own
toolkit repo); `oracle/` + `coverage-probe/` were built for the a13-cpu
gap-fix sessions and are new here. Both stacks are stdlib-only or
capstone/keystone-only.

## 6. Session handoff checklist (do this before you stop)

1. All new scripts committed under `tools/re/` (they are the next
   session's muscle memory).
2. New `gap_*` golden tests green: `cargo test -p a13-cpu`.
3. Fresh coverage numbers recorded in PARITY.md + parity.json
   (`decode sweep %`, top remaining classes with counts).
4. Real-data findings (bugs the fixtures exposed) written into
   PARITY.md — numbered, with the fixture that exposed them.
5. **Back up to S3 — the second mirror.** The GitHub mirror is live again
   (jogresskhan/ios-rust; the old 20kiwy account stayed suspended) — push
   there AND to the IDrive e2 vault:

   ```bash
   source ~/.config/ios-rust/s3.env        # endpoint/region/keys (NOT in the repo)
   python3 tools/s3_backup.py snapshot ios-research-vault
   # → re-archives HEAD into the export tree, refreshes the git bundle,
   #   and uploads: ios-rust-export/, bundle, ios-re-toolkit/, research-docs/,
   #   verdicts/ios-rust-latest.json, INDEX-latest.md
   ```

   Bucket layout is self-describing: read `research/INDEX-latest.md` first.
   `git clone <bundle>` restores the repo with full history.
