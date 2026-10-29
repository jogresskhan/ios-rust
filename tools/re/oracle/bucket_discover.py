#!/usr/bin/env python3
"""bucket_discover.py — derive (mask, value) decode rules for a bucket of REAL
kernel words, using capstone as ground truth.

Given a top-8-bit bucket (e.g. 0x5a) and the real kernelcache, this tool:
  1. sweeps __TEXT_EXEC.__text for words in the bucket,
  2. decodes each with capstone (the oracle),
  3. groups words by mnemonic and intersects the fixed bits,
  4. VALIDATES each rule: every word matching (mask,value) must decode to the
     same mnemonic (and prints the reject count — must be 0),
  5. emits paste-ready Rust guards: `if w & 0xMASK == 0xVALUE -> mnemonic`.

Usage:
    python3 tools/re/oracle/bucket_discover.py <kernelcache> 0x5a [min_count]
Requires: capstone, the kernelcache crate's LZFSE path is NOT needed — the
sweep runs on the DECOMPRESSED image (use `ios-rust kc info` / coverage-probe
to dump it, or pass a raw decompressed image with --decompressed).
"""
import sys
import collections

try:
    import capstone
except ImportError:
    sys.exit("pip3 install capstone")

TOP = 0xFF00_0000


def bucket_words(img: bytes, bucket: int):
    n = len(img) // 4
    words = memoryview(img).cast("I")
    out = []
    for i in range(n):
        w = words[i]
        if (w & TOP) == bucket:
            out.append(w)
    return out


def derive(rules: dict, examples: dict):
    """Intersect fixed bits per mnemonic."""
    for mn, words in examples.items():
        mask = 0xFFFF_FFFF
        val = words[0]
        for w in words[1:]:
            diff = (w ^ val) & mask
            mask &= ~diff & 0xFFFF_FFFF
        rules[mn] = (mask, val & mask)


def validate(img_words, rules, md):
    """Every word matching (mask,value) must capstone-decode to that mnemonic."""
    report = {}
    for mn, (mask, val) in rules.items():
        hit = ok = 0
        for w in img_words:
            if (w & mask) == val:
                hit += 1
                try:
                    i = next(md.disasm(w.to_bytes(4, "little"), 0))
                    if i.mnemonic == mn:
                        ok += 1
                except StopIteration:
                    pass
        report[mn] = (hit, ok, hit - ok)
    return report


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    path, bucket = sys.argv[1], int(sys.argv[2], 0) << 24  # top-8-bit bucket
    min_count = int(sys.argv[3]) if len(sys.argv) > 3 else 16
    img = open(path, "rb").read()
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)

    print(f"collecting bucket {bucket:#04x} words …", file=sys.stderr)
    words = bucket_words(img, bucket)
    print(f"bucket words: {len(words)}", file=sys.stderr)

    examples = collections.defaultdict(list)
    for w in words:
        try:
            i = next(md.disasm(w.to_bytes(4, "little"), 0))
            examples[i.mnemonic].append(w)
        except StopIteration:
            pass

    rules = {}
    derive(rules, examples)
    # drop tiny/ambiguous rules
    rules = {m: r for m, r in rules.items() if len(examples[m]) >= min_count}

    print(f"\n# bucket {bucket:#04x} — {len(rules)} rules (min {min_count} words each)")
    total = 0
    for mn, (mask, val) in sorted(rules.items(), key=lambda kv: -len(examples[kv[0]])):
        n = len(examples[mn])
        total += n
        print(f"# {mn:<10} ~{n:>6} words   if (w & 0x{mask:08X}) == 0x{val:08X}")
    print(f"# covered by rules: {total}/{len(words)}")

    print("\n# validation (hit / capstone-ok / reject):")
    rep = validate(words, rules, md)
    bad = 0
    for mn, (hit, ok, rej) in sorted(rep.items()):
        if rej:
            bad += rej
            print(f"#  REJECT {mn}: {hit} hits, {ok} ok, {rej} rejected")
    print(f"# total rejects: {bad}  (must be 0 before pasting into decode.rs)")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
