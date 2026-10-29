#!/usr/bin/env python3
"""unknown_census.py — capstone ground-truth census of the words OUR decoder
rejects. Groups by (top-byte, mnemonic), intersects fixed bits, validates
every rule against the full unknown set, prints a ranked work list.

Input: (index:u32, word:u32) LE pairs from coverage-probe's unkdump bin.
"""
import sys, struct, collections
import capstone

def load_pairs(path):
    data = open(path, "rb").read()
    n = len(data) // 8
    return [struct.unpack_from("<II", data, i * 8) for i in range(n)]

def main():
    pairs = load_pairs(sys.argv[1])
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)

    groups = collections.defaultdict(list)   # (top, mnem) -> [(idx, w)]
    invalid = collections.Counter()          # capstone can't decode either
    for idx, w in pairs:
        try:
            i = next(md.disasm(w.to_bytes(4, "little"), 0))
            groups[(w >> 24, i.mnemonic)].append((idx, w))
        except StopIteration:
            invalid[w >> 24] += 1

    print(f"unknown words: {len(pairs)}  capstone-invalid: {sum(invalid.values())}")
    if invalid:
        print("  invalid by top byte:", dict(invalid.most_common(12)))

    # per (top, mnem): intersect masks over words
    rows = []
    for (top, mnem), ws in groups.items():
        mask = 0xFFFF_FFFF
        val = ws[0][1]
        for _, w in ws[1:]:
            diff = (w ^ val) & mask
            mask &= ~diff & 0xFFFF_FFFF
        rows.append((len(ws), top, mnem, mask, val & mask, ws))

    rows.sort(reverse=True, key=lambda r: r[0])
    print(f"\n{'count':>7} {'top':>4} {'mnemonic':<22} {'mask':>10} {'value':>10}  rule-ok?")
    total_named = 0
    for cnt, top, mnem, mask, val, ws in rows[:60]:
        # validate: every word matching (mask,val) in the whole unknown set
        hit = ok = 0
        for _, w in pairs:
            if (w & mask) == val:
                hit += 1
                try:
                    i = next(md.disasm(w.to_bytes(4, "little"), 0))
                    if i.mnemonic == mnem:
                        ok += 1
                except StopIteration:
                    pass
        total_named += cnt
        print(f"{cnt:>7} {top:04x} {mnem:<22} {mask:08x} {val:08x}  {ok}/{hit}")
    print(f"\ntop-60 groups cover {total_named} words")
    print(f"named-by-capstone total: {len(pairs) - sum(invalid.values())}")

if __name__ == "__main__":
    main()
