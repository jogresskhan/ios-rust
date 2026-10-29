#!/usr/bin/env python3
"""Full top-byte-space census with step=1 — the definitive masks (session C).

Brute-forces complete 0xNN000000..0xNNFF0000+ spaces through capstone and
records EVERY (mnemonic -> mask/value) pair. Nothing is hand bit-split;
each mask/value is the intersection of all words capstone decodes as that
mnemonic within the space. Parallel across spaces."""
import sys, json, os
from concurrent.futures import ProcessPoolExecutor
sys.path.insert(0, os.path.dirname(__file__))
import mask_discover as MD

SPACES = [
    (0x0E000000, 0x0F000000),  # SIMD three-same + 2-reg-misc + reduce + ext/dup/ins
    (0x2E000000, 0x2F000000),
    (0x4E000000, 0x4F000000),
    (0x6E000000, 0x6F000000),
    (0x0C000000, 0x0E000000),  # ld/st multiple + single-structure
    (0x3C000000, 0x3E000000),  # SIMD ld/st: imm + regoff + unscaled (Q arms)
    (0xBC000000, 0xBD000000),  # SIMD ld/st regoff S arm
    (0xFC000000, 0xFD000000),  # SIMD ld/st regoff D arm
    (0x7C000000, 0x7D000000),  # SIMD ld/st H arms
    (0x1E000000, 0x1F000000),  # scalar FP S+D
    (0x5E000000, 0x5F000000),
    (0x7E000000, 0x7F000000),
    (0x9E000000, 0x9F000000),
    (0xD9000000, 0xDA000000),  # STLUR/LDAPUR 64
    (0x19000000, 0x1A000000),  # STLURB/STLURH/LDAPURB
    (0x99000000, 0x9A000000),  # LDAPUR 32
    (0xD6000000, 0xD6800000),  # PAC branch Z/0xD6 space
    (0x9C000000, 0x9D000000),  # LDR literal SIMD Q
    (0x5C000000, 0x5D000000),
    (0x1C000000, 0x1D000000),
]


def work(spec):
    lo, hi = spec
    hits = {}
    for w in range(lo, hi, 1):
        m = MD.decode(w)
        if m is not None:
            hits.setdefault(m, []).append(w)
    return (lo, hi, MD.masks(hits))


def main():
    out = {}
    with ProcessPoolExecutor(max_workers=10) as ex:
        for lo, hi, res in ex.map(work, SPACES):
            label = f"{lo:08x}_{hi:08x}"
            out[label] = {m: {"mask": mask, "val": val, "n": n}
                          for m, (val, mask, n) in res.items()}
            print(f"{label}: {len(res)} mnemonics", flush=True)
    json.dump(out, open("tools/re/oracle/m1close_full.json", "w"), indent=0)
    print("saved -> tools/re/oracle/m1close_full.json", flush=True)


if __name__ == "__main__":
    main()
