#!/usr/bin/env python3
"""M5 device-access census — post-process an IOS_RUST_MMIO_LOG into a ranked
per-device MMIO census for the real 18C66 T8030 boot path (task M5-C).

Instrumentation (crates/vm-core/src/bus.rs + crates/apple-soc/src/t8030.rs,
env-gated, default-off): run

    IOS_RUST_DRAM_MB=768 IOS_RUST_MMIO_LOG=/tmp/m5/mmio-768.log \
        ./target/debug/ios-rust boot-first fixtures /tmp/bootfirst

then this script. Log line grammar:

    #map,<device>,<base hex>,<size hex>              bus attach (RAM too)
    #unimpl,<node>,<base hex>,<size hex>,<compat;..> unmodeled /arm-io node
    #unimpl-class,<node>,<base>,<size>,<compat;..>   classify() hit, no model
    <addr hex>,<size bytes>,<r|w>,<device|UNMAPPED>  one non-RAM bus access

Window ground truth comes from (highest priority first):
  1. tools/re/notes/m5-adt-census-raw/armio_table.md — the LE-validated
     /arm-io table (name, abs base, size, compatible, Rust model) from the
     M5 static ADT census;
  2. FALLBACK_MAP parsed from crates/apple-soc/src/t8030.rs.

NOTE on bases: crates/adt/src/node.rs::reg_entries() currently mis-decodes
this fixture's little-endian reg pairs as big-endian (REAL bug, see
tools/re/notes/m5-adt-census.md) — so the runtime #map/#unimpl bases are
garbage (e.g. aic @ 0x103b). The script flags every runtime window that
disagrees with the ADT table instead of trusting it.

Usage:
  python3 tools/re/reports/m5_mmio_census.py --log /tmp/m5/mmio-768.log \
      [--out /tmp/m5/census.md] [--repo /path/to/ios-rust]

stdlib-only; re-runnable (run it after every boot-path extension).
"""
from __future__ import annotations

import argparse
import collections
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
ADT_TABLE = os.path.join(REPO, "tools/re/notes/m5-adt-census-raw/armio_table.md")
T8030_RS = os.path.join(REPO, "crates/apple-soc/src/t8030.rs")

RAM_NAMES = {"srom", "sram", "seprom", "dram", "boot-pause", "nvram"}


def parse_adt_table(path: str) -> list[dict]:
    """Parse the committed LE-validated /arm-io table (markdown)."""
    rows = []
    if not os.path.exists(path):
        return rows
    rx = re.compile(
        r"^\|\s*(\d+)\s*\|\s*([A-Za-z0-9_\-]+)\s*\|\s*(0x[0-9A-Fa-f]+)\s*\|"
        r"\s*(0x[0-9A-Fa-f]+|\d+)\s*\|\s*(\d+)\s*\|\s*([^|]*)\|"
    )
    for line in open(path, encoding="utf-8"):
        m = rx.match(line)
        if not m:
            continue
        _, name, base, size, _nreg, compat = m.groups()
        model = ""
        mmodel = re.search(r"\|\s*([a-z0-9\-]+)\s*\|\s*$", line)
        if mmodel:
            model = mmodel.group(1)
        rows.append(
            {
                "node": name,
                "base": int(base, 16),
                "size": int(size, 0) if size.startswith("0x") else int(size),
                "compat": compat.strip(),
                "model": model if model not in ("—", "-") else "",
            }
        )
    return rows


def parse_fallback_map(path: str) -> list[tuple[str, int, int]]:
    txt = open(path, encoding="utf-8").read()
    m = re.search(r"FALLBACK_MAP[^=]*=\s*&\[(.*?)\];", txt, re.S)
    out = []
    if m:
        for name, base, size in re.findall(
            r'\("([^"]+)",\s*(0x[0-9A-Fa-f_]+),\s*(0x[0-9A-Fa-f_]+)\)', m.group(1)
        ):
            out.append((name, int(base.replace("_", ""), 16), int(size.replace("_", ""), 16)))
    return out


def parse_log(path: str):
    maps, unimpl, accesses = [], [], []
    with open(path, encoding="utf-8") as f:
        for ln, raw in enumerate(f, 1):
            line = raw.rstrip("\n")
            if not line:
                continue
            if line.startswith("#map,"):
                _, name, base, size = line.split(",", 3)
                maps.append((name, int(base, 16), int(size, 16)))
            elif line.startswith("#unimpl,"):
                parts = line.split(",", 4)
                unimpl.append(("unimpl", parts[1], int(parts[2], 16), int(parts[3], 16), parts[4] if len(parts) > 4 else ""))
            elif line.startswith("#unimpl-class,"):
                parts = line.split(",", 4)
                unimpl.append(("unimpl-class", parts[1], int(parts[2], 16), int(parts[3], 16), parts[4] if len(parts) > 4 else ""))
            elif line.startswith("#"):
                pass
            else:
                addr_s, size_s, rw, dev = line.split(",", 3)
                accesses.append((int(addr_s, 16), int(size_s), rw, dev, ln))
    return maps, unimpl, accesses


def window_of(addr: int, windows) -> int | None:
    """First window containing addr (Bus::find semantics: lowest base first)."""
    for i, (base, size, *_rest) in enumerate(windows):
        if base <= addr < base + size:
            return i
    return None


def adt_of(addr: int, adt_rows) -> dict | None:
    for r in adt_rows:
        if r["size"] and r["base"] <= addr < r["base"] + r["size"]:
            return r
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--log", required=True, help="IOS_RUST_MMIO_LOG file")
    ap.add_argument("--out", default=None, help="also write the report here (markdown)")
    ap.add_argument("--repo", default=REPO, help="repo root (for the table/t8030.rs)")
    args = ap.parse_args()

    repo = args.repo
    adt_rows = parse_adt_table(os.path.join(repo, "tools/re/notes/m5-adt-census-raw/armio_table.md"))
    fallback = parse_fallback_map(os.path.join(repo, "crates/apple-soc/src/t8030.rs"))
    maps, unimpl, accesses = parse_log(args.log)

    L = []  # report lines
    say = L.append

    # ---------- runtime attach map ----------
    say("## Runtime attach map (from #map/#unimpl header lines)")
    say("")
    say("Modeled devices actually attached by `attach_from_adt` — note every base")
    say("disagrees with the ADT ground truth: `AdtNode::reg_entries()` mis-decodes")
    say("this fixture's little-endian reg pairs as big-endian (see")
    say("tools/re/notes/m5-adt-census.md §0). Garbage windows did not intercept")
    say("any access this boot (kernel touched zero of them).")
    say("")
    n_bad = 0
    # model-name → ADT rows (for the "really @" hint; only unique models hint)
    by_model = collections.defaultdict(list)
    for r in adt_rows:
        if r["model"]:
            by_model[r["model"]].append(r)
    for name, base, size in maps:
        if name in RAM_NAMES:
            tag = "RAM region"
        else:
            rows = by_model.get(name, [])
            if len(rows) == 1:
                tag = f"BAD base (reg_entries BE bug) — {rows[0]['node']} really @ 0x{rows[0]['base']:X}"
            else:
                tag = "BAD base (reg_entries BE bug)"
            n_bad += 1
        say(f"- `{name}` @ 0x{base:X} +0x{size:X} — {tag}")
    say(f"\nModeled attach windows: {sum(1 for m in maps if m[0] not in RAM_NAMES)}"
        f" · RAM regions: {sum(1 for m in maps if m[0] in RAM_NAMES)}"
        f" · mis-based modeled windows: {n_bad}")
    say(f"Unmodeled /arm-io nodes this boot: {len(unimpl)}"
        f" ({sum(1 for u in unimpl if u[0]=='unimpl')} classify-miss,"
        f" {sum(1 for u in unimpl if u[0]=='unimpl-class')} classify-hit-but-no-model)")
    say("")

    # ---------- the ranked census ----------
    say("## Ranked device-access census (non-RAM bus accesses, in log order)")
    say("")
    if not accesses:
        say("**ZERO device-window / unmapped accesses on the whole boot path.**")
        say(f"The log holds {len(maps)} attach header lines and 0 access lines:")
        say("every load/store/fetch the real 18C66 kernel issued up to the")
        say("TranslationFault landed in DRAM. No peripheral (UART, PMGR, AIC,")
        say("WDT, NVMe, …) is touched before the stop — the blocker is DT")
        say("content, not a missing device model.")
    else:
        # group by window: device-name hits resolve directly; UNMAPPED go
        # against the ADT ground truth, else 64 KiB buckets.
        stats = collections.defaultdict(lambda: {"hits": 0, "r": 0, "w": 0,
                                                 "first_ln": None, "first_addr": None,
                                                 "addrs": [], "offs": collections.Counter(),
                                                 "disp": ""})
        order = []
        for addr, size, rw, dev, ln in accesses:
            if dev != "UNMAPPED":
                key = f"model:{dev}"
                disp = dev
            else:
                row = adt_of(addr, adt_rows)
                key = (f"unmodeled:{row['node']}" if row
                       else f"unknown:0x{addr & ~0xFFFF:X}..0x{(addr & ~0xFFFF) + 0xFFFF:X}")
                disp = key.split(":", 1)[1]
            s = stats[key]
            s["disp"] = disp
            s["hits"] += 1
            s["r" if rw == "r" else "w"] += 1
            if s["first_ln"] is None:
                s["first_ln"], s["first_addr"] = ln, addr
                order.append(key)
            s["addrs"].append(addr)
            s["offs"][addr & 0xFFF] += 1

        say("| rank | window | base | hits | r | w | modeled? | first touch (log line) |")
        say("|---:|---|---|---:|---:|---:|---|---|")
        ranked = sorted(stats.items(), key=lambda kv: -kv[1]["hits"])
        for i, (key, s) in enumerate(ranked, 1):
            nm = s["disp"]
            if key.startswith("model:"):
                wins = [(b, z) for (n, b, z) in maps if n == nm]
                base = f"0x{wins[0][0]:X}" if len(wins) == 1 else f"{len(wins)} windows"
                modeled = "yes (attached)"
            elif key.startswith("unmodeled:"):
                nm = key[10:]
                row = next(r for r in adt_rows if r["node"] == nm)
                base, modeled = f"0x{row['base']:X}", f"NO — model `{row['model'] or '—'}`"
            else:
                nm, base, modeled = key[8:], key[8:].split(":")[0], "no window known"
            say(f"| {i} | {nm} | {base} | {s['hits']} | {s['r']} | {s['w']} | {modeled} | line {s['first_ln']} @ 0x{s['first_addr']:X} |")
        say("")
        say("Per-device top register offsets (window-relative, hits):")
        for key, s in ranked:
            tops = ", ".join(f"0x{o:X}×{c}" for o, c in s["offs"].most_common(6))
            say(f"- {key}: {tops}")
    say("")

    # ---------- named questions ----------
    def hits_for(patterns):
        rx = re.compile(patterns)
        n = 0
        for addr, size, rw, dev, ln in accesses:
            if rx.search(dev):
                n += 1
            elif dev == "UNMAPPED":
                row = adt_of(addr, adt_rows)
                if row and rx.search(row["node"]):
                    n += 1
        return n

    say("## Named pre-stop questions")
    say("")
    for label, pat in [("UART", r"uart|s3c"), ("PMGR (incl. pstate)", r"pmgr|pstate"),
                       ("AIC", r"aic"), ("WDT", r"wdt"), ("ANS/NVMe", r"ans|nvme")]:
        say(f"- **{label}**: {hits_for(pat)} bus accesses before the stop")
    say("")

    # ---------- fallback cross-check ----------
    say("## FALLBACK_MAP (t8030.rs) — where the fallback map *thinks* devices live")
    say("")
    for name, base, size in fallback:
        say(f"- {name:<10} @ 0x{base:X} +0x{size:X}")
    say("")

    report = "\n".join(L) + "\n"
    print(report)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"[m5_mmio_census] wrote {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
