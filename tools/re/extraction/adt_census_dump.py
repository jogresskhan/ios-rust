#!/usr/bin/env python3
"""M5 ADT census dumper v2 — LE validation pass.
Validated endianness: all multi-byte prop values are LITTLE-endian u32/u64
(#interrupt-cells=01 00 00 00, phandle, #main-cpus=6, reg u64 LE pairs).
reg entries: (u64 LE addr, u64 LE size), arm-io-relative; /arm-io ranges
maps [0x0->0x200000000, 4GB] and [0x600000000->0x600000000, 8GB].
"""
import struct, json

PATH_ADT = "/tmp/adt-n104ap.bin"


def parse_flat(buf, off, path):
    nprops, nchildren = struct.unpack_from("<II", buf, off)
    p = off + 8
    node = {"path": path, "props": {}, "raw_props": [], "children": []}
    for _ in range(nprops):
        name = buf[p:p + 32].split(b"\0")[0].decode()
        ln = struct.unpack_from("<I", buf, p + 32)[0] & 0x7FFFFFFF
        node["raw_props"].append(name)
        node["props"][name] = buf[p + 36:p + 36 + ln]
        p = (p + 36 + ln + 3) & ~3
    if "name" in node["props"]:
        node["path"] = path.rstrip("/") + "/" + node["props"]["name"].rstrip(b"\0").decode()
    for _ in range(nchildren):
        c, p = parse_flat(buf, p, node["path"] + "/")
        node["children"].append(c)
    return node, p


def u32s(d):
    if len(d) % 4 or not d:
        return None
    return list(struct.unpack_from("<%dI" % (len(d) // 4), d))


def u64s(d):
    if len(d) % 8 or not d:
        return None
    return list(struct.unpack_from("<%dQ" % (len(d) // 8), d))


def compat(d):
    return [s.decode() for s in d.split(b"\0") if s]


def find(node, path):
    cur = node
    for s in path.strip("/").split("/"):
        nxt = [c for c in cur["children"] if c["path"].rsplit("/", 1)[-1] == s]
        if not nxt:
            return None
        cur = nxt[0]
    return cur


def walk(n):
    yield n
    for c in n["children"]:
        yield from walk(c)


def dump(node, out):
    out.append(f"== {node['path']} ==")
    for k in node["raw_props"]:
        d = node["props"][k]
        if k == "reg":
            es = u64s(d)
            if es is None:
                out.append(f"  reg=<{len(d)}B, ragged> {d.hex(' ')}")
            else:
                out.append(f"  reg=" + " ".join(f"[0x{a:X}+0x{s:X}]" for a, s in zip(es[0::2], es[1::2])))
        elif k == "compatible":
            out.append("  compatible=" + ",".join(compat(d)))
        elif k in ("clock-gates", "power-gates", "interrupts", "interrupt-parent",
                   "#interrupt-cells", "#address-cells", "#size-cells", "AAPL,phandle"):
            v = u32s(d)
            out.append(f"  {k}={v if v is not None else d.hex()}")
        else:
            try:
                s = d.decode()
                printable = all(ch == "\0" or 31 < ord(ch) < 127 for ch in s)
            except UnicodeDecodeError:
                printable = False
            if printable and len(s) < 80:
                out.append(f'  {k}="{s.rstrip(chr(0))}"')
            else:
                v = u32s(d)
                if v is not None and len(v) <= 28:
                    out.append(f"  {k}=[LE u32 x{len(v)}]{v}")
                else:
                    out.append(f"  {k}=<{len(d)}B> {d[:32].hex(' ')}{'…' if len(d) > 32 else ''}")
    for c in node["children"]:
        dump(c, out)


def main():
    raw = open(PATH_ADT, "rb").read()
    root, end = parse_flat(raw, 0, "/")
    assert end == len(raw)
    all_nodes = list(walk(root))
    armio = find(root, "arm-io")

    # absolute base: ranges window 1 maps child 0..4G -> +0x200000000
    def absolute(a):
        return a + 0x200000000 if a < 0x400000000 else a

    rows = []
    for c in armio["children"]:
        d = c["props"].get("reg", b"")
        es = u64s(d) or []
        ragged = bool(d) and len(d) % 8 != 0
        base = absolute(es[0]) if es else None
        size = es[1] if len(es) >= 2 else 0
        nreg = len(es) // 2
        cp = compat(c["props"].get("compatible", b""))
        irq = u32s(c["props"].get("interrupts", b"")) or []
        cg = u32s(c["props"].get("clock-gates", b"")) or []
        pg = u32s(c["props"].get("power-gates", b"")) or []
        rows.append(dict(name=c["path"].rsplit("/", 1)[-1], base=base, size=size,
                         nreg=len(es) // 2, ragged=ragged, compat=cp, irq=irq, cg=cg, pg=pg,
                         path=c["path"], props=c["raw_props"]))
    bybase = sorted([r for r in rows if r["base"] is not None], key=lambda r: r["base"])
    noreg = [r for r in rows if r["base"] is None]
    print(f"#arm-io children={len(rows)} with-reg={len(bybase)} no-reg={len(noreg)}")
    for r in bybase:
        print(f"ROW|{r['name']}|0x{r['base']:X}|0x{r['size']:X}|{r['nreg']}|{';'.join(r['compat'])}|{r['irq']}|{r['cg']}|{r['pg']}")
    for r in noreg:
        print(f"NOREG|{r['name']}|{';'.join(r['compat'])}|{r['irq']}")

    out = []
    for sel in ["arm-io/aic", "arm-io/aic-timebase", "arm-io/pmgr", "arm-io/smc",
                "arm-io/wdt", "arm-io/ans", "arm-io/sart-ans", "arm-io/dart-ans2",
                "arm-io/uart0", "arm-io/uart4", "arm-io/uart7", "arm-io/sgx",
                "arm-io/disp0", "arm-io/dpa", "arm-io/dart-disp0", "arm-io/aop",
                "arm-io/dockchannel-uart", "arm-io/aes", "arm-io/gpio", "arm-io/mipi-dsim"]:
        n = find(root, "arm-io/" + sel.split("/")[-1]) if sel.startswith("arm-io/") else find(root, sel)
        # pick by name within arm-io to survive duplicate names
        nm = sel.rsplit("/", 1)[-1]
        n = None
        for c in armio["children"]:
            if c["path"].rsplit("/", 1)[-1] == nm:
                n = c
                break
        if n:
            dump(n, out)
    print("FULLDUMP-START")
    print("\n".join(out))
    print("FULLDUMP-END")

    out = []
    cpus = find(root, "cpus")
    if cpus:
        dump(cpus, out)
    print("CPUS-START")
    print("\n".join(out))
    print("CPUS-END")

    # save structured arm-io rows for the gap analysis
    json.dump(rows, open("/home/z/tmp-re/armio_rows.json", "w"), indent=1)

    # interrupt-parent phandle map (aica)
    ph = {}
    for n in all_nodes:
        if "AAPL,phandle" in n["props"]:
            ph[u32s(n["props"]["AAPL,phandle"])[0]] = n["path"]
    print("PHANDLE-MAP-START")
    for k in sorted(ph):
        print(f"0x{k:X} {ph[k]}")
    print("PHANDLE-MAP-END")


if __name__ == "__main__":
    main()
