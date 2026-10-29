#!/usr/bin/env python3
"""M5 ADT census dumper — T8030 (n104ap, iOS 14.2 18C66) DeviceTree.

Format authority: crates/adt/src/lib.rs + node.rs (parse_flat path):
node = { LE u32 nprops, LE u32 nchildren } then nprops x
{ char name[32]; LE u32 len (bit31 = placeholder flag); data[len] 4-aligned }
then nchildren child nodes pre-order. Node name = 'name' property.
reg = BE u64 pairs (16B) or BE u32 pairs (8B) — mirror of AdtNode::reg_entries.
compatible = NUL-separated string blob.
"""
import struct

PATH_ADT = "/tmp/adt-n104ap.bin"
PLACEHOLDER = 1 << 31


def parse_flat(buf, off, path):
    nprops, nchildren = struct.unpack_from("<II", buf, off)
    p = off + 8
    node = {"path": path, "props": {}, "children": []}
    for _ in range(nprops):
        name = buf[p:p + 32].split(b"\0")[0].decode()
        ln = struct.unpack_from("<I", buf, p + 32)[0] & 0x7FFFFFFF
        vstart, vend = p + 36, p + 36 + ln
        node["props"][name] = buf[vstart:vend]
        p = (vend + 3) & ~3
    if "name" in node["props"]:
        node["path"] = path.rstrip("/") + "/" + node["props"]["name"].rstrip(b"\0").decode()
    for _ in range(nchildren):
        c, p = parse_flat(buf, p, node["path"] + "/")
        node["children"].append(c)
    return node, p


def reg_entries(data):
    """Mirror AdtNode::reg_entries: BE u64 pairs if sane, else BE u32 pairs."""
    out = []
    if len(data) % 8 != 0:
        return out
    u64_ok = (len(data) % 16 == 0) and all(
        struct.unpack_from(">Q", c, 0)[0] <= 0x4_0000_0000
        for c in _chunks(data, 16))
    if u64_ok and len(data) % 16 == 0:
        for c in _chunks(data, 16):
            out.append((struct.unpack_from(">Q", c, 0)[0], struct.unpack_from(">Q", c, 8)[0]))
    else:
        for c in _chunks(data, 8):
            out.append((struct.unpack_from(">I", c, 0)[0], struct.unpack_from(">I", c, 4)[0]))
    return out


def _chunks(b, n):
    return [b[i:i + n] for i in range(0, len(b) - n + 1, n)]


def u32s(data):
    if len(data) % 4 or not data:
        return None
    return list(struct.unpack_from(">%dI" % (len(data) // 4), data))


def compat(data):
    return [s.decode() for s in data.split(b"\0") if s]


def try_str(data):
    try:
        s = data.decode()
    except UnicodeDecodeError:
        return None
    if all(ch == "\0" or 31 < ord(ch) < 127 for ch in s):
        return s.rstrip("\0")
    return None


def fmt_prop(name, data):
    if name in ("reg", "ranges", "assigned-addresses"):
        es = reg_entries(data)
        return "reg=" + " ".join(f"[0x{a:X}+0x{s:X}]" for a, s in es)
    if name == "compatible":
        return "compatible=" + ",".join(compat(data))
    if name in ("clock-gates", "power-gates", "interrupts", "fixed-interrupts",
                "interrupt-parent", "interrupt-cells", "#interrupt-cells"):
        v = u32s(data)
        if v is not None:
            return f"{name}={v} ({len(v)}u32)"
    if (name.endswith("-cells") or name in ("cpu-number", "cluster-number",
                                            "clock-frequency", "timebase-frequency",
                                            "bus-frequency", "fixed-frequency",
                                            "core-count", "state", "vm-flag", "iovm-flag")):
        v = u32s(data)
        if v is not None:
            return f"{name}={v}"
    s = try_str(data)
    if s is not None and len(s) < 100:
        return f'{name}="{s}"'
    v = u32s(data)
    if v is not None and len(v) <= 24:
        return f"{name}=[BE]{v}"
    return f"{name}=<{len(data)}B: {data[:24].hex(' ')}{'…' if len(data) > 24 else ''}>"


def dump_node(node, out):
    out.append(f"== {node['path']} ==")
    for k, v in node["props"].items():
        out.append(f"  {fmt_prop(k, v)}")
    for c in node["children"]:
        dump_node(c, out)


def find(node, path):
    cur = node
    for s in path.strip("/").split("/"):
        nxt = [c for c in cur["children"] if c["path"].rsplit("/", 1)[-1] == s]
        if not nxt:
            return None
        cur = nxt[0]
    return cur


def walk(node):
    yield node
    for c in node["children"]:
        yield from walk(c)


def main():
    raw = open(PATH_ADT, "rb").read()
    root, end = parse_flat(raw, 0, "/")
    assert end == len(raw), (end, len(raw))
    all_nodes = list(walk(root))
    print(f"# nodes={len(all_nodes)} bytes={len(raw)} parse_exact=True")

    armio = find(root, "arm-io")
    rows = []
    for c in armio["children"]:
        reg = reg_entries(c["props"]["reg"]) if "reg" in c["props"] else []
        base, size = (reg[0] if reg else (0, 0))
        cp = compat(c["props"]["compatible"]) if "compatible" in c["props"] else []
        nirq = len(u32s(c["props"].get("interrupts", b"")) or [])
        ncl = len(u32s(c["props"].get("clock-gates", b"")) or [])
        npg = len(u32s(c["props"].get("power-gates", b"")) or [])
        rows.append((base, size, c["path"].rsplit("/", 1)[-1], ";".join(cp), nirq, ncl, npg))
    rows.sort(key=lambda r: r[0])
    for r in rows:
        print(f"ARMIO|0x{r[0]:X}|0x{r[1]:X}|{r[2]}|{r[3]}|irq_u32={r[4]}|cg={r[5]}|pg={r[6]}")

    wanted = []
    for n in all_nodes:
        p = n["path"]
        cp = " ".join(compat(n["props"]["compatible"])) if "compatible" in n["props"] else ""
        nm = p.rsplit("/", 1)[-1]
        lo = nm.lower()
        if ("interruptcontroller" in cp.lower() or "aic" in lo or "interrupt" in cp.lower()
                or "timer" in lo or "timer" in cp.lower()
                or nm in ("pmgr", "smc", "wdt", "ans2", "sgx", "aop", "arm-io")
                or nm.startswith("dart") or nm.startswith("sart")
                or nm.startswith("uart") or nm.startswith("disp") or nm.startswith("dpa")
                or nm.startswith("mipi") or p == "/cpus"):
            wanted.append(n)
    out = []
    for n in wanted:
        dump_node(n, out)
    print("FULLDUMP-START")
    print("\n".join(out))
    print("FULLDUMP-END")

    out = []
    cpus = find(root, "cpus")
    if cpus:
        dump_node(cpus, out)
    print("CPUS-START")
    print("\n".join(out))
    print("CPUS-END")


if __name__ == "__main__":
    main()
