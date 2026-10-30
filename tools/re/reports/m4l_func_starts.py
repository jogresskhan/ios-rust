#!/usr/bin/env python3
"""M4-L #32 RE part 6: find function starts (pacibsp) containing the
pmap_map_range cluster, census their BL callers."""
import sys
sys.path.insert(0, '/home/z/my-project/s3-work/ios-rust/tools/re/extraction')
from m4a_common import seg_by_name, va2off, _mm
import capstone, struct

md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)

def find_func_start(va, max_back=0x4000):
    """Scan backwards for pacibsp (function prologue)."""
    off = va2off(va)
    start = max(off - max_back, 0)
    # walk backwards 4 bytes at a time; pacibsp = 0xD503237F
    o = off - 4
    while o > start:
        w = struct.unpack_from('<I', _mm, o)[0]
        if w == 0xD503237F:  # pacibsp
            return va - (off - o)
        o -= 4
    return None

for site in (0xfffffff007b81f50, 0xfffffff007b82b34, 0xfffffff007b83af0, 0xfffffff007a8d060):
    fs = find_func_start(site)
    print(f"site {site:#x} -> function start {fs:#x}" if fs else f"site {site:#x}: none")
