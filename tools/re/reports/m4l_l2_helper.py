#!/usr/bin/env python3
"""M4-L #32 RE part 2: the L2-table ensure helper @0x7b818a0 + writers of
[0x7701d10] (the per-L1-slot L2 table array pointer)."""
import sys
sys.path.insert(0, '/home/z/my-project/s3-work/ios-rust/tools/re/extraction')
from m4a_common import dis, show, va2off, u64va, u32va, read, seg_by_name

print("=== helper @0xfffffff007b818a0 (160 insns) ===")
show(0xfffffff007b818a0, 160, stop_at_ret=False)
