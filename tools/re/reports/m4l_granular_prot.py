#!/usr/bin/env python3
"""M4-L #32 RE: arm_vm_page_granular_prot (0x7b825d0) — what does it write,
and under which conditions does it SKIP the PTE fills? Capstone on real bytes.
"""
import sys
sys.path.insert(0, '/home/z/my-project/s3-work/ios-rust/tools/re/extraction')
from m4a_common import dis, show, va2off, u64va, u32va, read, seg_by_name, cstr_va

print("=== arm_vm_page_granular_prot @0xfffffff007b825d0 (first 160 insns) ===")
show(0xfffffff007b825d0, 160)
