#!/usr/bin/env python3
"""M4-L #32 RE part 4: (a) the ptov commit code @0x987c2dc context,
(b) the aborting callback site @0x7a8d064, (c) what calls granular_prot."""
import sys
sys.path.insert(0, '/home/z/my-project/s3-work/ios-rust/tools/re/extraction')
from m4a_common import dis, show, seg_by_name, read, u64va

print("=== commit context: 0xfffffff00987c280..0xfffffff00987c360 ===")
show(0xfffffff00987c280, 60, stop_at_ret=False)
print()
print("=== aborting callback: 0xfffffff007a8d000..0xfffffff007a8d0a0 ===")
show(0xfffffff007a8d000, 40, stop_at_ret=False)
