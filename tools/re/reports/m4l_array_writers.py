#!/usr/bin/env python3
"""M4-L #32 RE part 3: writers of [0x7701d10] + inner mapper 0x7b827b8 +
ptov-lookup tail (no-match path)."""
import sys, struct
sys.path.insert(0, '/home/z/my-project/s3-work/ios-rust/tools/re/extraction')
from m4a_common import dis, show, va2off, u64va, u32va, read, _mm, SEGS, seg_by_name

# --- 1. writers of 0x7701d10: scan __TEXT_EXEC for adrp+str/ldr pairs ---
# adrp to page 0x7701000 (0xfffffff007701000) then imm12 offset 0xd10
print("=== census: adrp 0xfffffff007701000 + imm 0xd10 (any ldr/str) in __TEXT_EXEC ===")
tex = seg_by_name('__TEXT_EXEC')
md_pat = None
import capstone
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
o = tex.off(tex.vmaddr)
end = o + tex.filesize
hits = []
code = _mm[o:end]
base_va = tex.vmaddr
for insn in md.disasm(code, base_va):
    if insn.mnemonic in ('adrp',):
        # adrp xN, target — op_str like "x8, #0xfffffff007701000"
        parts = insn.op_str.split(', ')
        if len(parts) == 2 and parts[1].lstrip('#') == '0xfffffff007701000':
            hits.append((insn.address, insn.mnemonic, insn.op_str, parts[0]))
    elif insn.mnemonic in ('ldr', 'str') and hits and insn.address - hits[-1][0] <= 16:
        # check imm offset 0xd10 referencing the same reg
        reg = hits[-1][3]
        if f'[{reg}, #0xd10]' in insn.op_str or f'[{reg}]' in insn.op_str and '#0xd10' in insn.op_str:
            print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}   (after adrp @ {hits[-1][0]:#x})")
            hits.append((insn.address, insn.mnemonic, insn.op_str, reg))

print()
print("=== value at [0xfffffff007701d10] in the FILE ===")
print(f"  file ships: {u64va(0xfffffff007701d10):#x}")
print()
print("=== inner mapper 0xfffffff007b827b8 (80 insns) ===")
show(0xfffffff007b827b8, 80, stop_at_ret=False)
print()
print("=== ptov-lookup tail 0xfffffff007b81a2c..0xfffffff007b81a80 ===")
show(0xfffffff007b81a2c, 24, stop_at_ret=False)
