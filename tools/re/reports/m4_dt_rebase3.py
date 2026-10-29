#!/usr/bin/env python3
"""M4 Bug #25 part 3: (a) arm_vm_init 0x7b82f20..0x7b83560 — the
physmap_base = phystokv(topOfKernelData) + early_random + ROUND_TWIG window,
(b) panic-string 0x73adec0 xrefs in __TEXT/__PPLTEXT/__DATA_CONST text,
(c) the e[0..5] inline slide fills (identify each region's orig_va/len),
(d) SecureDTLookupEntry's first assert (root pointer check).
Appended to /tmp/m4_dt_rebase.out."""
import sys
sys.path.insert(0, '/home/z/work/ios-rust/tools/re/extraction')
import m4a_common as K
import capstone

MD = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
MD.detail = False
MD.skipdata = True

def section(t):
    print(f'\n==== {t} ====')

def dis(va, n, label, marks=None):
    section(label)
    o = K.va2off(va)
    cnt = 0
    for ins in MD.disasm(K._mm[o:o + 4 * n + 16], va):
        if cnt >= n:
            break
        mk = ''
        if marks and ins.address in marks:
            mk = '   <== ' + marks[ins.address]
        tgt = ''
        if ins.mnemonic in ('bl', 'b') and ins.op_str.startswith('#'):
            try:
                t = int(ins.op_str[1:], 16)
                tgt = f'   -> {t:#x}'
            except Exception:
                pass
        print(f'  {ins.address:#x}: {ins.mnemonic:<9} {ins.op_str}{tgt}{mk}')
        cnt += 1

# -------------------------------------------- [20] physmap_base computation
dis(0xfffffff007b82f20, 0x200, '[20] arm_vm_init 0x7b82f20..: physmap_base = phystokv(topOfKernelData)+early_random, ROUND_TWIG, physmap_end, static_memory_end',
    marks={0xfffffff007b82f38: 'phystokv(topOfKernelData)?'})

# -------------------------------------------- [21] physmap_base + TT window 2
dis(0xfffffff007b83120, 0x1c0, '[21] arm_vm_init 0x7b83120..: avail_start/avail_end/real_avail_end + init_ptpages + bootstrap tables')

# -------------------------------------------- [22] panic string xrefs elsewhere
section('[22] streaming xref 0x73adec0 in __TEXT / __PPLTEXT / __DATA_CONST')
for segname in ('__TEXT', '__PPLTEXT', '__DATA_CONST', '__TEXT_EXEC'):
    seg = K.seg_by_name(segname)
    if seg is None or seg.filesize == 0:
        continue
    o0 = seg.off(seg.vmaddr)
    adrp_state = {}
    found = []
    for insn in MD.disasm(K._mm[o0:o0 + seg.filesize], seg.vmaddr):
        m = insn.mnemonic
        try:
            if m == 'adrp':
                r, imm = insn.op_str.split(', #')
                adrp_state[r] = int(imm, 16) & 0xFFFFFFFFFFFF
            elif m == 'add' and ', #' in insn.op_str:
                parts = insn.op_str.split(', ')
                if len(parts) == 3 and parts[1] in adrp_state:
                    addr = (adrp_state[parts[1]] + int(parts[2][1:], 16)) & 0xFFFFFFFFFFFF
                    if addr == 0x73adec0:
                        found.append((insn.address, segname))
        except Exception:
            pass
    print(f'  [{segname}] {len(found)} refs: ' + ', '.join(f'{a:#x}' for a, _ in found))

# -------------------------------------------- [23] e[0..5] inline fill probes
dis(0xfffffff007b83a00, 0x60, '[23] e[?] inline slide fill #1 (which orig_va/len?)')
dis(0xfffffff007b83c40, 0x40, '[23b] inline fill w/ keep_linkedit branch')
dis(0xfffffff007b83e40, 0x70, '[23c] inline fill before e[6]')

# -------------------------------------------- [24] SecureDTLookupEntry root check
dis(0xfffffff008137198, 0x60, '[24] SecureDTLookupEntry @0x8137198 — the first ASSERT_IN_DT on the root pointer')
dis(0xfffffff00813749c, 0x40, '[24b] SecureDTGetProperty @0x813749c (6-arg hardened form?)')
