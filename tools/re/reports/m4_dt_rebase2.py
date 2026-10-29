#!/usr/bin/env python3
"""M4 Bug #25 part 2: (a) arm_vm_physmap_slide body 0x7b825d0, (b) the
physmap_base computation + early_random + ROUND_TWIG window in arm_vm_init,
(c) end_kern writer window, (d) streaming xref for the DT-region panic string
(no capstone detail — OOM-safe), (e) the panic caller + p provenance,
(f) fn 0x7b815b0 window at 0x7b81fa8 (4th PE_state.deviceTreeHead xref).
Output appended to /tmp/m4_dt_rebase.out."""
import sys, struct
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

def find_func_start(va, max_back=0x8000):
    for a in range(va - 4, va - max_back, -4):
        o = K.va2off(a)
        if o is None:
            continue
        ins = next(MD.disasm(K._mm[o:o + 4], a), None)
        if ins is None:
            continue
        if ins.mnemonic == 'pacibsp':
            pv = next(MD.disasm(K._mm[K.va2off(a - 4):K.va2off(a - 4) + 4], a - 4), None)
            if pv is None or pv.mnemonic in ('retab', 'ret', 'brk', 'b', 'nop', 'pacibsp'):
                return a
    return None

# ---------------------------------------------------------- [11] slide helper
dis(0xfffffff007b825d0, 90, '[11] arm_vm_physmap_slide @ 0x7b825d0 (out-of-line copy used for e[6])',
    marks={0xfffffff007b825d0: 'arm_vm_physmap_slide(temp_table, orig_va, len, prot, granule)'})

# ------------------------------------------- [12] physmap_base computation
dis(0xfffffff007b83550, 0x120, '[12] arm_vm_init 0x7b83550..0x7b837c0: physmap_base = phystokv(topOfKernelData)+early_random, ROUND_TWIG; segment globals; end_kern writer',
    marks={0xfffffff007b83758: 'str [0x7702568] = end_kern'})

# ------------------------------------------------------- [13] end_kern window
dis(0xfffffff007b836d0, 0x40, '[13] end_kern write window (what feeds [0x7702568]?)')

# -------------------------------------------- [14] e[6] out-of-line call args
dis(0xfffffff007b83ea0, 0x2c, '[14] e[6] slide arg setup (orig_va=end_kern, len=phystokv(top)-end_kern) + PE_slide block')

# ---------------------------------------------- [15] panic string xref (fast)
section('[15] streaming xref: "Device tree pointer outside of device tree region" (0x73adec0)')
seg = K.seg_by_name('__TEXT_EXEC')
o0 = seg.off(seg.vmaddr)
adrp_state = {}
hits = []
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
                    hits.append((insn.address, f'add {insn.op_str}'))
    except Exception:
        pass
print(f'  {len(hits)} refs to panic string 0x73adec0:')
for a, t in hits:
    fs = find_func_start(a)
    print(f'    {a:#x}: {t}   (enclosing fn {fs:#x})' if fs else f'    {a:#x}: {t}')

# ------------------------------------------- [16] the panicking walk function
if hits:
    site = hits[0][0]
    fs = find_func_start(site)
    dis(fs, 0x120, f'[16] panic caller fn @ {fs:#x} (which pointer is x1?)',
        marks={site: 'panic(...) with assert_in_dt_region args'})

# --------------------------------- [17] fn containing 0x7b81fa8 xref window
fs17 = find_func_start(0xfffffff007b81fa8)
dis(0xfffffff007b81f60, 0x30, f'[17] 0x7b81fa8 window (PE_state.deviceTreeHead 4th xref; enclosing fn {fs17:#x})')

# ------------------------------------------- [18] iterator/lookup check sites
section('[18] DT walk assert sites (SecureDTLookupEntry / IterateEntries region 0x8137700..0x8137840)')
dis(0xfffffff008137780, 0x38, '[18a] SecureDTIterateEntries region-check + panic',
    marks={0xfffffff0081377ec: 'ldr DTRootNode', 0xfffffff0081377f8: 'ldr DTEnd',
           0xfffffff008137820: 'panic target (outside region)'})

# ------------------------------------------- [19] SecureDTLookupEntry root path
dis(0xfffffff0081375ec - 0x800, 0x10, '[19a] probe around GetFirstChild 0x81375ec (context)')
