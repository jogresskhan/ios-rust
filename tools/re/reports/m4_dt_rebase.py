#!/usr/bin/env python3
"""M4 DT-rebase RE (task 2-a, retry): Bug #25 — the arm_vm_init rebase
`PE_slide_devicetree(e[DT].va - end_kern)` at 0x7b83f54 corrupts the DT globals.
Three focused windows + global-xref scans + the arithmetic, capstone-only,
/tmp/kc18c66.macho via m4a_common. Output: /tmp/m4_dt_rebase.out.
Companion to tools/re/notes/m4-dt-rebase-re.md (supersedes the 2026-10-30 draft
run: same windows, plus the end_kern-writer and DT-global-writer census)."""
import sys
sys.path.insert(0, '/home/z/work/ios-rust/tools/re/extraction')
import m4a_common as M
import capstone

def section(t):
    print(f'\n==== {t} ====')

def dump(va, n, label, va_end=None):
    section(label)
    M.show(va, n, stop_at_ret=False, va_end=va_end)

# 0. segments + getlastaddr (what the kernel computes as end_kern)
section('[0] Mach-O segments + getlastaddr() = max(vmaddr+vmsize) (kernel_mach_header.c:52)')
for s in M.SEGS:
    print(f'  {s}')
last = max(s.vmaddr + s.vmsize for s in M.SEGS)
print(f'  getlastaddr() = {last:#x}   round_page(16K) = {(last + 0x3FFF) & ~0x3FFF:#x}')
print(f'  (kernel PAGE_SIZE=16K -> end_kern = {(last + 0x3FFF) & ~0x3FFF:#x}; '
      f'PA side under the emulator identity PA = KVA - LINK_BASE + LOAD_PA: '
      f'{((last + 0x3FFF) & ~0x3FFF) - 0xFFFFFFF007004000 + 0x801004000:#x})')
segHIGHEST = 0xFFFFFFF007724058
print(f'  segHIGHESTKC global = 0x7724058: file value = {M.u64va(segHIGHEST)} '
      f'(0 => cbz at 0x7b83740 takes the getlastaddr path)')

# 1. WINDOW A — the rebase site 0x7b83f54 +-0x300 with the e[DT] inline fill
dump(0xfffffff007b83e60, 0xe0, '[A1] e[DT] (entry 4) inline arm_vm_physmap_slide fill + slide-arg setup 0x7b83e60..')
dump(0xfffffff007b83f40, 0x38, '[A2] THE REBASE BLOCK 0x7b83f40..0x7b83fc8 (gate, umaddl tail, PE_slide_devicetree inlined)')
dump(0xfffffff007b83fc8, 0x30, '[A3] after the rebase: next physmap fill (remainder region)')

# 2. WINDOW B — region_list build: temp_ptov_table @ sp+0x50, ptov_index, physmap_base
dump(0xfffffff007b825d0, 0x60, '[B1] out-of-line arm_vm_physmap_slide @0x7b825d0 (pa/va/len fill, stride 0x18)')
dump(0xfffffff007b83030, 0x60, '[B2] physmap_base = phystokv(topOfKernelData) + early_random slide (arm_vm_init)')
section('[B3] ptov_index identity: [x21+0x160] with x21 = adrp 0x7702000 -> global u32 @0x7702160')
print(f'  file u32 @0x7702160 (ptov_index) = {M.u32va(0xfffffff007702160)}  (ships 0, SECURITY_READ_ONLY_LATE)')

# 3. WINDOW B/C — the end_kern writer ([0x7702568]) + seg-globals window
dump(0xfffffff007b836a0, 0x50, '[C1] getlastaddr() call + cache + seg-globals 0x7b836a0..')
dump(0xfffffff007b83730, 0x30, '[C2] end_kern writer: cbz segHIGHESTKC -> [0x7702568] = round_page(...)')

# 4. WINDOW C — DT-global writer census: the clearer @0x80326a8 and PE_slide out-of-line
dump(0xfffffff008032690, 0x30, '[C3] DT-globals clearer @0x80326a8 (str xzr x3 + wzr) — enclosing code')
dump(0xfffffff008136eb0, 0x20, '[C4] writer 0x8136eb0 ("DeviceTree overflow" str) head')
dump(0xfffffff0081398e4, 0x30, '[C5] rebaser 0x81398e4 (no BL callers) head')

# 5. global xref scans — raw ADRP prefilter (memory-cheap: the full adrp_add_scan
#    over __TEXT_EXEC OOM-kills this sandbox; m4a_xref.py prefilter approach instead)
section('[D] raw-ADRP prefilter + capstone confirm: [0x7702568]/DT globals/ptov_index')
import struct
TARGET_PAGES = {0xFFFFFFF007702000: 'end_kern/ptov_index page', 0xFFFFFFF007444000: 'DT globals page'}
WANT = {0xfffffff007702568: 'end_kern[0x7702568]', 0xfffffff007702160: 'ptov_index[0x7702160]',
        0xfffffff007744988: 'DTRootNode[0x744988]', 0xfffffff007744990: 'DTEnd[0x744990]',
        0xfffffff007744998: 'DTflag[0x744998]', 0xfffffff0077449a0: 'DTSize[0x7449a0]',
        0xfffffff007744ad0: 'DThead[0x744ad0]', 0xfffffff007744ae0: 'DTsize[0x744ae0]'}

def adrp_imm(w):
    if (w & 0x9F000000) != 0x90000000:
        return None
    rd = w & 0x1F
    immlo = (w >> 29) & 3
    immhi = (w >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= 1 << 21
    return rd, imm << 12

for segname in ('__TEXT_EXEC', '__TEXT', '__PPLTEXT'):
    seg = M.seg_by_name(segname)
    o, n = seg.off(seg.vmaddr), seg.filesize
    words = struct.unpack_from(f'<{n//4}I', M._mm, o)
    hits = []
    for i, w in enumerate(words):
        r = adrp_imm(w)
        if r is None:
            continue
        rd, off = r
        tgt = ((seg.vmaddr + 4 * i) & ~0xFFF) + off
        if (tgt & ~0xFFF) not in TARGET_PAGES:
            continue
        hits.append((seg.vmaddr + 4 * i, rd, tgt))
    print(f'  [{segname}] {len(words)} words, {len(hits)} ADRPs into watched pages')
    for a, rd, tgt in hits:
        # find the consumer: add-imm materializing a target, or ldr/str [x{rd},#d]
        win = M.dis(a, 5, stop_at_ret=False)
        for j, (aa, sz, txt, insn) in enumerate(win):
            if aa == a:
                continue
            m0 = txt.split()[0]
            try:
                ops = insn.operands
            except capstone.CsError:
                continue
            if m0 in ('ldr', 'str', 'ldrb', 'strb', 'ldrsw') and len(ops) >= 2 and \
               ops[-1].type == capstone.arm64.ARM64_OP_MEM and insn.reg_name(ops[-1].mem.base) == f'x{rd}':
                addr = tgt + ops[-1].mem.disp
                if addr in WANT:
                    print(f'    {a:#x}: adrp x{rd},#{tgt & ~0xFFF:#x} ; {aa:#x}: {m0} {insn.op_str}  -> {WANT[addr]}')
                break
            if m0 == 'add' and len(ops) == 3 and ops[1].type == capstone.arm64.ARM64_OP_REG and \
               insn.reg_name(ops[1].reg) == f'x{rd}' and ops[2].type == capstone.arm64.ARM64_OP_IMM:
                addr = tgt + ops[2].imm
                # next memory op on the materialized reg
                for aa2, sz2, txt2, insn2 in M.dis(aa + sz, 3, stop_at_ret=False):
                    ops2 = insn2.operands
                    if len(ops2) >= 2 and ops2[-1].type == capstone.arm64.ARM64_OP_MEM and \
                       insn2.reg_name(ops2[-1].mem.base) == f'x{rd}':
                        if addr in WANT:
                            print(f'    {a:#x}: adrp x{rd} ; {aa:#x}: add x{rd},#0x{ops[2].imm:x} ; {aa2:#x}: {txt2}  -> {WANT[addr]}')
                        break
                break
            if m0 in ('b', 'br', 'ret', 'blr'):
                break

# 6. the assert that panics (SecureDTLookupEntry 0x8137198 / IterateEntries 0x8137790)
dump(0xfffffff008137198, 0x14, '[E] SecureDTLookupEntry assert: ptr in [DTRootNode, DTEnd)')
dump(0xfffffff0081377ec, 0x14, '[E2] SecureDTIterateEntries assert + panic("Device tree pointer outside...")')

# 7. arithmetic — python is the authority
section('[F] arithmetic (python)')
head_before = 0xFFFFFFF009BAD000       # [0x744ad0] after PE_init_platform (live store 0x81399c8)
head_after_observed = 0x80000011       # panic x1, session H (bf-text-zero.log insn 8,135,397)
dtend_observed = 0x0                   # panic x2
size = 0x35C2C                         # deviceTreeLength / [0x744ae0]
print(f'  head_before (bootstrap-KVA)   = {head_before:#x}')
print(f'  head_after observed (panic x1)= {head_after_observed:#x}')
print(f'  implied delta = head_after - head_before = {head_after_observed - head_before:#x}')
print(f'  DTEnd observed (panic x2)     = {dtend_observed:#x}  '
      f'(SecureDTInit would give head+size = {head_after_observed + size:#x} => x2=0 is NOT '
      f'a completed rebase+SecureDTInit pair)')
print(f'  head_before - DTEnd_before    = {head_before - (head_before + size):#x} '
      f'(DTEnd_before = {head_before + size:#x})')

# current emulator contract (boot_real.rs StagedLayout, live [stage] line)
LOAD_PA = 0x801004000
LINK_BASE = 0xFFFFFFF007004000
image_bytes = 45778056
dt_bytes = 0x35C2C
page = lambda x, p=0x1000: (x + p - 1) & ~(p - 1)
end_kern_emu = page(LOAD_PA + image_bytes)          # 0x803BAD000
dt_pa = end_kern_pa_fix = 0
end_kern_emu = page(LOAD_PA + image_bytes)
dt_pa_emu = end_kern_emu
ba_pa_emu = page(dt_pa_emu + dt_bytes)
top_emu = page(ba_pa_emu + 0x2E0)
gVirt, gPhys = LINK_BASE, LOAD_PA
print(f'\n  --- CURRENT emulator staging (StagedLayout::compute, image_bytes=file size) ---')
print(f'  end_kern_emu(PA) = {end_kern_emu:#x}   dt_pa = {dt_pa_emu:#x}   ba_pa = {ba_pa_emu:#x}   top = {top_emu:#x}')
end_kern_kernel = (last + 0x3FFF) & ~0x3FFF          # getlastaddr round16K, VA
print(f'  kernel end_kern (getlastaddr, VA) = {end_kern_kernel:#x}  '
      f'PA = {end_kern_kernel - 0xFFFFFFF007004000 + LOAD_PA:#x}')
print(f'  => emulator stages DT {end_kern_kernel - 0xFFFFFFF007004000 + LOAD_PA - dt_pa_emu:#x} '
      f'BELOW the kernel-own end_kern (vmsize-vs-filesize gap) => blob KVA '
      f'{LINK_BASE + (dt_pa_emu - LOAD_PA):#x} overlaps the loaded __LINKEDIT/__PRELINK_INFO tail')
phystokv_top = top_emu - gPhys + gVirt
print(f'  phystokv(topOfKernelData) = {phystokv_top:#x}')
e_dt_len = phystokv_top - end_kern_kernel
print(f'  e[DT].len = phystokv(top) - end_kern = {e_dt_len:#x}  '
      f'(negative => wraps to {e_dt_len & (2**64-1):#x})')
SIGMA = 0x4000 + 0x20000 + 0x118000   # segKLDDATA + segBOOTDATA + segPRELINKINFO (linkedit pair skipped)
print(f'  Sigma(len0..len3) = {SIGMA:#x} (len0=segLOWEST-gVirtBase=0, keep_linkedit=TRUE fileset kernel)')
print(f'  e[DT].va = physmap_base + {SIGMA:#x};  rebase delta = e[DT].va - end_kern')
print(f'  head_after = head_before + delta = e[DT].va + (head_before - end_kern) '
      f'= e[DT].va {(head_before - end_kern_kernel):#x}')
print(f'  => head_after = e[DT].va - {-(head_before - end_kern_kernel):#x}: '
      f'{(head_before - end_kern_kernel):#x} BELOW the DT region start -> NOT covered by any '
      f'physmap entry (e[0..3] cover [physmap_base, physmap_base+{SIGMA:#x}) all ABOVE head_after)')

print(f'\n  --- FIX SPEC staging (blob above kernel-own end_kern) ---')
ek_va = (last + 0x3FFF) & ~0x3FFF
dt_pa_fix = page(ek_va - 0xFFFFFFF007004000 + LOAD_PA, 0x4000)
ba_pa_fix = page(dt_pa_fix + dt_bytes, 0x4000)
top_fix = page(ba_pa_fix + 0x2E0, 0x4000)
for k, v in [
    ('end_kern_va(kernel, unchanged)', ek_va),
    ('dt_pa (NEW)', dt_pa_fix),
    ('bootstrap-KVA of DT (boot_args.deviceTreeP)', LINK_BASE + (dt_pa_fix - LOAD_PA)),
    ('ba_pa (NEW)', ba_pa_fix),
    ('top_of_kernel_data (NEW)', top_fix),
    ('phystokv(top) (NEW)', top_fix - gPhys + gVirt),
    ('e[DT].len (NEW)', (top_fix - gPhys + gVirt) - ek_va),
    ('deviceTreeLength (unchanged)', dt_bytes),
]:
    print(f'  {k:46s} = {v:#x}')
delta_fix = (SIGMA) + (LINK_BASE + (dt_pa_fix - LOAD_PA)) - ek_va
head_fix = head_before + delta_fix
print(f'  head_after(fix) = e[DT].va + {LINK_BASE + (dt_pa_fix - LOAD_PA) - ek_va:#x} '
      f'-> inside [e[DT].va, e[DT].va+len) = mapped physmap window OK')
print(f'  DTEnd_after(fix) = head + 0x35C2C = {head_fix + dt_bytes:#x} (<= e[DT].va+len OK)')
print(f'  SecureDTIsLockedDown: kvtophys(head)={dt_pa_fix:#x} > kvtophys(kernel)={LOAD_PA:#x} '
      f'-> gate=0, rebase RUNS and lands head on the blob\'s physmap VA')

section('[G] panic string + arg regs (cross-check)')
print('  ', repr(M.cstr_va(0xfffffff0073adec0)))
