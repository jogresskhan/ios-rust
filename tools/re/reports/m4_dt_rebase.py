#!/usr/bin/env python3
"""M4 Bug #25 — the arm_vm_init DeviceTree rebase (PE_slide_devicetree inline)
at call site 0xfffffff007b83f54: instruction-level RE of why the emulator run
corrupted DTRootNode/DTEnd (panic x1=0x80000011, x2=DTEnd=0 @ insn 8,135,397).

Everything is capstone-decoded from /tmp/kc18c66.macho (18C66 T8030). The
kernel-side ground truth (xnu-7195.121.3 source, local tree) is used ONLY to
name functions: arm_vm_init.c arm_vm_physmap_init() → arm_vm_physmap_slide()
(temp_ptov_table on stack) → PE_slide_devicetree(temp[ptov_index-1].va -
end_kern) → SecureDTInit. Output archived at /tmp/m4_dt_rebase.out.
Companion note: tools/re/notes/m4-dt-rebase-re.md."""
import sys, struct
sys.path.insert(0, '/home/z/work/ios-rust/tools/re/extraction')
import m4a_common as K
import capstone
import m4a_blscan as BL

MD = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
MD.detail = True
MD.skipdata = True

VMI = 0xfffffff007b82e34     # arm_vm_init (pacibsp back-scan anchor, dt-gate note)
SLIDE_CALL = 0xfffffff007b83f54   # bl SecureDTIsLockedDown; rebase block follows
OVERFLOW_TARGET = 0xfffffff007b84850
PANIC_STR = 0xfffffff0073adec0    # "Device tree pointer outside of device tree region..."
CLEARER = 0xfffffff0080326a8      # "str xzr x3 + wzr" DT-globals clearer (aic-timer note)
REBASER = 0xfffffff0081398e4      # out-of-line slide helper (no BL callers)
WRITER = 0xfffffff008136eb0       # "DeviceTree overflow" writer fn
GATE_FN = 0xfffffff008136f10      # SecureDTIsLockedDown

def section(t):
    print(f'\n==== {t} ====')

def lines_in(va_lo, va_hi, note=None):
    out, va = [], va_lo
    while va < va_hi:
        o = K.va2off(va)
        if o is None:
            break
        ins = next(MD.disasm(K._mm[o:o + 4], va), None)
        if ins is None:
            out.append((va, '.word', f'{K.u32va(va):08x}'))
            va += 4
            continue
        out.append((ins.address, ins.mnemonic, ins.op_str))
        va += ins.size
    return out

def show(va_lo, va_hi, marks=None, bytes_=False):
    for a, m, ops in lines_in(va_lo, va_hi):
        b = ''
        if bytes_:
            o = K.va2off(a)
            b = '  ' + K._mm[o:o + 4].hex() if o is not None else ''
        mk = ''
        if marks and a in marks:
            mk = '   <== ' + marks[a]
        print(f'  {a:#x}: {m:<10} {ops}{b}{mk}')

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

def fn_end(start, max_bytes=0x4000):
    """First retab/ret that follows a non-branch tail (heuristic fn end)."""
    va = start
    end = start
    while va < start + max_bytes:
        o = K.va2off(va)
        if o is None:
            break
        ins = next(MD.disasm(K._mm[o:o + 4], va), None)
        if ins is None:
            break
        if ins.mnemonic in ('ret', 'retab'):
            # peek next: if next is pacibsp, this ret ends the fn
            nxt = next(MD.disasm(K._mm[K.va2off(va + ins.size):K.va2off(va + ins.size) + 4], va + ins.size), None)
            if nxt is not None and nxt.mnemonic == 'pacibsp':
                return va + ins.size
        va += ins.size
    return start + max_bytes

def resolve_scan(va_lo, va_hi, lo_pages=((0x76e8000, 0x7a18000), (0x98ac000, 0x9b00000), (0x9b00000, 0x9b20000), (0x7004000, 0x76e8000))):
    """Linear scan with adrp-state; print every global access whose resolved
    VA lands inside the kernel data segments (link-relative low form)."""
    state = {}
    out = []
    for a, m, ops in lines_in(va_lo, va_hi):
        if m == 'adrp':
            try:
                r, imm = ops.split(', #')
                state[r] = int(imm, 16) & 0xFFFFFFFFFFFF
            except Exception:
                pass
            continue
        if m in ('add', 'ldr', 'ldrb', 'ldrsw', 'str', 'strb', 'ldur', 'stur'):
            if m == 'add' and ', #' in ops:
                parts = ops.split(', ')
                if len(parts) == 3 and parts[1] in state and parts[2].startswith('#'):
                    try:
                        addr = (state[parts[1]] + int(parts[2][1:], 16)) & 0xFFFFFFFFFFFF
                    except Exception:
                        continue
                    low = addr & 0xFFFFFFF
                    if any(l <= low < h for l, h in lo_pages):
                        out.append((a, f'add {ops}', addr))
                continue
            if '[' in ops:
                inner = ops.split('[')[1].rstrip(']')
                base, _, disp = inner.partition(', ')
                if base in state:
                    d = int(disp[1:], 16) if disp.startswith('#') else 0
                    addr = (state[base] + d) & 0xFFFFFFFFFFFF
                    low = addr & 0xFFFFFFF
                    if any(l <= low < h for l, h in lo_pages):
                        out.append((a, f'{m} {ops}', addr))
    return out

# ---------------------------------------------------------------- [1] segments
section('[1] Mach-O segments (top-level kernelcache)')
for s in K.SEGS:
    print(f'  {s}')

# ------------------------------------------------------- [2] arm_vm_init frame
section('[2] arm_vm_init frame: start/end, prologue register setup')
start = find_func_start(SLIDE_CALL)
end = fn_end(start)
print(f'  arm_vm_init start {start:#x}  heuristic end {end:#x}  size {end-start:#x}')
show(start, start + 0x90, bytes_=False,
     marks={start: 'arm_vm_init (pacibsp)'})

# --------------------------------------------- [3] exact slide-block disasm
section('[3] THE SLIDE BLOCK 0x7b83f40..0x7b83fd0 (bytes + capstone)')
show(0xfffffff007b83f40, 0xfffffff007b83fd0, bytes_=True, marks={
    0xfffffff007b83f54: 'bl SecureDTIsLockedDown(0x8136f10)',
    0xfffffff007b83f5c: 'tbnz w0,#0 → skip (locked-down)',
    0xfffffff007b83f98: 'overflow → panic 0x7b84850',
})

# ------------------------------- [4] resolved global accesses in arm_vm_init
section('[4] all global accesses resolved inside arm_vm_init (adrp-state scan)')
acc = resolve_scan(start, min(end, start + 0x2200))
KNOWN = {}
for a, txt, addr in acc:
    print(f'  {a:#x}: {txt:<34} -> {addr:#x} (low {addr & 0xFFFFFFF:#x})')

# ------------------------------------------------- [5] panic string xref site
section('[5] who calls panic("Device tree pointer outside...") — xrefs to 0x73adec0')
hits, count = K.adrp_add_scan('__TEXT_EXEC', [PANIC_STR])
print(f'  scanned {count} insns; {len(hits)} refs')
for a, t, addr in hits:
    print(f'    {a:#x}: {t}   -> {addr:#x}')
    fs = find_func_start(a)
    print(f'      enclosing fn start: {fs:#x}' if fs else '      (no fn start found)')

# --------------------------------------------- [6] overflow panic target win
section('[6] overflow panic target 0x7b84850 (head+size carry → panic)')
show(OVERFLOW_TARGET - 0x20, OVERFLOW_TARGET + 0x60)

# ----------------------------------------------------------- [7] helper fns
section('[7] clearer 0x80326a8 / rebaser 0x81398e4 / writer 0x8136eb0')
show(CLEARER, CLEARER + 0x60)
show(REBASER, REBASER + 0x80)
show(WRITER, WRITER + 0x40)
print('  BL callers of clearer:')
for h in BL.bl_scan('__TEXT_EXEC', [CLEARER])[CLEARER]:
    va = h[1] if isinstance(h, tuple) else h
    print(f'    call site {va:#x} (fn {find_func_start(va)})')

# ------------------------------------------------------------- [8] ADT blob
section('[8] real ADT blob head (/tmp/adt-n104ap.bin) — what sits at +0x0..0x40')
try:
    adt = open('/tmp/adt-n104ap.bin', 'rb').read()
    head = adt[:0x40]
    print('  ' + head.hex(' '))
    print(f'  root node: nProperties={struct.unpack_from("<I", adt, 0)[0]} '
          f'nChildren={struct.unpack_from("<I", adt, 4)[0]}')
    off = 8
    name = adt[off:adt.find(b'\0', off)].decode()
    print(f'  first prop: name @+{off:#x} = "{name}" '
          f'(len field @+{adt.find(b"\0", off) + 1:#x}, value @+{adt.find(b"\0", off) + 5:#x})')
except Exception as e:
    print(f'  (no ADT fixture: {e})')

# --------------------------------------------------- [9] gate fn window once
section('[9] SecureDTIsLockedDown 0x8136f10 (gate) — 1-line recap (full dump in m4_dt_caller_chain.out)')
show(GATE_FN, GATE_FN + 0x40)

# ------------------------------------------------------- [10] the arithmetic
section('[10] ARITHMETIC — emulator staged values vs kernel-computed rebase')
gVirtBase = 0xFFFFFFF007004000
gPhysBase = 0x0000000801004000
memSize   = 0x0000000040000000
topOfKD   = 0x0000000803BE4000
end_kern  = 0xFFFFFFF009BAD000
dt_head0  = 0xFFFFFFF009BAD000
dt_size   = 0x0000000000035C2C
phystokv_top = (topOfKD - gPhysBase + gVirtBase) % (1 << 64)
print(f'  phystokv(topOfKernelData)      = {phystokv_top:#x}  (ptov_table empty → gVirtBase/gPhysBase fallback)')
rand = 0  # early_random() & 0x3FFFFFFF & ~0x3FFF; emulator value TBD
physmap_base = phystokv_top + rand
twig = 1 << 25  # 16K granule L2 block = 32MB
physmap_base_rt = ((physmap_base + twig - 1) // twig) * twig
print(f'  + physmap_slide (early_random) = {rand:#x}; ROUND_TWIG(32MB) → {physmap_base_rt:#x}')
len_boot = 0x20000
t6va = physmap_base_rt + len_boot
print(f'  temp[6].va = physmap_base + 0x20000 (BOOTDATA len; other lens 0) = {t6va:#x}')
slide = (t6va - end_kern) % (1 << 64)
head_new = (dt_head0 + slide) % (1 << 64)
print(f'  slide = temp[6].va - end_kern = {slide:#x}')
print(f'  head_new = head_old + slide   = {head_new:#x}')
print(f'  DTEnd_new = head_new + 0x35C2C = {(head_new + dt_size) % (1<<64):#x}')
print(f'  panic pointer p=0x80000011 ⇒ if p = head_new + 0x11 (root "name" prop value @+0x11):')
print(f'     head_new would be 0x800000000; slide = {(0x800000000 - dt_head0) % (1<<64):#x};')
print(f'     temp[6].va = 0x800000000 ⇒ physmap_base = {0x800000000 - len_boot:#x} (NOT of the form phystokv(top)+rand) ⇒ some input the kernel read differed.')
print(f'  0x80000011 - 0x9BAD000 (low48) = {(0x80000011 - 0x9BAD000) % (1<<48):#x}')
print(f'  head_old(full) → p: delta = {(0x80000011 - dt_head0) % (1<<64):#x}')
print(f'  len[6] = round_page(phystokv(top) - end_kern) = {((phystokv_top - end_kern) % (1<<64)):#x}')
print(f'  DT fits in e[6] region? dt_size 0x35C2C <= len[6]-0?  (DT @ region base since dt_pa == end_kern_pa)')
