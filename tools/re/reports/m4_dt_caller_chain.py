#!/usr/bin/env python3
"""M4-A: DT-gate caller chain — capstone-derived evidence for the
TranslationFault va=0x4 @ pc=0xfffffff0081377b4 stop.

Everything printed here is decoded with capstone from /tmp/kc18c66.macho
(18C66 T8030). No hand bit-splitting: BL/branch targets come from capstone
operands; the BL scan uses m4a_blscan (arm64 BL/B encoding check via the
top-byte pattern, confirmed by capstone re-decode of each hit).

Sections:
  [1] faulting function (x30=0xfffffff007b8cc10 caller)
  [2] caller function + BL scan for ITS callers (one level up)
  [3] SecureDTIsLockedDown gate fn 0xfffffff008136f10 + call site 0x…7b83f54
  [4] the real DT populate path (boot_args copy -> PE_state -> DT globals)
  [5] shipped file bytes of the DT globals / boot_args copy
  [6] string anchors ("cpus", panic strings) + ADRP xrefs
"""
import sys, struct, hashlib
sys.path.insert(0, '/home/z/my-project/download/ios-rust/tools/re/extraction')
import m4a_common as K
import capstone
import m4a_blscan as BL

MD = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
MD.detail = True

ITER_NEXT   = 0xfffffff008137790   # faulting fn
CALL_SITE   = 0xfffffff007b8cc0c   # bl -> ITER_NEXT (return 0x…cc10 == x30)
GATE_FN     = 0xfffffff008136f10   # SecureDTIsLockedDown (prior M4 note)
GATE_CALL   = 0xfffffff007b83f54   # bl GATE_FN inside arm_vm_init
KVTOPHYS_AT = 0xfffffff008169574
DT_INIT_FN  = 0xfffffff00813995c   # SecureDTInit-populate fn (prior M4 note)
ARM_INIT    = 0xfffffff007b80288   # memmoves the 0x2e0 boot_args copy

def lines_in(va_lo, va_hi):
    """Linear capstone decode of [va_lo, va_hi)."""
    out = []
    va = va_lo
    while va < va_hi:
        o = K.va2off(va)
        if o is None:
            break
        for insn in MD.disasm(K._mm[o:o+4], va):
            out.append(insn)
        va += 4
    return out

def disasm_func(start, max_bytes=0x400, stops=('ret', 'retab', 'b.'), label=''):
    """Decode from start until the first unconditional return (ret/retab)."""
    out, va = [], start
    while va < start + max_bytes:
        o = K.va2off(va)
        if o is None:
            break
        insn = next(MD.disasm(K._mm[o:o+4], va), None)
        if insn is None:
            break
        out.append(insn)
        if insn.mnemonic in stops:
            break
        va += insn.size
    return out

def show(insns, annotate=None):
    for i in insns:
        note = ''
        if annotate:
            note = '  ; ' + annotate(i)
        tgt = ''
        if i.mnemonic in ('bl', 'b') and i.operands and i.operands[0].type == capstone.arm64.ARM64_OP_IMM:
            t = i.operands[0].imm & ((1 << 64) - 1)
            tgt = f'   -> {t:#x}'
        print(f'  {i.address:#x}: {i.mnemonic:<10} {i.op_str}{tgt}{note}')

def find_func_start(va, max_back=0x6000):
    """Scan back for the nearest pacibsp whose preceding insn is a retab/ret
    (or nothing) — the Apple prologue pattern."""
    addrs = [a for a in range(va - 4, va - max_back, -4)]
    for a in addrs:
        o = K.va2off(a)
        if o is None:
            continue
        ins = next(MD.disasm(K._mm[o:o+4], a), None)
        if ins is None:
            continue
        if ins.mnemonic == 'pacibsp':
            prev = next(MD.disasm(K._mm[K.va2off(a-4):K.va2off(a-4)+4], a-4), None)
            if prev is None or prev.mnemonic in ('retab', 'ret', 'brk', 'b', 'nop'):
                return a
    return None

def bl_targets_in(insns):
    out = []
    for i in insns:
        if i.mnemonic == 'bl' and i.operands[0].type == capstone.arm64.ARM64_OP_IMM:
            out.append((i.address, i.operands[0].imm))
    return out

def cond_branches_in(insns):
    out = []
    for i in insns:
        if i.mnemonic in ('cbz', 'cbnz', 'tbz', 'tbnz') or (
                i.mnemonic.startswith('b.') or
                (i.mnemonic in ('b',) and i.op_str.startswith('#') and False)):
            pass
        if i.mnemonic in ('cbz', 'cbnz', 'tbz', 'tbnz') or i.mnemonic.startswith('b.'):
            if i.operands and i.operands[-1].type == capstone.arm64.ARM64_OP_IMM:
                out.append((i.address, i.mnemonic, i.op_str, i.operands[-1].imm))
        elif i.mnemonic == 'b' and i.operands and i.operands[0].type == capstone.arm64.ARM64_OP_IMM:
            out.append((i.address, 'b', i.op_str, i.operands[0].imm))
    return out

def globals_state(vas):
    for va in vas:
        b = K.read(va, 16)
        print(f'  {va:#x}: {b.hex() if b else "(no file backing)"}')

print('== [1] faulting function: SecureDTIterateEntries @ %#x ==' % ITER_NEXT)
f1 = disasm_func(ITER_NEXT, 0x200)
show(f1)
print(f'  ({len(f1)} insns, ends at {f1[-1].address:#x})')

print()
print('== [2] caller: window around call site %#x ==' % CALL_SITE)
for i in lines_in(CALL_SITE - 0x60, CALL_SITE + 0x30):
    mark = '   <== bl -> faulting fn (return addr = x30 at stop)' if i.address == CALL_SITE else ''
    print(f'  {i.address:#x}: {i.mnemonic:<10} {i.op_str}{mark}')

caller_start = find_func_start(CALL_SITE)
print(f'  caller function start (nearest pacibsp after retab/ret): {caller_start:#x}')
fc = disasm_func(caller_start, 0x600)
print(f'  -- full function from {caller_start:#x}: {len(fc)} insns, ends {fc[-1].address:#x} --')
show(fc)
bls = bl_targets_in(fc)
print(f'  BL targets inside caller: ')
for a, t in bls:
    print(f'    {a:#x}: bl {t:#x}')

print()
print('== [2b] who calls the caller? BL-scan __TEXT_EXEC for %#x ==' % caller_start)
hits = BL.bl_scan('__TEXT_EXEC', [caller_start])[caller_start]
print(f'  {len(hits)} direct BL/B hits')
for h in hits:
    va = h[1] if isinstance(h, tuple) else h
    # find each caller's function start
    st = find_func_start(va)
    print(f'    call site {va:#x}  (function start {st:#x})' if st else f'    call site {va:#x}')

print()
print('== [2c] level-2 caller fn %#x (= arm_init candidate): window around its bl to ml_parse_cpu_topology ==' % 0xfffffff007b80288)
for i in lines_in(0xfffffff007b80928, 0xfffffff007b80998):
    mark = '   <== bl ml_parse_cpu_topology' if i.address == 0xfffffff007b80968 else ''
    print(f'  {i.address:#x}: {i.mnemonic:<10} {i.op_str}{mark}')
print('  who calls arm_init (BL-scan):')
for h in BL.bl_scan('__TEXT_EXEC', [ARM_INIT])[ARM_INIT]:
    va = h[1] if isinstance(h, tuple) else h
    st = find_func_start(va)
    print(f'    call site {va:#x} (function start {st:#x})' if st else f'    call site {va:#x}')

print()
print('== [3] gate fn %#x (SecureDTIsLockedDown candidate) ==' % GATE_FN)
fg = disasm_func(GATE_FN, 0x300)
show(fg)
print(f'  ({len(fg)} insns)')
print('  -- callee %#x (kvtophys_at) --' % KVTOPHYS_AT)
show(disasm_func(KVTOPHYS_AT, 0x100))

print()
print('== [3b] arm_vm_init call site %#x: gate + guarded store block ==' % GATE_CALL)
start_vmi = find_func_start(GATE_CALL)
print(f'  enclosing function start: {start_vmi:#x}')
win = lines_in(GATE_CALL - 0x10, GATE_CALL + 0x90)
show(win)
print('  conditional/unconditional branches in [call, +0x80):')
for a, mn, ops, tgt in cond_branches_in(lines_in(GATE_CALL, GATE_CALL + 0x80)):
    skip = '   <-- SKIPS the 0x…7b83fa0 store block' if GATE_CALL < tgt and tgt >= 0xfffffff007b83fc8 else ''
    panic = '   <-- overflow panic path' if tgt == 0xfffffff007b84850 else ''
    print(f'    {a:#x}: {mn:<6} {ops}  -> {tgt:#x}{skip}{panic}')

print()
print('== [4] the real DT-populate fn %#x ==' % DT_INIT_FN)
f4 = disasm_func(DT_INIT_FN, 0x400)
show(f4)
print(f'  ({len(f4)} insns)')
print('  its callers (BL-scan __TEXT_EXEC):')
for h in BL.bl_scan('__TEXT_EXEC', [DT_INIT_FN])[DT_INIT_FN]:
    va = h[1] if isinstance(h, tuple) else h
    st = find_func_start(va)
    print(f'    call site {va:#x} (function start {st:#x})')

print()
print('== [4b] arm_init %#x — boot_args copy hunt (adrp→0x7702128 / 0x2e0 / memmove) ==' % ARM_INIT)
body = lines_in(ARM_INIT, 0xfffffff007b80968)
adrp_state2 = {}
keep = []
for i in body:
    m = i.mnemonic
    if m == 'adrp':
        try:
            adrp_state2[i.op_str.split(', ')[0]] = int(i.op_str.split('#')[1], 16)
        except Exception:
            pass
        continue
    hot = False
    txt = f'{m} {i.op_str}'
    if m in ('add', 'ldr', 'str') and '[' in i.op_str or (m == 'add' and len(i.op_str.split(', ')) == 3):
        parts = i.op_str.split(', ')
        try:
            if m == 'add' and parts[1] in adrp_state2:
                addr = adrp_state2[parts[1]] + int(parts[2][1:], 16)
                if 0xfffffff007702100 <= addr < 0xfffffff007702140:
                    hot = True
            elif '[' in i.op_str:
                inner = i.op_str.split('[')[1].rstrip(']')
                base, _, disp = inner.partition(', ')
                if base in adrp_state2:
                    addr = adrp_state2[base] + (int(disp[1:], 16) if disp.startswith('#') else 0)
                    if 0xfffffff007702100 <= addr < 0xfffffff007702140:
                        hot = True
        except Exception:
            pass
    if m == 'bl' and i.op_str == '#0xfffffff00987c290':
        hot = True
    if i.op_str in ('#0x2e0', '#0x2d0'):
        hot = True
    if hot:
        keep.append(i.address)
ctx = set()
for a in keep:
    for k in range(-6, 7):
        ctx.add(a + 4 * k)
for i in body:
    if i.address in ctx:
        mark = '   <== HOT' if i.address in keep else ''
        t = ''
        if i.mnemonic == 'bl' and i.operands[0].type == capstone.arm64.ARM64_OP_IMM:
            t = f'   -> {i.operands[0].imm & ((1<<64)-1):#x}'
        print(f'  {i.address:#x}: {i.mnemonic:<10} {i.op_str}{t}{mark}')

print()
print('== [5] shipped file bytes of the DT globals / boot_args copy ==')
globals_state([
    0xfffffff007744988,  # DTRootNode
    0xfffffff007744990,  # DTEnd
    0xfffffff007744998,  # DTInitialized (w32)
    0xfffffff0077449a0,  # DTSize
    0xfffffff007744ad0,  # PE_state.deviceTreeHead
    0xfffffff007744ae0,  # PE_state.deviceTreeSize
    0xfffffff007744a38,  # PE_state (initialized once-guard w32)
    0xfffffff007702128,  # boot_args copy target (0x2e0 bytes)
    0xfffffff007702128 + 0x60,  # copy.deviceTreeP
    0xfffffff007702128 + 0x68,  # copy.deviceTreeLength
    0xfffffff007702568,  # global A in the rebase delta
])

print()
print('== [6] string anchors ==')
for s in ('cpus', 'DeviceTree overflow: %p, size %#zx', 'device-tree'):
    hits_s = K.find_str(s, '__TEXT')
    print(f'  "{s}": ' + ', '.join(f'{va:#x}' for va, _ in hits_s[:6]))
print('  cstr @0x73ade9b (prior note panic VA):', repr(K.cstr_va(0xfffffff0073ade9b, 64)))
print('  cstr @0x73a8785:', repr(K.cstr_va(0xfffffff0073a8785)))
print('  cstr @0x73adff6:', repr(K.cstr_va(0xfffffff0073adff6)))

print()
print('== [6b] streaming ADRP+ADD/LDR xref scan (one pass, no detail — OOM-safe) ==')
TARGETS = {
    0xfffffff007702188: 'bootargs_copy+0x60 (deviceTreeP)',
    0xfffffff007702190: 'bootargs_copy+0x68 (deviceTreeLength)',
    0xfffffff007702128: 'bootargs_copy base',
    0xfffffff007744ad0: 'PE_state.deviceTreeHead',
    0xfffffff007744ae0: 'PE_state.deviceTreeSize',
    0xfffffff0098e4658: 'x21 at stop (topology_info?)',
}
hits2 = {t: [] for t in TARGETS}
seg = K.seg_by_name('__TEXT_EXEC')
o0 = seg.off(seg.vmaddr)
md2 = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
md2.skipdata = True   # linear scan must survive literal pools / data words
adrp_state = {}
nscan = 0
for insn in md2.disasm(K._mm[o0:o0 + seg.filesize], seg.vmaddr):
    nscan += 1
    m = insn.mnemonic
    if m == 'adrp':
        try:
            r = insn.op_str.split(', ')[0]
            page = int(insn.op_str.split('#')[1], 16)
            adrp_state[r] = page
        except Exception:
            pass
    elif m in ('add', 'ldr', 'str', 'ldrb', 'strb', 'ldrsw', 'ldrsw'):
        parts = insn.op_str.split(', ')
        try:
            if m == 'add' and len(parts) == 3 and parts[1] in adrp_state and parts[2].startswith('#'):
                addr = adrp_state[parts[1]] + int(parts[2][1:], 16)
                if addr in hits2:
                    hits2[addr].append((insn.address, f'add {insn.op_str}'))
            elif m in ('ldr', 'str', 'ldrb', 'strb', 'ldrsw') and len(parts) >= 2 and '[' in parts[1]:
                inner = parts[1].split('[')[1].rstrip(']')
                base, _, disp = inner.partition(', ')
                if base in adrp_state:
                    addr = adrp_state[base] + (int(disp[1:], 16) if disp.startswith('#') else 0)
                    if addr in hits2:
                        hits2[addr].append((insn.address, f'{m} {insn.op_str}'))
        except Exception:
            pass
print(f'  scanned {nscan} insns')
for t in sorted(TARGETS):
    print(f'  {TARGETS[t]} ({t:#x}): {len(hits2[t])} refs')
    for a, txt in hits2[t][:14]:
        print(f'    {a:#x}: {txt}')
