#!/usr/bin/env python3
"""M4 text-zeroing part 2: DT panic sites, poison provenance, function starts."""
import sys, capstone, struct
sys.path.insert(0, '/home/z/work/ios-rust/tools/re/extraction')
import m4a_common as M

md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)

def find_func_start(va, back=0x800):
    for b in range(0, back, 4):
        c = va - b
        w = M.u32va(c)
        if w is None:
            continue
        ins = next(md.disasm(w.to_bytes(4, 'little'), 0), None)
        if ins and ins.mnemonic in ('pacibsp', 'paciasp'):
            return c
    return None

def dump(lo, hi):
    for a, sz, t, _ in M.dis(lo, (hi - lo) // 4 + 8, stop_at_ret=False, va_end=hi):
        print(f'{a:#x}: {t}')

if __name__ == '__main__':
    sec = sys.argv[1] if len(sys.argv) > 1 else 'dt'
    if sec == 'dt':
        fs = find_func_start(0xfffffff00813718c)
        print(f'== function containing panic site 0x813718c starts at {fs:#x} ==' if fs
              else '== no pacibsp backward from 0x813718c ==')
        if fs:
            dump(fs, 0xfffffff0081371c8)
        print()
        print('== second site window 0x8137390..0x81373d8 ==')
        dump(0xfffffff008137390, 0xfffffff0081373d8)
        print()
        print('== third site window 0x8137460..0x813749c ==')
        dump(0xfffffff008137460, 0xfffffff00813749c)
    elif sec == 'funcstarts':
        for va in (0xfffffff00816c360, 0xfffffff00816c458, 0xfffffff0081607b8,
                   0xfffffff007a585d0, 0xfffffff00816c340, 0xfffffff00816c348):
            fs = find_func_start(va)
            print(f'{va:#x}: fn-start {fs:#x}' if fs else f'{va:#x}: none within 0x800')
    elif sec == 'before_lookup':
        print('== bytes 0x8137160..0x81371b0 ==')
        b = M.read(0xfffffff008137160, 0x50)
        for k in range(0, 0x50, 4):
            w = struct.unpack_from('<I', b, k)[0]
            ins = next(md.disasm(w.to_bytes(4, 'little'), 0), None)
            print(f'  {0xfffffff008137160 + k:#x}: {w:08x}  '
                  f'{ins.mnemonic + " " + ins.op_str if ins else ".word"}')
