#!/usr/bin/env python3
"""Step 0 (M4-a): decompress IM4P/LZFSE kernelcache.release.iphone12b -> /tmp/kc18c66.macho"""
import struct, sys, liblzfse

path = '/home/z/my-project/s3-work/ios-rust/fixtures/kernelcache.release.iphone12b'
out = '/tmp/kc18c66.macho'
raw = open(path, 'rb').read()
print(f'fixture size: {len(raw):#x}')

i = raw.find(b'IM4P')
assert i > 0, 'IM4P magic not found'
print(f'IM4P magic at {i:#x}')
# IM4P header: 'IM4P' + type(4) + version(4) + payload_size(4) + ... then ASN.1-ish; find LZFSE blob
# LZFSE block magic starts with 'bvx-'/'bvx2'/'bvx$'/'bvxn'
for magic in (b'bvx-', b'bvx2', b'bvx$', b'bvxn'):
    j = raw.find(magic, i)
    if j > 0:
        print(f'LZFSE stream ({magic}) at {j:#x}')
        break
payload = raw[j:]
dec = liblzfse.decompress(payload)
print(f'decompressed: {len(dec):#x} bytes')
# trim trailing padding (pages of zeros)
magic = struct.unpack_from('<I', dec, 0)[0]
print(f'magic: {magic:#x}')
assert magic == 0xFEEDFACF, 'not a 64-bit Mach-O'
# trim trailing zeros in 4KB pages
end = len(dec)
while end >= 0x1000 and dec[end-0x1000:end] == b'\0'*0x1000:
    end -= 0x1000
trimmed = dec[:end]
print(f'trimmed: {len(trimmed):#x} bytes (removed {len(dec)-end:#x} of page padding)')
open(out, 'wb').write(trimmed)
print(f'wrote {out}')

# quick segment dump
mm = trimmed
def u32(o): return struct.unpack_from('<I', mm, o)[0]
def u64(o): return struct.unpack_from('<Q', mm, o)[0]
ncmds = u32(16); off = 32
for _ in range(ncmds):
    cmd, cs = u32(off), u32(off+4)
    if cmd == 0x19:
        name = mm[off+8:off+24].rstrip(b'\0').decode()
        print(f'  seg {name:16s} va={u64(off+24):#x} sz={u64(off+32):#x} fo={u64(off+40):#x} fsz={u64(off+48):#x}')
    off += cs
