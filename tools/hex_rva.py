#!/usr/bin/env python
# usage: python hex_rva.py <pe_file> <rva_hex> <len_hex>
import struct, sys

path = sys.argv[1]
rva0 = int(sys.argv[2], 16)
ln = int(sys.argv[3], 16)
data = open(path, 'rb').read()

e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
coff = e_lfanew + 4
nsec = struct.unpack_from('<H', data, coff + 2)[0]
opt_size = struct.unpack_from('<H', data, coff + 16)[0]
opt = coff + 20
secs = []
so = opt + opt_size
for i in range(nsec):
    o = so + i * 40
    name = data[o:o + 8].rstrip(b'\0').decode('latin1')
    vsize, vaddr, rawsize, rawptr = struct.unpack_from('<IIII', data, o + 8)
    secs.append((name, vaddr, vsize, rawptr, rawsize))

for n, va, vs, rp, rs in secs:
    if va <= rva0 < va + rs:
        off = rp + (rva0 - va)
        chunk = data[off:off + ln]
        for i in range(0, len(chunk), 32):
            c = chunk[i:i + 32]
            asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in c)
            print(f"{rva0 + i:06x}  {c.hex(' ')}  {asc}")
        break
else:
    print("rva not in any raw-backed section")
