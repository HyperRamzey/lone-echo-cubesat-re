#!/usr/bin/env python
# Plain hexdump at raw file offset (for virtual-layout dumps where off == rva).
# usage: python xr.py <file> <off_hex> <len_hex>
import sys

path = sys.argv[1]
off = int(sys.argv[2], 16)
ln = int(sys.argv[3], 16)
d = open(path, 'rb').read()
chunk = d[off:off + ln]
for i in range(0, len(chunk), 32):
    c = chunk[i:i + 32]
    asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in c)
    print(f"{off + i:08x}  {c.hex(' ')}  {asc}")
