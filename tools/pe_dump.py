#!/usr/bin/env python
# Static PE utilities for the Lone Echo script DLLs.
# usage: python pe_dump.py <pe_file> [strings_out]
import struct, sys

path = sys.argv[1]
strout = sys.argv[2] if len(sys.argv) > 2 else None
data = open(path, 'rb').read()

e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
assert data[e_lfanew:e_lfanew + 4] == b'PE\0\0'
coff = e_lfanew + 4
nsec = struct.unpack_from('<H', data, coff + 2)[0]
opt_size = struct.unpack_from('<H', data, coff + 16)[0]
opt = coff + 20
magic = struct.unpack_from('<H', data, opt)[0]
image_base = struct.unpack_from('<Q' if magic == 0x20B else '<I', data, opt + 24)[0]
secs = []
so = opt + opt_size
for i in range(nsec):
    o = so + i * 40
    name = data[o:o + 8].rstrip(b'\0').decode('latin1')
    vsize, vaddr, rawsize, rawptr = struct.unpack_from('<IIII', data, o + 8)
    secs.append((name, vaddr, vsize, rawptr, rawsize))

print(f"file={path} size={len(data)} image_base={image_base:#x}")
for n, va, vs, rp, rs in secs:
    print(f"  {n:8s} rva={va:#010x} vsize={vs:#x} rawptr={rp:#x} rawsize={rs:#x}")

def r2o(rva):
    for n, va, vs, rp, rs in secs:
        if va <= rva < va + max(vs, rs):
            o = rp + (rva - va)
            return o if o < len(data) else None
    return None

def o2r(off):
    for n, va, vs, rp, rs in secs:
        if rp <= off < rp + rs:
            return va + (off - rp)
    return None

def rd_q(rva):
    o = r2o(rva);  return struct.unpack_from('<Q', data, o)[0] if o is not None else None

def rd_d(rva):
    o = r2o(rva);  return struct.unpack_from('<I', data, o)[0] if o is not None else None

print("\n-- slots (from decompiled condition fns) --")
for s in (0x3B218, 0x3B3C0, 0x3B5B0, 0x3B690, 0x3B418):
    v = rd_q(s);  print(f"  q RVA {s:#x} = {v if v is None else hex(v)}")
for s in (0x3B504, 0x3B4B0, 0x3B488, 0x3B344):
    v = rd_d(s);  print(f"  d RVA {s:#x} = {v} {('(' + hex(v) + ')') if v is not None else ''}")

consts = [0xF55FB2B40DCABB9A, 0xA642026AC86E4BA9, 0x41D2C932082E0612,
          0x6ECF46A27E30A8A9, 0x0E4781FFED010801]
print("\n-- const search --")
for c in consts:
    b = struct.pack('<Q', c)
    hits = []; st = 0
    while True:
        i2 = data.find(b, st)
        if i2 < 0: break
        hits.append(i2); st = i2 + 1
    print(f"  {c:016X}: {len(hits)} hits")
    for i2 in hits[:10]:
        rva = o2r(i2)
        print(f"    off {i2:#x} rva {('NA' if rva is None else hex(rva))}")
        if rva is not None and 0x38000 <= rva < 0x40000:
            for k in range(-3, 4):
                if k == 0: continue
                v = rd_q(rva + 8 * k)
                print(f"      rva{k:+d} {hex(rva + 8 * k)} = {v if v is None else hex(v)}")

print("\n-- hexdump rva 0x3B000..0x3B800 --")
o1 = r2o(0x3B000); o2 = r2o(0x3B800)
if o1 and o2:
    for line in range(0, o2 - o1, 32):
        chunk = data[o1 + line:o1 + line + 32]
        asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in chunk)
        print(f"  {0x3B000 + line:06x}  {chunk.hex(' ')}  {asc}")

if strout:
    out = []
    i2 = 0; n = len(data)
    while i2 < n:
        if 32 <= data[i2] < 127:
            j = i2
            while j < n and 32 <= data[j] < 127:
                j += 1
            if j - i2 >= 4:
                rva = o2r(i2)
                out.append(f"{('NA' if rva is None else hex(rva))}: {data[i2:j].decode('latin1')}")
            i2 = j
        else:
            i2 += 1
    open(strout, 'w', encoding='latin1').write('\n'.join(out))
    print(f"\nwrote {len(out)} strings -> {strout}")
