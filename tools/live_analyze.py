#!/usr/bin/env python
# Analyze the live memory dump of the cubesat tracker module.
import struct, os, re, sys

LIVE = r"C:\Users\admin\AppData\Local\Temp\opencode\le_re\live"
LOG = r"C:\Users\admin\AppData\Local\Temp\opencode\le_re\dump_mod.log"

mods = []
with open(LOG, encoding='utf-8-sig', errors='replace') as f:
    for line in f:
        m = re.match(r'\s+(0x[0-9a-f]+) (0x[0-9a-f]+) (\S+)  (.*)$', line)
        if m:
            mods.append((int(m.group(1), 16), int(m.group(2), 16), m.group(3), m.group(4).strip()))

def modof(addr):
    for base, size, name, path in mods:
        if base <= addr < base + size:
            return name, addr - base
    return None, None

trk = None
for f in os.listdir(LIVE):
    if f.startswith('ee298562'):
        trk = os.path.join(LIVE, f)
print("tracker dump:", os.path.basename(trk))
d = open(trk, 'rb').read()
print("dump size:", len(d))

def q(rva): return struct.unpack_from('<Q', d, rva)[0]
def u32(rva): return struct.unpack_from('<I', d, rva)[0]

print("\n== condition-fn slots (live) ==")
for rva in (0x3B218, 0x3B3C0, 0x3B5B0, 0x3B690, 0x3B418):
    v = q(rva)
    name, off = (None, None)
    if v > 0x10000:
        name, off = modof(v)
    print(f"  q rva {rva:#x} = {v:#018x}" + (f"  -> {name}+{off:#x}" if name else ""))
for rva in (0x3B504, 0x3B4B0, 0x3B488, 0x3B344):
    v = u32(rva)
    print(f"  d rva {rva:#x} = {v} ({v:#x})")

print("\n== full .data scan, nonzero qwords ==")
for rva in range(0x3B000, 0x3B7B8, 8):
    v = q(rva)
    if not v:
        continue
    name, off = (None, None)
    if v > 0x10000:
        name, off = modof(v)
    lo = v & 0xFFFFFFFF
    hi = v >> 32
    print(f"  {rva:#06x}: {v:#018x}  lo={lo:#x} hi={hi:#x}" + (f"  -> {name}+{off:#x}" if name else ""))

# also resolve the callback target file offsets for later disassembly
for rva in (0x3B218, 0x3B3C0, 0x3B5B0, 0x3B690, 0x3B418):
    v = q(rva)
    if v > 0x10000:
        name, off = modof(v)
        if name:
            print(f"pointer-slot {rva:#x} -> {name}+{off:#x}")
