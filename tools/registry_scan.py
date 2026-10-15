#!/usr/bin/env python
# Find {hash, "OlPrEfIx", name} registry entries in a binary and print name->hash pairs.
# usage: python registry_scan.py <file> [max_print]
import struct, sys, re

path = sys.argv[1]
maxn = int(sys.argv[2]) if len(sys.argv) > 2 else 300
d = open(path, 'rb').read()
MARK = b'OlPrEfIx'

pairs = []
pos = 0
while True:
    i = d.find(MARK, pos)
    if i < 0:
        break
    pos = i + 1
    # hash = qword before marker
    h = struct.unpack_from('<Q', d, i - 8)[0] if i >= 8 else None
    # name follows marker
    j = i + 8
    end = j
    while end < len(d) and d[end] != 0 and end - j < 64:
        end += 1
    name = d[j:end].decode('latin1', 'replace')
    # preceding bytes may be extra fields (pointers); record raw previous qwords for context
    prev = []
    for k in range(1, 5):
        o = i - 8 * k
        if o >= 0:
            prev.append(struct.unpack_from('<Q', d, o)[0])
    pairs.append((i, h, name, prev))

print(f"marker hits: {len(pairs)}")
seen = {}
out = 0
for i, h, name, prev in pairs:
    if not name or not all(32 <= ord(c) < 127 for c in name):
        continue
    key = (name, h)
    if key in seen:
        continue
    seen[key] = True
    prevs = ' '.join(f'{p:#018x}' for p in prev[:3])
    print(f"  {h:#018x}  {name!r}   @{i:#x}  prev3: {prevs}")
    out += 1
    if out >= maxn:
        print("  ...")
        break
