#!/usr/bin/env python
# Dump all registry entries {hash, "OlPrEfIx", name} from a binary to TSV.
# usage: python registry_dump.py <file> <out.tsv>
import struct, sys

path, out = sys.argv[1], sys.argv[2]
d = open(path, 'rb').read()
MARK = b'OlPrEfIx'

rows = []
pos = 0
while True:
    i = d.find(MARK, pos)
    if i < 0:
        break
    pos = i + 1
    h = struct.unpack_from('<Q', d, i - 8)[0] if i >= 8 else None
    j = i + 8
    end = j
    while end < len(d) and d[end] != 0 and end - j < 64:
        end += 1
    name = d[j:end].decode('latin1', 'replace')
    ok = end > j and all(32 <= ord(c) < 127 for c in name)
    rows.append((i, h, name, ok))

with open(out, 'w', encoding='utf-8') as f:
    f.write("off\thash\tname\n")
    for i, h, name, ok in rows:
        f.write(f"{i:#x}\t{h:#018x}\t{name}\n")

print(f"marker hits: {len(rows)}, valid names: {sum(1 for r in rows if r[3])}")
# quick structure overview: distribution of name lengths, unique hashes
from collections import Counter
uniq = Counter(r[1] for r in rows if r[3])
print(f"unique hashes among valid: {len(uniq)}")
dup = [h for h, n in uniq.items() if n > 1]
print(f"duplicated hashes: {len(dup)} (first few: {[hex(x) for x in dup[:5]]})")
# high dword clustering
hd = Counter((r[1] >> 32) for r in rows if r[3])
top = hd.most_common(10)
print("top high-dwords:", [(hex(k), v) for k, v in top])
