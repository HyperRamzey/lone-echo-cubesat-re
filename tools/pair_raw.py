#!/usr/bin/env python
# Dump ALL Hamming-1 pairs for selected lengths with full detail.
import collections

rows = []
for line in open(r'C:\Users\admin\AppData\Local\Temp\opencode\le_re\registry_exe.tsv', encoding='utf-8'):
    p = line.rstrip('\n').split('\t')
    if len(p) == 3 and p[0] != 'off':
        rows.append((int(p[0], 16), int(p[1], 16), p[2]))

bylen = collections.defaultdict(list)
for off, h, name in rows:
    bylen[len(name)].append((name, h))

for L in (9, 10, 13, 17):
    names = bylen[L]
    print(f"===== L={L} (n={len(names)}) =====")
    cnt = 0
    for a in range(len(names)):
        na, ha = names[a]
        for b in range(a + 1, len(names)):
            nb, hb = names[b]
            diffs = [i for i in range(L) if na[i] != nb[i]]
            if len(diffs) != 1:
                continue
            i = diffs[0]
            x = ha ^ hb
            bp = [k for k in range(8) if (x >> (8 * k)) & 0xFF]
            print(f"  i={i:2} {na!r:22} vs {nb!r:22} chars {na[i]!r}->{nb[i]!r} "
                  f"dh={x:#018x} bytes={bp}")
            cnt += 1
    print(f"  total pairs: {cnt}")
    print()
