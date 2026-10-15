#!/usr/bin/env python
# Derive the byte-shift layout of the hash from Hamming-1 pairs.
# For a pair differing in exactly one char index i, dh = (T(c)^T(c')) << 8*pos(i,L)
# so the single set byte in dh reveals pos(i,L) directly.
import collections

rows = []
for line in open(r'C:\Users\admin\AppData\Local\Temp\opencode\le_re\registry_exe.tsv', encoding='utf-8'):
    p = line.rstrip('\n').split('\t')
    if len(p) == 3 and p[0] != 'off':
        rows.append((int(p[0], 16), int(p[1], 16), p[2]))

bylen = collections.defaultdict(list)
for off, h, name in rows:
    bylen[len(name)].append((name, h))

print("== Hamming-1 pair byte layout: pos(i,L) = changed byte index in XOR ==")
for L in sorted(bylen):
    if L < 1 or L > 64:
        continue
    names = bylen[L]
    layout = collections.defaultdict(collections.Counter)
    leftover = []
    for a in range(len(names)):
        na, ha = names[a]
        for b in range(a + 1, len(names)):
            nb, hb = names[b]
            diffs = [i for i in range(L) if na[i] != nb[i]]
            if len(diffs) != 1:
                continue
            i = diffs[0]
            x = ha ^ hb
            bp = tuple(k for k in range(8) if (x >> (8 * k)) & 0xFF)
            layout[i].update(bp)
            leftover.append((i, na[i], nb[i], bp))
    if not layout:
        continue
    summary = {i: layout[i].most_common(2) for i in sorted(layout)}
    print(f"L={L:2} pairs_per_index: " +
          "; ".join(f"i={i}:{summary[i]}" for i in summary))
print()
print("== raw samples for a few lengths ==")
for L in (9, 10, 11, 12):
    names = bylen[L]
    shown = 0
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
            print(f"  L={L} {na!r} vs {nb!r}  i={i} chars {na[i]!r}->{nb[i]!r} "
                  f"bytepos={bp} dh={x:#x}")
            shown += 1
            break
        if shown >= 6:
            break
