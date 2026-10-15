#!/usr/bin/env python
# 1) identify bad names for L=4..8, 2) test wrap-around packing for L>=9.
import collections

rows = []
for line in open(r'C:\Users\admin\AppData\Local\Temp\opencode\le_re\registry_exe.tsv', encoding='utf-8'):
    p = line.rstrip('\n').split('\t')
    if len(p) == 3 and p[0] != 'off':
        rows.append((int(p[0], 16), int(p[1], 16), p[2]))

MASKB = 0xFFFFFFFFFFFFFFFF

def T(c):
    return ((ord(c) & 0xDF) ^ 0x06) & 0xFF

def packed_shift(name):
    L = len(name)
    v = 0
    for k in range(min(L, 8)):
        v ^= T(name[L - 1 - k]) << (8 * k)
    return v & MASKB

def packed_wrap(name):
    L = len(name)
    v = 0
    for i, ch in enumerate(name):
        v ^= T(ch) << (8 * ((L - 1 - i) % 8))
    return v & MASKB

bylen = collections.defaultdict(list)
for off, h, name in rows:
    bylen[len(name)].append((name, h))

# bad names for L=4..8 under packed_shift
print("== bad names (packed_shift), L=4..8 ==")
for L in range(4, 9):
    names = bylen[L]
    A = names[0][1] ^ packed_shift(names[0][0])
    bads = [(n, h, h ^ packed_shift(n)) for n, h in names if (h ^ packed_shift(n)) != A]
    # majority A (recompute from most frequent value)
    vals = collections.Counter(h ^ packed_shift(n) for n, h in names)
    A2 = vals.most_common(1)[0][0]
    bads = [(n,) for n, h in names if (h ^ packed_shift(n)) != A2]
    print(f"  L={L}: bad={bads}")

# wrap test for L>=9
print()
print("== wrap test for L=9..15 ==")
for L in range(9, 16):
    names = bylen[L]
    vals = collections.Counter(h ^ packed_wrap(n) for n, h in names)
    A2, cnt = vals.most_common(1)[0]
    print(f"  L={L}: n={len(names)} dominant A={A2:#018x} count={cnt} distinct={len(vals)}")
    if len(names) <= 12:
        for n, h in names:
            print(f"      {n!r:20} A={h ^ packed_wrap(n):#018x}")
