#!/usr/bin/env python
# Solve the byte-shift hash structure: h = seed(L) rotated/xored with per-char contributions.
import struct, collections, sys

rows = []
for line in open(r'C:\Users\admin\AppData\Local\Temp\opencode\le_re\registry_exe.tsv', encoding='utf-8'):
    p = line.rstrip('\n').split('\t')
    if len(p) == 3 and p[0] != 'off':
        rows.append((int(p[0], 16), int(p[1], 16), p[2]))

bylen = collections.defaultdict(list)
for off, h, name in rows:
    bylen[len(name)].append((name, h))

# 1) check the rol64 model: h = rol64(seed_L, 8*L) ^ XOR_i rol64(T(c_i), 8*(L-1-i))
# For L=1: h(c) = rol(seed1,8) ^ T(c)  -> byte0 diffs = T diffs
# For L=2: h = rol(seed2,16) ^ (T(c0)<<8) ^ T(c1) if no bits are lost

def diff_bytes(a, b):
    """bytes where the two 64-bit values differ"""
    x = a ^ b
    return [i for i in range(8) if (x >> (8*i)) & 0xFF]

# Show for L=1 all chars and their byte0
one = sorted(bylen[1])
print("== L=1 ==")
for n, h in one:
    print(f"  {n!r:6} {h:#018x}  byte0={h & 0xFF:#04x}")

print()
print("== L=2 : byte layout of each ==")
for n, h in sorted(bylen[2])[:12]:
    print(f"  {n!r:6} {h:#018x}  low16={h & 0xFFFF:#06x}")

print()
print("== L=3 : byte layout ==")
for n, h in sorted(bylen[3])[:12]:
    print(f"  {n!r:6} {h:#018x}  low24={h & 0xFFFFFF:#08x}")

print()
print("== L=4 : byte layout ==")
for n, h in sorted(bylen[4])[:12]:
    print(f"  {n!r:6} {h:#018x}  low32={h & 0xFFFFFFFF:#010x}")

print()
print("== L=5 : high dwords per name (all 16-ish) ==")
for n, h in sorted(bylen[5]):
    print(f"  {n!r:8} {h:#018x}  hi={h >> 32:#010x} lo={h & 0xFFFFFFFF:#010x}")

print()
print("== L=6 samples ==")
for n, h in sorted(bylen[6])[:20]:
    print(f"  {n!r:10} {h:#018x}  hi={h >> 32:#010x} lo={h & 0xFFFFFFFF:#010x}")

print()
print("== L=9 samples ==")
for n, h in sorted(bylen[9])[:10]:
    print(f"  {n!r:16} {h:#018x}")
