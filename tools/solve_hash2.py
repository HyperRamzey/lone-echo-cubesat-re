#!/usr/bin/env python
# Validate the model h = A(L) ^ packed(name) and find the A(L) recurrence.
import collections

rows = []
for line in open(r'C:\Users\admin\AppData\Local\Temp\opencode\le_re\registry_exe.tsv', encoding='utf-8'):
    p = line.rstrip('\n').split('\t')
    if len(p) == 3 and p[0] != 'off':
        rows.append((int(p[0], 16), int(p[1], 16), p[2]))

MASKB = 0xFFFFFFFFFFFFFFFF

def T(c):
    return ((ord(c) & 0xDF) ^ 0x06) & 0xFF

def packed(name):
    L = len(name)
    v = 0
    for k in range(min(L, 8)):
        ch = name[L - 1 - k]
        v ^= T(ch) << (8 * k)
    return v & MASKB

bylen = collections.defaultdict(list)
for off, h, name in rows:
    bylen[len(name)].append((name, h))

# Compute A(L) from the first sample, verify across all samples of that length
A = {}
print("== A(L) extraction & verification ==")
for L in sorted(bylen):
    names = bylen[L]
    n0, h0 = names[0]
    a = h0 ^ packed(n0)
    bad = 0
    for n, h in names[1:]:
        if (h ^ packed(n)) != a:
            bad += 1
    A[L] = a
    print(f"  L={L:2} n={len(names):3} bad={bad:3}  A={a:#018x}")

# Show A(L) for L=1..12 as byte arrays LSB-first
print()
print("== A(L) bytes LSB-first, L=1..12 ==")
for L in range(1, 13):
    if L in A:
        bs = [(A[L] >> (8 * k)) & 0xFF for k in range(8)]
        print(f"  A({L:2}) = " + " ".join(f"{b:02x}" for b in bs))

# Test recurrences
print()
print("== recurrence tests ==")

def rol(x, n):
    n %= 64
    return ((x << n) | (x >> (64 - n))) & MASKB

def ror(x, n):
    n %= 64
    return ((x >> n) | (x << (64 - n))) & MASKB

Ls = sorted(l for l in A if 1 <= l <= 14)
print("rol-left con checks:")
for i in range(1, len(Ls)):
    l0, l1 = Ls[i - 1], Ls[i]
    c = A[l1] ^ rol(A[l0], 8)
    print(f"  A({l1}) ^ rol(A({l0}),8) = {c:#018x}")

print("ror con checks:")
for i in range(1, len(Ls)):
    l0, l1 = Ls[i - 1], Ls[i]
    c = A[l1] ^ ror(A[l0], 8)
    print(f"  A({l1}) ^ ror(A({l0}),8) = {c:#018x}")

print("shift-left con checks (A(L) = A(L-1)<<8 ^ C):")
for i in range(1, len(Ls)):
    l0, l1 = Ls[i - 1], Ls[i]
    c = A[l1] ^ ((A[l0] << 8) & MASKB)
    print(f"  A({l1}) ^ A({l0})<<8 = {c:#018x}")

print("shift-right con checks (A(L) = A(L-1)>>8 ^ C):")
for i in range(1, len(Ls)):
    l0, l1 = Ls[i - 1], Ls[i]
    c = A[l1] ^ (A[l0] >> 8)
    print(f"  A({l1}) ^ A({l0})>>8 = {c:#018x}")
