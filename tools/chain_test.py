#!/usr/bin/env python
# Diagnose s=8,9,10,46 pairs; test CRC-chain hypothesis for MUL(s); derive table.
import collections

MOD = 1 << 64
MASK = MOD - 1

rows = []
for line in open(r'C:\Users\admin\AppData\Local\Temp\opencode\le_re\registry_exe.tsv', encoding='utf-8'):
    pp = line.rstrip('\n').split('\t')
    if len(pp) == 3 and pp[0] != 'off':
        rows.append((int(pp[0], 16), int(pp[1], 16), pp[2]))

def T(c):
    return ((ord(c) & 0xDF) ^ 0x06) & 0xFF

bylen = collections.defaultdict(list)
for off, h, name in rows:
    bylen[len(name)].append((name, h))

pairs = []
for L, names in bylen.items():
    for a in range(len(names)):
        na, ha = names[a]
        for b in range(a + 1, len(names)):
            nb, hb = names[b]
            diffs = [i for i in range(L) if na[i] != nb[i]]
            if len(diffs) != 1:
                continue
            i = diffs[0]
            pairs.append((L - 1 - i, T(na[i]) ^ T(nb[i]), ha ^ hb, na, nb))

per_shift = collections.defaultdict(list)
for s, delta, dh, na, nb in pairs:
    per_shift[s].append((delta, dh, na, nb))

print("== diagnostics for problem shifts ==")
for s in (8, 9, 10, 46):
    print(f"-- s={s}: {len(per_shift[s])} pairs")
    for delta, dh, na, nb in per_shift[s][:12]:
        extra = ""
        if delta == 0:
            extra = "DELTA-0"
        else:
            k = (delta & -delta).bit_length() - 1
            if dh % (1 << k) == 0:
                u = delta >> k
                base = (dh >> k) * pow(u, -1, MOD >> k) % (MOD >> k)
                cands = [base + (j << (64 - k)) for j in range(1 << min(k, 4))]
                extra = "M candidates: " + ", ".join(
                    f"{c:#018x}" for c in cands[:4]) + ("..." if k > 4 else "")
            else:
                extra = f"IMPOSSIBLE (v2(dh)<{k})"
        print(f"   {na!r} vs {nb!r} delta={delta:#04x} dh={dh:#018x}  {extra}")

print()
print("== CRC-chain test ==")

def gen_tab_msb(poly):
    tab = []
    for i in range(256):
        c = i << 56
        for _ in range(8):
            if c & (1 << 63):
                c = ((c << 1) ^ poly) & MASK
            else:
                c = (c << 1) & MASK
        tab.append(c)
    return tab

# known MULs extracted earlier (with ambiguity); we test chain for both branches
known = {
    0: 0x1, 1: 0x100, 2: 0x10000, 3: 0x1000000, 4: 0x100000000,
    5: 0x10000000000, 6: 0x1000000000000, 7: 0x100000000000000,
    8: 0x2b5926535897936a,
    11: 0xec5c10c7baa6e079, 12: 0xff6116d9ff702146, 13: 0xe3a7b6fb8de8f2c7,
    14: 0x9fdf893ac3932087, 15: 0xa840f5dc35b6ee34, 16: 0xcee141f781be55d5,
    17: 0xefcd68d642359cba, 18: 0x8e411117db5b714e, 19: 0xf1160c4539b73a39,
    21: 0x84df4c1dd5237f71, 22: 0xa582f328b63f7ca6, 23: 0xbf0a124c8cb5786f,
    24: 0xd4c128f0b85b4cd1, 26: 0xc29e0f93927ec426, 27: 0x8bab66f89680f6ca,
    28: 0xd3e4f94e7486419a, 29: 0xb0c52e6be87dab7c, 30: 0x8eba7e6a4bca8dd5,
}

poly = 0x2b5926535897936a
tab = gen_tab_msb(poly)
print(f"tab[1] = {tab[1]:#018x} (should equal MUL(8))")
print(f"tab[0x2b] = {tab[0x2b]:#018x}")

# chain from MUL(8)
st = known[8]
chain = {8: st}
for s in range(9, 65):
    st = ((st << 8) & MASK) ^ tab[(st >> 56) & 0xFF]
    chain[s] = st

print()
for s in range(9, 31):
    if s in known:
        a = known[s]
        b = a ^ (1 << 63)
        ok = "MATCH" if chain[s] in (a, b) else "MISMATCH"
        print(f"  s={s:2} chain={chain[s]:#018x} extracted={a:#018x} alt={b:#018x}  {ok}")

# also test with poly candidate derived differently, e.g. tab[1] flipped
poly2 = poly ^ (1 << 63)
tab2 = gen_tab_msb(poly2)
st = known[8]
chain2 = {8: st}
for s in range(9, 65):
    st = ((st << 8) & MASK) ^ tab2[(st >> 56) & 0xFF]
    chain2[s] = st
print()
print("== same with poly top bit flipped ==")
for s in range(9, 31):
    if s in known:
        a = known[s]
        b = a ^ (1 << 63)
        ok = "MATCH" if chain2[s] in (a, b) else "MISMATCH"
        print(f"  s={s:2} chain2={chain2[s]:#018x}  {ok}")
