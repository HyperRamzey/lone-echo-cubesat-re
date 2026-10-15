#!/usr/bin/env python
# Extract empirical MUL(shift) table assuming dh = delta * MUL(s) mod 2^64.
import collections

MOD = 1 << 64

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

print(f"shifts with pairs: {sorted(per_shift)}")
print()
MUL = {}
for s in sorted(per_shift):
    cands = collections.Counter()
    odd_done = False
    for delta, dh, na, nb in per_shift[s]:
        if delta == 0:
            continue
        if delta & 1:
            m = dh * pow(delta, -1, MOD) % MOD
            cands[m] += 1
            odd_done = True
        else:
            k = (delta & -delta).bit_length() - 1
            if (dh & (delta & -delta) - 1) or dh % (delta & -delta) != 0:
                continue
            # v2 checks: need v2(dh) >= k
            if dh % (1 << k) != 0:
                continue
            u = delta >> k
            base = (dh >> k) * pow(u, -1, MOD >> k) % (MOD >> k)
            for j in range(1 << k):
                cands[base + (j << (64 - k))] += 1
    names_ok = {}
    for m, c in cands.items():
        # validate against ALL pairs of this shift
        good = all((delta * m) % MOD == dh for delta, dh, _, _ in per_shift[s])
        if good:
            MUL[s] = m
            names_ok[m] = c
    print(f"s={s:2} pairs={len(per_shift[s]):3} consistent-MULs: "
          f"{ {hex(m): c for m, c in names_ok.items()} if names_ok else 'NONE'}")

print()
print("== MUL table ==")
for s in sorted(MUL):
    print(f"  MUL({s:2}) = {MUL[s]:#018x}")
