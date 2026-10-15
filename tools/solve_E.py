#!/usr/bin/env python
# Solve E(T,s) as a black box from Hamming-1 pairs, then test whether
# E(T,s) = tab[f(T,s)] for simple index functions f.
import collections

P = 0x2b5926535897936a
K = 0x95ac9329ac4bc9b5
M = (1 << 64) - 1


def emu_table():
    out = []
    for v in range(256):
        dl = v & 0x80
        cf = 1 if dl != 0 else 0
        r8 = M if cf else 0
        r8 &= P
        rcx = r8 ^ K
        dl = v
        for mask in (0x40, 0x20, 0x10, 0x08, 0x04, 0x02):
            zf = 1 if (dl & mask) == 0 else 0
            dl = v
            if zf:
                rcx = r8
            r8 = (rcx * 2) & M
            rcx = r8 ^ K
        cl = v
        rdx = r8 ^ K
        zf = 1 if (cl & 1) == 0 else 0
        if zf:
            rdx = r8
        rdx = (rdx * 2) & M
        out.append(rdx)
    return out


tab = emu_table()

rows = []
for line in open(r'C:\Users\admin\AppData\Local\Temp\opencode\le_re\registry_exe.tsv', encoding='utf-8'):
    pp = line.rstrip('\n').split('\t')
    if len(pp) == 3 and pp[0] != 'off':
        rows.append((int(pp[0], 16), int(pp[1], 16), pp[2]))

ALNUM = set('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz')


def T(c):
    return ((ord(c) & 0xDF) ^ 0x06) & 0xFF


bylen = collections.defaultdict(list)
for off, h, name in rows:
    if all(c in ALNUM for c in name):
        bylen[len(name)].append((name, h))

pairs = collections.defaultdict(list)
for L, names in bylen.items():
    for a in range(len(names)):
        na, ha = names[a]
        for b in range(a + 1, len(names)):
            nb, hb = names[b]
            diffs = [i for i in range(L) if na[i] != nb[i]]
            if len(diffs) != 1:
                continue
            i = diffs[0]
            pairs[L - 1 - i].append((T(na[i]), T(nb[i]), ha ^ hb, na, nb))

print(f"shifts available: {sorted(pairs)}")
# solve E per shift via union-find over GF(2) (values up to global xor const)
for s in sorted(pairs):
    parent = {}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    vals = {}

    def union(a, b, d):
        # E[a] ^ E[b] = d
        for x in (a, b):
            if x not in parent:
                parent[x] = x
                vals[x] = 0
        ra, rb = find(a), find(b)
        if ra == rb:
            return (vals[a] ^ vals[b]) == d
        parent[ra] = rb
        vals[ra] = vals[a] ^ vals[b] ^ d
        return True

    ok = True
    for t1, t2, dh, na, nb in pairs[s]:
        if not union(t1, t2, dh):
            ok = False
    comps = collections.defaultdict(list)
    for t in parent:
        comps[find(t)].append(t)
    big = max(comps.values(), key=len)
    print(f"s={s:2} pairs={len(pairs[s]):4} consistent={ok} components={len(comps)} biggest={len(big)}")

# detailed E for s=8 and s=9
for s in (8, 9, 10):
    E = {}
    Enext = collections.defaultdict(list)
    for t1, t2, dh, na, nb in pairs[s]:
        Enext[t1].append((t2, dh))
        Enext[t2].append((t1, dh))
    E[0x5E if s == 8 else (0x16 if s == 9 else 0x16)] = 0
    # BFS
    queue = list(E.keys())
    while queue:
        t = queue.pop()
        for t2, dh in Enext[t]:
            if t2 not in E:
                E[t2] = E[t] ^ dh
                queue.append(t2)
    print(f"\ns={s} solved E entries: {len(E)}")
    # test index functions: E(T) ?= tab[(T+c)&FF] ^ D
    cands = {
        'T+s': lambda T0: (T0 + s) & 0xFF,
        'T^s': lambda T0: (T0 ^ s) & 0xFF,
        'T+8s': lambda T0: (T0 + 8 * s) & 0xFF,
        'T^8s': lambda T0: (T0 ^ (8 * s)) & 0xFF,
        'T': lambda T0: T0 & 0xFF,
    }
    for nm, fn in cands.items():
        Ds = collections.Counter(E[t] ^ tab[fn(t)] for t in E)
        top, cnt = Ds.most_common(1)[0]
        print(f"   E=tab[{nm}]^D: best D={top:#018x} covers {cnt}/{len(E)}")
