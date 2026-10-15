#!/usr/bin/env python
# Test hash models against all registry pairs.
# Model family: h = A(L) ^ XOR_i (term_i) ; term_i involves T(c_i) and MUL(shift_i).
# MUL(0..7) = 256^s observed. MUL(8) = 0x2b5926535897936a observed.
# Hypothesis: MUL(s) = 256^s mod p with p = 2^64 - MUL(8).
import collections

M8 = 0x2b5926535897936a
MOD64 = 1 << 64
p_hyp = MOD64 - M8

rows = []
for line in open(r'C:\Users\admin\AppData\Local\Temp\opencode\le_re\registry_exe.tsv', encoding='utf-8'):
    pp = line.rstrip('\n').split('\t')
    if len(pp) == 3 and pp[0] != 'off':
        rows.append((int(pp[0], 16), int(pp[1], 16), pp[2]))

def T(c):
    return ((ord(c) & 0xDF) ^ 0x06) & 0xFF

# sanity: primality of p_hyp (Miller-Rabin)
def is_prime(n):
    if n < 2:
        return False
    for sp in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]:
        if n % sp == 0:
            return n == sp
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]:
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True

print(f"p_hyp = 2^64 - M8 = {p_hyp:#018x}")
print(f"p_hyp prime? {is_prime(p_hyp)}")
for s in range(0, 13):
    m_modp = pow(256, s, p_hyp)
    m_pure = pow(256, s, MOD64)
    print(f"  MUL({s:2}): mod-p = {m_modp:#018x}   mod-2^64 = {m_pure:#018x}")

# collect Hamming-1 pairs
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
            pairs.append((L, i, na, nb, ha ^ hb))

print(f"\ntotal Hamming-1 pairs: {len(pairs)}")

def check_model(name, mulfn, mode):
    """mode: 'xor_prod' => dh = (T1*M)^(T2*M) ; 'dt_prod' => dh = (T1^T2)*M mod 2^64 ;
             'sub_prod' => dh = (T1-T2)*M mod 2^64"""
    bad = []
    for L, i, na, nb, dh in pairs:
        s = L - 1 - i
        if s < 8:      # near-field is trivially consistent; skip to focus on far field
            continue
        M = mulfn(s)
        t1, t2 = T(na[i]), T(nb[i])
        if mode == 'xor_prod':
            pred = ((t1 * M) & (MOD64 - 1)) ^ ((t2 * M) & (MOD64 - 1))
        elif mode == 'dt_prod':
            pred = ((t1 ^ t2) * M) & (MOD64 - 1)
        else:
            pred = ((t1 - t2) * M) & (MOD64 - 1)
        if pred != dh:
            bad.append((L, i, s, na, nb, na[i], nb[i], dh, pred))
    return bad

for mode in ('xor_prod', 'dt_prod', 'sub_prod'):
    bad = check_model(mode, lambda s: pow(256, s, p_hyp), mode)
    print(f"\nmode={mode} (mod-p MUL): bad={len(bad)}")
    for b in bad[:6]:
        L, i, s, na, nb, ca, cb, dh, pred = b
        print(f"   L={L} i={i} s={s} {na!r} vs {nb!r} ({ca!r}->{cb!r}) dh={dh:#018x} pred={pred:#018x}")

# also test MUL as pure mod 2^64 (i.e. 0 for s>=8) for comparison
for mode in ('dt_prod',):
    bad = check_model(mode, lambda s: pow(256, s, MOD64), mode)
    print(f"\nmode={mode} (mod-2^64 MUL): bad={len(bad)}")
