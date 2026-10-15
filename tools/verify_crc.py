#!/usr/bin/env python
# Verify: registry_hash == CRC64(seed=0, tolower(name)) ^ F(len) ?
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


def crc0(s):
    st = 0
    for ch in s:
        c = ord(ch)
        if 0x41 <= c <= 0x5A:
            c += 0x20
        st = tab[(st >> 56) & 0xFF] ^ ((st << 8) & M) ^ c
    return st


rows = []
for line in open(r'C:\Users\admin\AppData\Local\Temp\opencode\le_re\registry_exe.tsv', encoding='utf-8'):
    pp = line.rstrip('\n').split('\t')
    if len(pp) == 3 and pp[0] != 'off':
        rows.append((int(pp[1], 16), pp[2]))

bylen = collections.defaultdict(list)
for h, name in rows:
    bylen[len(name)].append((name, h, h ^ crc0(name)))

print("len : nsamples, distinct F values (h ^ crc0)")
bad = []
for L in sorted(bylen):
    Fs = collections.Counter(f for _, _, f in bylen[L])
    top = Fs.most_common(3)
    flag = '' if len(Fs) == 1 else '   <-- MULTIPLE'
    print(f"L={L:2}: n={len(bylen[L]):4} distinctF={len(Fs):3}{flag}  top={[f'{f:#018x}x{c}' for f, c in top]}")
    if len(Fs) != 1:
        # show offenders
        F0 = top[0][0]
        for name, h, f in bylen[L][:400]:
            if f != F0:
                bad.append((L, name, h))
print()
print(f"total={len(rows)} lengths with single F: {sum(1 for L in bylen if len(set(f for _,_,f in bylen[L]))==1)}/{len(bylen)}")
print("sample offenders:")
for L, name, h in bad[:15]:
    print(f"  L={L} {name!r} h={h:#018x} crc0={crc0(name):#018x}")
