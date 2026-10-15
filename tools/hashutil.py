#!/usr/bin/env python
# Final Lone Echo string hash: H(name) = CRC64(seed=0, tolower(name)) ^ F(len).
# Table emulated from exe code at RVA 0x8d110 (verified vs live table);
# F(L) derived as mode of (registry_h ^ crc0) per length.
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


TAB = emu_table()
F = {}


def _load_F():
    global F
    if F:
        return F
    per = collections.defaultdict(collections.Counter)
    for line in open(r'C:\Users\admin\AppData\Local\Temp\opencode\le_re\registry_exe.tsv', encoding='utf-8'):
        pp = line.rstrip('\n').split('\t')
        if len(pp) == 3 and pp[0] != 'off':
            h, name = int(pp[1], 16), pp[2]
            per[len(name)][h ^ crc0(name)] += 1
    for L, c in per.items():
        top, cnt = c.most_common(1)[0]
        if cnt >= 2 or len(c) == 1:
            F[L] = top
    return F


def crc0(s):
    st = 0
    for ch in s:
        c = ord(ch)
        if 0x41 <= c <= 0x5A:
            c += 0x20
        st = TAB[(st >> 56) & 0xFF] ^ ((st << 8) & M) ^ c
    return st


def H(name):
    _load_F()
    return crc0(name) ^ F[len(name)]


if __name__ == '__main__':
    _load_F()
    print(f"F table: {len(F)} lengths")
    checks = [
        ('normal', 0x41d2c932082e0612),
        ('Normal', 0x41d2c932082e0612),
        ('UpdateObjectives', 0x986B5CA0E864B14F),
        ('PlaybackAudio', 0xD02BC9E37DFD4CB3),
        ('StopPlayback', 0xF8C99A96227057A1),
        ('UpdateObjective', 0x260899432029E7B7),
        ('PlaybackStopped', 0x3DB3DD4D1F740A0C),
    ]
    for name, expect in checks:
        got = H(name)
        print(f"  H({name!r})={got:#018x} expect={expect:#018x} {'OK' if got == expect else 'FAIL'}")
    # full re-verify
    n_ok = n_tot = 0
    fails = []
    for line in open(r'C:\Users\admin\AppData\Local\Temp\opencode\le_re\registry_exe.tsv', encoding='utf-8'):
        pp = line.rstrip('\n').split('\t')
        if len(pp) == 3 and pp[0] != 'off':
            h, name = int(pp[1], 16), pp[2]
            n_tot += 1
            if len(name) in F and H(name) == h:
                n_ok += 1
            else:
                fails.append((name, h))
    print(f"full verify: {n_ok}/{n_tot}")
    for name, h in fails[:25]:
        print(f"  FAIL L={len(name)} {name!r} reg={h:#018x}")
