#!/usr/bin/env python
# Emulate the runtime table-gen function at exe RVA 0x8d110 exactly as coded,
# compare against the live generated table at 0x14360d8 and against a standard
# MSB-first CRC64 table for poly 0x2b5926535897936a, then test carryless-linearity
# of single-char deltas at shifts 8 and 9.
import struct

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


def crc_msb_table(poly):
    tab = []
    for i in range(256):
        c = i << 56
        for _ in range(8):
            if c & (1 << 63):
                c = ((c << 1) ^ poly) & M
            else:
                c = (c << 1) & M
        tab.append(c)
    return tab


def carryless(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = (a << 1) & M
        b >>= 1
    return r


tab = emu_table()
print(f"emu tab[0]={tab[0]:#018x} tab[1]={tab[1]:#018x} (expect 0x0 / 0x2b5926535897936a)")

d = open(r'C:\Users\admin\AppData\Local\Temp\opencode\le_re\live\loneecho.exe_7ff7a9180000.bin', 'rb').read()
live = struct.unpack('<' + 'Q' * 8, d[0x14360d0:0x14360d0 + 64])
print("live qwords at 0x14360d0:")
for i, q in enumerate(live):
    print(f"   [{i}] {q:#018x}   emu_tab[{i}]={tab[i]:#018x}  {'OK' if q == tab[i] else 'DIFF'}")

std = crc_msb_table(P)
nm = sum(1 for a, b in zip(tab, std) if a != b)
print(f"emu vs standard CRC64/MSB table (poly=M8): {256 - nm}/256 match")
for i in range(4):
    print(f"   tab[{i}] emu={tab[i]:#018x} std={std[i]:#018x}")

print()
print("== carryless-linearity of deltas (dh = carryless(delta, X), X = dh(delta=1)) ==")
X8 = 0x2b5926535897936a   # dh(delta=1) at shift 8, direct from pairs
M9 = 0x1520c15ca86529ae   # dh(delta=1) at shift 9, direct from body0/1component pair
tests = [
    (0x1E, 0x148D82449EB4C68C, X8, 's=8 L->R'),
    (0x02, 0x56B24CA6B12F26D4, X8, 's=8 x->z'),
    (0x07, 0x40BB60C401AC4F20, M9, 's=9 s->t sedgecount'),
    (0x1E, 0x9574B8E65FE1F708, M9, 's=9 L->R'),
]
for delta, obs, X, label in tests:
    pred = carryless(delta, X)
    print(f"  {label}: delta={delta:#04x} obs={obs:#018x} carryless_pred={pred:#018x} {'MATCH' if pred == obs else 'diff'}")
