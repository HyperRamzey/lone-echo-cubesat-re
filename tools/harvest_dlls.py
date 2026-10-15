#!/usr/bin/env python
# Harvest strings from all 561 scene DLLs; match against 4 unknown hashes.
import os, re, sys, time
sys.path.insert(0, r'C:\Users\admin\AppData\Local\Temp\opencode\le_re')
from hashutil import TAB, F, _load_F

_load_F()
M = (1 << 64) - 1
TARGETS = {0xF55FB2B40DCABB9A: 'A', 0xA642026AC86E4BA9: 'B',
           0x6ECF46A27E30A8A9: 'C', 0x0E4781FFED010801: 'D'}
TABL, FL = TAB, F
trans = bytes((c + 0x20 if 0x41 <= c <= 0x5A else c) for c in range(256))


def Hstr(s):
    bs = s.translate(trans)
    st = 0
    for b in bs:
        st = TABL[(st >> 56) & 0xFF] ^ ((st << 8) & M) ^ b
    return st ^ FL[len(bs)]


dd = r'C:\Games\Lone Echo\_data\5828984418\win7\primary\b074cf486db462a7\v2997918933'
t0 = time.time()
nfiles = nhash = 0
for fn in sorted(os.listdir(dd)):
    if not fn.endswith('.dll'):
        continue
    nfiles += 1
    data = open(os.path.join(dd, fn), 'rb').read()
    seen = set()
    for m in re.findall(rb'[ -~]{4,128}', data):
        if m in seen:
            continue
        seen.add(m)
        if len(m) not in FL:
            continue
        nhash += 1
        h = Hstr(m)
        if h in TARGETS:
            print(f"HIT {h:#018x} ({TARGETS[h]}) = {m!r} in {fn}", flush=True)
print(f"done: {nfiles} files, {nhash} hashed, {time.time()-t0:.1f}s")
