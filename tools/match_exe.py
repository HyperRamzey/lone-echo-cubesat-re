#!/usr/bin/env python
# Bulk-match exe strings against the 4 unknown condition hashes.
import sys, time
sys.path.insert(0, r'C:\Users\admin\AppData\Local\Temp\opencode\le_re')
from hashutil import TAB, F, _load_F

_load_F()
M = (1 << 64) - 1
TARGETS = {0xF55FB2B40DCABB9A: 'A', 0xA642026AC86E4BA9: 'B',
           0x6ECF46A27E30A8A9: 'C', 0x0E4781FFED010801: 'D'}
TABL = TAB
FL = F
trans = bytes((c + 0x20 if 0x41 <= c <= 0x5A else c) for c in range(256))

t0 = time.time()
n = nskip = 0
seen = set()
for line in open(r'C:\Users\admin\AppData\Local\Temp\opencode\le_exe_strings.txt', encoding='utf-8', errors='replace'):
    s = line.rstrip('\n')
    L = len(s)
    if L not in FL or s in seen:
        nskip += 1
        continue
    seen.add(s)
    try:
        bs = s.encode('latin-1')
    except UnicodeEncodeError:
        nskip += 1
        continue
    n += 1
    bs = bs.translate(trans)
    st = 0
    for b in bs:
        st = TABL[(st >> 56) & 0xFF] ^ ((st << 8) & M) ^ (b if b < 0x80 else (b | 0xFFFFFFFFFFFFFF00))
    h = st ^ FL[L]
    if h in TARGETS:
        print(f"HIT {h:#018x} ({TARGETS[h]}) = {s!r}", flush=True)
print(f"hashed {n}, skipped {nskip}, {time.time()-t0:.1f}s")
