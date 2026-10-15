#!/usr/bin/env python
# Hash every identifier-like string in the tracker DLL; report those whose
# hash occurs in the DLL (i.e. every name the script references by hash).
import re, struct, sys
sys.path.insert(0, r'C:\Users\admin\AppData\Local\Temp\opencode\le_re')
from hashutil import H, _load_F

_load_F()
dll = open(r'C:\Users\admin\AppData\Local\Temp\opencode\le_re\cubesat_quest_global.dll', 'rb').read()
strs = sorted(set(m.decode('ascii') for m in re.findall(rb'[ -~]{4,}', dll)))
ids = [s for s in strs if re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*', s)]
print(f"ascii runs={len(strs)} identifiers={len(ids)}")

targets = {0xF55FB2B40DCABB9A: 'COND-A?', 0xA642026AC86E4BA9: 'COND-B?',
           0x6ECF46A27E30A8A9: 'COND-C?', 0x0E4781FFED010801: 'COND-D?',
           0x41D2C932082E0612: 'normal?'}
print("== target check ==")
found = []
for s in ids:
    if len(s) not in (1, 2):
        pass
    try:
        from hashutil import F
        if len(s) not in F:
            continue
        h = H(s)
    except KeyError:
        continue
    c = dll.count(struct.pack('<Q', h))
    if c:
        tag = targets.get(h, '')
        print(f"  {c:3}x {h:#018x} {s!r} {tag}")
        found.append((s, h, c))
print(f"total mapped: {len(found)}")
