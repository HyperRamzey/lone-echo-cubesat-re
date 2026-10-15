#!/usr/bin/env python
import re, sys
sys.path.insert(0, r'C:\Users\admin\AppData\Local\Temp\opencode\le_re')
from hashutil import H, F, _load_F

_load_F()
asm = open(r'C:\Users\admin\AppData\Local\Temp\opencode\le_re\tracker_text.asm').read().splitlines()
dll = open(r'C:\Users\admin\AppData\Local\Temp\opencode\le_re\cubesat_quest_global.dll', 'rb').read()
strs = set(m.decode('ascii') for m in re.findall(rb'[ -~]{4,}', dll))
h2n = {}
for s in strs:
    if len(s) in F:
        try:
            h2n[H(s)] = s
        except KeyError:
            pass
seen = set()
for l in asm:
    a = int(l.split()[0], 16)
    if 0x1800054e0 <= a <= 0x180005700 and 'movabs' in l:
        m = re.search(r'0x[0-9a-f]{16}', l)
        if m:
            h = int(m.group(0), 16)
            if h not in seen:
                seen.add(h)
                print(hex(h), h2n.get(h, '???'))
