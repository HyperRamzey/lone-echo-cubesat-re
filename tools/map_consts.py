#!/usr/bin/env python
# Map tracker-module strings -> hashes; find which hashes occur in the DLL.
import struct, sys
sys.path.insert(0, r'C:\Users\admin\AppData\Local\Temp\opencode\le_re')
from hashutil import H, F, _load_F

_load_F()
dll = open(r'C:\Users\admin\AppData\Local\Temp\opencode\le_re\cubesat_quest_global.dll', 'rb').read()

strings = [l.rstrip('\n') for l in open(
    r'C:\Users\admin\AppData\Local\Temp\opencode\le_re\ee298_strings.txt', encoding='utf-8', errors='replace')]
print(f"strings: {len(strings)}, dll bytes: {len(dll)}")

targets = {0xF55FB2B40DCABB9A, 0xA642026AC86E4BA9, 0x6ECF46A27E30A8A9,
           0x0E4781FFED010801, 0x41D2C932082E0612}
print("== target constants ==")
hits = []
n_hashable = 0
for s in strings:
    if not s or len(s) not in F:
        continue
    n_hashable += 1
    h = H(s)
    if h in targets:
        c = dll.count(struct.pack('<Q', h))
        print(f"  {h:#018x} = H({s!r})  occurs {c}x in DLL")
        hits.append(s)
print(f"hashable strings: {n_hashable}")

print()
print("== all strings whose hash occurs in DLL (>=1x) ==")
found = []
for s in strings:
    if not s or len(s) not in F:
        continue
    h = H(s)
    c = dll.count(struct.pack('<Q', h))
    if c:
        found.append((c, h, s))
found.sort(reverse=True)
for c, h, s in found[:60]:
    print(f"  {c:3}x {h:#018x} {s!r}")
print(f"... total {len(found)} mapped")
