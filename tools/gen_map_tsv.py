#!/usr/bin/env python
# Regenerate the identifier->hash mapping table as TSV.
import re, sys
sys.path.insert(0, r'C:\Users\admin\AppData\Local\Temp\opencode\le_re')
from hashutil import H, F, _load_F

_load_F()
dll = open(r'C:\Users\admin\AppData\Local\Temp\opencode\le_re\cubesat_quest_global.dll', 'rb').read()
import struct
strs = sorted(set(m.decode('ascii') for m in re.findall(rb'[ -~]{4,}', dll)))
ids = [s for s in strs if re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*', s)]
rows = []
for s in ids:
    if len(s) not in F:
        continue
    h = H(s)
    c = dll.count(struct.pack('<Q', h))
    if c:
        rows.append((s, hex(h), c))
rows.sort()
with open(r'C:\Users\admin\AppData\Local\Temp\opencode\le_re\quest_hashes.tsv', 'w') as f:
    f.write('name\thash64\toccurrences_in_tracker\n')
    for s, h, c in rows:
        f.write(f'{s}\t{h}\t{c}\n')
print(f'wrote {len(rows)} mappings')
