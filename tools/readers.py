#!/usr/bin/env python
# Find all reads of event counters via [rbx+0x60]-anchored struct accesses.
import re

asm = open(r'C:\Users\admin\AppData\Local\Temp\opencode\le_re\tracker_text.asm').read().splitlines()
# offsets of interest: report counters + sharing-played + find counters
WANT = {0x18, 0x1c, 0x4c, 0x50, 0x60, 0x80,  # report per-area
        0x84, 0x40, 0x7c, 0x3c,              # sharing played 0110/0120/0130/0020
        0x08, 0x24, 0x1c, 0x34, 0x48, 0x68, 0x34, 0x68}  # find per-area (subset)
# find struct-base loads, then counter cmps shortly after
baseload = [i for i, l in enumerate(asm) if re.search(r'mov\s+r(ax|cx|dx), qword ptr \[rbx \+ 0x60\]', l)]
print(f"struct base loads: {len(baseload)}")
for i in baseload:
    for l in asm[i:i + 12]:
        m = re.search(r'(cmp|mov|inc|add|lea|and|or|xor)\s+[^[]*\[r(ax|cx|dx) \+ (0x[0-9a-f]+)\]', l)
        if m:
            off = int(m.group(3), 16)
            if off in WANT:
                op = m.group(1)
                print(f"{asm[i].split()[0]} base -> {l.strip()} [{op} off={off}]")
                break
