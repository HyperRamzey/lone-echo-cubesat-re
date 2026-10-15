#!/usr/bin/env python
# Find code referencing the runtime hash table (live VA base+0x14360d0) via
# RIP-relative LEA scan, then dump disassembly around hits.
import struct

BASE = 0x7ff7a9180000
d = open(r'C:\Users\admin\AppData\Local\Temp\opencode\le_re\live\loneecho.exe_7ff7a9180000.bin', 'rb').read()
TAB = BASE + 0x14360d0
print(f"table VA {TAB:#x}, image size {len(d):#x}")

hits = []
i = 0
n = len(d)
while i < n - 7:
    b0 = d[i]
    if b0 in (0x48, 0x4C) and d[i + 1] == 0x8D:
        modrm = d[i + 2]
        if (modrm & 0xC7) == 0x05:  # mod=00, rm=101 -> rip+disp32
            disp = struct.unpack('<i', d[i + 3:i + 7])[0]
            tgt = BASE + i + 7 + disp
            if abs(tgt - TAB) < 0x2000:
                hits.append((i, tgt))
                i += 7
                continue
    i += 1
print(f"LEA hits near table: {len(hits)}")
for off, tgt in hits[:20]:
    print(f"  fileoff {off:#x} (VA {BASE + off:#x}) -> {tgt:#x} (delta {tgt - TAB:+#x})")
