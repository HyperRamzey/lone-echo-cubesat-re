#!/usr/bin/env python
# Scan binaries for the MUL/table constants (little-endian qword occurrences).
import os, struct

targets = {
    "M8": 0x2b5926535897936a,
    "M11": 0xec5c10c7baa6e079,
    "M12": 0xff6116d9ff702146,
}

files = [r"C:\Games\Lone Echo\loneecho.exe"]
d = r"C:\Users\admin\AppData\Local\Temp\opencode\le_re\live"
files += [os.path.join(d, f) for f in os.listdir(d) if f.endswith('.bin')]

for path in files:
    try:
        data = open(path, 'rb').read()
    except OSError:
        continue
    hits = []
    for name, v in targets.items():
        b = struct.pack('<Q', v)
        pos = 0
        n = 0
        first = []
        while True:
            i = data.find(b, pos)
            if i < 0:
                break
            n += 1
            if len(first) < 3:
                first.append(hex(i))
            pos = i + 1
        if n:
            hits.append(f"{name}x{n}@{','.join(first)}")
    if hits:
        print(f"{os.path.basename(path)}: {' '.join(hits)}")
