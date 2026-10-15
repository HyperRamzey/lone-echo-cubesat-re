#!/usr/bin/env python
import struct
import capstone

path = r'C:\Games\Lone Echo\_data\5828984418\win7\primary\b074cf486db462a7\v2997918933\f8f021252cbf86eb.dll'
dll = open(path, 'rb').read()
BASE = 0x180000000
TVA, TRAW = 0x1000, 0x400
cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
# POI event hashes (computed earlier)
import sys
sys.path.insert(0, r'C:\Users\admin\AppData\Local\Temp\opencode\le_re')
from hashutil import H, _load_F
_load_F()
for s in ['evt_cubesat_poi_add_liv_report_1', 'evt_cubesat_poi_add_liv_report_2', 'evt_cubesat_poi_add_liv_report_3']:
    h = H(s)
    b = struct.pack('<Q', h)
    i = dll.find(b)
    print(f"===== {s} {h:#018x} at file {i:#x} =====")
    if i < 0:
        continue
    start = max(0, i - 0xc0)
    code = dll[start:i + 0x60]
    for ins in cs.disasm(code, BASE + (start - TRAW + TVA)):
        mark = ' <==' if (ins.address <= BASE + (i - TRAW + TVA) < ins.address + ins.size) else ''
        print(f"    {ins.address:#x} {ins.mnemonic:8} {ins.op_str}{mark}")
    print()
