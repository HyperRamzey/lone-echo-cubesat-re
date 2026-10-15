#!/usr/bin/env python
import struct
import capstone

path = r'C:\Users\admin\AppData\Local\Temp\opencode\le_re\cubesat_quest_global.dll'
dll = open(path, 'rb').read()
IMAGE_BASE = 0x180000000
TVA, TRAW = 0x1000, 0x400
cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
for h in (0x8787dc832e5b6bdf, 0x8787dc832e5b6bdc, 0x8787dc832e5b6bdd):
    b = struct.pack('<Q', h)
    i = dll.find(b)
    print(f"===== {h:#018x} at file {i:#x} =====")
    start = max(0, i - 0x50)
    code = dll[start:i + 0x90]
    for ins in cs.disasm(code, IMAGE_BASE + (start - TRAW + TVA)):
        mark = ' <==' if (ins.address <= IMAGE_BASE + (i - TRAW + TVA) < ins.address + ins.size) else ''
        print(f"    {ins.address:#x} {ins.mnemonic:8} {ins.op_str}{mark}")
    print()
