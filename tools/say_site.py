#!/usr/bin/env python
# Disassemble around a KNOWN sharing line hash to map say-descriptor slots.
import struct
import capstone

path = r'C:\Users\admin\AppData\Local\Temp\opencode\le_re\cubesat_quest_global.dll'
dll = open(path, 'rb').read()
IMAGE_BASE = 0x180000000
# .text VA 0x1000 raw 0x400
TVA, TRAW = 0x1000, 0x400


def to_rva(off):
    return off - TRAW + TVA


cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
target = struct.pack('<Q', 0xa7c3909e04f2f446)  # CUBSAT_0110_SHARING_WITH_LIV
pos = 0
n = 0
while True:
    i = dll.find(target, pos)
    if i < 0 or n >= 3:
        break
    pos = i + 1
    n += 1
    print(f"===== occ {n} file {i:#x} RVA {to_rva(i):#x} =====")
    start = max(0, i - 0x80)
    code = dll[start:i + 0x50]
    for ins in cs.disasm(code, IMAGE_BASE + to_rva(start)):
        mark = ' <==' if (ins.address <= IMAGE_BASE + to_rva(i) < ins.address + ins.size) else ''
        print(f"    {ins.address:#x} {ins.mnemonic:8} {ins.op_str}{mark}")
    print()
