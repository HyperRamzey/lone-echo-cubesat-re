#!/usr/bin/env python
# Map file offsets to RVAs in the tracker DLL; disassemble around the unknown constants.
import struct

path = r'C:\Users\admin\AppData\Local\Temp\opencode\le_re\cubesat_quest_global.dll'
dll = open(path, 'rb').read()
IMAGE_BASE = 0x180000000

pe = struct.unpack('<I', dll[0x3C:0x40])[0]
nsec = struct.unpack('<H', dll[pe + 6:pe + 8])[0]
opt = pe + 24
soff = opt + struct.unpack('<H', dll[pe + 20:pe + 22])[0]
secs = []
for i in range(nsec):
    b = soff + i * 40
    name = dll[b:b + 8].rstrip(b'\x00').decode('ascii', 'replace')
    vsz, va, rawsz, raw = struct.unpack('<IIII', dll[b + 8:b + 24])
    secs.append((name, va, raw, rawsz))
    print(f"  {name:8} VA {va:#x} raw {raw:#x} size {rawsz:#x}")


def to_rva(off):
    for name, va, raw, rawsz in secs:
        if raw <= off < raw + rawsz:
            return va + (off - raw)
    return None


import capstone
cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
cs.detail = False

consts = [0xA642026AC86E4BA9, 0x6ECF46A27E30A8A9, 0x0E4781FFED010801]
for h in consts:
    b = struct.pack('<Q', h)
    pos = 0
    print(f"===== {h:#018x} =====")
    while True:
        i = dll.find(b, pos)
        if i < 0:
            break
        pos = i + 1
        rva = to_rva(i)
        print(f"  file {i:#x} -> RVA {rva:#x} (VA {IMAGE_BASE + rva:#x})")
        # disassemble window [i-0x60, i+0x40]
        start = max(0, i - 0x60)
        code = dll[start:i + 0x48]
        va = IMAGE_BASE + to_rva(start)
        for ins in cs.disasm(code, va):
            mark = ' <==' if (ins.address <= IMAGE_BASE + rva < ins.address + ins.size) else ''
            print(f"    {ins.address:#x} {ins.mnemonic:8} {ins.op_str}{mark}")
        print()
