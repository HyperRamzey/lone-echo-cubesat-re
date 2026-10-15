#!/usr/bin/env python
# Disassemble around find/report event hashes to determine emit vs await direction.
import struct
import capstone

path = r'C:\Users\admin\AppData\Local\Temp\opencode\le_re\cubesat_quest_global.dll'
dll = open(path, 'rb').read()
IMAGE_BASE = 0x180000000
TVA, TRAW = 0x1000, 0x400
RVA, RRAW = 0x33000, 0x31a00


def to_rva(off):
    if TRAW <= off < TRAW + 0x31600:
        return off - TRAW + TVA
    if RRAW <= off < RRAW + 0x7200:
        return off - RRAW + RVA
    return None


cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
pairs = [(0xc5c728e157f0ca17, 'evt_cube_sat_find_containers'),
         (0x3264d62625fd1911, 'evt_cube_sat_report_containers'),
         (0x8063db49081e5184, 'logs_found'),
         (0x85697efbd71916a4, 'total_sats_found')]
for h, name in pairs:
    b = struct.pack('<Q', h)
    i = dll.find(b)
    print(f"===== {name} {h:#018x} at file {i:#x} =====")
    if i < 0:
        print("  NOT FOUND")
        continue
    start = max(0, i - 0xa0)
    code = dll[start:i + 0x60]
    base = to_rva(start)
    if base is None:
        print("  (non-text/rdata?) raw bytes:", dll[i - 16:i + 24].hex())
        continue
    for ins in cs.disasm(code, IMAGE_BASE + base):
        mark = ' <==' if (ins.address <= IMAGE_BASE + to_rva(i) < ins.address + ins.size) else ''
        print(f"    {ins.address:#x} {ins.mnemonic:8} {ins.op_str}{mark}")
    print()
