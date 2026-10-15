#!/usr/bin/env python
# Full .text disassembly of tracker DLL for offline mining.
import capstone

path = r'C:\Users\admin\AppData\Local\Temp\opencode\le_re\cubesat_quest_global.dll'
dll = open(path, 'rb').read()
IMAGE_BASE = 0x180000000
code = dll[0x400:0x400 + 0x31600]
cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
lines = []
for ins in cs.disasm(code, IMAGE_BASE + 0x1000):
    lines.append(f"{ins.address:#x} {ins.mnemonic:8} {ins.op_str}")
open(r'C:\Users\admin\AppData\Local\Temp\opencode\le_re\tracker_text.asm', 'w').write('\n'.join(lines))
print(f"wrote {len(lines)} insns")
