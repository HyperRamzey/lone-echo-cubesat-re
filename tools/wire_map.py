#!/usr/bin/env python
# Extract full (event_hash, counter_offset, threshold) wiring from dispatch chains.
import struct
import capstone

path = r'C:\Users\admin\AppData\Local\Temp\opencode\le_re\cubesat_quest_global.dll'
dll = open(path, 'rb').read()
IMAGE_BASE = 0x180000000
TVA, TRAW = 0x1000, 0x400

cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
# region covering both chains: file 0x29300-0x2a800 approx (RVA 0x29f00+)
start, end = 0x29000, 0x2b000
code = dll[start:end]
insns = list(cs.disasm(code, IMAGE_BASE + (start - TRAW + TVA)))
print(f"disassembled {len(insns)} insns")
# walk: find movabs rax, H followed by cmp [rdi], rax
triples = []
for k, ins in enumerate(insns):
    if ins.mnemonic == 'movabs' and ins.op_str.startswith('rax, 0x'):
        h = int(ins.op_str.split(',')[1].strip(), 16)
        # next should be cmp qword ptr [rdi], rax
        if k + 1 < len(insns) and insns[k + 1].mnemonic == 'cmp' and '[rdi]' in insns[k + 1].op_str:
            # scan ahead up to 12 insns for cmp dword [rax+OFF], THR and inc dword [rcx+OFF]
            off = thr = None
            for j in range(k + 2, min(k + 14, len(insns))):
                o = insns[j]
                if o.mnemonic == 'cmp' and 'dword ptr [rax +' in o.op_str:
                    try:
                        off = int(o.op_str.split('[rax +')[1].split(']')[0], 16)
                        thr = int(o.op_str.split(',')[1].strip(), 16)
                    except ValueError:
                        pass
                if o.mnemonic == 'inc' and 'dword ptr [rcx +' in o.op_str:
                    try:
                        ioff = int(o.op_str.split('[rcx +')[1].split(']')[0], 16)
                    except ValueError:
                        ioff = None
                    triples.append((h, off, thr, ioff))
                    break
print(f"wired arms: {len(triples)}")
for h, off, thr, ioff in triples:
    print(f"  evt={h:#018x} check_off={off} thr={thr} inc_off={ioff}")
