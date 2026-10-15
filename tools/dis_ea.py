#!/usr/bin/env python
# Disassemble from a live module dump (image layout: file offset == RVA).
# usage: python dis.py <dumpfile> <base_hex> <rva_hex> <len_hex> [<rva_hex> <len_hex> ...]
import sys, re
import capstone

path = sys.argv[1]
base = int(sys.argv[2], 16)
pairs = []
rest = sys.argv[3:]
for i in range(0, len(rest), 2):
    pairs.append((int(rest[i], 16), int(rest[i + 1], 16)))

d = open(path, 'rb').read()
print(f"# {path} base={base:#x} size={len(d):#x}")
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

def annot(txt, ins):
    # replace absolute addresses that fall inside this dump's image range with +rva
    def sub(m):
        try:
            v = int(m.group(0), 16)
        except ValueError:
            return m.group(0)
        if base <= v < base + len(d):
            return f"{m.group(0)}(+{v - base:#x})"
        return m.group(0)
    return re.sub(r'0x[0-9a-f]{7,16}', sub, txt)

for rva, ln in pairs:
    code = d[rva:rva + ln]
    print(f"\n=== rva {rva:#x} len {ln:#x} ===")
    for ins in md.disasm(code, base + rva):
        ops = annot(ins.op_str, ins)
        # rip-relative target
        extra = ""
        try:
            for op in ins.operands:
                if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                    tgt = ins.address + ins.size + op.mem.disp
                    if base <= tgt < base + len(d):
                        extra = f"   ; mem-> +{tgt - base:#x}"
                    else:
                        extra = f"   ; mem-> {tgt:#x}"
                elif op.type == capstone.x86.X86_OP_IMM and ins.mnemonic in ('call', 'jmp'):
                    tgt = op.imm
                    if base <= tgt < base + len(d):
                        extra = f"   ; -> +{tgt - base:#x}"
                    elif tgt > 0x10000:
                        extra = f"   ; -> {tgt:#x}"
        except Exception:
            pass
        print(f"  +{ins.address - base:#08x}  {ins.mnemonic:8s} {ops}{extra}")
