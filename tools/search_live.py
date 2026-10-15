#!/usr/bin/env python
# Search a live module dump for a qword value / ascii string and print neighborhoods,
# resolving pointers via the module map from dump_mod.log.
import struct, re, sys, os

LIVE = r"C:\Users\admin\AppData\Local\Temp\opencode\le_re\live"
LOG = r"C:\Users\admin\AppData\Local\Temp\opencode\le_re\dump_mod.log"

mods = []
with open(LOG, encoding='utf-8-sig', errors='replace') as f:
    for line in f:
        m = re.match(r'\s+(0x[0-9a-f]+) (0x[0-9a-f]+) (\S+)  (.*)$', line)
        if m:
            mods.append((int(m.group(1), 16), int(m.group(2), 16), m.group(3), m.group(4).strip()))

def modof(addr):
    for base, size, name, path in mods:
        if base <= addr < base + size:
            return name, addr - base
    return None, None

dump_path = sys.argv[1]
base = int(sys.argv[2], 16)
d = open(dump_path, 'rb').read()

qwords = [int(x, 16) for x in sys.argv[3].split(',') if x]
strings = sys.argv[4].split(',') if len(sys.argv) > 4 and sys.argv[4] else []

def rd(addr):
    # read bytes at absolute address if inside this dump
    if base <= addr < base + len(d):
        return d[addr - base:addr - base + 64]
    return None

def cstr_at_any(addr, maxlen=64):
    b = rd(addr)
    if not b:
        return None
    end = b.find(b'\x00')
    if end <= 0:
        return None
    s = b[:end]
    if all(32 <= c < 127 for c in s):
        return s.decode()
    return None

print("== qword hits ==")
for q in qwords:
    pat = struct.pack('<Q', q)
    pos = 0
    n = 0
    while n < 12:
        i = d.find(pat, pos)
        if i < 0:
            break
        n += 1
        rva = i
        print(f"\n{q:#018x} @ +{rva:#x}")
        for k in range(-4, 5):
            if k == 0:
                continue
            o = rva + 8 * k
            if o < 0 or o + 8 > len(d):
                continue
            v = struct.unpack_from('<Q', d, o)[0]
            note = ""
            name, off = modof(v)
            if name:
                note = f" -> {name}+{off:#x}"
                s = cstr_at_any(v)
                if s:
                    note += f'  "{s[:48]}"'
            print(f"   {o:#08x}{k:+d}: {v:#018x}{note}")
        pos = i + 1

print("\n== string hits ==")
for s in strings:
    pat = s.encode()
    pos = 0
    n = 0
    while n < 8:
        i = d.find(pat, pos)
        if i < 0:
            break
        n += 1
        print(f"\n'{s}' @ +{i:#x}")
        for k in range(-6, 7):
            if k == 0:
                continue
            o = i + 8 * k
            if o < 0 or o + 8 > len(d):
                continue
            v = struct.unpack_from('<Q', d, o)[0]
            note = ""
            name, off = modof(v)
            if name:
                note = f" -> {name}+{off:#x}"
                s2 = cstr_at_any(v)
                if s2:
                    note += f'  "{s2[:48]}"'
            elif 0x1000 <= v < (1 << 40):
                note = f" (small: {v:#x})"
            print(f"   {o:#08x}{k:+d}: {v:#018x}{note}")
        pos = i + 1
