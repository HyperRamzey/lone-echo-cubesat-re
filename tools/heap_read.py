#!/usr/bin/env python
# Read live process memory regions and dump with qword interpretation + module resolution.
# usage: python heap_read.py <pid> <addr_hex> <len_hex> [<addr_hex> <len_hex> ...]
import ctypes, re, struct, sys
from ctypes import wintypes

pid = int(sys.argv[1])
regions = []
rest = sys.argv[2:]
for i in range(0, len(rest), 2):
    regions.append((int(rest[i], 16), int(rest[i + 1], 16)))

LOG = r"C:\Users\admin\AppData\Local\Temp\opencode\le_re\dump_mod.log"
mods = []
with open(LOG, encoding='utf-8-sig', errors='replace') as f:
    for line in f:
        m = re.match(r'\s+(0x[0-9a-f]+) (0x[0-9a-f]+) (\S+)  (.*)$', line)
        if m:
            mods.append((int(m.group(1), 16), int(m.group(2), 16), m.group(3)))

def modof(addr):
    for base, size, name in mods:
        if base <= addr < base + size:
            return name, addr - base
    return None, None

k32 = ctypes.WinDLL('kernel32', use_last_error=True)
h = k32.OpenProcess(0x400 | 0x10, False, pid)
if not h:
    raise SystemExit(f"OpenProcess failed {ctypes.get_last_error()}")
RPM = k32.ReadProcessMemory
RPM.restype = wintypes.BOOL
RPM.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]

def cstr(addr, maxlen=96):
    buf = ctypes.create_string_buffer(512)
    got = ctypes.c_size_t(0)
    if not RPM(h, ctypes.c_void_p(addr), buf, 512, ctypes.byref(got)) or not got.value:
        return None
    b = buf.raw[:got.value]
    end = b.find(b'\x00')
    if end <= 0:
        return None
    s = b[:min(end, maxlen)]
    if all(32 <= c < 127 for c in s):
        return s.decode()
    return None

for addr, ln in regions:
    buf = ctypes.create_string_buffer(ln)
    got = ctypes.c_size_t(0)
    ok = RPM(h, ctypes.c_void_p(addr), buf, ln, ctypes.byref(got))
    if not ok:
        print(f"# read failed at {addr:#x} (err {ctypes.get_last_error()})")
        continue
    data = buf.raw[:got.value]
    print(f"\n### {addr:#x}..{addr + ln:#x} ({len(data)} bytes)")
    for off in range(0, len(data), 32):
        chunk = data[off:off + 32]
        asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in chunk)
        print(f"{addr + off:#014x}  {chunk.hex(' ')}  {asc}")
    print("-- qwords --")
    for off in range(0, len(data) - 7, 8):
        v = struct.unpack_from('<Q', data, off)[0]
        if not v:
            continue
        name, rva = modof(v)
        note = ""
        if name:
            note = f" -> {name}+{rva:#x}"
            s = cstr(v)
            if s:
                note += f'  "{s}"'
        lo = v & 0xFFFFFFFF
        if lo and not name and 0x1000 <= v < (1 << 48):
            note = f" (lo={lo:#x} hi={v >> 32:#x})"
        if name or (v > 0x10000 and not name):
            print(f"  [{off:#06x}] {addr + off:#014x} = {v:#018x}{note}")
