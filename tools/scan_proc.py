#!/usr/bin/env python
# Scan the whole game process memory for the five tracker constants (LE qwords).
import ctypes, struct, sys
from ctypes import wintypes

pid = int(sys.argv[1])
extra_strings = sys.argv[2:] if len(sys.argv) > 2 else []

k32 = ctypes.WinDLL('kernel32', use_last_error=True)

class MBI(ctypes.Structure):
    _fields_ = [('BaseAddress', ctypes.c_ulonglong),
                ('AllocationBase', ctypes.c_ulonglong),
                ('AllocationProtect', wintypes.DWORD),
                ('__a1', wintypes.DWORD),
                ('RegionSize', ctypes.c_ulonglong),
                ('State', wintypes.DWORD),
                ('Protect', wintypes.DWORD),
                ('Type', wintypes.DWORD),
                ('__a2', wintypes.DWORD)]

PROCESS_QUERY_INFORMATION = 0x400
PROCESS_VM_READ = 0x0010
h = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
if not h:
    raise SystemExit(f"OpenProcess failed {ctypes.get_last_error()}")

k32.VirtualQueryEx.restype = ctypes.c_size_t
k32.VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.POINTER(MBI), ctypes.c_size_t]
RPM = k32.ReadProcessMemory
RPM.restype = wintypes.BOOL
RPM.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]

consts = [0xF55FB2B40DCABB9A, 0xA642026AC86E4BA9, 0x41D2C932082E0612,
          0x6ECF46A27E30A8A9, 0x0E4781FFED010801]
pats = [(struct.pack('<Q', c), c) for c in consts]
spats = [(s.encode(), s) for s in extra_strings]

CH = 4 * 1024 * 1024
addr = 0x10000
max_addr = 0x7FFFFFFFFFFF
hits = []
shits = []
scanned = 0
regions = 0

while addr < max_addr:
    mbi = MBI()
    if not k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
        addr += 0x1000
        continue
    base = mbi.BaseAddress
    size = mbi.RegionSize
    if not size:
        addr += 0x1000
        continue
    prot = mbi.Protect
    readable = (mbi.State == 0x1000) and (prot & 0x06 in (0x02, 0x04, 0x06)) and not (prot & 0x100)
    if readable and mbi.Type in (0x10000, 0x20000, 0x40000):  # PRIVATE, MAPPED, IMAGE
        regions += 1
        off = 0
        while off < size:
            n = min(CH, size - off)
            buf = ctypes.create_string_buffer(n)
            got = ctypes.c_size_t(0)
            if RPM(h, ctypes.c_void_p(base + off), buf, n, ctypes.byref(got)) and got.value:
                data = buf.raw[:got.value]
                for pat, c in pats:
                    pos = 0
                    while True:
                        i = data.find(pat, pos)
                        if i < 0:
                            break
                        hits.append((c, base + off + i))
                        pos = i + 1
                for pat, s in spats:
                    pos = 0
                    cnt = 0
                    while cnt < 4:
                        i = data.find(pat, pos)
                        if i < 0:
                            break
                        shits.append((s, base + off + i))
                        pos = i + 1
                        cnt += 1
                scanned += got.value
            off += n
    addr = base + size

print(f"scanned {scanned / (1024*1024):.0f} MB over {regions} regions")
print("\n== constant hits ==")
for c, a in hits[:400]:
    print(f"{c:016X} @ {a:#x}")
print(f"total constant hits: {len(hits)}")
print("\n== string hits ==")
for s, a in shits[:80]:
    print(f"{s} @ {a:#x}")
print(f"total string hits: {len(shits)}")
