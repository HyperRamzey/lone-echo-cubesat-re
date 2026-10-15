#!/usr/bin/env python
# Read-only live module dumper for the running game process.
# usage: python dump_mod.py <pid> <outdir> <substr1[,substr2...]>
# prints all modules (base/size/path) and dumps matches to <outdir>\<name>_<base>.bin
import ctypes, sys, os
from ctypes import wintypes

pid = int(sys.argv[1]); outdir = sys.argv[2]
subs = [s.lower() for s in sys.argv[3].split(',')]
os.makedirs(outdir, exist_ok=True)

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
LIST_MODULES_ALL = 3

class MODULEINFO(ctypes.Structure):
    _fields_ = [('lpBaseOfDll', ctypes.c_void_p),
                ('SizeOfImage', wintypes.DWORD),
                ('EntryPoint', ctypes.c_void_p)]

k32 = ctypes.WinDLL('kernel32', use_last_error=True)
psapi = ctypes.WinDLL('psapi', use_last_error=True)

k32.OpenProcess.restype = wintypes.HANDLE
h = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
if not h:
    raise SystemExit(f"OpenProcess failed: {ctypes.get_last_error()}")
print(f"opened pid {pid}")

arr = (wintypes.HMODULE * 4096)()
needed = wintypes.DWORD()
if not psapi.EnumProcessModulesEx(h, arr, ctypes.sizeof(arr), ctypes.byref(needed), LIST_MODULES_ALL):
    raise SystemExit(f"EnumProcessModulesEx failed: {ctypes.get_last_error()}")
count = needed.value // ctypes.sizeof(wintypes.HMODULE)
print(f"{count} modules")

psapi.GetModuleBaseNameW.argtypes = [wintypes.HANDLE, wintypes.HMODULE, wintypes.LPWSTR, wintypes.DWORD]
psapi.GetModuleFileNameExW.argtypes = [wintypes.HANDLE, wintypes.HMODULE, wintypes.LPWSTR, wintypes.DWORD]
psapi.GetModuleInformation.argtypes = [wintypes.HANDLE, wintypes.HMODULE, ctypes.POINTER(MODULEINFO), wintypes.DWORD]

def modname(hm):
    b = ctypes.create_unicode_buffer(260)
    psapi.GetModuleBaseNameW(h, hm, b, 260)
    return b.value

def modpath(hm):
    b = ctypes.create_unicode_buffer(1024)
    psapi.GetModuleFileNameExW(h, hm, b, 1024)
    return b.value

RPM = k32.ReadProcessMemory
RPM.restype = wintypes.BOOL
RPM.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]

def read(addr, size):
    buf = ctypes.create_string_buffer(size)
    got = ctypes.c_size_t(0)
    if not RPM(h, ctypes.c_void_p(addr), buf, size, ctypes.byref(got)):
        return None
    return buf.raw[:got.value]

for i in range(count):
    hm = arr[i]
    name = modname(hm); path = modpath(hm)
    mi = MODULEINFO()
    psapi.GetModuleInformation(h, hm, ctypes.byref(mi), ctypes.sizeof(mi))
    base = int(mi.lpBaseOfDll or 0); size = int(mi.SizeOfImage)
    print(f"  {base:#012x} {size:#010x} {name}  {path}")
    low = name.lower() + '|' + path.lower()
    if any(s in low for s in subs):
        out = os.path.join(outdir, f"{name}_{base:x}.bin")
        data = read(base, size)
        if data is None:
            print("    READ FAILED")
            continue
        with open(out, 'wb') as f:
            f.write(data)
        print(f"    dumped -> {out} ({len(data)} bytes)")
print("done")
