#!/usr/bin/env python
# Try candidate 64-bit string hashes against known name->hash pairs.
M64 = (1 << 64) - 1
M32 = (1 << 32) - 1

KNOWN = {
    "UpdateObjectives": 0x986B5CA0E864B14F,
    "PlaybackAudio": 0xD02BC9E37DFD4CB3,
    "StopPlayback": 0xF8C99A96227057A1,
    "UpdateObjective": 0x260899432029E7B7,
    "PlaybackStopped": 0x3DB3DD4D1F740A0C,
}

TARGETS = {
    0xF55FB2B40DCABB9A: "?F55F",
    0xA642026AC86E4BA9: "?A642",
    0x41D2C932082E0612: "?41D2",
    0x6ECF46A27E30A8A9: "?6ECF",
    0x0E4781FFED010801: "?0E47",
    0x360D97C7A10515CF: "?360D(say v13)",
    0x86A75427E2ED3F85: "?86A7(say v16)",
    0xE32DC7DCD08145BC: "?E32D(say v17)",
}

def fnv1a64(b):
    h = 0xcbf29ce484222325
    for c in b:
        h ^= c
        h = (h * 0x100000001b3) & M64
    return h

def fnv1_64(b):
    h = 0xcbf29ce484222325
    for c in b:
        h = (h * 0x100000001b3) & M64
        h ^= c
    return h

def djb2(b):
    h = 5381
    for c in b:
        h = (h * 33 + c) & M64
    return h

def djb2a(b):
    h = 5381
    for c in b:
        h = ((h * 33) ^ c) & M64
    return h

def djb2_32(b):
    h = 5381
    for c in b:
        h = (h * 33 + c) & M32
    return h

def sdbm(b):
    h = 0
    for c in b:
        h = (c + (h << 6) + (h << 16) - h) & M64
    return h

def java_hash(b):
    h = 0
    for c in b:
        h = (h * 31 + c) & M64
    return h

def rol(x, r, bits=64):
    x &= (1 << bits) - 1
    return ((x << r) | (x >> (bits - r))) & ((1 << bits) - 1)

def crc64(data, poly, init=0, refin=False, refout=False, xorout=0):
    # build table
    tab = []
    for i in range(256):
        if refin:
            c = i
            for _ in range(8):
                c = (c >> 1) ^ (poly if c & 1 else 0)
        else:
            c = i << 56
            for _ in range(8):
                c = ((c << 1) ^ (poly if c & (1 << 63) else 0)) & M64
        tab.append(c)
    crc = init
    for byte in data:
        if refin:
            crc = tab[(crc ^ byte) & 0xFF] ^ (crc >> 8)
        else:
            crc = tab[((crc >> 56) ^ byte) & 0xFF] ^ ((crc << 8) & M64)
    return (crc ^ xorout) & M64

def murmur64a(data, seed=0):
    m = 0xc6a4a7935bd1e995
    r = 47
    h = (seed ^ (len(data) * m)) & M64
    i = 0
    n = len(data) // 8 * 8
    while i < n:
        k = int.from_bytes(data[i:i + 8], 'little')
        k = (k * m) & M64
        k ^= k >> r
        k = (k * m) & M64
        h ^= k
        h = (h * m) & M64
        i += 8
    tail = data[n:]
    if tail:
        for j, c in enumerate(tail):
            h ^= c << (8 * j)
        h = (h * m) & M64
    h ^= h >> r
    h = (h * m) & M64
    h ^= h >> r
    return h

def xxh64(data, seed=0):
    P1, P2, P3, P4, P5 = 0x9E3779B185EBCA87, 0xC2B2AE3D27D4EB4F, 0x165667B19E3779F9, 0x85EBCA77C2B2AE63, 0x27D4EB2F165667C5
    def rnd(a, inp):
        a = (a + inp * P2) & M64
        a = rol(a, 31)
        return (a * P1) & M64
    def merge(acc, val):
        val = rnd(0, val)
        acc ^= val
        return (acc * P1 + P4) & M64
    n = len(data)
    i = 0
    if n >= 32:
        v1 = (seed + P1 + P2) & M64
        v2 = (seed + P2) & M64
        v3 = seed
        v4 = (seed - P1) & M64
        while i + 32 <= n:
            v1 = rnd(v1, int.from_bytes(data[i:i + 8], 'little')); i += 8
            v2 = rnd(v2, int.from_bytes(data[i:i + 8], 'little')); i += 8
            v3 = rnd(v3, int.from_bytes(data[i:i + 8], 'little')); i += 8
            v4 = rnd(v4, int.from_bytes(data[i:i + 8], 'little')); i += 8
        h = (rol(v1, 1) + rol(v2, 7) + rol(v3, 12) + rol(v4, 18)) & M64
        h = merge(h, v1); h = merge(h, v2); h = merge(h, v3); h = merge(h, v4)
    else:
        h = (seed + P5) & M64
    h = (h + n) & M64
    while i + 8 <= n:
        h ^= rnd(0, int.from_bytes(data[i:i + 8], 'little'))
        h = (rol(h, 27) * P1 + P4) & M64
        i += 8
    if i + 4 <= n:
        h ^= (int.from_bytes(data[i:i + 4], 'little') * P1) & M64
        h = (rol(h, 23) * P2 + P3) & M64
        i += 4
    while i < n:
        h ^= (data[i] * P5) & M64
        h = (rol(h, 11) * P1) & M64
        i += 1
    h ^= h >> 33
    h = (h * P2) & M64
    h ^= h >> 29
    h = (h * P3) & M64
    h ^= h >> 32
    return h

ALGS = {
    'fnv1a64': fnv1a64, 'fnv1_64': fnv1_64,
    'djb2_64': djb2, 'djb2a_64': djb2a, 'djb2_32': djb2_32,
    'sdbm64': sdbm, 'java31_64': java_hash,
    'crc64_iso_refl': lambda b: crc64(b, 0xD800000000000000, 0, True, True, 0),
    'crc64_ecma': lambda b: crc64(b, 0x42F0E1EBA9EA3693, 0, False, False, 0),
    'crc64_xz_refl': lambda b: crc64(b, 0x42F0E1EBA9EA3693, M64, True, True, M64),
    'crc64_jones_refl': lambda b: crc64(b, 0xAD93D23594C935A9, M64, True, True, 0),
    'crc64_we_refl': lambda b: crc64(b, 0x42F0E1EBA9EA3693, M64, True, True, M64),
    'murmur64a_0': lambda b: murmur64a(b, 0),
    'murmur64a_0x2545F4914F6CDD1D': lambda b: murmur64a(b, 0x2545F4914F6CDD1D),
    'xxh64_0': lambda b: xxh64(b, 0),
    'xxh64_1': lambda b: xxh64(b, 1),
}

# transformations of the input
def variants(name):
    b = name.encode('ascii')
    out = {
        'plain': b, 'lower': name.lower().encode(), 'upper': name.upper().encode(),
        'nul': b + b'\x00', 'utf16le': name.encode('utf-16-le'),
        'utf16le_nul': name.encode('utf-16-le') + b'\x00\x00',
    }
    return out

solved = {}
for algname, fn in ALGS.items():
    for var in ('plain', 'lower', 'upper', 'nul', 'utf16le', 'utf16le_nul'):
        ok = 0
        for name, want in KNOWN.items():
            got = fn(variants(name)[var])
            if got == want:
                ok += 1
        if ok >= 2:
            print(f"ALG {algname} on {var}: matched {ok}/5")
        if ok == 5:
            solved[(algname, var)] = fn

print("\nfully solved:", list(solved.keys()) or "NONE")

# also try the siphash? left out. Try some extra seeds for murmur
if not solved:
    for seed in range(0, 64):
        ok = all(murmur64a(variants(n)['plain'], seed) == w for n, w in KNOWN.items())
        if ok:
            print("murmur64a seed", seed)

# if solved, map targets
for (algname, var), fn in solved.items():
    print(f"\n-- mapping with {algname}/{var} --")
    cands = ["CUBSAT_0110_SHARING_WITH_LIV", "CUBSAT_0120_LIV_SHARING_TWO", "CUBSAT_0130_LIV_SHARING_THREE",
             "CUBSAT_0020_LIV_LOG", "CUBSAT_0010_COMMAND_CANDIDATE",
             "logs_found", "total_sats_found", "total_sats", "last_played_log", "log_to_play",
             "playing_log", "egg_progress", "friend_made",
             "evt_cube_sat_find_stn_int", "evt_cube_sat_report_stn_int",
             "evt_cube_sat_find_ext_misc", "evt_cube_sat_report_ext_misc",
             "obj_glb_cube_sats_", "share", "Liv", "target", "echo1"]
    rev = {v: k for k, v in TARGETS.items()}
    for c in cands:
        bb = variants(c)[var] if var in variants(c) else c.encode()
        h = fn(bb)
        mark = ""
        if h in rev:
            mark = f"   <<< MATCHES {rev[h]}"
        print(f"  {c}: {h:#018x}{mark}")
