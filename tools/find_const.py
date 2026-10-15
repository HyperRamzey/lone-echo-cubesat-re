#!/usr/bin/env python
# Search all live module dumps for known constants; report which modules contain them.
import os, struct, sys

dumps = r"C:\Users\admin\AppData\Local\Temp\opencode\le_re\live"
consts = {
    "F55FB2B40DCABB9A": 0xF55FB2B40DCABB9A,
    "A642026AC86E4BA9": 0xA642026AC86E4BA9,
    "41D2C932082E0612": 0x41D2C932082E0612,
    "6ECF46A27E30A8A9": 0x6ECF46A27E30A8A9,
    "0E4781FFED010801": 0x0E4781FFED010801,
    "UpdateObjectives": 0x986B5CA0E864B14F,
    "PlaybackAudio": 0xD02BC9E37DFD4CB3,
    "StopPlayback": 0xF8C99A96227057A1,
    "UpdateObjective": 0x260899432029E7B7,
    "PlaybackStopped": 0x3DB3DD4D1F740A0C,
}
only = sys.argv[1:] if len(sys.argv) > 1 else None

for fn in sorted(os.listdir(dumps)):
    if not fn.endswith('.bin'):
        continue
    if fn.startswith('loneecho.exe'):
        continue
    p = os.path.join(dumps, fn)
    try:
        d = open(p, 'rb').read()
    except OSError:
        continue
    hits = []
    for name, v in consts.items():
        if only and name not in only:
            continue
        n = d.count(struct.pack('<Q', v))
        if n:
            hits.append(f"{name}x{n}")
    if hits:
        print(f"{fn}  [{' '.join(hits)}]")
