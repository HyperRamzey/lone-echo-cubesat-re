#!/usr/bin/env python
# Match 4 unknown condition hashes against: all DLL strings, engine words, exe strings.
import re, struct, sys
sys.path.insert(0, r'C:\Users\admin\AppData\Local\Temp\opencode\le_re')
from hashutil import H, F, _load_F

_load_F()
TARGETS = {0xF55FB2B40DCABB9A, 0xA642026AC86E4BA9, 0x6ECF46A27E30A8A9, 0x0E4781FFED010801}

dll = open(r'C:\Users\admin\AppData\Local\Temp\opencode\le_re\cubesat_quest_global.dll', 'rb').read()
strs = sorted(set(m.decode('ascii') for m in re.findall(rb'[ -~]{4,}', dll)))
print(f"== DLL strings ({len(strs)}) vs targets ==")
for s in strs:
    if len(s) in F:
        try:
            h = H(s)
        except KeyError:
            continue
        if h in TARGETS:
            print(f"  HIT {h:#018x} = {s!r}")

words = '''event trigger condition state node enter exit true false check status update timer
signal message normal default idle active ready done start stop spawn destroy create enable
disable show hide play pause tick frame init reset clear set get value data info log audio
playback playing stopped playlog jack liv atlas sat sats cubesat report find found play
objective objectives player global script function call return enter exit area zone room
proximity distance touch scan restore transfer share shared sharing checkin log logs egg
friend made progress total all complete done first second last next prev current waypoint
marker beacon prompt nag hint tutorial lock unlock door open close pick put take grab use
voice line dialogue subtitle caption hud ui menu button press hold release hand hands touch
controller hmd head gaze look move walk teleport climb push pull throw catch fly zero gravity
grabbable highlight outline glow color red green blue white yellow objective world space station
reactor engine solar panel array antenna dish relay beacon signal strength progress'''.split()
print("== engine words vs targets ==")
for w in words:
    if len(w) in F and H(w) in TARGETS:
        print(f"  HIT {H(w):#018x} = {w!r}")
print("done words")
