#!/usr/bin/env python
import struct, sys
sys.path.insert(0, r'C:\Users\admin\AppData\Local\Temp\opencode\le_re')
from hashutil import H, _load_F

_load_F()
trk = open(r'C:\Users\admin\AppData\Local\Temp\opencode\le_re\cubesat_quest_global.dll', 'rb').read()
for s in ['evt_cubesat_poi_add_liv_report_1', 'evt_cubesat_poi_add_liv_report_2',
          'evt_cubesat_poi_add_liv_report_3', 'Speak to Liv', 'event_jack_got_jacked']:
    h = H(s)
    c = trk.count(struct.pack('<Q', h))
    print(f"{h:#018x} {s!r} in-tracker:{c}x")
