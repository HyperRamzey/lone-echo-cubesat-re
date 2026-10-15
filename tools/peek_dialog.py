#!/usr/bin/env python
import json
d = json.load(open(r'C:\Users\admin\AppData\Local\Temp\opencode\le_re\all_dialog.json', encoding='utf-8'))
big = sorted(d.items(), key=lambda kv: -len(kv[1]['lines']))[:3]
for name, v in big:
    print('===== ' + name + ' (' + v['file'] + ') ' + str(len(v['lines'])) + ' lines =====')
    for line in v['lines'][:12]:
        print('  ' + line[:150])
