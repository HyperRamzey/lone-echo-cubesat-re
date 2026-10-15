#!/usr/bin/env python
# Render all_dialog.json as a single markdown file grouped by module.
import json

d = json.load(open(r'C:\Users\admin\AppData\Local\Temp\opencode\le_re\all_dialog.json', encoding='utf-8'))
mods = sorted(d.items(), key=lambda kv: kv[0])
total = sum(len(v['lines']) for _, v in mods)
out = []
out.append('# Lone Echo — dialogue dump (all quest scripts)')
out.append('')
out.append(f'Source: compiled per-scene script DLLs in `_data/5828984418/win7/primary/b074cf486db462a7/v2997918933/`.')
out.append(f'Modules with dialogue: {len(mods)}. Total lines: {total}.')
out.append('Module headings are script names where recoverable, else the DLL filename (stable ID).')
out.append('Parentheticals like `(alt)`, `(concerned)` are engine direction markers stored with the lines.')
out.append('')
for name, v in mods:
    out.append(f'## {name}  ({len(v["lines"])} lines, {v["file"]})')
    out.append('')
    for line in v['lines']:
        out.append(f'- {line}')
    out.append('')
open(r'C:\Users\admin\AppData\Local\Temp\opencode\le_re\ALL_DIALOGUE.md', 'w', encoding='utf-8').write('\n'.join(out))
print(f'wrote ALL_DIALOGUE.md ({total} lines, {len(mods)} modules)')
