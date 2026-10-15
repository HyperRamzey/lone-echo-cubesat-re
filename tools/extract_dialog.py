#!/usr/bin/env python
# Extract dialogue-like strings from all quest DLLs, labeled by script name.
import os, re, json

dd = r'C:\Games\Lone Echo\_data\5828984418\win7\primary\b074cf486db462a7\v2997918933'
out = {}


def script_name(data, fn):
    m = re.search(rb'in script ([A-Za-z0-9_]+) externally', data)
    if m:
        return m.group(1).decode('ascii')
    m = re.search(rb'script ([A-Za-z0-9_]+)', data)
    if m:
        return m.group(1).decode('ascii')
    return fn


def is_dialog(s):
    if s.startswith('!This program cannot be run in DOS mode'):
        return False
    if len(s) < 16:
        return False
    if ' ' not in s:
        return False
    # exclude identifiers/paths/code
    if re.fullmatch(r'[A-Za-z0-9_:\-.\\/]+', s) and '_' in s and ' ' not in s:
        return False
    if s.startswith(('evt_', 'obj_', 'glb_', 'CUBSAT_', 'ALN_', 'STN_')):
        return False
    if re.fullmatch(r'[A-Z0-9_]+', s):
        return False
    if '\\' in s or s.endswith(('.dll', '.exe', '.sav', '.txt')):
        return False
    if 'Tried to call function' in s or 'concurrent calls' in s:
        return False
    # must look like speech/narration: letters + spaces + some punctuation
    letters = sum(1 for c in s if c.isalpha())
    if letters < len(s) * 0.5:
        return False
    return True


n_dll = n_lines = 0
for fn in sorted(os.listdir(dd)):
    if not fn.endswith('.dll'):
        continue
    data = open(os.path.join(dd, fn), 'rb').read()
    strs = sorted(set(m.decode('ascii', 'replace') for m in re.findall(rb'[ -~]{16,400}', data)))
    dlg = sorted(set(s for s in strs if is_dialog(s)))
    if dlg:
        out[script_name(data, fn)] = {'file': fn, 'lines': dlg}
        n_dll += 1
        n_lines += len(dlg)
print(f"dlls with dialogue: {n_dll}, total lines: {n_lines}")
json.dump(out, open(r'C:\Users\admin\AppData\Local\Temp\opencode\le_re\all_dialog.json',
                    'w', encoding='utf-8'), indent=1, ensure_ascii=False)
# script name census
for name in sorted(out)[:80]:
    print(f"{len(out[name]['lines']):4}  {name}  ({out[name]['file']})")
