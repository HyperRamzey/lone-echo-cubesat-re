# Lone Echo — CubeSat collection quest reverse engineering

**Question:** does checking in with Liv about the CubeSats / audio logs change anything, or can it be ignored?

**Answer: it can be safely ignored.** Sharing the logs with Liv (the three "Speak to Liv" report POIs) plays extra dialogue — Jack's three sharing lines, Liv's log line, Liv's puzzled reply — but nothing in quest logic reads the report/sharing state. Progression and the "Cube-Sat Reactivation" objective are driven by **finding (scanning) sats only**.

## Contents

- `README.md` — this writeup
- `dialogue/ALL_DIALOGUE.md` — every dialogue line from all 190 quest script modules (5,355 lines)
- `dialogue/all_dialog.json` — same data, machine-readable (module → lines)
- `tools/hashutil.py` — the cracked string-hash function (self-contained, stdlib only)
- `tools/quest_hashes.tsv` — 66 identifier → hash mappings for the CubeSat tracker

## 1. String hash (engine-wide, cracked from exe code)

All script identifiers, events, VO line IDs and engine registry names hash with one function:

```
H(name) = CRC64(seed=0, tolower(name)) XOR F(len(name))
```

- The 256-entry table is **generated at runtime** by code at `loneecho.exe` RVA `0x8d110`
  (`mov r11, 0x2b5926535897936a`; bit-serial loop; verified bit-exact against the live
  table at image offset `0x14360d0`). It matches a standard MSB-first CRC-64 table for
  only the first 8 entries — custom polynomial/behavior beyond that.
- The consumer is the string-hash at RVA `0x8d010`:
  `state = tab[state>>56] ^ (state<<8) ^ tolower(byte)`, seed in `rdx`.
  Short strings pack as pure bytes because `tab[0] = 0` keeps `state>>56 == 0`.
- `F(len)` is a per-length 64-bit finalization constant, derived empirically
  (single-valued for 54/55 sampled lengths, 4,205 registry entries).

Verification (`tools/hashutil.py`): **4,205/4,224** exe registry entries reproduce exactly
(the 19 misses are L=64 same-name-different-hash scoped duplicates, a separate subsystem),
plus 7/7 independent binder pairs (`UpdateObjectives`, `PlaybackAudio`, `StopPlayback`,
`UpdateObjective`, `PlaybackStopped`, `normal`/`Normal`).

## 2. CubeSat tracker layout (`ee298562f6744a57.dll` = `glb_global_player_cube_sat_tracking`)

- Objective `obj_glb_cube_sats_` / "Cube-Sat Reactivation": *"Scan the I/O ports of all Cube-Sats facility wide"*.
- State struct at `[rbx+0x60]` holds per-area find/report counters plus globals:
  `logs_found` @+0x198, `total_sats_found` @+0x19c.
- One big event-dispatch chain (29 arms, ~`0x180029c00`–`0x18002a4a0`) maps each incoming
  event hash → threshold check → counter increment. Wired events include all six
  `evt_cube_sat_find_*`, all six `evt_cube_sat_report_*`, all `CUBSAT_*` VO completions,
  beacons, and `evt_moved_rad_raptor`.
- Sharing VO completions (`CUBSAT_0110/0120/0130`, `CUBSAT_0020_LIV_LOG`) each have a
  played-counter (cap 1) at struct offsets 132/64/124/60.
- Report POIs: three `evt_cubesat_poi_add_liv_report_1/2/3` ("Speak to Liv"), managed by
  `f8f021252cbf86eb.dll`; the tracker subscribes and plays the sharing lines on report.

## 3. Why sharing is consequence-free

- Exhaustive mining of the full `.text` disassembly (55,957 insns) for **every**
  `dword-cmp` against report/sharing/played counter offsets finds only the dispatch arms'
  own saturation checks. **No branch anywhere gates on report/sharing state.**
- The only progression gates in quest logic are `total_sats_found >= 2` and `>= 3`
  (`0x18001b544`, `0x18001c674`, `0x18001cdaf`, `0x18001deef`) — find-driven staging.
  `logs_found` is never compared (objective-UI display only).
- The `UpdateObjectives` payload publishes 16 named tokens — all find-side
  (`*_sats`, `*_sats_found`, `logs_found`, `total_sats_found`, `total_sats`) plus misc.
  No report-side tokens exist (report counters are anonymous struct offsets).
- Direction is finds → sharing (POIs/nags unlock progressively as you find logs), never reverse.

## 4. Unmapped hashes (open items, do not affect the conclusion)

Four 64-bit constants in condition/say descriptors match no plain string in the exe,
any of the 561 scene DLLs, 279k exe strings, or 1–2 char brute force:
`0xF55F…`, `0xA642…`, `0x6ECF…`, `0x0E47…`. One is confirmed to sit in a say-descriptor
VO-line-ID slot (same layout as the mapped `CUBSAT_*` say-sites), so they are most likely
external VO-line/engine names. Their roles are established; naming them is not needed
for the quest answer.

## 5. Reproducing

```powershell
python tools\hashutil.py   # verifies 7/7 pairs + full registry (needs registry_exe.tsv + exe)
```

`hashutil.py` contains the table emulator, the CRC, and the `F(len)` derivation. Point it
at any Lone Echo string to get the engine hash (lengths 1–52, 54, 57 covered).

## 6. Full RE chain (everything found, not just the quest)

- **Name registry** (`tools/registry_dump.py`): the exe's `.rdata` holds 4,224
  `{u64 hash, "OlPrEfIx" marker, NUL-padded name}` entries — the engine's entire hashed
  string namespace (events, inputs, properties, debug symbols). Harvested to
  `registry_exe.tsv` (4,224 rows; sheet not shipped, regenerate with the script).
- **Hash investigation arc**: single-char-delta pair analysis first proved a per-position
  model `dh = ΔT·MUL(shift)` with `MUL(0..7) = 256^s` (`pair_layout.py`, `extract_mul.py`);
  the far-field law broke integer-multiply fits, which led to hunting the constant
  `0x2b5926535897936a` in the image — found **in code**, not data (`find_mul_const.py`).
- **Key exe addresses** (image-relative; live base varies, e.g. `0x7ff7a9180000`):
  - `0x8d110` — 256-entry table generator (unrolled bitwise; emulated in `table_emu.py`)
  - `0x8d010` — string hash (`state = tab[state>>56] ^ (state<<8) ^ tolower(c)`, seed in `rdx`)
  - `0x14360d0` — the generated table (verified live); `0x8d1e0`/`0x8d04a` reference it
- **Live analysis**: `dump_mod.py` (276/392 modules, 46 MB), `scan_proc.py`, `heap_read.py`,
  `live_analyze.py`, `search_live.py` — read-only live-process inspection (need a running
  game + its PID; scripts take PID/base as written or trivially editable).
- **Tracker + POI**: see §2–§4. Full `.text` disassembly mined via capstone (`full_dis.py`
  + the `*_ctx.py` / `wire_map.py` / `readers.py` / `payload_list.py` miners).

## 7. Tool inventory

Hash cracking: `hash_test.py`, `solve_hash.py`, `solve_hash2.py`, `solve_hash3.py`,
`pair_layout.py`, `pair_raw.py`, `extract_mul.py`, `test_model.py`, `chain_test.py`,
`table_emu.py`, `solve_E.py`, `verify_crc.py`, `hashutil.py` (final, self-contained).
Registry: `registry_dump.py`, `registry_scan.py`. Constant hunting: `find_const.py`,
`find_mul_const.py`, `lea_scan.py`, `match_exe.py`, `match_targets1.py`, `harvest_dlls.py`,
`map_consts.py`, `map_ids.py`, `gen_map_tsv.py`, `poi_check.py`.
Disassembly miners (capstone, need the DLL + live offsets as noted in each file):
`dis_ea.py`, `hex_rva.py`, `pe_dump.py`, `xr.py`, `full_dis.py`, `cond_dis.py`,
`say_site.py`, `evt_ctx.py`, `wire_map.py`, `readers.py`, `payload_list.py`,
`poi_ctx.py`, `f8_ctx.py`. Dialogue: `extract_dialog.py`, `peek_dialog.py`,
`gen_dialog_md.py`. Live process: `dump_mod.py`, `scan_proc.py`, `heap_read.py`,
`live_analyze.py`, `search_live.py`.
All scripts are research snapshots — paths/PIDs are hardcoded for the original session;
grep for `C:\\` / `Temp\\opencode` / PID literals to adapt.
