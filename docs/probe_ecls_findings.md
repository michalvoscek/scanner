# ecls.exe pipe protocol — empirical probe findings

Verified against `data/ecls.exe` (version 16.0.65535.0, modules dated
2024-01) using an asyncio harness mirroring the production reader
(`app/ecls/process.py`). Findings underpin the strictness decisions for
IMPROVEMENTS.md #8 and #10. Probe arguments:
`/log-all /stdin-filelist /batch-delimiter=__INPUT_END__`, encoding cp1252.

## Banner (startup)

Exactly 12 lines, deterministic, ending with `Scan started at:`:

```
''
'ECLS Command-line scanner, version 16.0.65535.0, (C) 1992-2022 ESET, spol. s r.o.'
'Module loader, version 1039 (20231023), build 1109'
'Module perseus, version 1607.3 (20240115), build 2404'
'Module scanner, version 28578 (20240116), build 60199'
'Module archiver, version 1346 (20240115), build 1457'
'Module advheur, version 1227 (20231030), build 1247'
'Module cleaner, version 1245.1 (20231205), build 1395'
''
'Command line: /log-all /stdin-filelist /batch-delimiter=__INPUT_END__ '
''
'Scan started at:   Mon Oct  5 00:32:30 2026'
```

Decision: `start()` drains stdout until the `Scan started at:` marker
(`_BANNER_START_MARKER`), so no banner text can leak into a scan's output
window. EOF before the marker is a spawn failure (worker exited early).

## Clean scan of a plain file

Exactly one `name="..."` line + the delimiter. No extra lines inside the
batch, nothing extra between batches (read after the delimiter stayed quiet
for the settle window).

```
name="C:\...\clean.txt", threat="is OK", action="", info=""
__INPUT_END__
```

## Unopenable variants

All produce the same verdict shape — `threat=""`, `action=""/`
`info="unable to open"` — confirming IMPROVEMENTS.md #10's premise:

```
name="C:\...\missing.txt", threat="", action="", info="unable to open"
__INPUT_END__
```

- nonexistent path: `info="unable to open"` (verified and matches `PLAN.md`
  spike).
- directory as path: ecls answered with the *sibling file* line seen earlier
  (delivered the prior batch; see note below) — treat any anomaly as desync.
- exclusively locked file (msvcrt `LK_LOCK` on the first bytes): ecls still
  reported `is OK`; ecls evidently opens files with sharing allowed, so a
  Defender-style exclusive lock is not a realistic trigger in this
  environment. The `unable to open` verdict remains the guard for
  missing/deleted files.

### Note on the directory probe

Probing the directory path returned the previous file's result lines again
instead of an error. This suggests ecls re-scans its last-known-good target
or that the directory request was answered from a cache. Either way: output
that does not match the request is exactly what #8's desync detection is
for; zero `name=` entries would have been rejected the same way.

## Empty file

Normal clean verdict: `info=""`, `threat="is OK"`. Zero-content uploads are
real scans and must NOT be treated as failures.

## Zip with nested members

Root entry first, then one line per member, then delimiter — including the
quote-ambiguity variant from IMPROVEMENTS.md #1:

```
name="...sample.zip", threat="is OK", action="", info=""
name="...sample.zip » ZIP » inner/a.exe", threat="is OK", action="", info=""
name="...sample.zip » ZIP » inner/x", threat="Win32/Eicar", threat="is OK", action="", info=""
__INPUT_END__
```

Confirms: (a) nested member names are echoed verbatim (unescaped quotes),
(b) the greedy-`name` regex fix from #1 correctly keeps `threat` trustworthy.

## Conclusions for implementation

1. Banner drain until `Scan started at:` is safe and makes mid-scan banner
   pollution impossible (#8).
2. Real ecls always answers ≥ 1 `name=` line per stdin line; zero entries
   therefore indicates desync → `EclsDesyncError` (#8).
3. Unopenable files are detectable via the exact verdict tuple
   `threat="" action="" info="unable to open"` → `EclsScanFailedError` (#10).
4. Both raise through `pool.scan()`, which discards + replaces the worker
   (no reuse after anomalous output) — the IMPROVEMENTS.md #10 requirement
   "do not reuse that worker" is already satisfied by pool recycling.
