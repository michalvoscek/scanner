# Improvements — Code Review Findings

Review of the current implementation against the assignment in `README.md`.
All hard requirements are met (both endpoints, multipart input, persistent
ecls.exe pool started at startup, dynamic parallel routing, output shape with
`name` split on `»`). The findings below are hardening opportunities, ordered
by severity. Ideas already listed in `INTERVIEW_QA.md` §6 (metrics, health
endpoint, bounded request queue with 503, graceful drain, periodic worker
recycling) are intentionally not repeated here.

## 1. ~~Parser: `threat` field spoofable via crafted inner filename (medium-high)~~ — FIXED

`app/ecls/parser.py:17` — all four regex groups are non-greedy. A nested
archive member named e.g. `x", threat="Win32/Eicar` makes ecls emit:

```
name="upload_abc.zip » ZIP » x", threat="Win32/Eicar", threat="is OK", action="", info=""
```

The non-greedy `name` group stops at the *first* `", threat="`, so
attacker-controlled text lands in the security-relevant `threat` field.
Since ecls does not escape quotes, the format is inherently ambiguous, but
making **only the first group greedy** (`name="(.*)"`) anchors on the *last*
`", threat="` occurrence, keeping `threat`/`action`/`info` trustworthy; the
junk stays harmlessly inside `name`.

**Fix:** one-line regex change + a parser unit test with a quote-injected name.

## 2. A worker that dies while idle costs one client request (medium)

`app/ecls/pool.py:48-69` — a worker process that exits between scans stays in
`_free`. The next `scan()` hands out the corpse, the write/read fails, and the
client gets a 500 even though the pool recovers immediately afterwards.

**Fix:** liveness check on handout (expose `is_alive` on `EclsProcess` via
`proc.returncode is None`); if dead, discard + replace and draw another worker
without failing the request. Optionally retry the scan once on a fresh worker
(scans are idempotent; trade-off: a crash-inducing file would then kill two
workers instead of one). Add an integration test: kill an idle worker, assert
the next request still returns 200.

## 3. Cancellation during worker spawn leaks an ecls.exe process (medium)

`app/ecls/process.py:51-82` — `start()` cleans up on `TimeoutError` but not on
`asyncio.CancelledError`. If cancellation lands between
`create_subprocess_exec` and the banner read, the `EclsProcess` is dropped
with the child still running → orphaned idle ecls.exe.

**Fix:** wrap the post-spawn body in `except BaseException: await self.stop(); raise`.

## 4. Timeout 500s have an empty reason; error detail is inconsistent (low-medium)

`app/main.py:64` — on timeout `str(TimeoutError())` is `""`, so the client
receives `scan failed for uploaded file 'x': ` with an empty reason. Also,
`/scanFile` embeds `{exc}` in the client-facing detail (leaks internal temp
paths / exception text) while `/scanMultipleFiles` deliberately does not.

**Fix:** special-case `TimeoutError` → `"scan timed out after {timeout_s} s"`;
keep exception details in logs only, matching the multi-file endpoint.

## 5. Blocking filesystem calls on the event loop (medium)

`app/uploads.py` — `tempfile.mkdtemp` (line 67), `path.open("wb")` (line 72)
and `shutil.rmtree` in `remove_upload` (line 89, called per file from endpoint
`finally`) all run on the event loop, while `target.write` is already
offloaded via `run_in_threadpool`. A slow disk, or Windows Defender locking a
just-written sample, stalls every other scan's pipe read and can false-timeout
healthy workers.

**Fix:** offload open/mkdtemp/rmtree with `run_in_threadpool` as well, so slow
disks cannot stall in-flight pipe reads of other scans.

## 6. Minor correctness / design warts (low)

- **`Settings.delimiter` parameter is silently ignored**
  (`app/config.py:80,91`): it is a dataclass field, but `__post_init__`
  unconditionally overwrites it — `Settings(delimiter="X")` accepts and
  discards the value. Make it a computed `@property` (or a private derived
  attribute) instead of a constructor field.
- **Pool overshoot race** (`app/ecls/pool.py:_heal` and `_replace`): two
  concurrent `scan()` calls while the pool is below target both pass the
  `len < workers` check and both spawn. `_replace` does not account for an
  in-flight `_heal` either, and nothing ever shrinks the pool, so a burst of
  crashes can permanently exceed the configured size (spawn storm of heavy
  ecls processes). Reserve a slot under an `asyncio.Lock` before awaiting
  `start()`, and do not spawn a replacement if healing already covered it.
- **`ECLS_CMD`/`ECLS_ARGS` use plain `.split()`** (`app/config.py:99,103`): a
  path with spaces (`C:\Program Files\...`) breaks.
  `shlex.split(posix=False)` handles quoted tokens.
- **Shutdown grace reuses `startup_timeout_s`** (`app/ecls/process.py:94`) —
  semantically a different budget; give it its own constant/setting.

## 7. Docs & tests (low)

- **Usage documentation is missing**: `README.md` is the assignment text. Add
  a short section (or separate file) covering how to run
  (`uvicorn app.main:app`), the `ECLS_*` env vars, and the caveat that uvicorn
  must run as a single process — multiple uvicorn workers would multiply the
  ecls pools.
- **Test additions accompanying the fixes above:** parser quote-injection
  test (#1), dead-idle-worker transparency test (#2). Optionally pin down the
  `»`-in-upload-filename behavior with a test (currently allowed and restored
  verbatim as a single `name` element — a defensible choice, but
  undocumented).
- `tests/test_api.py:255` (`test_scans_run_in_parallel`): the wall-clock
  assertion (`elapsed < 4 * 0.5`, i.e. `< 2 s`) can flake on loaded machines;
  the interval-overlap assertion is already the robust one — the timing assert
  could be relaxed or dropped.

## 8. Parser fails open on unparsed or empty output (medium-high)

`app/ecls/process.py:150-153` skips any line that does not match and still
returns 200, putting the worker back in the pool. Zero `name=` lines, or a
dropped threat line, looks like a clean scan. `start()` only consumes the
first banner line (`app/ecls/process.py:71-73`), so later banner text is
indistinguishable from a bad result line.

**Fix:** drain the banner at startup. After that, unexpected lines or zero
entries are a desync: fail the request and recycle the worker.

## 9. Archive member names can break the pipe framing (medium-high, unverified against ecls)

Upload names never reach stdin, but ecls echoes nested member names with no
escaping. A member whose name contains a newline and `__INPUT_END__` can end
the read early, return a short 200, and leave the rest of that output for the
next client (temp paths, names, verdicts). `data/ecls.exe` was not in the tree,
so this needs a check against the real binary. If ecls strips newlines, item 1
is sufficient.

## 10. `unable to open` and empty results are HTTP 200 (medium)

The server just wrote the file, so `info="unable to open"` means it was not
scanned. It is still returned as a normal entry. Callers that only check
status, or that treat any non-named threat as clean, get a false negative.
Same for `scan_results: []`.

**Fix:** treat `unable to open` and zero entries as 500. Do not reuse that
worker if the output was incomplete.

## 11. cp1252 temp paths fail on Slovak Windows and thrash the pool (medium-high)

Encoding is hardcoded cp1252. Generated filenames are ASCII, but the absolute
temp path is not. `č ď ľ ň ŕ ť` do not encode; a profile such as
`C:\Users\Kováč\...` makes every scan raise `UnicodeEncodeError` before any
IO. `pool.scan` still discards and respawns a healthy worker. `»` is `0xBB`
in both cp1250 and cp1252, so the spike would not have caught this.

**Fix:** pin an ASCII temp dir, or encode paths with the ANSI code page
(`mbcs`). Do not recycle a worker for a pre-IO encode error.

## 12. Shutdown can hang waiters or orphan a process (medium)

`scan()` checks `_closed` once, then can block forever on `_free.get()` after
`shutdown()` has drained the queue and stopped workers. Nothing fails those
waiters. `_heal` / `_replace` can also finish `start()` after shutdown and
`_add` a process nobody stops.

**Fix:** recheck `_closed` after every await; wake or fail queue waiters on
shutdown; do not `_add` after close. `start()` still needs the item 3
`finally: stop()`.

## 13. One request can pin the service (medium)

`/scanMultipleFiles` saves every file, then queues one `pool.scan` per file.
No file-count, total-byte, or result-entry cap. `ECLS_MAX_UPLOAD_MB` defaults
to unlimited and is applied only while copying into the scan dir, after
Starlette has already spooled the body. The free-worker queue is FIFO, so one
bulk call sits ahead of later callers. Distinct from the deferred
bounded-queue/503 item, which is about many requests.

**Fix:** cap files per request and total bytes; enforce the body limit before
spooling; cap parsed entries.

## 14. Temp dirs and samples can leak (low-medium)

`rmtree(..., ignore_errors=True)` swallows a Windows sharing violation. A
crash leaves `ecls_*` directories, including malware samples. No startup sweep.

## 15. All-or-nothing multi-scan amplifies load (deliberate)

One failure discards successful results after the scans ran. A client retry
scans the whole batch again. Worth keeping only if callers cannot use partial
results.

## 16. Smaller residual risks (low)

- `Path.suffix` keeps only the last segment, so `archive.tar.gz` is scanned as
  `.gz` (`app/uploads.py:57-62`). A miss if ecls picks the unpacker by
  extension.
- `normalize_entries` uses case-sensitive `startswith`
  (`app/ecls/parser.py:58`). If ecls changes case or prefixes `\\?\`, the
  response contains the temp path.
- Workers run as the API user. No Job Object, so out-of-process unpackers can
  survive `terminate()`. No `CREATE_NO_WINDOW`.
- `stop()` closes stdin without `await wait_closed()`, so shutdown may always
  burn the grace period and kill.
- `ECLS_WORKERS` has no upper bound.
- Sent paths are not rejected if they contain CR/LF (only an issue if
  `ECLS_TEMP_BASE` does).

The mock never dies while idle, never emits a newline inside a name, and
always prints a clean banner, so items 2, 8, 9, and 12 are invisible to the
current suite.

## Suggested implementation order

1. #8–#10 and the #3 `start()` finally — false negatives and process leaks.
2. #2, the heal/replace lock from #6, and #12 — pool lifecycle.
3. #11, then #4 and #5.
4. #13, then the remaining #6 items, #7, and #14–#16.
