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

## 5. Blocking filesystem calls on the event loop (low-medium)

`app/uploads.py` — `tempfile.mkdtemp` (line 67), `path.open("wb")` (line 72)
and `shutil.rmtree` in `remove_upload` (line 89, called per file from endpoint
`finally`) all run on the event loop, while `target.write` is already
offloaded via `run_in_threadpool`.

**Fix:** offload open/mkdtemp/rmtree with `run_in_threadpool` as well, so slow
disks cannot stall in-flight pipe reads of other scans.

## 6. Minor correctness / design warts (low)

- **`Settings.delimiter` parameter is silently ignored**
  (`app/config.py:80,91`): it is a dataclass field, but `__post_init__`
  unconditionally overwrites it — `Settings(delimiter="X")` accepts and
  discards the value. Make it a computed `@property` (or a private derived
  attribute) instead of a constructor field.
- **Pool overshoot race** (`app/ecls/pool.py:_heal`): two concurrent `scan()`
  calls while the pool is below target both pass the `len < workers` check and
  both spawn → pool permanently exceeds the configured size (nothing ever
  shrinks it). Guard healing/spawning with an `asyncio.Lock`.
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
- `tests/test_api.py:198` (`test_scans_run_in_parallel`): the wall-clock
  assertion (`elapsed < 2 s`) can flake on loaded machines; the
  interval-overlap assertion is already the robust one — the timing assert
  could be relaxed or dropped.

## Suggested implementation order

1. #1–#4 plus the delimiter-field and heal-lock items from #6 — meaningful
   hardening, small localized changes, each with a test.
2. #5 and the remaining #6 items — polish.
3. #7 — docs and test robustness.
