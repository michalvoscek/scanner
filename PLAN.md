# Implementation Plan — Parallel File Scanning API (FastAPI + ecls.exe)

## Goal

FastAPI server application exposing two endpoints for scanning files with the ESET Command Line Scanner (`ecls.exe`):

- `POST /scanFile` — scan a single uploaded file
- `POST /scanMultipleFiles` — scan multiple uploaded files in parallel

Uploads are received as `multipart/form-data`. The server keeps a pool of persistent `ecls.exe`
processes running in stream mode (pipes), started at server startup:

```
data\ecls.exe /log-all /stdin-filelist /batch-delimiter=__INPUT_END__
```

File paths are fed to a scanner process via stdin; results are read from stdout until the
`__INPUT_END__` delimiter line. Results are parsed into:

```json
{
  "scan_results": [
    { "name": ["test.zip", "ZIP", "ah_dna.exe"], "threat": "is OK", "action": "", "info": "" }
  ]
}
```

`name` is produced by splitting the ecls `name="..."` value on the `»` character and stripping
whitespace. For multiple files, results are concatenated in upload order.

## Confirmed decisions

| Decision | Choice |
|---|---|
| Test suite | Full: parser unit tests + mock-scanner integration tests |
| Multipart field names | `/scanFile` → `file`; `/scanMultipleFiles` → repeated `files` |
| Dependencies | Project virtualenv `.venv`, pinned `requirements.txt` |
| Worker pool size | Default 4, env-configurable |
| Worker recycle policy | Any scan failure / timeout / EOF / desync ⇒ kill + respawn; a suspect worker never returns to the queue |
| `/scanMultipleFiles` partial failure | All-or-nothing: 500 with detail naming the failed upload(s); successful results discarded |
| Startup worker failure | Fail fast — abort lifespan startup; never run degraded with an empty pool |
| Python | 3.13 (installed), asyncio Proactor event loop (Windows default, supports subprocess pipes) |

## Project structure

```
eset/
├── app/
│   ├── __init__.py
│   ├── main.py          # FastAPI app factory, lifespan (start/stop pool), endpoints
│   ├── config.py        # env-driven settings: ECLS command, workers, timeout, encoding
│   ├── models.py        # Pydantic: ScanEntry, ScanResponse
│   ├── uploads.py       # save UploadFile -> unique temp dir (sanitized name), cleanup
│   └── ecls/
│       ├── __init__.py
│       ├── process.py   # one persistent ecls subprocess + scan() pipe protocol
│       ├── pool.py      # N processes, acquire/release via asyncio.Queue, restart, shutdown
│       └── parser.py    # parse raw ecls output lines -> [ScanEntry]
├── tests/
│   ├── conftest.py      # fixtures: mock scanner command, async client, app override
│   ├── mock_ecls.py     # fake scanner speaking the same stdin/stdout protocol
│   ├── test_parser.py   # unit tests on README sample output
│   └── test_api.py      # integration tests: pool + endpoints via mock scanner
├── requirements.txt     # fastapi, uvicorn, python-multipart
├── requirements-dev.txt # pytest, pytest-asyncio, httpx
├── pyproject.toml       # pytest + pytest-asyncio config (asyncio_mode = auto)
├── PLAN.md              # this file
├── README.md            # assignment (unchanged)
└── data/                # ecls.exe + module DLLs (untracked, unchanged)
```

## Steps

### 0. Spike — verify ecls.exe protocol (before coding)

Run `data\ecls.exe /log-all /stdin-filelist /batch-delimiter=__INPUT_END__` interactively
with a test file and confirm empirically:

- [ ] how a batch is terminated on stdin (expected: path lines + `__INPUT_END__` line; newline style)
- [ ] output terminates with `__INPUT_END__` line
- [ ] encoding of `»` (UTF-8 vs cp1252) — decides stdout decoding
- [ ] `name=` echoes the full path we send (confirms normalization requirement)

Record findings and lock protocol constants (encoding, input terminator, newline style) in `config.py`.

### 1. Scaffold

- [ ] `python -m venv .venv` at project root
- [ ] `requirements.txt` + `requirements-dev.txt`; install into venv
- [ ] Create package layout above

### 2. Models & config

- [ ] `ScanEntry { name: list[str], threat: str, action: str, info: str }`
- [ ] `ScanResponse { scan_results: list[ScanEntry] }`
- [ ] Settings via environment variables with defaults:
  - `ECLS_CMD` — scanner command (default: `data/ecls.exe`; overridable as list, e.g. `[python, tests/mock_ecls.py]` for tests). Resolved to an absolute path relative to the project root at config load — never depend on CWD
  - `ECLS_WORKERS` — pool size (default 4)
  - `ECLS_TIMEOUT_S` — per-scan timeout (default 300)
  - `ECLS_ENCODING` — pipe encoding (from spike, default `utf-8`)
  - `ECLS_ARGS` — extra args (default `/log-all /stdin-filelist /batch-delimiter=__INPUT_END__`)

### 3. Parser (`app/ecls/parser.py`)

- [ ] Match lines with a tolerant regex `^\s*name="(.*?)", threat="(.*?)", action="(.*?)", info="(.*?)"\s*$`
      — non-greedy values, tolerates leading whitespace and trailing `\r` (CRLF output)
- [ ] Decode with `ECLS_ENCODING, errors="replace"` so a stray byte never 500s a scan
- [ ] Split `name` on `»`, strip each part
- [ ] Ignore banner / `Command line:` / `Scan started at:` / blank lines
- [ ] Normalize: caller supplies exactly one (sent_temp_path → original_filename) mapping per scan;
      replace the temp path as a prefix of the *first name component only* (nested entries keep their
      `» ZIP » inner` parts untouched). Per-scan mapping, so duplicate upload names in one request
      each normalize to their own original name. If ecls outputs bare filenames, this is a no-op

### 4. Process & pool (`app/ecls/process.py`, `app/ecls/pool.py`)

- [ ] `EclsProcess`: spawn via `asyncio.create_subprocess_exec` (stdin/stdout PIPE; stderr drained
      by a background reader task — on the Proactor loop an undrained pipe can hang `wait()`)
- [ ] `async scan(path) -> list[ScanEntry]`: per-process in-flight lock; write `path` + delimiter
      line to stdin, flush; read stdout lines until `__INPUT_END__`; parse; apply path→name mapping
- [ ] Failure isolation — a worker's pipe stream is one-shot per scan: EOF / broken pipe / parse
      desync / timeout ⇒ discard the worker (kill + respawn a fresh one); it is NEVER returned to
      the queue, otherwise the next request reads stale `name=` lines from the aborted batch
- [ ] `EclsPool`: spawn N processes; free workers tracked in `asyncio.Queue`;
      `scan(path)` = acquire → scan → release healthy worker (or recycle on failure, then release
      the fresh one)
- [ ] `shutdown()` sequencing: close stdin → `wait(timeout=…)` → `terminate()` → `kill()`,
      while draining stdout/stderr
- [ ] Startup: if any of the N workers fails to spawn, abort lifespan startup (fail fast) — the
      server must not start degraded with an empty pool
- [ ] Per-scan timeout guard (`asyncio.wait_for`) that routes into the recycle path above

### 5. Uploads & endpoints (`app/uploads.py`, `app/main.py`)

- [ ] Save each upload to a unique per-file temp dir (`tempfile.mkdtemp` under configurable base),
      sanitized basename only (strip directory components — path-traversal safe; reject empty,
      control characters `\n\r\t`, and the literal `__INPUT_END__` — the stdin protocol is line-based
      and such names would corrupt batch framing)
- [ ] Cleanup temp dir in `finally`, after the scan fully completes (no open ecls handles)
- [ ] All handlers `async def` — sync `def` handlers get bounced to the threadpool and would block
      threads on pipe reads
- [ ] `POST /scanFile`: `file: UploadFile = File(...)` → single scan → `ScanResponse`
- [ ] `POST /scanMultipleFiles`: `files: list[UploadFile] = File(...)` → save all, then
      `asyncio.gather(..., return_exceptions=True)` over pool → concatenate results in upload order
      (gather preserves order regardless of completion order)
- [ ] Partial failure policy (confirmed decision): all-or-nothing — if any scan raised, respond 500
      with detail naming the failed upload(s); results of successful scans are discarded
- [ ] Lifespan: start pool on startup (fail fast on spawn failure), shutdown on exit
- [ ] Errors: scan failure/timeout → 500 with detail naming the upload; invalid filename /
      empty upload list → FastAPI 422
- [ ] (optional) `ECLS_MAX_UPLOAD_MB` guard, default unlimited — nice-to-have, not required by
      the assignment

### 6. Tests

- [ ] `tests/test_parser.py` — README sample (incl. nested `ZIP` entries, empty fields),
      junk-line tolerance, `»` splitting with surrounding spaces
- [ ] `tests/mock_ecls.py` — reads path lines + delimiter from stdin, prints banner +
      `name="..."` lines (echoing input paths) + `__INPUT_END__`; ignores the real ecls argv it is
      launched with (`/log-all /stdin-filelist /batch-delimiter=…`); special upload names trigger
      crash / hang (never respond) for failure tests. Implements the *assumed* protocol — backport
      any Step 0 spike findings (encoding, newline style, terminator) to the mock
- [ ] `tests/test_api.py` — integration via `httpx.AsyncClient` with `ECLS_CMD` pointed at
      the mock: single file, multiple files (order preserved), empty upload list → 422,
      duplicate upload names in one request (unique temp dirs + per-scan mapping),
      scan failure → 500 naming the failed upload, worker recycle after mock crash,
      timeout → worker recycled not reused (stale-output/desync check)
- [ ] pytest-asyncio `asyncio_mode = "auto"` in `pyproject.toml` — no per-test markers

### 7. Run & verify

- [ ] `pytest` — all tests green inside `.venv`
- [ ] Start server: `uvicorn app.main:app` (from venv)
- [ ] Manual smoke test against real `data\ecls.exe`:
      create a test zip (e.g. `Compress-Archive`), `curl -F "file=@test.zip" http://.../scanFile`,
      `curl -F "files=@a.exe" -F "files=@test.zip" http://.../scanMultipleFiles`
- [ ] Compare JSON output shape with README samples

## Risks / open points

- Exact stdin protocol (input delimiter) and encoding to be confirmed in Step 0 spike —
  parser/protocol constants will be adjusted if findings differ from assumptions.
- If `name=` output contains the full temp path, normalization (Step 3) handles it; if ecls
  outputs bare filenames, normalization becomes a no-op.
- ecls.exe may emit other line formats (e.g. errors) — unknown lines are ignored, count tracked.
