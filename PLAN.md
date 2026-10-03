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
  - `ECLS_CMD` — scanner command (default: `data/ecls.exe`; overridable as list, e.g. `[python, tests/mock_ecls.py]` for tests)
  - `ECLS_WORKERS` — pool size (default 4)
  - `ECLS_TIMEOUT_S` — per-scan timeout (default 300)
  - `ECLS_ENCODING` — pipe encoding (from spike, default `utf-8`)
  - `ECLS_ARGS` — extra args (default `/log-all /stdin-filelist /batch-delimiter=__INPUT_END__`)

### 3. Parser (`app/ecls/parser.py`)

- [ ] Match lines with regex `^name="(.*)", threat="(.*)", action="(.*)", info="(.*)"$`
- [ ] Split `name` on `»`, strip each part
- [ ] Ignore banner / `Command line:` / `Scan started at:` / blank lines
- [ ] Normalize: replace sent absolute temp path with original upload filename (path→name mapping supplied by caller)

### 4. Process & pool (`app/ecls/process.py`, `app/ecls/pool.py`)

- [ ] `EclsProcess`: spawn via `asyncio.create_subprocess_exec` (stdin/stdout PIPE, stderr drained)
- [ ] `async scan(path) -> list[ScanEntry]`: per-process in-flight lock; write `path` + delimiter
      line to stdin, flush; read stdout lines until `__INPUT_END__`; parse; apply path→name mapping
- [ ] Dead-process detection and transparent restart
- [ ] `EclsPool`: spawn N processes; free workers tracked in `asyncio.Queue`;
      `scan(path)` = acquire → scan → release; `shutdown()` = close stdin → wait → terminate
- [ ] Per-scan timeout guard

### 5. Uploads & endpoints (`app/uploads.py`, `app/main.py`)

- [ ] Save each upload to a unique per-file temp dir (`tempfile.mkdtemp` under configurable base),
      sanitized basename only (strip directory components — path-traversal safe, reject empty)
- [ ] Cleanup temp dir in `finally`
- [ ] `POST /scanFile`: `file: UploadFile = File(...)` → single scan → `ScanResponse`
- [ ] `POST /scanMultipleFiles`: `files: list[UploadFile] = File(...)` → save all, then
      `asyncio.gather` over pool → concatenate results in upload order
- [ ] Lifespan: start pool on startup, shutdown on exit
- [ ] Errors: scan failure → 500 with detail; upload validation → FastAPI 422

### 6. Tests

- [ ] `tests/test_parser.py` — README sample (incl. nested `ZIP` entries, empty fields),
      junk-line tolerance, `»` splitting with surrounding spaces
- [ ] `tests/mock_ecls.py` — reads path lines + delimiter from stdin, prints banner +
      `name="..."` lines (echoing input paths) + `__INPUT_END__`
- [ ] `tests/test_api.py` — integration via `httpx.AsyncClient` with `ECLS_CMD` pointed at
      the mock: single file, multiple files (order preserved), empty upload list → 422,
      worker restart after mock crash

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
