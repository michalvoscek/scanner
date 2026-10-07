# ecls scan API

A FastAPI service that wraps the ESET Command Line Scanner (`ecls.exe`) for
parallel file scanning. On startup the server spawns a pool of persistent
`ecls.exe` instances running in stream mode (`/log-all /stdin-filelist
/batch-delimiter=__INPUT_END__`) and talks to them over their stdin/stdout
pipes, so no process startup cost is paid per request. Incoming scans are
routed dynamically to free workers, and `/scanMultipleFiles` scans its files
in parallel across the pool.

## Endpoints

Both endpoints accept `multipart/form-data` uploads and return the parsed
scanner output with `name` split on the `»` character.

- `POST /scanFile` — scan a single file (multipart field `file`).
- `POST /scanMultipleFiles` — scan several files in parallel (multipart field
  `files`); all-or-nothing: any failure means no results are returned.

Example response:

```json
{
    "scan_results": [
        {"name": ["test.zip"], "threat": "is OK", "action": "", "info": ""},
        {"name": ["test.zip", "ZIP", "ah_dna.exe"], "threat": "is OK", "action": "", "info": ""}
    ]
}
```

A detected threat is reported in `threat` (e.g. `threat: "Win32/Eicar`), clean
files show `threat: "is OK"`.

## Requirements

- Windows (the bundled `data/ecls.exe` and the scanner's pipe/encoding
  behavior are Windows-specific; pipe encoding defaults to cp1252)
- Python 3.13+

## Installation

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Running the app

```powershell
uvicorn app.main:app
```

Or from Python directly:

```powershell
python -c "import uvicorn; uvicorn.run('app.main:app')"
```

Interactive API docs are then available at `http://127.0.0.1:8000/docs`.

**Run uvicorn as a single process (do not pass `--workers N`).** The ecls pool
lives inside the application process, so each uvicorn worker would start its
own pool of `ECLS_WORKERS` scanner processes, multiplying memory usage and
procesload. Process-level parallelism across scanner instances is already
provided by the pool itself; use `ECLS_WORKERS` to scale it.

## Configuration (environment variables)

| Variable | Default | Meaning |
| --- | --- | --- |
| `ECLS_CMD` | `data/ecls.exe` | Scanner executable (plus optional extra arguments, whitespace-separated). Relative paths are resolved against the project root. |
| `ECLS_ARGS` | `/log-all /stdin-filelist /batch-delimiter=__INPUT_END__` | Arguments passed to ecls.exe. The delimiter must stay in sync with the argument — it is derived from `/batch-delimiter=`. |
| `ECLS_WORKERS` | `4` | Number of persistent ecls.exe processes in the pool. |
| `ECLS_TIMEOUT_S` | `300` | Per-file scan timeout in seconds. |
| `ECLS_STARTUP_TIMEOUT_S` | `20` | Timeout for spawning a worker and reading its banner. |
| `ECLS_ENCODING` | `cp1252` | Encoding of the scanner pipe. |
| `ECLS_TEMP_BASE` | system temp | Base directory for per-upload scan directories. |
| `ECLS_MAX_UPLOAD_MB` | unlimited | Per-file upload size cap in MB (oversized uploads get HTTP 413). |

## Testing

```powershell
pip install -r requirements-dev.txt
pytest
```

Tests run against `tests/mock_ecls.py`, a scripted stand-in for the real
scanner, so no ESET engine files are needed.

### Test files (`test_files/`)

The fixture folder for integration tests is git-ignored; provide your own
samples. Two subfolders drive the parametrized tests in `tests/test_api.py`:

```
test_files/
├── threats/   # every file here must be detected as a threat
└── safe/      # every file here must scan clean
```

- The mock scanner detects threat samples automatically: `tests/conftest.py`
  computes the SHA-256 digest of every file currently in `threats/` and
  passes it to the mock, which then reports matching content as a detected
  threat. Dropping a sample into the folder is the only setup needed — no
  code changes. Anything else scans clean, which is all `safe/` requires.
- For synthetic files, a `#MOCK THREAT=<name>` line in the uploaded content
  makes the mock report that verdict directly.
- Files in `safe/` need no preparation; arbitrary files scan clean.
- Empty subfolders are fine — the corresponding tests simply have no cases.

Run only these file-based tests, with the full scanner API response for
every file printed:

```powershell
pytest -m test_files -v -s
```

- `-m test_files` selects the marked tests (use `-m "not test_files"` to
  exclude them from a full run)
- `-v` prints one line per scanned file (the filename is in the test ID)
- `-s` shows the pretty-printed JSON that the API returned for each file

Everything else (protocol edge cases, worker pool behavior) uses inline
mock content and runs in the default `pytest` invocation.
