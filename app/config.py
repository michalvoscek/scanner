"""Environment-driven settings for the scanning service.

Protocol constants locked in by the Step 0 spike against data/ecls.exe:

- pipe encoding is cp1252: the "»" name separator arrives as the single
  byte 0xBB (not UTF-8)
- request/response is per stdin line: one file path line makes ecls print
  the ``name="..."`` result lines for that file followed by a single
  ``__INPUT_END__`` line on stdout; the /batch-delimiter value is an OUTPUT
  marker only and must never be written to stdin (ecls would try to scan
  it as a path)
- ecls echoes the exact path sent on stdin as the first ``name`` component
- output lines are CRLF-terminated
- closing stdin makes ecls print a summary and exit promptly
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_ECLS_CMD = "data/ecls.exe"
DEFAULT_ECLS_ARGS = "/log-all /stdin-filelist /batch-delimiter=__INPUT_END__"
DEFAULT_DELIMITER = "__INPUT_END__"
DEFAULT_ENCODING = "cp1252"
DEFAULT_WORKERS = 4
DEFAULT_TIMEOUT_S = 300.0
DEFAULT_STARTUP_TIMEOUT_S = 20.0


def _resolve_executable(token: str) -> str:
    path = Path(token)
    if path.is_absolute():
        return token
    rooted = PROJECT_ROOT / path
    if rooted.exists():
        return str(rooted)
    return token


def _delimiter_from_args(args: tuple[str, ...]) -> str:
    marker = "/batch-delimiter="
    for arg in args:
        if arg.startswith(marker) and arg[len(marker) :]:
            return arg[len(marker) :]
    return DEFAULT_DELIMITER


def _positive_int(raw: str | None, default: int) -> int:
    if raw is None or not raw.strip():
        return default
    value = int(raw)
    if value < 1:
        raise ValueError(f"expected a positive integer, got {raw!r}")
    return value


def _positive_float(raw: str | None, default: float) -> float:
    if raw is None or not raw.strip():
        return default
    value = float(raw)
    if value <= 0:
        raise ValueError(f"expected a positive number, got {raw!r}")
    return value


@dataclass(frozen=True)
class Settings:
    ecls_cmd: tuple[str, ...] = (_resolve_executable(DEFAULT_ECLS_CMD),)
    ecls_args: tuple[str, ...] = tuple(DEFAULT_ECLS_ARGS.split())
    workers: int = DEFAULT_WORKERS
    timeout_s: float = DEFAULT_TIMEOUT_S
    startup_timeout_s: float = DEFAULT_STARTUP_TIMEOUT_S
    encoding: str = DEFAULT_ENCODING
    temp_base: Path | None = None
    max_upload_bytes: int | None = None
    delimiter: str = DEFAULT_DELIMITER

    def __post_init__(self) -> None:
        if not self.ecls_cmd:
            raise ValueError("ecls_cmd must not be empty")
        if self.workers < 1:
            raise ValueError("workers must be >= 1")
        if self.timeout_s <= 0:
            raise ValueError("timeout_s must be > 0")
        if self.startup_timeout_s <= 0:
            raise ValueError("startup_timeout_s must be > 0")
        object.__setattr__(self, "delimiter", _delimiter_from_args(self.ecls_args))

    @property
    def scanner_argv(self) -> tuple[str, ...]:
        return (*self.ecls_cmd, *self.ecls_args)

    @classmethod
    def from_env(cls) -> Settings:
        raw_cmd = os.environ.get("ECLS_CMD", DEFAULT_ECLS_CMD).split()
        if not raw_cmd:
            raise ValueError("ECLS_CMD must not be empty")
        ecls_cmd = (_resolve_executable(raw_cmd[0]), *raw_cmd[1:])
        ecls_args = tuple(os.environ.get("ECLS_ARGS", DEFAULT_ECLS_ARGS).split())
        temp_base = os.environ.get("ECLS_TEMP_BASE", "").strip()
        max_upload_mb = os.environ.get("ECLS_MAX_UPLOAD_MB", "").strip()
        max_upload_bytes = (
            int(float(max_upload_mb) * (1 << 20))
            if max_upload_mb and float(max_upload_mb) > 0
            else None
        )
        return cls(
            ecls_cmd=ecls_cmd,
            ecls_args=ecls_args,
            workers=_positive_int(os.environ.get("ECLS_WORKERS"), DEFAULT_WORKERS),
            timeout_s=_positive_float(
                os.environ.get("ECLS_TIMEOUT_S"), DEFAULT_TIMEOUT_S
            ),
            startup_timeout_s=_positive_float(
                os.environ.get("ECLS_STARTUP_TIMEOUT_S"), DEFAULT_STARTUP_TIMEOUT_S
            ),
            encoding=os.environ.get("ECLS_ENCODING", DEFAULT_ENCODING),
            temp_base=Path(temp_base) if temp_base else None,
            max_upload_bytes=max_upload_bytes,
        )
