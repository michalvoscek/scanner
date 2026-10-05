"""Environment-driven settings for the scanning service.

Protocol constants locked in by the Step 0 spike against data/ecls.exe:

- pipe encoding is the Windows ANSI code page (mbcs; ACP=1252 on the probe
  machine, where "»" arrived as the single byte 0xBB, ruling out UTF-8).
  mbcs rather than a pinched cp1252: ACP varies per system (1250 on Slovak
  Windows) and ecls, like typical Win32 console programs, most likely decodes
  its stdin via CP_ACP. ASCII paths encode identically under every ACP, so
  the default wire need for non-ASCII bytes is limited to the echoed
  archive member names in scanner output.
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
import tempfile
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_ECLS_CMD = "data/ecls.exe"
DEFAULT_ECLS_ARGS = "/log-all /stdin-filelist /batch-delimiter=__INPUT_END__"
DEFAULT_DELIMITER = "__INPUT_END__"
# Windows ANSI code page (GetACP); identical to cp1252 on the probe machine.
# See the module docstring for why mbcs and not a hard-coded cp1252.
DEFAULT_ENCODING = "mbcs"
DEFAULT_WORKERS = 4
DEFAULT_TIMEOUT_S = 300.0
DEFAULT_STARTUP_TIMEOUT_S = 20.0

# A non-ASCII temp directory breaks the pipe protocol on any encoding that
# cannot represent the profile characters (e.g. 'č' fits cp1250 but not
# cp1252). %ALLUSERSPROFILE% (usually C:\ProgramData) is machine-local,
# ASCII by construction on every Windows install, writable and deletable
# by non-elevated processes (unlike C:\Windows\Temp, where a created
# directory cannot be removed again). Upload dir names and file names are
# generated ASCII (see app.uploads), so scan paths are protocol-safe by
# construction when they live under this base.
SCAN_DIR_NAME = "ecls-scan"


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


def _default_scan_base() -> Path:
    r"""Machine-local, path-encoding-safe scan base for uploaded samples.

    %ALLUSERSPROFILE% (normally C:\ProgramData) exists on every Windows
    install with an ASCII name; %TEMP% lives inside the user profile whose
    absolute path can contain characters outside a fixed ACP such as
    cp1252 (e.g. C:\Users\Kováč\...). Falls back to %TEMP% when
    ALLUSERSPROFILE is unset (e.g. non-Windows dev environments).
    """
    allusers = os.environ.get("ALLUSERSPROFILE", "")
    if allusers.strip():
        return Path(allusers) / SCAN_DIR_NAME
    return Path(tempfile.gettempdir()) / SCAN_DIR_NAME


def _validate_scan_dir(dir_candidate: Path, encoding: str) -> None:
    r"""Fail fast when the scan dir cannot carry the pipe protocol.

    Three failure modes, all cheap to check at startup instead of failing
    per request (which would also thrash the pool, IMPROVEMENTS.md #11):

    - the absolute path is not encodable in the wire encoding ('č' is
      representable in cp1250 but not cp1252)
    - the directory is not usable: cannot be created, written to, and
      deleted again (C:\Windows\Temp accepts create but refuses delete)
    """
    probe = dir_candidate / "ecls_probe_write"
    try:
        str(probe).encode(encoding)
    except UnicodeEncodeError as exc:
        raise ValueError(
            f"scan dir {str(dir_candidate)!r} is not representable in the "
            f"pipe encoding {encoding!r}; set ECLS_TEMP_BASE to an "
            f"{encoding}-safe directory"
        ) from exc
    try:
        dir_candidate.mkdir(parents=True, exist_ok=True)
        probe.write_bytes(b"probe")
        probe.unlink()
    except OSError as exc:
        raise ValueError(
            f"scan dir {str(dir_candidate)!r} is not usable "
            f"(create/write/delete failed): {exc}"
        ) from exc


@dataclass(frozen=True)
class Settings:
    ecls_cmd: tuple[str, ...] = (_resolve_executable(DEFAULT_ECLS_CMD),)
    ecls_args: tuple[str, ...] = tuple(DEFAULT_ECLS_ARGS.split())
    workers: int = DEFAULT_WORKERS
    timeout_s: float = DEFAULT_TIMEOUT_S
    startup_timeout_s: float = DEFAULT_STARTUP_TIMEOUT_S
    encoding: str = DEFAULT_ENCODING
    # None = derive at startup (ASCII-safe machine-local dir, see
    # scan_base()); an explicit ECLS_TEMP_BASE is honored but validated.
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

    @property
    def scan_base(self) -> Path:
        """Validated base directory for uploaded samples.

        ``temp_base`` wins when set (operator override); otherwise an
        ASCII-safe machine-local location is derived. Validation lives in
        ``validate_scan_dir()`` so tests and exotic deployments can opt in
        explicitly, and so the app factory can fail fast at startup.
        """
        if self.temp_base is not None:
            return self.temp_base
        return _default_scan_base()

    def validate_scan_dir(self) -> None:
        """Prove the scan directory is usable for the pipe protocol.

        Raises ValueError with an operator-actionable message otherwise.
        Called from the app lifespan, so a broken deployment fails at
        startup instead of 500-ing (and recycling workers) per request.
        """
        _validate_scan_dir(self.scan_base, self.encoding)

    @classmethod
    def from_env(cls) -> "Settings":
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
            timeout_s=_positive_float(os.environ.get("ECLS_TIMEOUT_S"), DEFAULT_TIMEOUT_S),
            startup_timeout_s=_positive_float(
                os.environ.get("ECLS_STARTUP_TIMEOUT_S"), DEFAULT_STARTUP_TIMEOUT_S
            ),
            encoding=os.environ.get("ECLS_ENCODING", DEFAULT_ENCODING),
            temp_base=Path(temp_base) if temp_base else None,
            max_upload_bytes=max_upload_bytes,
        )
