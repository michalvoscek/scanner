"""Unit tests for environment-driven settings."""

from __future__ import annotations

import sys
from pathlib import Path

from app.config import PROJECT_ROOT, Settings


def test_defaults_reference_real_scanner_and_protocol():
    settings = Settings()
    assert settings.ecls_cmd[0] == str(PROJECT_ROOT / "data" / "ecls.exe")
    assert Path(settings.ecls_cmd[0]).is_absolute()
    assert settings.ecls_args == (
        "/log-all",
        "/stdin-filelist",
        "/batch-delimiter=__INPUT_END__",
    )
    assert settings.delimiter == "__INPUT_END__"
    assert settings.workers == 4
    assert settings.timeout_s == 300.0
    assert settings.encoding == "cp1252"
    assert settings.temp_base is None
    assert settings.max_upload_bytes is None
    assert settings.scanner_argv == (*settings.ecls_cmd, *settings.ecls_args)


def test_delimiter_follows_batch_delimiter_argument():
    settings = Settings(ecls_args=("/log-all", "/stdin-filelist", "/batch-delimiter=XX_END__"))
    assert settings.delimiter == "XX_END__"
    assert Settings(ecls_args=("/log-all",)).delimiter == "__INPUT_END__"


def test_from_env_reads_overrides(monkeypatch, tmp_path):
    monkeypatch.setenv("ECLS_CMD", f"{sys.executable} tests/mock_ecls.py")
    monkeypatch.setenv("ECLS_WORKERS", "7")
    monkeypatch.setenv("ECLS_TIMEOUT_S", "12.5")
    monkeypatch.setenv("ECLS_ENCODING", "latin-1")
    monkeypatch.setenv("ECLS_TEMP_BASE", str(tmp_path))
    monkeypatch.setenv("ECLS_MAX_UPLOAD_MB", "1.5")
    settings = Settings.from_env()
    assert settings.ecls_cmd[1].endswith("mock_ecls.py")
    assert settings.workers == 7
    assert settings.timeout_s == 12.5
    assert settings.encoding == "latin-1"
    assert settings.temp_base == tmp_path
    assert settings.max_upload_bytes == int(1.5 * (1 << 20))
    assert settings.delimiter == "__INPUT_END__"


def test_from_env_resolves_relative_executable_against_project_root(monkeypatch):
    monkeypatch.setenv("ECLS_CMD", "data/ecls.exe")
    settings = Settings.from_env()
    assert settings.ecls_cmd == (str(PROJECT_ROOT / "data" / "ecls.exe"),)


def test_from_env_keeps_non_path_executable_tokens(monkeypatch):
    monkeypatch.setenv("ECLS_CMD", "python mock_scanner.py")
    settings = Settings.from_env()
    assert settings.ecls_cmd == ("python", "mock_scanner.py")


def test_invalid_values_are_rejected():
    for kwargs in (
        {"workers": 0},
        {"timeout_s": 0},
        {"timeout_s": -1.0},
        {"startup_timeout_s": 0},
        {"ecls_cmd": ()},
    ):
        try:
            Settings(**kwargs)
        except ValueError:
            continue
        raise AssertionError(f"Settings({kwargs!r}) should have raised")
