"""Shared fixtures: mock-scanner settings, app factory override, client."""

from __future__ import annotations

import functools
import hashlib
import sys
from pathlib import Path

import httpx
import pytest
import pytest_asyncio

from app.config import Settings
from app.main import create_app

MOCK_ECLS = Path(__file__).resolve().parent / "mock_ecls.py"
TEST_FILES_DIR = Path(__file__).resolve().parent.parent / "test_files"
THREATS_DIR = TEST_FILES_DIR / "threats"

TEST_TIMEOUT_S = 6.0
TEST_STARTUP_TIMEOUT_S = 15.0


@functools.lru_cache(maxsize=1)
def _threat_digests() -> tuple[str, ...]:
    """SHA-256 digests of the files currently in test_files/threats.

    Passed to the mock scanner so that dropping a sample into the folder is
    the only registration it needs; the mock reports matching contents as
    threats with no further per-sample setup. Files added after pytest
    collection are picked up by the next test run.
    """
    if not THREATS_DIR.is_dir():
        return ()
    return tuple(
        hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(THREATS_DIR.iterdir())
        if path.is_file()
    )


def _make_settings(**overrides) -> Settings:
    log_dir = overrides.pop("log_dir", None)
    mock_args = overrides.pop("mock_args", None)
    ecls_cmd = [sys.executable, str(MOCK_ECLS)]
    if log_dir is not None:
        ecls_cmd += ["--log", str(log_dir)]
    ecls_cmd += [f"--threat={digest}" for digest in _threat_digests()]
    if mock_args:
        ecls_cmd += list(mock_args)
    values = {
        "ecls_cmd": tuple(ecls_cmd),
        "ecls_args": (
            "/log-all",
            "/stdin-filelist",
            "/batch-delimiter=__INPUT_END__",
        ),
        "workers": 4,
        "timeout_s": TEST_TIMEOUT_S,
        "startup_timeout_s": TEST_STARTUP_TIMEOUT_S,
        "encoding": "cp1252",
        "temp_base": None,
        "max_upload_bytes": None,
    }
    values.update(overrides)
    return Settings(**values)


@pytest.fixture
def make_settings():
    return _make_settings


@pytest_asyncio.fixture
async def client(make_settings):
    app = create_app(make_settings())
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as http_client:
            yield http_client
