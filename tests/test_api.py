"""Integration tests: pool + endpoints against the mock scanner."""

from __future__ import annotations

import sys
import time

import httpx
import pytest

from app.main import create_app


async def scan_file(client, filename, content):
    return await client.post(
        "/scanFile", files={"file": (filename, content, "application/octet-stream")}
    )


async def scan_multiple(client, uploads):
    files = [("files", (name, content, "application/octet-stream")) for name, content in uploads]
    return await client.post("/scanMultipleFiles", files=files)


async def test_scan_file_returns_readme_shape(client):
    response = await scan_file(client, "test.zip", b"plain")
    assert response.status_code == 200
    assert response.json() == {
        "scan_results": [{"name": ["test.zip"], "threat": "is OK", "action": "", "info": ""}]
    }


async def test_scan_file_nested_zip_entries(client):
    content = b"#MOCK ZIP\nah_dna.exe\nah_dna.ini\n"
    response = await scan_file(client, "test.zip", content)
    assert response.status_code == 200
    assert response.json() == {
        "scan_results": [
            {"name": ["test.zip"], "threat": "is OK", "action": "", "info": ""},
            {"name": ["test.zip", "ZIP", "ah_dna.exe"], "threat": "is OK", "action": "", "info": ""},
            {"name": ["test.zip", "ZIP", "ah_dna.ini"], "threat": "is OK", "action": "", "info": ""},
        ]
    }


async def test_scan_file_reports_custom_threat(client):
    response = await scan_file(client, "bad.exe", b"#MOCK THREAT=TestTrojan.A\n")
    assert response.status_code == 200
    assert response.json()["scan_results"][0]["threat"] == "TestTrojan.A"


async def test_quote_injection_from_nested_filename_never_reaches_threat(client):
    """IMPROVEMENTS.md #1, end to end through /scanFile.

    A nested member named `x", threat="Win32/Eicar` makes the scanner emit
    `name="... » ZIP » x", threat="Win32/Eicar", threat="is OK", ...`. The
    client must only ever see the scanner's own verdict in `threat`; the
    injected text must stay inside `name`.
    """
    content = b'#MOCK ZIP\nx", threat="Win32/Eicar\n'
    response = await scan_file(client, "crafted.zip", content)
    assert response.status_code == 200
    entries = response.json()["scan_results"]
    # The injected text must remain visible in `name` (never silently dropped)...
    assert any(
        "Win32/Eicar" in part for entry in entries for part in entry["name"]
    )
    # ...while threat/action/info stay the scanner's own verdicts.
    for entry in entries:
        assert entry["threat"] == "is OK"
        assert entry["action"] == ""
        assert entry["info"] == ""


async def test_scan_multiple_files_preserves_upload_order(client):
    uploads = [
        ("a.txt", b"alpha"),
        ("test.zip", b"#MOCK ZIP\ninner1\ninner2\n"),
        ("b.txt", b"beta"),
    ]
    response = await scan_multiple(client, uploads)
    assert response.status_code == 200
    results = response.json()["scan_results"]
    assert [entry["name"][0] for entry in results] == [
        "a.txt",
        "test.zip",
        "test.zip",
        "test.zip",
        "b.txt",
    ]
    inners = [entry["name"][2] for entry in results if len(entry["name"]) == 3]
    assert inners == ["inner1", "inner2"]


async def test_scan_multiple_files_empty_upload_list_is_rejected(client):
    response = await client.post("/scanMultipleFiles")
    assert response.status_code == 422


async def test_scan_multiple_files_requires_files_field(client):
    response = await client.post("/scanMultipleFiles", data={"unrelated": "1"})
    assert response.status_code == 422


async def test_duplicate_upload_names_normalize_independently(client):
    uploads = [
        ("test.zip", b"#MOCK THREAT=first\n"),
        ("test.zip", b"#MOCK THREAT=second\n"),
    ]
    response = await scan_multiple(client, uploads)
    assert response.status_code == 200
    results = response.json()["scan_results"]
    assert [entry["name"][0] for entry in results] == ["test.zip", "test.zip"]
    assert [entry["threat"] for entry in results] == ["first", "second"]


async def test_path_traversal_filename_is_sanitized_to_basename(client):
    response = await scan_file(client, "../../evil.sh", b"x")
    assert response.status_code == 200
    assert response.json()["scan_results"][0]["name"] == ["evil.sh"]


async def test_delimiter_filename_is_rejected(client):
    response = await scan_file(client, "__INPUT_END__", b"x")
    assert response.status_code == 422
    assert "delimiter" in response.json()["detail"]


async def test_empty_filename_is_rejected(client):
    response = await scan_file(client, "", b"x")
    assert response.status_code == 422


async def test_scan_crash_returns_500_naming_upload_and_recycles_worker(client):
    response = await scan_file(client, "doomed.zip", b"#MOCK CRASH")
    assert response.status_code == 500
    assert "doomed.zip" in response.json()["detail"]

    followup = await scan_file(client, "fine.txt", b"ok")
    assert followup.status_code == 200
    assert followup.json()["scan_results"] == [
        {"name": ["fine.txt"], "threat": "is OK", "action": "", "info": ""}
    ]


async def test_scan_timeout_returns_500_and_worker_is_replaced(make_settings):
    app = create_app(make_settings(timeout_s=1.5))
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            response = await scan_file(client, "hanging.txt", b"#MOCK HANG")
            assert response.status_code == 500
            assert "hanging.txt" in response.json()["detail"]

            followup = await scan_file(client, "after.txt", b"clean")
            assert followup.status_code == 200
            assert followup.json()["scan_results"] == [
                {"name": ["after.txt"], "threat": "is OK", "action": "", "info": ""}
            ]


async def test_desynced_worker_is_never_reused(make_settings):
    app = create_app(make_settings(timeout_s=1.5))
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            response = await scan_file(client, "stale.zip", b"#MOCK DESYNC")
            assert response.status_code == 500

            clean = await scan_file(client, "after.txt", b"clean")
            assert clean.status_code == 200
            assert "stale.zip" not in clean.text
            assert clean.json()["scan_results"] == [
                {"name": ["after.txt"], "threat": "is OK", "action": "", "info": ""}
            ]


async def test_unable_to_open_verdict_is_a_failure_not_clean_200(make_settings):
    """IMPROVEMENTS.md #10: 'unable to open' means the file was NOT scanned.

    The verdict shape (verified against the real scanner) is threat='',
    action='', info='unable to open' — previously returned as a normal 200
    entry, a false negative for callers that only check the status code.
    """
    app = create_app(make_settings(workers=1))
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            response = await scan_file(client, "locked.zip", b"#MOCK UNOPENABLE")
            assert response.status_code == 500
            assert "locked.zip" in response.json()["detail"]
            # the failing scan must not leak the internal temp path
            assert "upload_" not in response.text
            # the pool must not have lost a worker to this failure
            assert app.state.ecls_pool.size == 1

            followup = await scan_file(client, "after.txt", b"clean")
            assert followup.status_code == 200
            assert followup.json()["scan_results"] == [
                {"name": ["after.txt"], "threat": "is OK", "action": "", "info": ""}
            ]


async def test_zero_entries_answer_is_a_desync_failure(make_settings):
    """IMPROVEMENTS.md #8: zero name= lines before the delimiter is desync."""
    app = create_app(make_settings(workers=1))
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            response = await scan_file(client, "silent.zip", b"#MOCK NOENTRIES")
            assert response.status_code == 500
            assert app.state.ecls_pool.size == 1

            followup = await scan_file(client, "after.txt", b"clean")
            assert followup.status_code == 200
            assert followup.json()["scan_results"] == [
                {"name": ["after.txt"], "threat": "is OK", "action": "", "info": ""}
            ]


async def test_junk_line_inside_batch_is_a_desync_failure(make_settings):
    """IMPROVEMENTS.md #8: after the banner drain, every line before the
    delimiter must parse as a result entry; anything else fails the request."""
    app = create_app(make_settings(workers=1))
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            response = await scan_file(client, "noisy.zip", b"#MOCK JUNKLINE")
            assert response.status_code == 500
            assert app.state.ecls_pool.size == 1

            followup = await scan_file(client, "after.txt", b"clean")
            assert followup.status_code == 200
            assert followup.json()["scan_results"] == [
                {"name": ["after.txt"], "threat": "is OK", "action": "", "info": ""}
            ]


async def test_unable_to_open_in_multi_scan_is_all_or_nothing(client):
    """IMPROVEMENTS.md #10+#15: one unscanned file fails the whole batch."""
    uploads = [
        ("good.txt", b"good"),
        ("bad.zip", b"#MOCK UNOPENABLE"),
    ]
    response = await scan_multiple(client, uploads)
    assert response.status_code == 500
    detail = response.json()["detail"]
    assert "'bad.zip'" in detail
    assert "good.txt" not in detail


async def test_delayed_banner_is_drained_and_never_leaks_into_results(make_settings):
    """IMPROVEMENTS.md #8: the banner is drained until its marker, however
    late it arrives; banner text must never surface as scan output."""
    app = create_app(
        make_settings(mock_args=["/delayed-banner=0.3"], workers=1)
    )
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            response = await scan_file(client, "test.zip", b"plain")
            assert response.status_code == 200
            assert response.json()["scan_results"] == [
                {"name": ["test.zip"], "threat": "is OK", "action": "", "info": ""}
            ]


async def test_startup_fails_when_banner_never_completes(make_settings):
    """IMPROVEMENTS.md #8: a scanner that never finishes its banner is a
    spawn failure, not a worker that silently misparses later."""
    app = create_app(
        make_settings(mock_args=["/nobanner"], startup_timeout_s=2.0, workers=1)
    )
    with pytest.raises(Exception):
        async with app.router.lifespan_context(app):
            pass


async def test_multiple_files_partial_failure_is_all_or_nothing(client):
    uploads = [
        ("good.txt", b"good"),
        ("bad.zip", b"#MOCK CRASH"),
    ]
    response = await scan_multiple(client, uploads)
    assert response.status_code == 500
    detail = response.json()["detail"]
    assert "'bad.zip'" in detail
    assert "good.txt" not in detail


async def test_custom_batch_delimiter_is_honoured_end_to_end(make_settings):
    settings = make_settings(
        ecls_args=("/log-all", "/stdin-filelist", "/batch-delimiter=XX_END__")
    )
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            response = await scan_file(client, "test.zip", b"plain")
            assert response.status_code == 200
            assert response.json()["scan_results"][0]["name"] == ["test.zip"]


async def test_max_upload_size_is_enforced(make_settings):
    app = create_app(make_settings(max_upload_bytes=16))
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            response = await scan_file(client, "big.bin", b"x" * 64)
            assert response.status_code == 413
            assert "big.bin" in response.json()["detail"]


async def test_scans_run_in_parallel(make_settings, tmp_path):
    settings = make_settings(log_dir=tmp_path, timeout_s=10.0)
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            uploads = [(f"f{i}.txt", b"#MOCK SLEEP=0.5\n") for i in range(4)]
            started = time.perf_counter()
            response = await scan_multiple(client, uploads)
            elapsed = time.perf_counter() - started
            assert response.status_code == 200
            assert len(response.json()["scan_results"]) == 4

    spans = {}
    for log_file in sorted(tmp_path.glob("*.log")):
        for line in log_file.read_text(encoding="utf-8").splitlines():
            parts = line.split("\t")
            if len(parts) != 4:
                continue
            kind, timestamp, _pid, path = parts
            spans.setdefault(path, {})[kind] = float(timestamp)
    intervals = [
        (events["start"], events["end"])
        for events in spans.values()
        if "start" in events and "end" in events
    ]
    assert len(intervals) == 4
    max_concurrency = max(
        sum(1 for start, end in intervals if start <= point < end)
        for point, _ in intervals
    )
    assert max_concurrency >= 2
    assert elapsed < 4 * 0.5


async def test_startup_fails_fast_when_scanner_dies_immediately(make_settings):
    app = create_app(
        make_settings(ecls_cmd=(sys.executable, "-c", "import sys; sys.exit(0)"))
    )
    with pytest.raises(Exception):
        async with app.router.lifespan_context(app):
            pass


async def test_startup_fails_fast_when_scanner_exe_is_missing(make_settings):
    app = create_app(
        make_settings(ecls_cmd=("definitely-missing-scanner-xyz.exe",))
    )
    with pytest.raises(Exception):
        async with app.router.lifespan_context(app):
            pass


async def test_unencodable_scan_base_fails_at_startup(
    make_settings, tmp_path, monkeypatch
):
    """IMPROVEMENTS.md #11: a temp path that cannot be encoded in the wire
    encoding breaks every scan; that must fail at startup, not 500 (and
    respawn healthy workers) per request."""
    # 'č' is representable in cp1250 but NOT in cp1252 (conftest encoding)
    hostile_base = tmp_path / "Kováč"
    hostile_base.mkdir()
    app = create_app(make_settings(temp_base=hostile_base))
    with pytest.raises(Exception) as excinfo:
        async with app.router.lifespan_context(app):
            pass
    assert "not representable" in str(excinfo.value)


async def test_unencodable_sent_path_keeps_healthy_worker(make_settings, tmp_path):
    """IMPROVEMENTS.md #11: a pre-IO encode error must not recycle a worker.

    A filename whose temp path cannot be encoded in the wire encoding (here
    driven directly against the pool; the endpoint maps any scan failure to
    500) must leave the worker untouched: it goes back to the queue instead
    of being discarded and replaced.
    """
    nonascii = "Kováč"
    try:
        hostile_base = tmp_path / nonascii
        hostile_base.mkdir(parents=True)
    except OSError:
        pytest.skip(f"filesystem cannot host {nonascii!r}")
    app = create_app(make_settings())
    async with app.router.lifespan_context(app):
        pool = app.state.ecls_pool
        workers_before = pool.size
        queue_before = pool._free.qsize()
        # A path containing 'č' is not encodable in conftest's cp1252.
        unencodable = str(hostile_base / "s.clf")
        with pytest.raises(UnicodeEncodeError):
            unencodable.encode("cp1252", errors="strict")
        try:
            await pool.scan(unencodable, "hostile")
        except Exception as exc:
            assert "not representable" in str(exc)
        else:
            raise AssertionError("unencodable path should have failed")
        # The worker was never discarded and is still handed out.
        assert pool.size == workers_before
        assert pool._free.qsize() == queue_before
        # Answer 200 with the same worker afterwards.
        clean_file = tmp_path / "clean.txt"
        clean_file.write_text("clean")
        entries = await pool.scan(str(clean_file), "after")
        assert entries[0].threat == "is OK"


