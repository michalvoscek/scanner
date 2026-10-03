"""One persistent ecls.exe subprocess speaking the stdin/stdout pipe protocol.

Protocol (verified against data/ecls.exe, see app.config):

- one file path line on stdin -> ``name="..."`` result lines followed by the
  batch delimiter line on stdout; the delimiter is never sent to stdin
- stdin EOF -> ecls prints a summary and exits
"""

from __future__ import annotations

import asyncio
import contextlib
import logging

from app.config import Settings
from app.ecls.parser import decode_line, normalize_entries, parse_line
from app.models import ScanEntry

logger = logging.getLogger(__name__)

_INPUT_NEWLINE = "\r\n"
_DRAIN_CHUNK = 4096


class EclsError(Exception):
    pass


class EclsSpawnError(EclsError):
    pass


class EclsStreamError(EclsError):
    pass


class EclsProcess:
    """A single scanner worker; one scan in flight at a time."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._proc: asyncio.subprocess.Process | None = None
        self._stderr_task: asyncio.Task[None] | None = None
        self._lock = asyncio.Lock()

    @property
    def started(self) -> bool:
        return self._proc is not None

    async def start(self) -> None:
        if self._proc is not None:
            return
        try:
            self._proc = await asyncio.create_subprocess_exec(
                *self._settings.scanner_argv,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except Exception as exc:
            self._proc = None
            raise EclsSpawnError(
                f"failed to start scanner process {self._settings.ecls_cmd[0]!r}: {exc}"
            ) from exc
        assert self._proc.stderr is not None
        self._stderr_task = asyncio.create_task(
            self._drain_forever(self._proc.stderr)
        )
        try:
            first_line = await asyncio.wait_for(
                self._proc.stdout.readline(), self._settings.startup_timeout_s
            )
        except TimeoutError as exc:
            await self.stop()
            raise EclsSpawnError(
                "scanner did not print its startup banner in time"
            ) from exc
        if not first_line:
            await self.stop()
            raise EclsSpawnError("scanner exited before printing its startup banner")
        logger.debug("scanner worker started (pid %s)", self._proc.pid)

    async def scan(self, sent_path: str, original_name: str) -> list[ScanEntry]:
        async with self._lock:
            return await self._scan_locked(sent_path, original_name)

    async def stop(self) -> None:
        """Shut the worker down: close stdin, wait, terminate, kill."""
        proc, self._proc = self._proc, None
        stderr_task, self._stderr_task = self._stderr_task, None
        if proc is None:
            return
        grace = self._settings.startup_timeout_s
        try:
            if proc.stdin is not None:
                proc.stdin.close()
        except Exception:
            logger.debug("closing scanner stdin failed", exc_info=True)
        drain_task = None
        if proc.stdout is not None:
            drain_task = asyncio.create_task(self._drain_forever(proc.stdout))
        try:
            try:
                await asyncio.wait_for(proc.wait(), grace)
            except TimeoutError:
                logger.warning(
                    "scanner pid %s did not exit after stdin close; terminating",
                    proc.pid,
                )
                await self._terminate_and_wait(proc, grace)
        finally:
            for task in (drain_task, stderr_task):
                if task is not None:
                    task.cancel()
                    with contextlib.suppress(BaseException):
                        await task
        logger.debug("scanner worker stopped (pid %s)", proc.pid)

    async def _scan_locked(
        self, sent_path: str, original_name: str
    ) -> list[ScanEntry]:
        proc = self._proc
        if proc is None or proc.stdin is None or proc.stdout is None:
            raise EclsStreamError("scanner process is not running")
        stdin, stdout = proc.stdin, proc.stdout
        try:
            payload = (sent_path + _INPUT_NEWLINE).encode(self._settings.encoding)
        except UnicodeEncodeError as exc:
            raise EclsStreamError(
                f"scanner path is not representable in {self._settings.encoding}: {sent_path!r}"
            ) from exc
        try:
            stdin.write(payload)
            await stdin.drain()
        except Exception as exc:
            raise EclsStreamError(f"failed to send path to scanner: {exc}") from exc
        entries: list[ScanEntry] = []
        ignored_lines = 0
        delimiter = self._settings.delimiter
        while True:
            raw = await stdout.readline()
            if not raw:
                raise EclsStreamError(
                    "scanner closed its output before the batch delimiter"
                )
            line = decode_line(raw, self._settings.encoding)
            if line == delimiter:
                break
            entry = parse_line(line)
            if entry is None:
                ignored_lines += 1
                continue
            entries.append(entry)
        logger.debug(
            "scan of %s produced %d entries (%d ignored lines)",
            sent_path,
            len(entries),
            ignored_lines,
        )
        return normalize_entries(entries, sent_path, original_name)

    async def _terminate_and_wait(
        self, proc: asyncio.subprocess.Process, grace: float
    ) -> None:
        for killer in (proc.terminate, proc.kill):
            try:
                killer()
            except ProcessLookupError:
                return
            except Exception:
                logger.debug("killing scanner pid %s failed", proc.pid, exc_info=True)
                continue
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(proc.wait(), grace)
                return
        logger.error("scanner pid %s refused to die", proc.pid)

    async def _drain_forever(self, stream: asyncio.StreamReader) -> None:
        while await stream.read(_DRAIN_CHUNK):
            pass
