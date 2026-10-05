"""Pool of persistent ecls scanner processes with failure recycling.

Workers are handed out through an asyncio.Queue. A worker that fails a scan
by protocol violation (timeout, EOF, broken pipe, desync) is killed and
never returned to the queue; a fresh replacement is spawned in its place.
Request-level failures raised before any protocol I/O (unencodable path)
leave the worker untouched: it goes straight back to the queue.
"""

from __future__ import annotations

import asyncio
import logging

from app.config import Settings
from app.ecls.process import (
    EclsProcess,
    EclsRequestError,
)
from app.models import ScanEntry

logger = logging.getLogger(__name__)


class EclsPool:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._workers: set[EclsProcess] = set()
        self._free: asyncio.Queue[EclsProcess] = asyncio.Queue()
        self._closed = False

    @property
    def size(self) -> int:
        return len(self._workers)

    async def start(self) -> None:
        if self._closed:
            raise RuntimeError("pool was shut down")
        try:
            for _ in range(self._settings.workers):
                worker = EclsProcess(self._settings)
                await worker.start()
                self._add(worker)
        except BaseException:
            await self.shutdown()
            raise
        logger.info(
            "ecls pool started with %d workers (cmd %r)",
            len(self._workers),
            self._settings.ecls_cmd,
        )

    async def scan(self, sent_path: str, original_name: str) -> list[ScanEntry]:
        if self._closed:
            raise RuntimeError("pool is shut down")
        await self._heal()
        if not self._workers:
            raise RuntimeError("no scanner workers available")
        worker = await self._free.get()
        try:
            entries = await asyncio.wait_for(
                worker.scan(sent_path, original_name), self._settings.timeout_s
            )
        except EclsRequestError:
            # The request failed before any protocol I/O (e.g. a path not
            # encodable in the wire encoding). The worker is untouched and
            # trustworthy: hand it straight back instead of recycling it
            # (IMPROVEMENTS.md #11).
            self._free.put_nowait(worker)
            raise
        except BaseException as exc:
            logger.warning(
                "scanner worker failed for %r (%r); recycling it",
                original_name,
                exc,
            )
            await self._discard(worker)
            await self._replace()
            raise
        self._free.put_nowait(worker)
        return entries

    async def shutdown(self) -> None:
        self._closed = True
        workers = list(self._workers)
        self._workers.clear()
        while True:
            try:
                self._free.get_nowait()
            except asyncio.QueueEmpty:
                break
        if workers:
            await asyncio.gather(
                *(worker.stop() for worker in workers), return_exceptions=True
            )
        logger.info("ecls pool shut down (%d workers)", len(workers))

    async def _heal(self) -> None:
        while len(self._workers) < self._settings.workers and not self._closed:
            worker = EclsProcess(self._settings)
            try:
                await worker.start()
            except Exception:
                logger.warning(
                    "failed to heal ecls pool to %d workers (currently %d)",
                    self._settings.workers,
                    len(self._workers),
                    exc_info=True,
                )
                return
            self._add(worker)

    async def _discard(self, worker: EclsProcess) -> None:
        self._workers.discard(worker)
        try:
            await worker.stop()
        except Exception:
            logger.warning("stopping failed scanner worker raised", exc_info=True)

    async def _replace(self) -> None:
        if self._closed:
            return
        worker = EclsProcess(self._settings)
        try:
            await worker.start()
        except Exception:
            logger.warning(
                "failed to replace failed scanner worker (pool at %d/%d)",
                len(self._workers),
                self._settings.workers,
                exc_info=True,
            )
            return
        self._add(worker)

    def _add(self, worker: EclsProcess) -> None:
        self._workers.add(worker)
        self._free.put_nowait(worker)
