"""FastAPI application exposing /scanFile and /scanMultipleFiles."""

from __future__ import annotations

import asyncio
import logging
import shutil
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.routing import APIRouter

from app.config import Settings
from app.ecls.pool import EclsPool
from app.models import ScanResponse
from app.uploads import (
    SavedUpload,
    UploadRejected,
    UploadTooLarge,
    remove_upload,
    save_upload,
)

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings: Settings = app.state.settings
    # Fail fast on an unusable/non-ASCII scan dir rather than 500-ing (and
    # recycling workers) on every request (IMPROVEMENTS.md #11).
    settings.validate_scan_dir()
    _sweep_stale_scan_dirs(settings.scan_base)
    pool = EclsPool(settings)
    await pool.start()
    app.state.ecls_pool = pool
    try:
        yield
    finally:
        await pool.shutdown()


def _sweep_stale_scan_dirs(scan_base: Path) -> None:
    """Best-effort removal of per-upload dirs left over from a crash.

    Each upload lives in its own ``ecls_*`` directory under ``scan_base``;
    a hard crash (or a Windows sharing violation during rmtree) can leave
    sample files behind. Only directories are swept and ignore_errors stays
    best-effort — never touch anything we did not create under scan_base.
    """
    try:
        entries = list(scan_base.iterdir())
    except OSError:
        return
    for entry in entries:
        if entry.is_dir() and entry.name.startswith("ecls_"):
            shutil.rmtree(entry, ignore_errors=True)


def get_settings_dep(request: Request) -> Settings:
    return request.app.state.settings


def get_pool(request: Request) -> EclsPool:
    return request.app.state.ecls_pool


router = APIRouter()


@router.post("/scanFile", response_model=ScanResponse)
async def scan_file(
    file: UploadFile = File(...),
    settings: Settings = Depends(get_settings_dep),
    pool: EclsPool = Depends(get_pool),
) -> ScanResponse:
    saved = await _save(file, settings)
    try:
        entries = await pool.scan(str(saved.path), saved.original_name)
    except Exception as exc:
        logger.error(
            "scan of upload %r failed: %r", saved.original_name, exc
        )
        raise HTTPException(
            status_code=500,
            detail=f"scan failed for uploaded file '{saved.original_name}': {exc}",
        ) from exc
    finally:
        remove_upload(saved)
    return ScanResponse(scan_results=entries)


@router.post("/scanMultipleFiles", response_model=ScanResponse)
async def scan_multiple_files(
    files: list[UploadFile] = File(...),
    settings: Settings = Depends(get_settings_dep),
    pool: EclsPool = Depends(get_pool),
) -> ScanResponse:
    saved: list[SavedUpload] = []
    try:
        for upload in files:
            saved.append(await _save(upload, settings))
        results = await asyncio.gather(
            *(pool.scan(str(item.path), item.original_name) for item in saved),
            return_exceptions=True,
        )
    finally:
        for item in saved:
            remove_upload(item)
    failures = [
        (item.original_name, result)
        for item, result in zip(saved, results)
        if isinstance(result, BaseException)
    ]
    if failures:
        names = ", ".join(f"'{name}'" for name, _ in failures)
        reasons = "; ".join(f"{name}: {result!r}" for name, result in failures)
        logger.error("scans failed: %s", reasons)
        raise HTTPException(
            status_code=500,
            detail=(
                f"scan failed for uploaded file(s) {names}; "
                "no results are returned"
            ),
        )
    entries = [entry for result in results for entry in result]
    return ScanResponse(scan_results=entries)


async def _save(upload: UploadFile, settings: Settings) -> SavedUpload:
    try:
        return await save_upload(upload, settings)
    except UploadTooLarge as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    except UploadRejected as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


def create_app(settings: Settings | None = None) -> FastAPI:
    app = FastAPI(title="ecls scan API", version="1.0.0", lifespan=lifespan)
    app.state.settings = settings if settings is not None else Settings.from_env()
    app.include_router(router)
    return app


app = create_app()
