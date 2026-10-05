"""Persist uploads to unique temp directories, safe for the line protocol.

Each upload lands in its own ``tempfile.mkdtemp`` directory under
``settings.scan_base`` (an ASCII-safe, validated machine-local dir) using a
generated, protocol-safe filename — the scanner only ever sees this path,
so neither upload names nor profile-path characters can ever break the
pipe encoding. The original name is kept for normalizing scanner output.
"""

from __future__ import annotations

import re
import shutil
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath

from fastapi import UploadFile
from starlette.concurrency import run_in_threadpool

from app.config import Settings

_SUFFIX_RE = re.compile(r"^[A-Za-z0-9]{1,10}$")
_READ_CHUNK = 1 << 20


class UploadRejected(ValueError):
    pass


class UploadTooLarge(Exception):
    pass


@dataclass(frozen=True)
class SavedUpload:
    path: Path
    directory: Path
    original_name: str


def sanitize_filename(raw: str | None, delimiter: str) -> str:
    if raw is None:
        raise UploadRejected("upload has no filename")
    name = PureWindowsPath(raw).name
    if not name:
        raise UploadRejected(f"upload has no usable filename: {raw!r}")
    if name == delimiter:
        raise UploadRejected(
            f"upload filename must not be the scanner delimiter {delimiter!r}"
        )
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in name):
        raise UploadRejected(f"upload filename contains control characters: {name!r}")
    return name


def _temp_suffix(raw: str | None) -> str:
    if raw:
        candidate = PureWindowsPath(raw).suffix.lstrip(".")
        if _SUFFIX_RE.match(candidate):
            return "." + candidate
    return ".bin"


async def save_upload(upload: UploadFile, settings: Settings) -> SavedUpload:
    original_name = sanitize_filename(upload.filename, settings.delimiter)
    directory = Path(
        await run_in_threadpool(
            tempfile.mkdtemp, prefix="ecls_", dir=settings.scan_base
        )
    )
    path = directory / f"upload_{uuid.uuid4().hex}{_temp_suffix(upload.filename)}"
    try:
        limit = settings.max_upload_bytes
        total = 0
        with path.open("wb") as target:
            while chunk := await upload.read(_READ_CHUNK):
                total += len(chunk)
                if limit is not None and total > limit:
                    raise UploadTooLarge(
                        f"upload {original_name!r} exceeds the size limit of {limit} bytes"
                    )
                await run_in_threadpool(target.write, chunk)
        return SavedUpload(
            path=path, directory=directory, original_name=original_name
        )
    except BaseException:
        shutil.rmtree(directory, ignore_errors=True)
        raise


def remove_upload(saved: SavedUpload) -> None:
    shutil.rmtree(saved.directory, ignore_errors=True)
