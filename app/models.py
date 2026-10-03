"""Pydantic response models shaped after the README sample output."""

from __future__ import annotations

from pydantic import BaseModel


class ScanEntry(BaseModel):
    name: list[str]
    threat: str
    action: str
    info: str


class ScanResponse(BaseModel):
    scan_results: list[ScanEntry]
