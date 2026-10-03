"""Parse raw ecls.exe stdout lines into scan entries.

Result lines look like::

    name="test.zip » ZIP » ah_dna.exe", threat="is OK", action="", info=""

Everything else (banner, module versions, ``Command line:``,
``Scan started at:``, blank lines, unknown formats) is ignored.
"""

from __future__ import annotations

import re

from app.models import ScanEntry

LINE_RE = re.compile(
    r'^\s*name="(.*?)", threat="(.*?)", action="(.*?)", info="(.*?)"\s*$'
)
GUILLEMET = "»"


def decode_line(raw: bytes, encoding: str) -> str:
    return raw.decode(encoding, errors="replace").rstrip("\r\n")


def parse_line(line: str) -> ScanEntry | None:
    match = LINE_RE.match(line)
    if match is None:
        return None
    parts = (part.strip() for part in match.group(1).split(GUILLEMET))
    return ScanEntry(
        name=[part for part in parts if part],
        threat=match.group(2),
        action=match.group(3),
        info=match.group(4),
    )


def normalize_entries(
    entries: list[ScanEntry], sent_path: str, original_name: str
) -> list[ScanEntry]:
    """Replace the echoed scanner path with the original upload name.

    ecls echoes the exact path sent on stdin as the *first* name component;
    only that component is rewritten, nested ``ZIP`` parts stay untouched.
    If the output does not contain the sent path this is a no-op.
    """
    normalized: list[ScanEntry] = []
    for entry in entries:
        if entry.name and entry.name[0].startswith(sent_path):
            remainder = entry.name[0][len(sent_path) :]
            name = [original_name + remainder, *entry.name[1:]]
            entry = entry.model_copy(update={"name": name})
        normalized.append(entry)
    return normalized
