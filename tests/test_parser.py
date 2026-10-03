"""Unit tests for the ecls output parser, based on the README sample."""

from __future__ import annotations

from app.ecls.parser import decode_line, normalize_entries, parse_line
from app.models import ScanEntry

README_LINES = [
    "ECLS Command-line scanner, version 11.1.65535.0, (C) 1992-2018 ESET, spol. s r.o.",
    "Module loader, version 1018NV (20190619), build 11051",
    "Module perseus, version 1554 (20190718), build 2047",
    "Module scanner, version 65715D (20190722), build 732494",
    "Module archiver, version 1289DNA (20190709), build 11390",
    "Module advheur, version 1193 (20190626), build 1175",
    "Module cleaner, version 1197 (20190711), build 1297",
    "Module pegasus, version 703707 (20190722), build 703707",
    "",
    "Command line: /log-all test.zip",
    "",
    "Scan started at:   Tue Jul 30 14:45:42 2019",
    'name="test.zip", threat="is OK", action="", info=""',
    'name="test.zip » ZIP » ah_dna.exe", threat="is OK", action="", info=""',
    'name="test.zip » ZIP » ah_dna.ini", threat="is OK", action="", info=""',
    'name="test.zip » ZIP » ecls.exe", threat="is OK", action="", info=""',
    "__INPUT_END__",
]


def parse_all(lines):
    entries = (parse_line(line) for line in lines)
    return [entry for entry in entries if entry is not None]


def test_readme_sample_parses_fully():
    assert parse_all(README_LINES) == [
        ScanEntry(name=["test.zip"], threat="is OK", action="", info=""),
        ScanEntry(name=["test.zip", "ZIP", "ah_dna.exe"], threat="is OK", action="", info=""),
        ScanEntry(name=["test.zip", "ZIP", "ah_dna.ini"], threat="is OK", action="", info=""),
        ScanEntry(name=["test.zip", "ZIP", "ecls.exe"], threat="is OK", action="", info=""),
    ]


def test_junk_lines_are_ignored():
    junk = [
        "",
        "   ",
        "\t",
        "ECLS Command-line scanner, version 11.1.65535.0, (C) 1992-2018 ESET, spol. s r.o.",
        "Command line: /log-all test.zip",
        "Scan started at:   Tue Jul 30 14:45:42 2019",
        "Scan completed at: Tue Jul 30 14:46:01 2019",
        "Total:             files - 1, objects 4",
        "Infected:          files - 0, objects 0",
        "WARNING! Something odd happened",
        "name=test.zip without quotes",
        '__INPUT_END__',
        "random trailing text",
    ]
    assert parse_all(junk) == []


def test_line_without_info_field_is_ignored():
    assert parse_line('name="test.zip", threat="is OK", action=""') is None


def test_leading_whitespace_and_trailing_cr_are_tolerated():
    line = '  name="test.zip", threat="is OK", action="", info=""\r'
    assert parse_line(line) == ScanEntry(
        name=["test.zip"], threat="is OK", action="", info=""
    )


def test_empty_and_nonempty_fields_roundtrip():
    line = 'name="x.exe", threat="a threat name »", action="cleaned", info="was infected"'
    assert parse_line(line) == ScanEntry(
        name=["x.exe"], threat="a threat name »", action="cleaned", info="was infected"
    )


def test_guillemet_split_strips_spaces_and_drops_empty_parts():
    line = 'name=" test.zip  »»  ZIP » ah_dna.exe ", threat="is OK", action="", info=""'
    assert parse_line(line) == ScanEntry(
        name=["test.zip", "ZIP", "ah_dna.exe"], threat="is OK", action="", info=""
    )


def test_decode_line_cp1252_guillemet():
    raw = 'name="test.zip » ZIP » a.exe", threat="is OK", action="", info=""'.encode(
        "cp1252"
    ) + b"\r\n"
    line = decode_line(raw, "cp1252")
    assert "»" in line
    assert parse_line(line) == ScanEntry(
        name=["test.zip", "ZIP", "a.exe"], threat="is OK", action="", info=""
    )


def test_decode_line_never_raises_on_stray_bytes():
    raw = b'name="x \xff\xfe\x9d y", threat="t", action="", info=""\r\n'
    line = decode_line(raw, "cp1252")
    assert parse_line(line) is not None


def test_normalize_replaces_sent_path_in_first_component_only():
    sent = r"C:\Temp\ecls_abc\upload_001.zip"
    entries = [
        ScanEntry(name=[sent], threat="is OK", action="", info=""),
        ScanEntry(name=[sent, "ZIP", "ah_dna.exe"], threat="is OK", action="", info=""),
    ]
    normalized = normalize_entries(entries, sent, "test.zip")
    assert normalized == [
        ScanEntry(name=["test.zip"], threat="is OK", action="", info=""),
        ScanEntry(name=["test.zip", "ZIP", "ah_dna.exe"], threat="is OK", action="", info=""),
    ]


def test_normalize_is_noop_for_bare_filenames():
    entries = [ScanEntry(name=["test.zip"], threat="is OK", action="", info="")]
    assert normalize_entries(entries, r"C:\Temp\ecls_abc\upload_001.zip", "test.zip") == entries


def test_normalize_is_noop_when_prefix_does_not_match():
    entries = [ScanEntry(name=["other.zip"], threat="is OK", action="", info="")]
    assert normalize_entries(entries, r"C:\Temp\ecls_abc\upload_001.zip", "test.zip") == entries


def test_normalize_tolerates_suffix_after_sent_path():
    sent = r"C:\Temp\ecls_abc\upload_001.zip"
    entries = [ScanEntry(name=[sent + " (1)"], threat="is OK", action="", info="")]
    assert normalize_entries(entries, sent, "test.zip") == [
        ScanEntry(name=["test.zip (1)"], threat="is OK", action="", info="")
    ]
