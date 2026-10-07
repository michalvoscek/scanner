"""Mock ecls scanner speaking the verified pipe protocol.

Ignores the scanner argv it is launched with, except for three details: an
optional ``--log PATH`` argument (records scan intervals for concurrency
assertions), repeated ``--threat=<sha256-hex>`` arguments (contents whose
SHA-256 digest matches are reported as threats) and the
``/batch-delimiter=...`` argument (the output marker it emits, exactly like
the real scanner).

The uploaded file's CONTENT drives the emitted results; directives are
lines starting with ``#MOCK ``:

    #MOCK ZIP           emit nested entries; remaining lines are inner names
    #MOCK THREAT=...    threat value for this file's entries
    #MOCK SLEEP=<secs>  delay the response to emulate a slow scan
    #MOCK CRASH         die immediately without answering
    #MOCK DIE           answer this scan normally, then die instead of idling
    #MOCK HANG          never answer
    #MOCK DESYNC        answer without the delimiter, keep serving
    #MOCK UNOPENABLE    answer with the verified unable-to-open verdict
    #MOCK NOENTRIES     answer with the delimiter but zero name= lines
    #MOCK JUNKLINE      emit one unparseable line before the delimiter
    #MOCK NOBANNER      never print the 'Scan started at:' banner line
    #MOCK DELAYED_BANNER=<secs>  delay the banner marker line

Threat-sample emulation: conftest passes the SHA-256 digests of the files
currently in test_files/threats; scanned content with a matching digest is
reported as a detected threat (root entry only — nested-chain shapes are
exercised by the #MOCK ZIP directive), mirroring the verified real verdict
shape `threat="...", action="retained"`. This takes precedence over #MOCK
directives; :Zone.Identifier sidecars are not emulated.
"""

from __future__ import annotations

import hashlib
import os
import sys
import time

ENCODING = "cp1252"
DEFAULT_DELIMITER = "__INPUT_END__"
GUILLEMET = "»"

THREAT_VERDICT = "Win32/ThreatSample"
THREAT_ACTION = "retained"


def emit(line: str) -> None:
    sys.stdout.buffer.write((line + "\r\n").encode(ENCODING))
    sys.stdout.buffer.flush()


def delimiter_from_argv(argv: list[str]) -> str:
    marker = "/batch-delimiter="
    for token in argv:
        if token.startswith(marker) and token[len(marker) :]:
            return token[len(marker) :]
    return DEFAULT_DELIMITER


def log_dir_from_argv(argv: list[str]) -> str:
    if "--log" in argv:
        index = argv.index("--log")
        if index + 1 < len(argv):
            return argv[index + 1]
    return ""


def threat_digests_from_argv(argv: list[str]) -> frozenset[str]:
    marker = "--threat="
    digests = []
    for token in argv:
        if token.startswith(marker):
            digest = token[len(marker) :]
            if digest:
                digests.append(digest)
    return frozenset(digests)


def log_event(log_dir: str, kind: str, sent_path: str) -> None:
    if not log_dir:
        return
    data = f"{kind}\t{time.time():.6f}\t{os.getpid()}\t{sent_path}\n".encode()
    log_file = os.path.join(log_dir, f"{os.getpid()}.log")
    fd = os.open(log_file, os.O_WRONLY | os.O_APPEND | os.O_CREAT)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)


def parse_directives(lines: list[str]) -> dict:
    directives = {
        "zip": False,
        "threat": "is OK",
        "sleep": 0.0,
        "crash": False,
        "die": False,
        "hang": False,
        "desync": False,
        "noentries": False,
        "junkline": False,
        "unopenable": False,
        "inner": [],
    }
    for line in lines:
        if not line.startswith("#MOCK "):
            directives["inner"].append(line)
            continue
        token = line[len("#MOCK ") :].strip()
        if token == "ZIP":
            directives["zip"] = True
        elif token == "CRASH":
            directives["crash"] = True
        elif token == "DIE":
            directives["die"] = True
        elif token == "HANG":
            directives["hang"] = True
        elif token == "DESYNC":
            directives["desync"] = True
        elif token == "NOENTRIES":
            directives["noentries"] = True
        elif token == "JUNKLINE":
            directives["junkline"] = True
        elif token == "UNOPENABLE":
            directives["unopenable"] = True
        elif token.startswith("THREAT="):
            directives["threat"] = token[len("THREAT=") :]
        elif token.startswith("SLEEP="):
            directives["sleep"] = float(token[len("SLEEP=") :])
    return directives


def arg_value_from_argv(argv: list[str], flag: str) -> str:
    for token in argv:
        if token.startswith(flag):
            return token[len(flag) :]
    return ""


def _threat_scan(
    sent_path: str, content: bytes, threat_digests: frozenset[str]
) -> tuple[str | None, list[str]]:
    """Emulate a real-scanner detection: when the content digest matches a
    registered threat digest, return the detected threat name plus the root
    result entry (no delimiter — the caller emits it after the batch);
    otherwise return (None, [])."""
    digest = hashlib.sha256(content).hexdigest()
    if digest not in threat_digests:
        return None, []
    return THREAT_VERDICT, [
        f'name="{sent_path}", threat="{THREAT_VERDICT}", '
        f'action="{THREAT_ACTION}", info=""'
    ]


def main() -> int:
    argv = sys.argv[1:]
    delimiter = delimiter_from_argv(argv)
    log_dir = log_dir_from_argv(argv)
    threat_digests = threat_digests_from_argv(argv)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)

    sys.stderr.buffer.write(b"WARNING! (mock) scanner started\r\n")
    sys.stderr.buffer.flush()

    # Banner faults arrive via argv (content directives cannot work pre-scan):
    # /nobanner omits the 'Scan started at:' marker line,
    # /delayed-banner=<secs> delays the whole banner.
    no_banner = "/nobanner" in argv
    delayed = arg_value_from_argv(argv, "/delayed-banner=")
    if delayed:
        time.sleep(float(delayed))
    emit("")
    emit("ECLS mock Command-line scanner, version 0.0.0.0, (C) 1992-2026 nobody")
    emit("")
    emit("Command line: " + " ".join(argv))
    emit("")
    if not no_banner:
        emit(f"Scan started at:   {time.ctime()}")

    scans = 0
    for raw in iter(sys.stdin.buffer.readline, b""):
        sent_path = raw.decode(ENCODING, errors="replace").rstrip("\r\n")
        if not sent_path:
            continue
        scans += 1
        log_event(log_dir, "start", sent_path)
        try:
            with open(sent_path, "rb") as handle:
                content_bytes = handle.read()
        except OSError:
            emit(f'name="{sent_path}", threat="", action="", info="unable to open"')
            emit(delimiter)
            log_event(log_dir, "end", sent_path)
            continue
        content = content_bytes.decode(ENCODING, errors="replace")
        directives = parse_directives(content.splitlines())
        if directives["crash"]:
            log_event(log_dir, "crash", sent_path)
            os._exit(2)
        if directives["sleep"]:
            time.sleep(directives["sleep"])
        if directives["hang"]:
            log_event(log_dir, "hang", sent_path)
            time.sleep(86400)
            continue
        if directives["noentries"]:
            # delimiter only: protocol violation (zero result entries)
            emit(delimiter)
            log_event(log_dir, "end", sent_path)
            continue
        detected_threat, threat_lines = _threat_scan(
            sent_path, content_bytes, threat_digests
        )
        threat = (
            detected_threat if detected_threat is not None else directives["threat"]
        )
        if directives["unopenable"]:
            # the verified real-scanner verdict for an unopenable file
            emit(f'name="{sent_path}", threat="", action="", info="unable to open"')
        elif threat_lines:
            for line in threat_lines:
                emit(line)
        else:
            emit(f'name="{sent_path}", threat="{threat}", action="", info=""')
        if directives["zip"]:
            for inner in directives["inner"]:
                nested = f"{sent_path} {GUILLEMET} ZIP {GUILLEMET} {inner}"
                emit(f'name="{nested}", threat="{threat}", action="", info=""')
        if directives["junkline"]:
            # an unparseable line inside the batch: protocol violation
            emit("mock banner debris inside a scan batch")
        if not directives["desync"]:
            emit(delimiter)
        log_event(log_dir, "end", sent_path)
        if directives["die"]:
            # exits after a complete answer: the worker is returned to the
            # pool and only then turns up dead, so the next scan finds a
            # corpse sitting in the free queue
            os._exit(0)

    emit("")
    emit(f"Scan completed at: {time.ctime()}")
    emit(f"Total:             files - {scans}, objects {scans}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
