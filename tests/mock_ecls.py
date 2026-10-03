"""Mock ecls scanner speaking the verified pipe protocol.

Ignores the scanner argv it is launched with, except for two details: an
optional ``--log PATH`` argument (records scan intervals for concurrency
assertions) and the ``/batch-delimiter=...`` argument (the output marker it
emits, exactly like the real scanner).

The uploaded file's CONTENT drives the emitted results; directives are
lines starting with ``#MOCK ``:

    #MOCK ZIP           emit nested entries; remaining lines are inner names
    #MOCK THREAT=...    threat value for this file's entries
    #MOCK SLEEP=<secs>  delay the response to emulate a slow scan
    #MOCK CRASH         die immediately without answering
    #MOCK HANG          never answer
    #MOCK DESYNC        answer without the delimiter, keep serving
"""

from __future__ import annotations

import os
import sys
import time

ENCODING = "cp1252"
DEFAULT_DELIMITER = "__INPUT_END__"
GUILLEMET = "»"


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


def log_event(log_dir: str, kind: str, sent_path: str) -> None:
    if not log_dir:
        return
    data = f"{kind}\t{time.time():.6f}\t{os.getpid()}\t{sent_path}\n".encode("utf-8")
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
        "hang": False,
        "desync": False,
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
        elif token == "HANG":
            directives["hang"] = True
        elif token == "DESYNC":
            directives["desync"] = True
        elif token.startswith("THREAT="):
            directives["threat"] = token[len("THREAT=") :]
        elif token.startswith("SLEEP="):
            directives["sleep"] = float(token[len("SLEEP=") :])
    return directives


def main() -> int:
    argv = sys.argv[1:]
    delimiter = delimiter_from_argv(argv)
    log_dir = log_dir_from_argv(argv)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)

    sys.stderr.buffer.write(b"WARNING! (mock) scanner started\r\n")
    sys.stderr.buffer.flush()
    emit("")
    emit("ECLS mock Command-line scanner, version 0.0.0.0, (C) 1992-2026 nobody")
    emit("")
    emit("Command line: " + " ".join(argv))
    emit("")
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
                content = handle.read().decode(ENCODING, errors="replace")
        except OSError:
            emit(f'name="{sent_path}", threat="", action="", info="unable to open"')
            emit(delimiter)
            log_event(log_dir, "end", sent_path)
            continue
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
        threat = directives["threat"]
        emit(f'name="{sent_path}", threat="{threat}", action="", info=""')
        if directives["zip"]:
            for inner in directives["inner"]:
                nested = f"{sent_path} {GUILLEMET} ZIP {GUILLEMET} {inner}"
                emit(f'name="{nested}", threat="{threat}", action="", info=""')
        if not directives["desync"]:
            emit(delimiter)
        log_event(log_dir, "end", sent_path)

    emit("")
    emit(f"Scan completed at: {time.ctime()}")
    emit(f"Total:             files - {scans}, objects {scans}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
