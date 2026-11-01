#!/usr/bin/env python3
from __future__ import annotations

import os
import socket
import sys
import time


DEFAULT_TIMEOUT_SECONDS = 5.0


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: tcping <host> <port>", file=sys.stderr)
        return 2

    host = argv[1].strip()
    try:
        port = int(argv[2])
    except ValueError:
        print(f"tcping invalid port: {argv[2]}", file=sys.stderr)
        return 2
    if not host or not 1 <= port <= 65535:
        print("tcping requires a non-empty host and a port from 1 to 65535", file=sys.stderr)
        return 2

    timeout = _timeout_seconds()
    started_at = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            elapsed_ms = int((time.monotonic() - started_at) * 1000)
            print(f"tcping {host}:{port} succeeded in {elapsed_ms} ms")
            return 0
    except OSError as exc:
        elapsed_ms = int((time.monotonic() - started_at) * 1000)
        print(
            f"tcping {host}:{port} failed after {elapsed_ms} ms: {exc}",
            file=sys.stderr,
        )
        return 1


def _timeout_seconds() -> float:
    raw_value = os.getenv("TCPING_TIMEOUT_SECONDS", "").strip()
    if not raw_value:
        return DEFAULT_TIMEOUT_SECONDS
    try:
        timeout = float(raw_value)
    except ValueError:
        return DEFAULT_TIMEOUT_SECONDS
    if timeout <= 0:
        return DEFAULT_TIMEOUT_SECONDS
    return timeout


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
