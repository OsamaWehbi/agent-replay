"""A recording proxy for MCP servers that use the stdio transport.

Put it in front of the server command in your MCP client configuration:

    agent-replay proxy --out run.mcp.jsonl -- npx -y @modelcontextprotocol/server-filesystem /work

Every JSON-RPC message in both directions is passed through unchanged and appended to the log, which
`agent-replay check` reads directly.
"""

from __future__ import annotations

import contextlib
import json

# The proxy exists to start the MCP server the user names.
import subprocess  # nosec B404
import sys
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO

MAX_RAW = 4000


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class _Log:
    def __init__(self, path: Path) -> None:
        self._file = path.open("a", encoding="utf-8", newline="\n")
        self._lock = threading.Lock()

    def record(self, direction: str, line: bytes) -> None:
        text = line.decode("utf-8", "replace").strip()
        if not text:
            return
        try:
            entry = {"ts": _now(), "dir": direction, "msg": json.loads(text)}
        except json.JSONDecodeError:
            entry = {"ts": _now(), "dir": direction, "raw": text[:MAX_RAW]}
        with self._lock:
            self._file.write(json.dumps(entry, ensure_ascii=True) + "\n")
            self._file.flush()

    def close(self) -> None:
        with self._lock:
            self._file.close()


def run(command: list[str], out: str | Path, stdin: BinaryIO | None = None, stdout: BinaryIO | None = None) -> int:
    """Run `command`, relay stdio between it and our own stdio, and log every line. Returns its exit code."""
    if not command:
        raise ValueError("no server command given")
    stdin = stdin or sys.stdin.buffer
    stdout = stdout or sys.stdout.buffer
    log = _Log(Path(out))
    try:
        proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE)  # nosec B603
    except OSError:
        log.close()
        raise
    if proc.stdin is None or proc.stdout is None:  # pragma: no cover - both are pipes
        raise RuntimeError("could not open pipes to the server")
    child_in, child_out = proc.stdin, proc.stdout

    def client_to_server() -> None:
        try:
            for line in iter(stdin.readline, b""):
                log.record("c2s", line)
                child_in.write(line)
                child_in.flush()
        except (BrokenPipeError, OSError, ValueError):
            pass
        finally:
            with contextlib.suppress(OSError):
                child_in.close()

    def server_to_client() -> None:
        for line in iter(child_out.readline, b""):
            log.record("s2c", line)
            try:
                stdout.write(line)
                stdout.flush()
            except (BrokenPipeError, OSError, ValueError):
                break

    upstream = threading.Thread(target=client_to_server, daemon=True)
    downstream = threading.Thread(target=server_to_client, daemon=True)
    upstream.start()
    downstream.start()
    code = proc.wait()
    downstream.join(timeout=5)
    log.close()
    return code
