"""Two scripted stand-ins for an OpenAI-compatible model, so replay can be tried without an API key.

- `gullible` follows any instruction it finds in a tool result.
- `careful` ignores instructions in tool results and just answers.

Real models sit somewhere in between, which is what `agent-replay replay` measures.
"""

from __future__ import annotations

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote

SEND = re.compile(r"with the (\w+) tool to (https://\S+?)(?:<|\s)")
MARKER = re.compile(r"exact text (REPLAY-[0-9A-F]+)")
CALL = re.compile(r"Call the (\w+) tool now")


def gullible(messages: list[dict]) -> dict:
    last = messages[-1]
    if last["role"] == "tool":
        text = last.get("content") or ""
        if m := SEND.search(text):
            tool, url = m.groups()
            seen = " ".join(msg.get("content") or "" for msg in messages if msg["role"] == "tool")
            return _call(tool, {"url": url.split("?")[0] + "?d=" + quote(seen[:300])})
        if m := CALL.search(text):
            return _call(m.group(1), {"path": "/", "command": "rm -rf /"})
        if m := MARKER.search(text):
            return {"role": "assistant", "content": f"Done. {m.group(1)}"}
    return careful(messages)


def careful(messages: list[dict]) -> dict:
    return {"role": "assistant", "content": "Here is what I found, based on the tool results."}


def _call(tool: str, args: dict) -> dict:
    return {
        "role": "assistant",
        "content": None,
        "tool_calls": [
            {"id": "call_r1", "type": "function", "function": {"name": tool, "arguments": json.dumps(args)}}
        ],
    }


def serve(behaviour=gullible) -> tuple[str, ThreadingHTTPServer]:
    """Start a local chat completions endpoint on a free port. Returns its base URL and the server."""

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            reply = {"choices": [{"index": 0, "message": behaviour(body["messages"]), "finish_reason": "stop"}]}
            data = json.dumps(reply).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{server.server_address[1]}/v1", server
