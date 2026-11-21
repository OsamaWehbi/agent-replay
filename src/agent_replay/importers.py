"""Turn logs from other tools into traces.

- `native`: the agent-replay JSONL format (see `trace.py`).
- `openai`: an OpenAI-compatible chat transcript. Either a JSON list of messages, an object with a `messages` key, or
  a JSON or JSONL log of request/response pairs, in which case the last request plus its response is used.
- `mcp`: a JSONL log of Model Context Protocol JSON-RPC messages, such as the one `agent-replay proxy` writes. Each
  line is a JSON-RPC message, or an object with `dir` and `msg` keys.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agent_replay.trace import FORMAT, Event, EventType, Trace, TraceError

FORMATS = ("auto", "native", "openai", "mcp")
MAX_FILE = 200 * 1024 * 1024


def _text(content: Any) -> str:
    """Message content as text. Handles plain strings and lists of content parts."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for part in content:
            if isinstance(part, dict):
                if "text" in part:
                    parts.append(str(part["text"]))
                elif part.get("type") == "resource" and isinstance(part.get("resource"), dict):
                    parts.append(str(part["resource"].get("text", "")))
                elif part.get("type") == "image_url":
                    url = part.get("image_url", {})
                    parts.append(f"[image {url.get('url', '') if isinstance(url, dict) else url}]")
                else:
                    parts.append(json.dumps(part, ensure_ascii=False))
            else:
                parts.append(str(part))
        return "\n".join(parts)
    if isinstance(content, dict):
        return json.dumps(content, ensure_ascii=False)
    return str(content)


def _args(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            value = json.loads(raw) if raw.strip() else {}
        except json.JSONDecodeError:
            return {"_raw": raw}
        return value if isinstance(value, dict) else {"_value": value}
    return {} if raw is None else {"_value": raw}


def from_openai_messages(messages: list[dict[str, Any]], source: str = "") -> Trace:
    events: list[Event] = []
    names: dict[str, str] = {}
    for msg in messages:
        if not isinstance(msg, dict):
            raise TraceError(f"{source or 'transcript'}: every message must be a JSON object")
        role = msg.get("role")
        text = _text(msg.get("content"))
        if role in ("system", "developer"):
            events.append(Event(type=EventType.system, content=text))
        elif role == "user":
            events.append(Event(type=EventType.user, content=text))
        elif role == "assistant":
            if text:
                events.append(Event(type=EventType.model, content=text))
            for call in msg.get("tool_calls") or []:
                fn = call.get("function") or {}
                cid = call.get("id")
                name = fn.get("name") or call.get("name") or "unknown"
                if cid:
                    names[cid] = name
                events.append(Event(type=EventType.tool_call, tool=name, args=_args(fn.get("arguments")), call_id=cid))
            legacy = msg.get("function_call")
            if legacy:
                events.append(
                    Event(type=EventType.tool_call, tool=legacy.get("name"), args=_args(legacy.get("arguments")))
                )
        elif role in ("tool", "function"):
            cid = msg.get("tool_call_id")
            events.append(
                Event(
                    type=EventType.tool_result,
                    tool=names.get(cid or "") or msg.get("name"),
                    call_id=cid,
                    content=text,
                )
            )
    return Trace(events=events, source=source)


def _openai_from_obj(obj: Any, source: str) -> Trace:
    if isinstance(obj, dict) and isinstance(obj.get("messages"), list):
        return from_openai_messages(obj["messages"], source)
    if isinstance(obj, list) and obj and all(isinstance(m, dict) and "role" in m for m in obj):
        return from_openai_messages(obj, source)
    if isinstance(obj, dict) and "request" in obj:
        obj = [obj]
    if isinstance(obj, list) and obj and isinstance(obj[-1], dict) and "request" in obj[-1]:
        last = obj[-1]
        messages = list((last.get("request") or {}).get("messages") or [])
        choices = (last.get("response") or {}).get("choices") or []
        if choices and isinstance(choices[0], dict) and choices[0].get("message"):
            messages.append(choices[0]["message"])
        return from_openai_messages(messages, source)
    raise TraceError(f"{source or 'input'}: not an OpenAI-compatible transcript")


def from_mcp_log(lines: list[Any], source: str = "") -> Trace:
    """Pair `tools/call` requests with their responses."""
    events: list[Event] = []
    pending: dict[str, str] = {}
    for item in lines:
        msg = item.get("msg") if isinstance(item, dict) and "msg" in item else item
        ts = item.get("ts") if isinstance(item, dict) else None
        if not isinstance(msg, dict):
            continue
        method = msg.get("method")
        mid = msg.get("id")
        key = json.dumps(mid)
        if method == "tools/call":
            params = msg.get("params") or {}
            name = params.get("name") or "unknown"
            pending[key] = name
            events.append(
                Event(
                    type=EventType.tool_call,
                    tool=name,
                    args=_args(params.get("arguments")),
                    call_id=str(mid),
                    ts=ts,
                )
            )
        elif method is None and mid is not None and key in pending:
            name = pending.pop(key)
            if "error" in msg:
                err = msg.get("error") or {}
                events.append(
                    Event(
                        type=EventType.tool_result,
                        tool=name,
                        call_id=str(mid),
                        content=str(err.get("message", err)),
                        is_error=True,
                        ts=ts,
                    )
                )
            else:
                result = msg.get("result") or {}
                text = _text(result.get("content"))
                if not text and result.get("structuredContent") is not None:
                    text = json.dumps(result["structuredContent"], ensure_ascii=False)
                events.append(
                    Event(
                        type=EventType.tool_result,
                        tool=name,
                        call_id=str(mid),
                        content=text,
                        is_error=bool(result.get("isError")),
                        ts=ts,
                    )
                )
    return Trace(events=events, source=source)


def _jsonl(text: str, source: str) -> list[Any]:
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        if line.strip():
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise TraceError(f"{source}:{n}: not valid JSON ({exc.msg})") from exc
    return out


def detect(text: str) -> str:
    stripped = text.lstrip()
    first = stripped.splitlines()[0] if stripped else ""
    try:
        head = json.loads(first)
    except json.JSONDecodeError:
        return "openai"  # a multi-line JSON document
    if isinstance(head, dict):
        if head.get("format") == FORMAT or head.get("type") in {t.value for t in EventType}:
            return "native"
        msg = head.get("msg", head)
        if isinstance(msg, dict) and msg.get("jsonrpc") == "2.0":
            return "mcp"
        if "request" in head or "role" in head:
            return "openai"
    return "openai"


def load(path: str | Path, fmt: str = "auto") -> Trace:
    path = Path(path)
    if fmt not in FORMATS:
        raise TraceError(f"unknown format {fmt!r}; choose one of {', '.join(FORMATS)}")
    if path.stat().st_size > MAX_FILE:
        raise TraceError(f"{path}: larger than {MAX_FILE // (1024 * 1024)} MB")
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    return loads(text, fmt, str(path))


def loads(text: str, fmt: str = "auto", source: str = "") -> Trace:
    if fmt == "auto":
        fmt = detect(text)
    if fmt == "native":
        return Trace.parse_jsonl(text, source)
    if fmt == "mcp":
        return from_mcp_log(_jsonl(text, source), source)
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        obj = _jsonl(text, source)
    return _openai_from_obj(obj, source)
