"""Record a trace from inside an agent.

```python
from agent_replay import Recorder

with Recorder("run.jsonl", meta={"agent": "support-bot"}) as rec:
    rec.user(question)
    lookup = rec.wrap(lookup_order)        # records every call and its result
    ...
    rec.model(answer)
```

For LangChain and LangGraph, pass `langchain_handler(rec)` in `callbacks`.
"""

from __future__ import annotations

import functools
import itertools
import json
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypeVar

from agent_replay.trace import FORMAT, VERSION, Event, EventType

F = TypeVar("F", bound=Callable[..., Any])


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _text(value: Any) -> str:
    if isinstance(value, str):
        return value
    content = getattr(value, "content", None)
    if isinstance(content, str):
        return content
    try:
        return json.dumps(value, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return str(value)


class Recorder:
    """Append events to a trace file as they happen, so a crash still leaves a usable trace."""

    def __init__(self, path: str | Path, meta: dict[str, Any] | None = None) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self._ids = itertools.count(1)
        self._file = self.path.open("w", encoding="utf-8", newline="\n")
        self._write({"format": FORMAT, "version": VERSION, "meta": meta or {}})

    def _write(self, obj: dict[str, Any]) -> None:
        with self._lock:
            self._file.write(json.dumps(obj, ensure_ascii=True, default=str) + "\n")
            self._file.flush()

    def event(self, event: Event) -> Event:
        event.ts = event.ts or _now()
        self._write(event.model_dump(mode="json", exclude_none=True, exclude_defaults=True))
        return event

    def system(self, text: str) -> None:
        self.event(Event(type=EventType.system, content=text))

    def user(self, text: str) -> None:
        self.event(Event(type=EventType.user, content=text))

    def model(self, text: str) -> None:
        self.event(Event(type=EventType.model, content=text))

    def tool_call(self, tool: str, args: dict[str, Any] | None = None, call_id: str | None = None) -> str:
        call_id = call_id or f"c{next(self._ids)}"
        self.event(Event(type=EventType.tool_call, tool=tool, args=dict(args or {}), call_id=call_id))
        return call_id

    def tool_result(self, call_id: str, content: Any, tool: str | None = None, is_error: bool = False) -> None:
        self.event(
            Event(type=EventType.tool_result, tool=tool, call_id=call_id, content=_text(content), is_error=is_error)
        )

    def wrap(self, fn: F, name: str | None = None) -> F:
        """Return `fn` wrapped so each call and its result (or exception) is recorded. Keyword arguments are kept by
        name; positional ones are recorded as `arg0`, `arg1` and so on."""
        tool = name or fn.__name__

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            recorded = {f"arg{i}": a for i, a in enumerate(args)} | kwargs
            cid = self.tool_call(tool, json.loads(json.dumps(recorded, default=str)))
            try:
                result = fn(*args, **kwargs)
            except Exception as exc:
                self.tool_result(cid, f"{type(exc).__name__}: {exc}", tool, is_error=True)
                raise
            self.tool_result(cid, result, tool)
            return result

        return wrapper  # type: ignore[return-value]

    def close(self) -> None:
        with self._lock:
            if not self._file.closed:
                self._file.close()

    def __enter__(self) -> Recorder:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


class LangChainEvents:
    """Callback methods that turn LangChain events into trace events. Use `langchain_handler()` to get a handler."""

    def __init__(self, recorder: Recorder) -> None:
        self.recorder = recorder
        self._calls: dict[str, tuple[str, str]] = {}

    def on_chat_model_start(self, serialized: Any, messages: list[list[Any]], **kwargs: Any) -> None:
        return None

    def on_tool_start(
        self, serialized: dict[str, Any] | None, input_str: str, *, run_id: Any = None, inputs: Any = None, **kw: Any
    ) -> None:
        name = (serialized or {}).get("name") or kw.get("name") or "tool"
        args = inputs if isinstance(inputs, dict) else {"input": input_str}
        cid = self.recorder.tool_call(name, args)
        self._calls[str(run_id)] = (cid, name)

    def on_tool_end(self, output: Any, *, run_id: Any = None, **kw: Any) -> None:
        cid, name = self._calls.pop(str(run_id), (f"orphan_{run_id}", kw.get("name") or "tool"))
        self.recorder.tool_result(cid, output, name)

    def on_tool_error(self, error: BaseException, *, run_id: Any = None, **kw: Any) -> None:
        cid, name = self._calls.pop(str(run_id), (f"orphan_{run_id}", "tool"))
        self.recorder.tool_result(cid, f"{type(error).__name__}: {error}", name, is_error=True)

    def on_llm_end(self, response: Any, **kw: Any) -> None:
        for generations in getattr(response, "generations", None) or []:
            for gen in generations:
                message = getattr(gen, "message", None)
                text = getattr(message, "content", None) if message is not None else getattr(gen, "text", "")
                if isinstance(text, str) and text.strip():
                    self.recorder.model(text)


def langchain_handler(recorder: Recorder) -> Any:
    """A LangChain callback handler that records into `recorder`. Requires `langchain-core`."""
    try:
        from langchain_core.callbacks import BaseCallbackHandler
    except ImportError as exc:  # pragma: no cover - depends on the user's environment
        raise ImportError("langchain_handler needs langchain-core: pip install langchain-core") from exc

    class Handler(LangChainEvents, BaseCallbackHandler):
        def __init__(self, rec: Recorder) -> None:
            LangChainEvents.__init__(self, rec)
            BaseCallbackHandler.__init__(self)

    return Handler(recorder)
