"""The trace format: one event per line of JSON, in the order the agent produced them.

```
{"format": "agent-replay", "version": 1, "meta": {"agent": "support-bot"}}
{"type": "user", "content": "Summarise my unread email"}
{"type": "tool_call", "tool": "read_inbox", "args": {"unread": true}, "call_id": "c1"}
{"type": "tool_result", "tool": "read_inbox", "call_id": "c1", "content": "..."}
{"type": "model", "content": "You have three unread messages..."}
```

The header line is optional. Steps are numbered from 1 in file order.
"""

from __future__ import annotations

import json
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, ValidationError

FORMAT = "agent-replay"
VERSION = 1


class EventType(StrEnum):
    system = "system"
    user = "user"
    model = "model"
    tool_call = "tool_call"
    tool_result = "tool_result"


class Event(BaseModel):
    type: EventType
    content: str = ""
    tool: str | None = None
    args: dict[str, Any] | None = None
    call_id: str | None = None
    is_error: bool = False
    ts: str | None = None
    meta: dict[str, Any] = Field(default_factory=dict)
    step: int = Field(default=0, exclude=True)
    line: int | None = Field(default=None, exclude=True)

    def args_text(self) -> str:
        """Every argument value as text, for searching. Keys are included because some tools take free-form maps."""
        if not self.args:
            return ""
        return json.dumps(self.args, ensure_ascii=False, sort_keys=True)

    def summary(self, width: int = 80) -> str:
        if self.type == EventType.tool_call:
            text = f"{self.tool}({self.args_text()})"
        elif self.type == EventType.tool_result:
            text = f"{self.tool or 'result'} -> {self.content}"
        else:
            text = self.content
        text = " ".join(text.split())
        return text if len(text) <= width else text[: width - 3] + "..."


class TraceError(ValueError):
    pass


class Trace(BaseModel):
    events: list[Event] = Field(default_factory=list)
    meta: dict[str, Any] = Field(default_factory=dict)
    source: str = Field(default="", exclude=True)

    def model_post_init(self, context: Any) -> None:
        self.renumber()

    def renumber(self) -> None:
        for i, event in enumerate(self.events, 1):
            event.step = i
        self.link_results()

    def link_results(self) -> None:
        """Give each tool result the name of its tool, from the matching call."""
        calls = {e.call_id: e for e in self.events if e.type == EventType.tool_call and e.call_id}
        for e in self.events:
            if e.type == EventType.tool_result and not e.tool and e.call_id in calls:
                e.tool = calls[e.call_id].tool

    @property
    def calls(self) -> list[Event]:
        return [e for e in self.events if e.type == EventType.tool_call]

    @property
    def results(self) -> list[Event]:
        return [e for e in self.events if e.type == EventType.tool_result]

    def result_for(self, call: Event) -> Event | None:
        later = self.events[call.step :]
        for e in later:
            if e.type != EventType.tool_result:
                continue
            if call.call_id and e.call_id == call.call_id:
                return e
            if not call.call_id and not e.call_id and e.tool == call.tool:
                return e
        return None

    def call_for(self, result: Event) -> Event | None:
        for e in reversed(self.events[: result.step - 1]):
            if e.type != EventType.tool_call:
                continue
            if result.call_id and e.call_id == result.call_id:
                return e
            if not result.call_id and e.tool == result.tool:
                return e
        return None

    def step(self, n: int) -> Event:
        if not 1 <= n <= len(self.events):
            raise TraceError(f"step {n} is out of range (1-{len(self.events)})")
        return self.events[n - 1]

    def to_jsonl(self) -> str:
        header = {"format": FORMAT, "version": VERSION, "meta": self.meta}
        lines = [json.dumps(header, ensure_ascii=True)]
        for e in self.events:
            lines.append(e.model_dump_json(exclude_none=True, exclude_defaults=True))
        return "\n".join(lines) + "\n"

    def save(self, path: str | Path) -> None:
        Path(path).write_text(self.to_jsonl(), encoding="utf-8", newline="\n")

    @classmethod
    def parse_jsonl(cls, text: str, source: str = "") -> Trace:
        events: list[Event] = []
        meta: dict[str, Any] = {}
        for n, raw in enumerate(text.splitlines(), 1):
            if not raw.strip():
                continue
            try:
                obj = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise TraceError(f"{source or 'trace'}:{n}: not valid JSON ({exc.msg})") from exc
            if not isinstance(obj, dict):
                raise TraceError(f"{source or 'trace'}:{n}: expected a JSON object")
            if obj.get("format") == FORMAT:
                if obj.get("version") != VERSION:
                    raise TraceError(f"{source or 'trace'}: unsupported trace version {obj.get('version')!r}")
                meta = obj.get("meta") or {}
                continue
            try:
                event = Event.model_validate(obj)
            except ValidationError as exc:
                raise TraceError(f"{source or 'trace'}:{n}: not a trace event ({exc.errors()[0]['msg']})") from exc
            event.line = n
            events.append(event)
        return cls(events=events, meta=meta, source=source)
