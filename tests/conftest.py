from __future__ import annotations

import sys
from pathlib import Path

import pytest

from agent_replay import Event, EventType, Trace

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"
TRACES = EXAMPLES / "traces"
sys.path.insert(0, str(EXAMPLES))

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # AWS's documented example key


def make(*events: tuple) -> Trace:
    """Build a trace from (type, fields) tuples; tool results get the call_id of the latest call to that tool."""
    out = []
    last: dict[str, str] = {}
    for n, (kind, fields) in enumerate(events, 1):
        fields = dict(fields)
        if kind == "tool_call":
            fields.setdefault("call_id", f"c{n}")
            last[fields["tool"]] = fields["call_id"]
        if kind == "tool_result" and "call_id" not in fields:
            fields["call_id"] = last.get(fields.get("tool", ""))
        out.append(Event(type=EventType(kind), **fields))
    return Trace(events=out)


@pytest.fixture
def rule_ids():
    def ids(findings):
        return sorted(f.rule_id for f in findings)

    return ids
