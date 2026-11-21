"""Report formats: a terminal table, JSON, SARIF 2.1.0, Markdown and a self-contained HTML timeline."""

from __future__ import annotations

import hashlib
import html
import json
from typing import Any

from rich.console import Console
from rich.table import Table
from rich.text import Text

from agent_replay import __version__
from agent_replay.policy import Severity
from agent_replay.rules import RULES, Finding, summarise
from agent_replay.trace import EventType, Trace

COLORS = {
    Severity.critical: "bold red",
    Severity.high: "red",
    Severity.medium: "yellow",
    Severity.low: "cyan",
    Severity.info: "dim",
}
SARIF_LEVEL = {
    Severity.critical: "error",
    Severity.high: "error",
    Severity.medium: "warning",
    Severity.low: "note",
    Severity.info: "note",
}
FORMATS = ("table", "json", "sarif", "markdown", "html")


def _plain(s: str) -> str:
    """Printable ASCII only, so hostile trace content cannot send escape sequences to a terminal."""
    return "".join(c if c.isascii() and (c.isprintable() or c == "\n") else f"\\u{ord(c):04x}" for c in s)


def table(results: list[tuple[Trace, list[Finding]]], console: Console) -> None:
    for trace, findings in results:
        console.print(Text(f"{trace.source or 'trace'}: {len(trace.events)} events, {len(findings)} finding(s)"))
        if not findings:
            continue
        t = Table(show_lines=False, header_style="bold")
        t.add_column("Severity")
        t.add_column("Rule")
        t.add_column("Step", justify="right")
        t.add_column("Finding", overflow="fold")
        for f in findings:
            msg = Text(_plain(f.message))
            if f.evidence:
                msg.append("\n" + _plain(f.evidence), style="dim")
            t.add_row(Text(f.severity.value, style=COLORS[f.severity]), f.rule_id, str(f.step), msg)
        console.print(t)


def to_json(results: list[tuple[Trace, list[Finding]]]) -> str:
    out = []
    for trace, findings in results:
        out.append(
            {
                "trace": trace.source,
                "events": len(trace.events),
                "summary": summarise(findings),
                "findings": [f.model_dump(mode="json") for f in findings],
            }
        )
    return json.dumps({"tool": "agent-replay", "version": __version__, "results": out}, indent=2)


def to_sarif(results: list[tuple[Trace, list[Finding]]]) -> str:
    used = sorted({f.rule_id for _, fs in results for f in fs})
    rules = [
        {
            "id": rid,
            "name": RULES[rid].title,
            "shortDescription": {"text": RULES[rid].title},
            "fullDescription": {"text": RULES[rid].description},
            "help": {"text": RULES[rid].remediation},
            "properties": {"tags": ["security", f"OWASP-{RULES[rid].owasp}"]},
            "defaultConfiguration": {"level": SARIF_LEVEL[RULES[rid].severity]},
        }
        for rid in used
    ]
    sarif_results = []
    for trace, findings in results:
        for f in findings:
            location: dict[str, Any] = {"artifactLocation": {"uri": (trace.source or "trace").replace("\\", "/")}}
            if f.line:
                location["region"] = {"startLine": f.line}
            digest = hashlib.sha256(f"{f.rule_id}|{f.step}|{f.tool}|{f.message}".encode()).hexdigest()[:32]
            sarif_results.append(
                {
                    "ruleId": f.rule_id,
                    "level": SARIF_LEVEL[f.severity],
                    "message": {"text": f"Step {f.step}: {f.message}"},
                    "locations": [{"physicalLocation": location}],
                    "partialFingerprints": {"agentReplayFinding/v1": digest},
                    "properties": {"severity": f.severity.value, "step": f.step, "related": f.related},
                }
            )
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "agent-replay",
                        "version": __version__,
                        "informationUri": "https://github.com/OsamaWehbi/agent-replay",
                        "rules": rules,
                    }
                },
                "results": sarif_results,
            }
        ],
    }
    return json.dumps(doc, indent=2)


def _md(s: str) -> str:
    return _plain(s).replace("|", "\\|").replace("\n", " ").replace("`", "'")


def to_markdown(results: list[tuple[Trace, list[Finding]]]) -> str:
    lines = ["# agent-replay report", ""]
    for trace, findings in results:
        counts = summarise(findings)
        badge = ", ".join(f"{n} {sev}" for sev, n in counts.items() if n) or "no findings"
        lines += [f"## {_md(trace.source or 'trace')}", "", f"{len(trace.events)} events: {badge}.", ""]
        if findings:
            lines += ["| Severity | Rule | Step | Finding |", "| --- | --- | --- | --- |"]
            for f in findings:
                lines.append(f"| {f.severity.value} | {f.rule_id} | {f.step} | {_md(f.message)} |")
            lines.append("")
    return "\n".join(lines) + "\n"


_CSS = """
:root { --bg:#fbfbfa; --fg:#1d1d1f; --muted:#6b6b70; --card:#fff; --line:#e3e3e0; --code:#f3f3f1;
  --crit:#b3261e; --high:#d9480f; --med:#b7791f; --low:#2b6cb0; --info:#6b6b70; --ok:#2f855a; }
@media (prefers-color-scheme: dark) { :root { --bg:#151517; --fg:#ececec; --muted:#a0a0a8; --card:#1e1e21;
  --line:#33333a; --code:#26262b; --crit:#ff6b60; --high:#ff8a4c; --med:#f0b94d; --low:#6cb2ff; --info:#a0a0a8;
  --ok:#5fd08f; } }
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--fg); font:15px/1.5 system-ui, -apple-system, Segoe UI, sans-serif; }
main { max-width: 980px; margin: 0 auto; padding: 32px 16px 64px; }
h1 { font-size: 22px; margin: 0 0 4px; } .sub { color: var(--muted); margin: 0 0 24px; }
.summary { display:flex; flex-wrap:wrap; gap:8px; margin-bottom:24px; }
.pill { border:1px solid var(--line); border-radius:999px; padding:2px 10px; font-size:13px; background:var(--card); }
.ev { display:grid; grid-template-columns: 44px 1fr; gap:12px; padding:10px 0; border-top:1px solid var(--line); }
.n { color:var(--muted); font-variant-numeric: tabular-nums; text-align:right; padding-top:2px; }
.kind { font-size:12px; font-weight:600; letter-spacing:.02em; text-transform:uppercase; color:var(--muted); }
.kind.tool_call { color: var(--low); } .kind.user { color: var(--ok); }
pre { background:var(--code); padding:8px 10px; border-radius:6px; overflow-x:auto; white-space:pre-wrap;
  word-break:break-word; margin:4px 0 0; font:13px/1.45 ui-monospace, SFMono-Regular, Consolas, monospace; }
details summary { cursor:pointer; color:var(--muted); font-size:13px; }
.f { border-left:3px solid var(--info); padding:4px 10px; margin-top:6px; background:var(--card); border-radius:0 6px 6px 0; }
.f.critical { border-color:var(--crit); } .f.high { border-color:var(--high); } .f.medium { border-color:var(--med); }
.f.low { border-color:var(--low); }
.f b { font-size:13px; } .f .ev-ref { color:var(--muted); font-size:13px; }
.flagged { background: linear-gradient(90deg, color-mix(in srgb, var(--high) 7%, transparent), transparent 60%); }
.injected { color: var(--crit); font-size:12px; font-weight:600; }
"""


def to_html(trace: Trace, findings: list[Finding], title: str | None = None) -> str:
    esc = html.escape
    by_step: dict[int, list[Finding]] = {}
    for f in findings:
        by_step.setdefault(f.step, []).append(f)
    counts = summarise(findings)
    pills = "".join(f'<span class="pill">{n} {sev}</span>' for sev, n in counts.items() if n) or (
        '<span class="pill">no findings</span>'
    )
    rows = []
    for e in trace.events:
        if e.type == EventType.tool_call:
            body = f"<div><b>{esc(e.tool or '')}</b></div><pre>{esc(json.dumps(e.args or {}, indent=2))}</pre>"
        elif e.type == EventType.tool_result:
            text = e.content if len(e.content) < 20000 else e.content[:20000] + "\n[truncated]"
            open_attr = " open" if e.step in by_step or len(text) < 400 else ""
            body = (
                f"<details{open_attr}><summary>{esc(e.tool or 'result')}: {len(e.content)} characters"
                f"{' (error)' if e.is_error else ''}</summary><pre>{esc(text)}</pre></details>"
            )
        else:
            body = f"<pre>{esc(e.content)}</pre>"
        if e.meta.get("injected"):
            body = '<div class="injected">injected by replay</div>' + body
        notes = "".join(
            f'<div class="f {f.severity.value}"><b>{esc(f.severity.value.upper())} {esc(f.rule_id)} '
            f"{esc(f.title)}</b><br>{esc(f.message)}"
            + (f'<br><span class="ev-ref">related: step {", ".join(map(str, f.related))}</span>' if f.related else "")
            + "</div>"
            for f in by_step.get(e.step, [])
        )
        flagged = " flagged" if e.step in by_step else ""
        rows.append(
            f'<div class="ev{flagged}" id="s{e.step}"><div class="n">{e.step}</div><div>'
            f'<div class="kind {e.type.value}">{esc(e.type.value.replace("_", " "))}</div>{body}{notes}</div></div>'
        )
    name = title or trace.source or "trace"
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>agent-replay: {esc(name)}</title><style>{_CSS}</style></head><body><main>"
        f"<h1>{esc(name)}</h1><p class='sub'>{len(trace.events)} events, checked by agent-replay {__version__}</p>"
        f'<div class="summary">{pills}</div>{"".join(rows)}</main></body></html>\n'
    )
