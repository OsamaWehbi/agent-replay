from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table
from rich.text import Text

from agent_replay import __version__, importers, proxy, report
from agent_replay.policy import Policy, Severity
from agent_replay.replay import PAYLOADS, ChatClient, ReplayError, replay
from agent_replay.rules import RULES, check
from agent_replay.trace import EventType, Trace, TraceError

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Flight recorder and security checker for AI agents.",
    context_settings={"help_option_names": ["-h", "--help"]},
)
console = Console(highlight=False)
err = Console(stderr=True, highlight=False)


def _version(value: bool) -> None:
    if value:
        console.print(f"agent-replay {__version__}")
        raise typer.Exit()


@app.callback()
def _root(
    version: bool = typer.Option(False, "--version", callback=_version, is_eager=True, help="Show the version."),
) -> None:
    pass


def _fail(message: str) -> None:
    err.print(f"[red]error:[/red] {escape(message)}")
    raise typer.Exit(2)


def _policy(path: Path | None) -> Policy:
    try:
        return Policy.load(path)
    except (OSError, ValueError) as exc:
        _fail(str(exc))
        raise  # unreachable


def _load(path: Path, fmt: str) -> Trace:
    try:
        return importers.load(path, fmt)
    except (OSError, TraceError) as exc:
        _fail(str(exc))
        raise  # unreachable


def _emit(text: str, output: Path | None) -> None:
    if output:
        output.write_text(text, encoding="utf-8", newline="\n")
        err.print(f"wrote {escape(str(output))}")
    else:
        sys.stdout.write(text if text.endswith("\n") else text + "\n")


@app.command("check")
def check_cmd(
    traces: list[Path] = typer.Argument(..., exists=True, dir_okay=False, help="Trace files to check."),
    policy: Path | None = typer.Option(None, "--policy", "-p", exists=True, dir_okay=False, help="Policy YAML file."),
    fmt: str = typer.Option("table", "--format", "-f", help=f"Output format: {', '.join(report.FORMATS)}."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write the report to a file."),
    source_format: str = typer.Option("auto", "--from", help="Input format: auto, native, openai or mcp."),
    fail_on: Severity = typer.Option(Severity.high, "--fail-on", help="Exit 1 if a finding is at least this severe."),
) -> None:
    """Check recorded traces for injected instructions, data exfiltration and risky actions."""
    if fmt not in report.FORMATS:
        _fail(f"unknown format {fmt!r}; choose one of {', '.join(report.FORMATS)}")
    pol = _policy(policy)
    results = [(t, check(t, pol)) for t in (_load(p, source_format) for p in traces)]
    if fmt == "table":
        report.table(results, console)
    elif fmt == "json":
        _emit(report.to_json(results), output)
    elif fmt == "sarif":
        _emit(report.to_sarif(results), output)
    elif fmt == "markdown":
        _emit(report.to_markdown(results), output)
    else:
        if len(results) != 1:
            _fail("the html format takes one trace at a time")
        _emit(report.to_html(*results[0]), output)
    worst = max((f.severity.rank for _, fs in results for f in fs), default=-1)
    if worst >= fail_on.rank:
        raise typer.Exit(1)


@app.command()
def show(
    trace: Path = typer.Argument(..., exists=True, dir_okay=False),
    policy: Path | None = typer.Option(None, "--policy", "-p", exists=True, dir_okay=False),
    source_format: str = typer.Option("auto", "--from", help="Input format: auto, native, openai or mcp."),
    width: int = typer.Option(110, help="Characters of each event to show."),
) -> None:
    """Print a trace as a timeline, with findings next to the steps they belong to."""
    t = _load(trace, source_format)
    findings = check(t, _policy(policy))
    by_step: dict[int, list] = {}
    for f in findings:
        by_step.setdefault(f.step, []).append(f)
    styles = {EventType.user: "green", EventType.tool_call: "blue", EventType.system: "magenta"}
    for e in t.events:
        line = Text(f"{e.step:>4}  ")
        line.append(f"{e.type.value:<12}", style=styles.get(e.type, "dim"))
        line.append(report._plain(e.summary(width)))
        console.print(line)
        for f in by_step.get(e.step, []):
            note = Text("      ")
            note.append(f"{f.severity.value.upper()} {f.rule_id} ", style=report.COLORS[f.severity])
            note.append(report._plain(f.message))
            console.print(note)
    console.print(Text(f"{len(t.events)} events, {len(findings)} finding(s)"))


@app.command()
def convert(
    source: Path = typer.Argument(..., exists=True, dir_okay=False),
    output: Path = typer.Option(..., "--output", "-o", help="Where to write the agent-replay trace."),
    source_format: str = typer.Option("auto", "--from", help="Input format: auto, openai or mcp."),
) -> None:
    """Convert an OpenAI-compatible transcript or an MCP log to the agent-replay trace format."""
    t = _load(source, source_format)
    t.save(output)
    err.print(f"wrote {len(t.events)} events to {escape(str(output))}")


@app.command("proxy", context_settings={"allow_extra_args": True, "ignore_unknown_options": True})
def proxy_cmd(
    ctx: typer.Context,
    out: Path = typer.Option(..., "--out", "-o", help="Log file for the recorded JSON-RPC messages."),
) -> None:
    """Run an MCP stdio server behind a recording proxy: agent-replay proxy -o run.mcp.jsonl -- SERVER COMMAND"""
    command = [a for a in ctx.args if a != "--"] if ctx.args[:1] == ["--"] else list(ctx.args)
    if not command:
        _fail("give the server command after --, for example: agent-replay proxy -o run.jsonl -- python server.py")
    try:
        code = proxy.run(command, out)
    except OSError as exc:
        _fail(f"could not start {command[0]}: {exc}")
        raise  # unreachable
    raise typer.Exit(code)


@app.command("replay")
def replay_cmd(
    trace: Path = typer.Argument(..., exists=True, dir_okay=False),
    model: str = typer.Option(..., "--model", "-m", help="Model name to send to the endpoint."),
    base_url: str = typer.Option(
        os.environ.get("OPENAI_BASE_URL", "http://localhost:11434/v1"),
        "--base-url",
        help="OpenAI-compatible endpoint (default: $OPENAI_BASE_URL or a local Ollama server).",
    ),
    api_key_env: str = typer.Option("OPENAI_API_KEY", help="Environment variable that holds the API key, if any."),
    at: int | None = typer.Option(
        None,
        "--at",
        help="Step of the tool result to inject into (default: the first "
        "result from a tool that returns third-party content).",
    ),
    payload: str = typer.Option("exfil", help=f"Built-in payload ({', '.join(PAYLOADS)}) or @FILE with your own."),
    mode: str = typer.Option("append", help="append the payload to the result, or replace the result with it."),
    policy: Path | None = typer.Option(None, "--policy", "-p", exists=True, dir_okay=False),
    tools_file: Path | None = typer.Option(
        None, "--tools", exists=True, dir_okay=False, help="JSON list of OpenAI tool definitions (default: inferred)."
    ),
    max_turns: int = typer.Option(8, min=1, max=50),
    source_format: str = typer.Option("auto", "--from"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Save the replayed trace."),
    html_out: Path | None = typer.Option(None, "--html", help="Save an HTML timeline of the replayed run."),
) -> None:
    """Re-run a recorded trace from one tool result with an injected payload, and report whether the agent followed it.

    Exit status 1 if the agent was compromised."""
    if mode not in ("append", "replace"):
        _fail("--mode must be append or replace")
    t = _load(trace, source_format)
    pol = _policy(policy)
    text = payload
    if payload.startswith("@"):
        try:
            text = Path(payload[1:]).read_text(encoding="utf-8")
        except OSError as exc:
            _fail(str(exc))
    elif payload not in PAYLOADS:
        _fail(f"unknown payload {payload!r}; use one of {', '.join(PAYLOADS)} or @FILE")
    tools = None
    if tools_file:
        try:
            tools = json.loads(tools_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            _fail(f"{tools_file}: {exc}")
    try:
        client = ChatClient(base_url, model, os.environ.get(api_key_env) or None)
        result = replay(t, client, at=at, payload=text, mode=mode, policy=pol, max_turns=max_turns, tools=tools)
    except (ReplayError, TraceError) as exc:
        _fail(str(exc))
        raise  # unreachable
    if output:
        result.trace.save(output)
    if html_out:
        html_out.write_text(report.to_html(result.trace, result.findings, f"replay of {t.source}"), encoding="utf-8")
    console.print(Text(f"Injected into step {result.at} ({t.step(result.at).tool}); the run {result.stopped}."))
    new_events = len(result.trace.events) - result.at
    console.print(Text(f"{new_events} event(s) after the injection, {len(result.new_findings)} new finding(s)."))
    for f in result.new_findings:
        note = Text("  ")
        note.append(f"{f.severity.value.upper()} {f.rule_id} step {f.step} ", style=report.COLORS[f.severity])
        note.append(report._plain(f.message))
        console.print(note)
    if result.compromised:
        console.print(Text("COMPROMISED: the agent followed the injected instructions.", style="bold red"))
        for s in result.signals:
            console.print(Text("  " + report._plain(s)))
        raise typer.Exit(1)
    console.print(Text("RESISTED: no sign that the agent followed the injected instructions.", style="green"))


@app.command("rules")
def rules_cmd() -> None:
    """List the rules."""
    t = Table(header_style="bold")
    t.add_column("Rule")
    t.add_column("Severity")
    t.add_column("OWASP")
    t.add_column("Title")
    for r in RULES.values():
        t.add_row(r.id, Text(r.severity.value, style=report.COLORS[r.severity]), r.owasp, r.title)
    console.print(t)


def main() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure:
            reconfigure(errors="replace")
    app(windows_expand_args=False)


if __name__ == "__main__":
    main()
