# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Trace format (JSONL, one event per step) with importers for OpenAI-compatible chat transcripts and request logs and
  for MCP JSON-RPC logs, and `agent-replay convert`.
- `Recorder` for Python agents, with `wrap()` for tool functions, and a LangChain and LangGraph callback handler.
- `agent-replay proxy`, a recording proxy for stdio MCP servers.
- `agent-replay check` with rules AR101 to AR105 (injected instructions, actions that follow them, data sent out
  directly or encoded, the combination of private data, untrusted content and outbound access, secrets passed to
  tools), AR201 to AR203 (sensitive or out-of-workspace writes, dangerous commands, hosts outside an allowlist),
  AR301 (custom policy rules) and AR401 (repeated calls).
- Policy files for the workspace, allowed hosts, tool capabilities, custom rules and ignored rules.
- Table, JSON, SARIF 2.1.0, Markdown and HTML timeline reports, and `agent-replay show`.
- `agent-replay replay`, which re-runs a trace from one tool result with an injected payload (`exfil`, `hijack`,
  `canary` or your own) against any OpenAI-compatible endpoint, with recorded or stubbed tool results, and reports
  whether the agent was compromised.
- Example traces, an example policy and a replay demo with scripted fake models.
