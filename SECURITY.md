# Security Policy

agent-replay reads traces that may contain hostile content (that is the point), so its own behaviour matters. This
document explains how to report a vulnerability and what each command does.

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Use GitHub's
[private vulnerability reporting](https://github.com/OsamaWehbi/agent-replay/security/advisories/new) on this
repository. You can expect an acknowledgement within 72 hours.

Useful reports include: a crafted trace that crashes or hangs the checker, a way to get script into the HTML report
or escape sequences into the terminal, a way to make `replay` execute a real tool call, or a reliable injection or
exfiltration pattern that the rules miss and that is not listed under known limitations in the README.

## What each command does

| Command | Reads | Writes | Network | Runs |
| --- | --- | --- | --- | --- |
| `check`, `show`, `rules` | the trace and policy files you name (traces over 200 MB are refused) | stdout, or `--output` | none | nothing |
| `convert` | the file you name | `--output` | none | nothing |
| `proxy` | stdin | stdout, the `--out` log | none of its own | the server command you give it |
| `replay` | the trace, policy and payload files you name | `--output`, `--html` | POST to `--base-url` only | nothing; tool calls are answered from the recording or stubbed |

- Trace content is treated as data. Terminal output is reduced to printable ASCII, the HTML report escapes
  everything it shows and loads no scripts, and reports show secrets only as redacted samples.
- `replay` sends the recorded conversation, including tool results, to the model endpoint you choose. Use an endpoint
  you are allowed to send that data to, or a local model. The API key is read from an environment variable and is
  only sent to that endpoint.
- The built-in replay payloads point at `collector.attacker.invalid`. The `.invalid` top-level domain is reserved and
  never resolves, so even a tool that did run could not deliver the data.

## Handling traces

Traces contain whatever the agent saw: user messages, file contents, credentials it read. Treat them like logs with
secrets in them, keep them out of public repositories and delete them when you no longer need them.

## Supported versions

Only the latest release receives security fixes during the 0.x series.
