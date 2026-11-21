"""Security checks over a trace.

The checker walks the trace in order and keeps track of what the agent has seen so far: which tool results held
private data or secrets, which ones came from third parties, and which ones contained instructions aimed at the
model. Each tool call is then checked against that history. This is what lets it say "the agent sent data it read
at step 4 to a host that an email at step 2 told it to use", rather than just flagging a suspicious call.
"""

from __future__ import annotations

import fnmatch
import ntpath
import posixpath
import re
from dataclasses import dataclass, field

from pydantic import BaseModel

from agent_replay.policy import Capability, Policy, Severity
from agent_replay.text import (
    URL,
    Fingerprint,
    Overlap,
    emails,
    host,
    injection_matches,
    overlap,
    redact,
    secret_matches,
    urls,
)
from agent_replay.trace import Event, EventType, Trace


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    owasp: str
    description: str
    remediation: str


RULES: dict[str, Rule] = {
    r.id: r
    for r in [
        Rule(
            "AR101",
            "Instructions injected in a tool result",
            Severity.medium,
            "LLM01",
            "A tool result contains text addressed to the model: instructions to ignore previous rules, call a tool, "
            "send data somewhere or keep something from the user. Raised to high when the agent acted on it.",
            "Treat tool results as data. Mark or isolate third-party content before it reaches the model, and require "
            "confirmation for actions that follow it.",
        ),
        Rule(
            "AR102",
            "Agent acted on injected instructions",
            Severity.high,
            "LLM01",
            "A tool call uses a host, address or tool that only appeared in an injected tool result, not in anything "
            "the user or system prompt said. The agent followed instructions from a third party.",
            "Require user confirmation for outbound, write and exec actions whose targets come from tool results.",
        ),
        Rule(
            "AR103",
            "Data sent out of the agent",
            Severity.high,
            "LLM02",
            "A call that sends data outside (an HTTP request, email, message or public post) carries content from an "
            "earlier result that held private data or secrets, directly or URL- or base64-encoded. Critical when the "
            "content is a secret.",
            "Block outbound calls that carry data from private sources, or restrict outbound calls to an allowlist.",
        ),
        Rule(
            "AR104",
            "Private data, untrusted content and outbound access in one run",
            Severity.medium,
            "LLM06",
            "The run read private data, read content written by third parties, and then made an outbound call. That "
            "combination is what makes data exfiltration through prompt injection possible, even when no copied data "
            "was found in the outbound call.",
            "Split the agent so that no single run holds all three, or require confirmation for outbound calls after "
            "untrusted content has been read.",
        ),
        Rule(
            "AR105",
            "Secret passed to a tool",
            Severity.medium,
            "LLM02",
            "A tool call's arguments contain a credential that the agent read from an earlier tool result.",
            "Keep credentials out of the model's context; give tools their own credentials instead.",
        ),
        Rule(
            "AR201",
            "Write to a sensitive path or outside the workspace",
            Severity.high,
            "LLM06",
            "A tool wrote to a startup file, SSH configuration, Git hook or system folder, or outside the policy's "
            "workspace.",
            "Restrict file tools to the workspace and review the change.",
        ),
        Rule(
            "AR202",
            "Dangerous command",
            Severity.high,
            "LLM06",
            "An exec tool ran a command that downloads and runs code, opens a reverse shell, deletes recursively from "
            "a root or home folder, weakens permissions or adds persistence.",
            "Run commands in a sandbox and require confirmation for these patterns.",
        ),
        Rule(
            "AR203",
            "Outbound call to a host that is not allowed",
            Severity.medium,
            "LLM06",
            "An outbound call went to a host outside the policy's `allowed_domains`.",
            "Add the host to the policy if it is expected; otherwise investigate why the agent called it.",
        ),
        Rule(
            "AR301",
            "Policy rule violated",
            Severity.high,
            "LLM06",
            "A call matched one of the custom rules in the policy file.",
            "See the rule's description in the policy file.",
        ),
        Rule(
            "AR401",
            "Repeated identical tool call",
            Severity.low,
            "LLM10",
            "The agent made the same call with the same arguments many times, which usually means it is stuck in a "
            "loop and spending tokens or API quota.",
            "Cap tool calls per run and stop on repeated identical calls.",
        ),
    ]
}


class Finding(BaseModel):
    rule_id: str
    title: str
    severity: Severity
    step: int
    line: int | None = None
    tool: str | None = None
    message: str
    evidence: str = ""
    related: list[int] = []
    owasp: str = ""

    def sort_key(self) -> tuple[int, int, str]:
        return (-self.severity.rank, self.step, self.rule_id)


SENSITIVE_WRITE = re.compile(
    r"(^|/)(\.ssh/|authorized_keys$|\.bashrc$|\.bash_profile$|\.zshrc$|\.profile$|\.git/hooks/|\.gitconfig$|"
    r"\.aws/|\.kube/|\.docker/config\.json$|\.npmrc$|\.pypirc$|crontab|cron\.d/|LaunchAgents/|LaunchDaemons/|"
    r"Startup/|systemd/)|^/(etc|usr|bin|sbin|boot|var/spool/cron)/|^[a-z]:/windows/",
    re.I,
)
SECRET_PATH = re.compile(
    r"(^|/)(\.env(\.[\w-]+)?$|\.aws/credentials$|\.ssh/id_[\w-]+$|\.netrc$|\.npmrc$|\.pypirc$|\.kube/config$|"
    r"\.docker/config\.json$|credentials(\.json)?$|secrets?\.(ya?ml|json|toml)$|\.git-credentials$|"
    r"[\w-]+\.pem$|[\w-]+\.key$)",
    re.I,
)
DANGEROUS_COMMANDS: list[tuple[str, re.Pattern[str]]] = [
    (
        "download and run",
        re.compile(r"\b(curl|wget|iwr|Invoke-WebRequest)\b[^|;&\n]*\|\s*(sudo\s+)?(ba|z|da)?sh\b", re.I),
    ),
    ("download and run", re.compile(r"\b(iex|Invoke-Expression)\b", re.I)),
    (
        "decode and run",
        re.compile(r"base64\s+(-d|--decode)[^|;&\n]*\|\s*(ba|z)?sh\b|-enc(odedcommand)?\s+[A-Za-z0-9+/=]{20,}", re.I),
    ),
    ("reverse shell", re.compile(r"/dev/tcp/|\bnc\b[^\n]*\s-e\s|\bmkfifo\b[^\n]*\bnc\b|\bsocat\b[^\n]*exec", re.I)),
    (
        "recursive delete",
        re.compile(r"\brm\s+-[a-z]*r[a-z]*f?[a-z]*\s+(--no-preserve-root\s+)?(/|~|\$HOME|\*)(\s|$)", re.I),
    ),
    ("recursive delete", re.compile(r"\bRemove-Item\b[^\n]*-Recurse[^\n]*\s(C:\\|~|\$HOME)", re.I)),
    ("weakened permissions", re.compile(r"\bchmod\s+(-R\s+)?(777|a\+rwx)\b|\bicacls\b[^\n]*\bEveryone:F\b", re.I)),
    (
        "persistence",
        re.compile(r"\bcrontab\s+-|\bschtasks\s+/create\b|>>?\s*~?/?[\w/.]*\.(bashrc|zshrc|profile)\b", re.I),
    ),
    ("disables security", re.compile(r"\bsetenforce\s+0\b|Set-MpPreference\b[^\n]*Disable|\bufw\s+disable\b", re.I)),
    ("credential access", re.compile(r"\bcat\s+[^\n]*(\.aws/credentials|\.ssh/id_|/etc/shadow)\b", re.I)),
]
PATH_IN_TEXT = re.compile(r"(?<![\w/:.])(?:~|\.{1,2})?/[\w.-]+(?:/[\w.-]+)*")
PATH_KEYS = {"path", "file", "filename", "file_path", "filepath", "target", "destination", "dest", "dir", "directory"}
COMMAND_KEYS = {"command", "cmd", "script", "code", "commands", "input", "args"}


def _norm_path(p: str) -> str:
    p = p.strip().strip("'\"").replace("\\", "/")
    if re.match(r"^[A-Za-z]:/", p):
        return ntpath.normpath(p).replace("\\", "/").lower()
    return posixpath.normpath(p) if p else p


def _paths(call: Event) -> list[str]:
    out = []
    for key, value in (call.args or {}).items():
        if isinstance(value, str) and (key.lower() in PATH_KEYS or re.match(r"^(~|/|[A-Za-z]:[\\/])", value)):
            out.append(value)
    return out


def _commands(call: Event) -> str:
    args = call.args or {}
    parts = [str(v) for k, v in args.items() if k.lower() in COMMAND_KEYS]
    return "\n".join(parts) if parts else call.args_text()


def _outside(path: str, workspace: str) -> bool:
    ws = _norm_path(workspace).rstrip("/")
    p = _norm_path(path)
    if not (p.startswith("/") or re.match(r"^[a-z]:/", p) or p.startswith("~")):
        p = _norm_path(posixpath.join(ws, p))
    return not (p == ws or p.startswith(ws + "/"))


@dataclass
class _Source:
    step: int
    labels: set[Capability]
    fingerprint: Fingerprint


@dataclass
class _Injection:
    step: int
    text: str
    finding: Finding
    targets: set[str] = field(default_factory=set)
    acted_on: bool = False


class Checker:
    def __init__(self, trace: Trace, policy: Policy | None = None) -> None:
        self.trace = trace
        self.policy = policy or Policy()
        self.findings: list[Finding] = []
        self.sources: list[_Source] = []
        self.injections: list[_Injection] = []
        self.trusted_text = ""  # what the user and system prompt said
        self.labels_seen: dict[Capability, int] = {}
        self.repeats: dict[tuple[str | None, str], int] = {}

    def add(self, rule_id: str, event: Event, message: str, **kw) -> Finding:
        rule = RULES[rule_id]
        finding = Finding(
            rule_id=rule_id,
            title=rule.title,
            severity=kw.pop("severity", rule.severity),
            step=event.step,
            line=event.line,
            tool=event.tool,
            message=message,
            owasp=rule.owasp,
            **kw,
        )
        self.findings.append(finding)
        return finding

    def capabilities(self, call: Event) -> set[Capability]:
        caps = self.policy.capabilities(call.tool)
        if not caps and urls(call.args_text()):
            caps = {Capability.egress}
        return caps

    def run(self) -> list[Finding]:
        for event in self.trace.events:
            if event.type in (EventType.user, EventType.system):
                self.trusted_text += "\n" + event.content
            elif event.type == EventType.tool_result:
                self.on_result(event)
            elif event.type == EventType.tool_call:
                self.on_call(event)
        self.trifecta()
        for inj in self.injections:
            if inj.acted_on:
                inj.finding.severity = Severity.high
        ignored = set(self.policy.ignore)
        return sorted((f for f in self.findings if f.rule_id not in ignored), key=Finding.sort_key)

    def on_result(self, result: Event) -> None:
        call = self.trace.call_for(result)
        tool_caps = self.policy.capabilities(result.tool)
        labels = tool_caps & {Capability.secret, Capability.private, Capability.untrusted}
        if secret_matches(result.content):
            labels.add(Capability.secret)
        if call is not None and any(SECRET_PATH.search(_norm_path(p)) for p in _paths(call)):
            labels |= {Capability.secret, Capability.private}
        matches = injection_matches(result.content)
        if matches:
            labels.add(Capability.untrusted)
            kinds = ", ".join(sorted({m.kind for m in matches}))
            sample = next((m.text for m in matches if m.kind not in ("hidden tag characters", "zero-width run")), "")
            finding = self.add(
                "AR101",
                result,
                f"Result of {result.tool or 'a tool'} contains instructions aimed at the model ({kinds}).",
                evidence=sample[:160],
            )
            targets = {host(u) for u in urls(result.content)} | emails(result.content)
            targets |= {
                _norm_path(p)
                for p in PATH_IN_TEXT.findall(URL.sub(" ", result.content))
                if p.count("/") > 1 or p.startswith("~")
            }
            targets |= {
                t.tool for t in self.trace.calls if t.tool and re.search(rf"\b{re.escape(t.tool)}\b", result.content)
            }
            self.injections.append(_Injection(result.step, result.content, finding, {t for t in targets if t}))
        for label in labels:
            self.labels_seen.setdefault(label, result.step)
        self.sources.append(_Source(result.step, labels, Fingerprint.of(result.content)))

    def on_call(self, call: Event) -> None:
        caps = self.capabilities(call)
        args = call.args_text()
        self.check_provenance(call, caps, args)
        flowed = self.check_flow(call, caps, args)
        if not flowed:
            self.check_secret_args(call, args)
        if Capability.write in caps:
            self.check_paths(call)
        if Capability.exec in caps:
            self.check_command(call)
        if Capability.egress in caps and self.policy.allowed_domains is not None:
            bad = sorted({h for h in map(host, urls(args)) if h and not self.policy.domain_allowed(h)})
            if bad:
                self.add("AR203", call, f"{call.tool} contacted {', '.join(bad)}, which the policy does not allow.")
        self.check_custom(call, caps, args)
        key = (call.tool, args)
        self.repeats[key] = self.repeats.get(key, 0) + 1
        if self.repeats[key] == self.policy.max_repeats:
            self.add("AR401", call, f"{call.tool} was called {self.policy.max_repeats} times with the same arguments.")

    def check_provenance(self, call: Event, caps: set[Capability], args: str) -> None:
        if not self.injections:
            return
        trusted = self.trusted_text.lower()
        used = {host(u) for u in urls(args)} | emails(args) | {_norm_path(p) for p in _paths(call)}
        for inj in self.injections:
            hits = sorted(t for t in inj.targets & used if t not in trusted)
            tool_directed = call.tool in inj.targets and call.tool and call.tool.lower() not in trusted
            risky = caps & {Capability.egress, Capability.write, Capability.exec, Capability.secret, Capability.private}
            if hits or (tool_directed and risky):
                inj.acted_on = True
                if hits:
                    message = (
                        f"{call.tool} uses {', '.join(hits)}, taken from the instructions injected at step {inj.step}; "
                        "the user never mentioned it."
                    )
                else:
                    message = (
                        f"{call.tool} was called as the instructions injected at step {inj.step} asked; "
                        "the user never asked for it."
                    )
                self.add(
                    "AR102",
                    call,
                    message,
                    related=[inj.step],
                    evidence=call.summary(160),
                )
                return

    def check_flow(self, call: Event, caps: set[Capability], args: str) -> bool:
        if Capability.egress not in caps or not args:
            return False
        trusted_fp = Fingerprint.of(self.trusted_text)
        hits: list[tuple[_Source, list[Overlap]]] = []
        for src in self.sources:
            if not src.labels & {Capability.secret, Capability.private}:
                continue
            found = [o for o in overlap(src.fingerprint, args) if not self._from_user(o, trusted_fp)]
            if found:
                hits.append((src, found))
        if not hits:
            return False
        secret = any(o.kind == "secret" for _, found in hits for o in found) or any(
            Capability.secret in s.labels for s, _ in hits
        )
        steps = [s.step for s, _ in hits]
        detail = "; ".join(f"{o.kind}: {o.sample}" for _, found in hits for o in found[:2])
        hosts = ", ".join(sorted({h for h in map(host, urls(args)) if h}))
        dest = f"to {hosts}" if hosts else "out of the agent"
        self.add(
            "AR103",
            call,
            f"{call.tool} sent data from step{'s' if len(steps) > 1 else ''} {', '.join(map(str, steps))} {dest}.",
            severity=Severity.critical if secret else Severity.high,
            related=steps,
            evidence=detail[:200],
        )
        return True

    @staticmethod
    def _from_user(o: Overlap, trusted: Fingerprint) -> bool:
        if o.kind == "identifier":
            return o.sample in trusted.tokens
        if o.kind == "email":
            return o.sample in trusted.emails
        return False

    def check_secret_args(self, call: Event, args: str) -> None:
        for m in secret_matches(args):
            if m.text in self.trusted_text:
                continue
            if any(m.text in s.fingerprint.secrets for s in self.sources):
                self.add(
                    "AR105", call, f"{call.tool} received a {m.kind} read earlier in the run.", evidence=redact(m.text)
                )
                return

    def check_paths(self, call: Event) -> None:
        for raw in _paths(call):
            p = _norm_path(raw)
            expanded = p.replace("~", "/home/user", 1) if p.startswith("~") else p
            if SENSITIVE_WRITE.search(expanded):
                self.add("AR201", call, f"{call.tool} wrote to {raw}, a sensitive location.", evidence=raw)
                return
            if self.policy.workspace and _outside(raw, self.policy.workspace):
                self.add(
                    "AR201",
                    call,
                    f"{call.tool} wrote to {raw}, outside the workspace {self.policy.workspace}.",
                    evidence=raw,
                )
                return

    def check_command(self, call: Event) -> None:
        command = _commands(call)
        for name, rx in DANGEROUS_COMMANDS:
            m = rx.search(command)
            if m:
                self.add("AR202", call, f"{call.tool} ran a command that matches '{name}'.", evidence=m.group(0)[:160])
                return

    def check_custom(self, call: Event, caps: set[Capability], args: str) -> None:
        for rule in self.policy.rules:
            if rule.tool and not fnmatch.fnmatchcase(call.tool or "", rule.tool):
                continue
            if rule.capability and rule.capability not in caps:
                continue
            if rule.args_match and not re.search(rule.args_match, args):
                continue
            if rule.after and rule.after not in self.labels_seen:
                continue
            self.add(
                "AR301",
                call,
                f"{rule.id}: {rule.description}",
                severity=rule.severity,
                evidence=call.summary(160),
                related=[self.labels_seen[rule.after]] if rule.after else [],
            )

    def trifecta(self) -> None:
        if any(f.rule_id == "AR103" for f in self.findings):
            return
        private = min(
            (self.labels_seen[c] for c in (Capability.private, Capability.secret) if c in self.labels_seen),
            default=None,
        )
        untrusted = self.labels_seen.get(Capability.untrusted)
        if private is None or untrusted is None:
            return
        after = max(private, untrusted)
        for call in self.trace.calls:
            if call.step > after and Capability.egress in self.capabilities(call):
                self.add(
                    "AR104",
                    call,
                    f"The run read private data (step {private}) and untrusted content (step {untrusted}), then made "
                    f"an outbound call with {call.tool}.",
                    related=sorted({private, untrusted}),
                )
                return


def check(trace: Trace, policy: Policy | None = None) -> list[Finding]:
    return Checker(trace, policy).run()


def summarise(findings: list[Finding]) -> dict[str, int]:
    counts = {s.value: 0 for s in reversed(Severity)}
    for f in findings:
        counts[f.severity.value] += 1
    return counts
