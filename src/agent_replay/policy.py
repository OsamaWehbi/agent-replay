"""What each tool can do, and the policy a trace is checked against.

Tools are classified by capability. A tool can have several: `fetch_url` both brings in untrusted content and sends
data out through its URL. The built-in classification looks at the tool name; a policy file can override it.

```yaml
workspace: /work/app          # file writes outside this folder are flagged
allowed_domains:              # network calls to other hosts are flagged
  - api.github.com
  - "*.example.com"
tools:                        # override or add capabilities, by tool name or glob
  lookup_customer: [private]
  "slack_*": [egress]
rules:                        # extra checks
  - id: no-refunds
    description: The support agent must never issue refunds
    severity: high
    tool: issue_refund
ignore: [AR401]               # rule IDs to skip
```
"""

from __future__ import annotations

import fnmatch
import re
from enum import StrEnum
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator


class Capability(StrEnum):
    # A capability name, not a password.
    secret = "secret"  # noqa: S105  # nosec B105
    private = "private"  # returns the user's or organisation's private data
    untrusted = "untrusted"  # returns content written by third parties (web pages, email, issues, documents)
    egress = "egress"  # sends data outside (HTTP requests, email, messages, public posts)
    write = "write"  # changes files or records
    exec = "exec"  # runs commands or code


class Severity(StrEnum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"

    @property
    def rank(self) -> int:
        return list(Severity).index(self)


_WORDS = {
    Capability.secret: {
        "secret",
        "secrets",
        "credential",
        "credentials",
        "token",
        "tokens",
        "vault",
        "password",
        "passwords",
        "keychain",
        "env",
        "apikey",
        "keys",
    },
    Capability.private: {
        "file",
        "files",
        "sql",
        "db",
        "database",
        "drive",
        "calendar",
        "contacts",
        "customer",
        "customers",
        "record",
        "records",
        "repo",
        "contents",
        "cat",
        "order",
        "orders",
        "account",
        "accounts",
        "profile",
        "invoice",
        "invoices",
        "billing",
        "crm",
        "employee",
        "employees",
        "patient",
        "patients",
        "payroll",
        "user",
        "users",
        "inbox",
        "mail",
        "email",
        "emails",
        "messages",
        "history",
        "notes",
        "documents",
        "docs",
    },
    Capability.untrusted: {
        "fetch",
        "browse",
        "browser",
        "web",
        "search",
        "scrape",
        "crawl",
        "http",
        "url",
        "download",
        "inbox",
        "mail",
        "email",
        "emails",
        "issue",
        "issues",
        "comments",
        "pull",
        "pr",
        "ticket",
        "tickets",
        "rss",
        "page",
        "navigate",
        "document",
        "documents",
        "pdf",
        "messages",
    },
    Capability.egress: {
        "send",
        "post",
        "fetch",
        "http",
        "request",
        "curl",
        "webhook",
        "upload",
        "publish",
        "share",
        "tweet",
        "slack",
        "discord",
        "notify",
        "reply",
        "forward",
        "comment",
        "create",
        "browse",
        "navigate",
        "url",
        "invite",
        "transfer",
        "pay",
        "submit",
    },
    Capability.write: {
        "write",
        "save",
        "edit",
        "create",
        "delete",
        "remove",
        "move",
        "rename",
        "patch",
        "apply",
        "update",
        "append",
        "mkdir",
        "rm",
        "commit",
        "push",
        "merge",
        "drop",
        "insert",
    },
    Capability.exec: {
        "exec",
        "execute",
        "shell",
        "bash",
        "sh",
        "cmd",
        "powershell",
        "terminal",
        "command",
        "run",
        "python",
        "eval",
        "subprocess",
        "script",
        "code",
        "interpreter",
    },
}
# Words that make a tool read-only even if another word suggests otherwise ("get_url" fetches, "read_url" fetches).
_READ_ONLY = {"read", "get", "list", "search", "view", "show", "describe", "lookup", "find"}
_EGRESS_ALWAYS = {
    "send",
    "post",
    "upload",
    "publish",
    "webhook",
    "tweet",
    "forward",
    "reply",
    "share",
    "fetch",
    "http",
    "curl",
    "request",
    "browse",
    "navigate",
    "notify",
    "invite",
    "transfer",
    "submit",
    "comment",
}


def _split(name: str) -> list[str]:
    name = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    return [w for w in re.split(r"[^A-Za-z0-9]+", name.lower()) if w]


def classify(name: str) -> set[Capability]:
    """Guess a tool's capabilities from its name."""
    words = set(_split(name))
    caps = {cap for cap, vocab in _WORDS.items() if words & vocab}
    read_only = bool(words & _READ_ONLY)
    if read_only and not words & _EGRESS_ALWAYS:
        caps.discard(Capability.egress)
    if read_only and not words & {"write", "save", "delete", "remove", "edit"}:
        caps.discard(Capability.write)
    if not read_only and words & {"write", "save", "delete", "send", "post", "create", "update", "reply", "forward"}:
        caps -= {Capability.private, Capability.untrusted}
    if words & {"keys", "token", "tokens"} and not words & {"get", "read", "list"}:
        caps.discard(Capability.secret)
    return caps


class CustomRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    description: str
    severity: Severity = Severity.high
    tool: str | None = None  # glob on the tool name
    capability: Capability | None = None
    args_match: str | None = None  # regex searched in the call's arguments
    after: Capability | None = None  # only once a result with this capability has been seen

    @field_validator("args_match")
    @classmethod
    def _regex(cls, value: str | None) -> str | None:
        if value is not None:
            try:
                re.compile(value)
            except re.error as exc:
                raise ValueError(f"args_match is not a valid regular expression: {exc}") from exc
        return value

    @model_validator(mode="after")
    def _has_condition(self) -> CustomRule:
        if not (self.tool or self.capability or self.args_match):
            raise ValueError(f"rule {self.id}: set at least one of tool, capability or args_match")
        return self


class Policy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    workspace: str | None = None
    allowed_domains: list[str] | None = None
    tools: dict[str, list[Capability]] = Field(default_factory=dict)
    rules: list[CustomRule] = Field(default_factory=list)
    ignore: list[str] = Field(default_factory=list)
    max_repeats: int = 5

    def capabilities(self, tool: str | None) -> set[Capability]:
        if not tool:
            return set()
        if tool in self.tools:
            return set(self.tools[tool])
        for pattern, caps in self.tools.items():
            if fnmatch.fnmatchcase(tool, pattern):
                return set(caps)
        return classify(tool)

    def domain_allowed(self, hostname: str) -> bool:
        if self.allowed_domains is None:
            return True
        hostname = hostname.lower().rstrip(".")
        for pattern in self.allowed_domains:
            p = pattern.lower().rstrip(".")
            if hostname == p or (p.startswith("*.") and (hostname.endswith(p[1:]) or hostname == p[2:])):
                return True
        return False

    @classmethod
    def load(cls, path: str | Path | None) -> Policy:
        if path is None:
            return cls()
        try:
            data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise ValueError(f"{path}: not valid YAML ({exc})") from exc
        try:
            return cls.model_validate(data)
        except ValidationError as exc:
            first = exc.errors()[0]
            where = ".".join(str(p) for p in first["loc"])
            raise ValueError(f"{path}: {where}: {first['msg']}") from exc
