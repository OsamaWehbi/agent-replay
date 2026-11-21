"""Text analysis shared by the rules: injected instructions, secrets, URLs and copied content."""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass
from urllib.parse import unquote_plus, urlsplit

# Instructions aimed at the model rather than the user. A tool result that contains one of these is how indirect
# prompt injection reaches an agent.
INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "override",
        re.compile(
            r"\b(ignore|disregard|forget|override)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all|your|system)\b"
            r"[^.\n]{0,20}\b(instructions?|prompts?|rules|guidelines|directives)\b",
            re.I,
        ),
    ),
    (
        "new instructions",
        re.compile(r"\b(new|updated|real|actual|hidden)\s+(instructions?|task|directive)s?\s*:", re.I),
    ),
    (
        "role change",
        re.compile(r"\byou\s+are\s+now\b|\bact\s+as\s+(?:an?\s+)?(?:unrestricted|admin|developer)\b", re.I),
    ),
    (
        "addressed to the model",
        re.compile(
            r"\b(?:attention|note|message|important|instructions?)\s+(?:to|for)\s+(?:the\s+)?"
            r"(?:ai|llm|assistant|agent|model|bot)\b"
            r"|\b(?:ai|llm)\s+(?:assistant|agent|model)s?\s*[:,-]"
            r"|^\s*(?:assistant|agent)\s*:",
            re.I | re.M,
        ),
    ),
    (
        "conceal from user",
        re.compile(
            r"\b(?:do\s+not|don't|never)\s+(?:tell|inform|mention|reveal|show)\b[^.\n]{0,30}\b(?:user|human|anyone)\b"
            r"|\bwithout\s+(?:telling|informing|asking)\s+the\s+user\b",
            re.I,
        ),
    ),
    (
        "tool directive",
        re.compile(
            r"\b(?:you\s+must|you\s+should|please|now)\s+(?:call|use|invoke|run|execute)\s+(?:the\s+)?"
            r"[`'\"]?[a-z][\w.-]*[`'\"]?\s+(?:tool|function|command)\b"
            r"|\bbefore\s+(?:answering|responding|replying|summari[sz]ing)\b[^.\n]{0,60}\b(?:call|send|fetch|read|run)\b",
            re.I,
        ),
    ),
    (
        "exfiltration request",
        re.compile(
            r"\b(?:send|post|forward|upload|email|exfiltrate|append)\b[^.\n]{0,60}"
            r"\b(?:to|at)\s+(?:https?://|[\w.+-]+@[\w-]+\.)",
            re.I,
        ),
    ),
    ("chat template token", re.compile(r"<\|(?:im_start|im_end|system|endoftext)\|>|\[/?INST\]|<<SYS>>", re.I)),
]

_TAG_CHARS = re.compile("[" + chr(0xE0000) + "-" + chr(0xE007F) + "]")
_ZERO_WIDTH = re.compile(
    "[" + "".join(map(chr, (0x200B, 0x200C, 0x200D, 0x2060, 0x2062, 0x2063, 0x2064, 0xFEFF))) + "]{3,}"
)

SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b")),
    ("API key", re.compile(r"\bsk-(?:proj-|live-|ant-)?[A-Za-z0-9_-]{20,}\b")),
    ("Slack token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("Stripe key", re.compile(r"\b[rs]k_live_[0-9A-Za-z]{20,}\b")),
    ("private key", re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----")),
    ("webhook secret", re.compile(r"\bwhsec_[A-Za-z0-9]{16,}\b")),
    ("password in URL", re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s:/@]+:([^\s:/@]{6,})@[\w.-]+")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    (
        "password or secret assignment",
        re.compile(
            r"(?i)\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|client[_-]?secret)\b\s*[:=]\s*"
            r"['\"]?([^\s'\"]{8,})"
        ),
    ),
]

URL = re.compile(r"\bhttps?://[^\s<>\"'`)\]}]+", re.I)
EMAIL = re.compile(r"\b[\w.+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b")
_WORD = re.compile(r"[a-z0-9]+")
_B64_RUN = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
_ID_TOKEN = re.compile(r"\b(?=[A-Za-z0-9_-]*\d)(?=[A-Za-z0-9_-]*[A-Za-z])[A-Za-z0-9_-]{12,}\b")
SHINGLE = 8


@dataclass(frozen=True)
class Match:
    kind: str
    text: str


def injection_matches(text: str) -> list[Match]:
    found = [Match(name, m.group(0)) for name, rx in INJECTION_PATTERNS if (m := rx.search(text))]
    if _TAG_CHARS.search(text):
        found.append(Match("hidden tag characters", "U+E00xx tag characters"))
    if _ZERO_WIDTH.search(text):
        found.append(Match("zero-width run", "zero-width characters"))
    return found


def secret_matches(text: str) -> list[Match]:
    out = []
    for name, rx in SECRET_PATTERNS:
        for m in rx.finditer(text):
            value = m.group(m.lastindex or 0)
            out.append(Match(name, value))
    return out


def redact(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "*" * min(12, len(value) - 6) + value[-2:]


def urls(text: str) -> list[str]:
    return [u.rstrip(".,;:!?") for u in URL.findall(text)]


def emails(text: str) -> set[str]:
    """Email addresses, ignoring user:password@host inside URLs."""
    return {e.lower() for e in EMAIL.findall(URL.sub(" ", text))}


def host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def decodings(text: str) -> list[str]:
    """`text` plus its URL-decoded form and any base64 runs it contains, decoded."""
    out = [text]
    unq = unquote_plus(text)
    if unq != text:
        out.append(unq)
    for source in (text, unq):
        for m in _B64_RUN.finditer(source):
            run = m.group(0).rstrip("=")
            padded = run + "=" * (-len(run) % 4)
            for decoder in (base64.b64decode, base64.urlsafe_b64decode):
                try:
                    decoded = decoder(padded).decode("utf-8")
                except (binascii.Error, UnicodeDecodeError, ValueError):
                    continue
                if decoded and sum(c.isprintable() or c.isspace() for c in decoded) / len(decoded) > 0.9:
                    out.append(decoded)
                    break
    return out


def _shingles(text: str) -> set[str]:
    words = _WORD.findall(text.lower())
    return {
        hashlib.blake2b(" ".join(words[i : i + SHINGLE]).encode(), digest_size=8).hexdigest()
        for i in range(len(words) - SHINGLE + 1)
    }


@dataclass
class Fingerprint:
    """What a tool result contained, in a form that can be searched for in later tool arguments."""

    secrets: dict[str, str]
    tokens: set[str]
    emails: set[str]
    shingles: set[str]

    @classmethod
    def of(cls, text: str) -> Fingerprint:
        secrets = {m.text: m.kind for m in secret_matches(text)}
        tokens = {t for t in _ID_TOKEN.findall(text) if t not in secrets and not t.lower().startswith("http")}
        return cls(secrets, tokens, emails(text), _shingles(text))


@dataclass(frozen=True)
class Overlap:
    kind: str  # "secret", "identifier", "email" or "text"
    sample: str


def overlap(source: Fingerprint, sink_text: str) -> list[Overlap]:
    """Content of `source` that also appears in `sink_text`, directly or after URL or base64 decoding."""
    variants = decodings(sink_text)
    joined = "\n".join(variants)
    lowered = joined.lower()
    found: list[Overlap] = []
    for value, kind in source.secrets.items():
        if value in joined:
            found.append(Overlap("secret", f"{kind} {redact(value)}"))
    for token in sorted(source.tokens):
        if token in joined:
            found.append(Overlap("identifier", token if len(token) <= 24 else token[:21] + "..."))
            break
    for email in sorted(source.emails):
        if email in lowered:
            found.append(Overlap("email", email))
            break
    if source.shingles:
        shared = set()
        for v in variants:
            shared |= source.shingles & _shingles(v)
        if shared:
            found.append(Overlap("text", f"{len(shared) + SHINGLE - 1}+ words copied"))
    return found
