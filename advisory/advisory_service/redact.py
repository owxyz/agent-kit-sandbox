"""Remove secrets and personal data from text before it leaves for a model provider.

Redaction is pattern-based and best effort: it errs towards removing too much.
It cannot recognise a secret with no recognisable shape, such as a bare hex key
or a short password printed on its own (see README, "What redaction misses").
"""
from __future__ import annotations

import collections
import math
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Dict, Iterable, Optional, Tuple

ANSI = re.compile(r"\x1b(?:\[[0-9;?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-Z\\^_])")
NOT_ALREADY = r"(?!\[REDACTED)"

SECRET_NAME = (
    r"[\w.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|"
    r"private[_-]?key|credential|connection[_-]?string|accountkey)[\w.-]*"
)
VALUE = r"(?:\"[^\"\n]*\"|'[^'\n]*'|[^\s\"',;]+)"

_RULES: Tuple[Tuple[str, "re.Pattern[str]", str], ...] = (
    ("private-key", re.compile(
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----.*?"
        r"(?:-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|\Z)", re.S), ""),
    ("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"), ""),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{10,}"), ""),
    ("openai-key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}"), ""),
    ("aws-key-id", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[A-Z0-9]{16}\b"), ""),
    ("google-key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}|\bya29\.[0-9A-Za-z_-]{20,}"), ""),
    ("slack-token", re.compile(r"\bxox[a-z]-[A-Za-z0-9-]{10,}"), ""),
    ("stripe-key", re.compile(r"\b[srp]k_(?:live|test)_[A-Za-z0-9]{10,}"), ""),
    ("package-token", re.compile(r"\b(?:npm_[A-Za-z0-9]{20,}|pypi-[A-Za-z0-9_-]{20,})"), ""),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"), ""),
    ("auth-header", re.compile(
        r"(?i)\b(authorization|proxy-authorization|x-api-key|x-auth-token|cookie|set-cookie)"
        r"(\"?[ \t]*:[ \t]*)" + NOT_ALREADY + r"[^\n]+"), r"\1\2"),
    ("bearer", re.compile(r"(?i)\b(bearer|basic)\s+" + NOT_ALREADY + r"(?=[A-Za-z._~+/-]*[0-9=])[A-Za-z0-9._~+/=-]{8,}"), r"\1 "),
    ("url-credential", re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^\s/:@]+:[^\s/@]+@"), r"\1"),
    ("url-secret", re.compile(
        r"(?i)([?&](?:sig|signature|x-amz-signature|x-amz-credential|x-amz-security-token|code|key)=)"
        + NOT_ALREADY + r"[^&\s\"']+"), r"\1"),
    ("cli-secret", re.compile(
        r"(?i)(--?(?:password|passwd|token|secret|api-key|apikey)[ ]+)" + NOT_ALREADY + VALUE), r"\1"),
    ("assignment", re.compile(
        r"(?i)(\b" + SECRET_NAME + r"[\"']?[ \t]*(?::=|=>|=|:)[ \t]*)" + NOT_ALREADY + VALUE), r"\1"),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b"), ""),
    ("git-identity", re.compile(
        r"(?im)^(\s*(?:author|committer|signed-off-by|co-authored-by)\s*:\s*)" + NOT_ALREADY + r".+$"), r"\1"),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), ""),
    ("phone", re.compile(
        r"(?<![\w.-])(?:\+\d{1,3}[ .-]?)?(?:\(\d{2,4}\)[ .-]?|\d{3}[ .-])\d{3}[ .-]\d{4}(?![\w-])"
        r"|(?<![\w.-])\+\d{8,15}(?![\w-])"), ""),
    ("ipv6", re.compile(r"(?i)\b(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}\b"), ""),
)
CARD = re.compile(r"(?<![\w.-])\d(?:[ -]?\d){12,18}(?![\w-])")
IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
HOME = re.compile(r"((?:/home/|/Users/|[A-Za-z]:\\Users\\))([^/\\\s:\"']+)")
HIGH_ENTROPY = re.compile(r"[A-Za-z0-9+/_=-]{32,}")
SERVICE_HOMES = frozenset({"runner", "ubuntu", "ec2-user", "circleci", "root", "shared"})


@dataclass
class Redacted:
    text: str
    counts: Dict[str, int] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return sum(self.counts.values())


def clean(text: str) -> str:
    """Drop terminal escapes and invisible characters that can hide text."""
    text = ANSI.sub("", text).replace("\r\n", "\n").replace("\r", "\n")
    return "".join(
        ch for ch in text
        if ch in "\n\t" or unicodedata.category(ch) not in ("Cc", "Cf", "Cs", "Co", "Cn")
    )


def _luhn(digits: str) -> bool:
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char)
        if index % 2:
            value = value * 2 - 9 if value > 4 else value * 2
        total += value
    return total % 10 == 0


def _entropy(token: str) -> float:
    counts = collections.Counter(token)
    return -sum(n / len(token) * math.log2(n / len(token)) for n in counts.values())


def _looks_random(token: str) -> bool:
    if re.fullmatch(r"[0-9a-fA-F]+", token):  # commit SHAs and digests help a diagnosis
        return False
    classes = (any(c.isupper() for c in token), any(c.islower() for c in token), any(c.isdigit() for c in token))
    return all(classes) and _entropy(token) >= 4.2


def redact(text: str, literals: Optional[Iterable[str]] = None) -> Redacted:
    """Return `text` with secrets and personal data replaced by typed placeholders."""
    counts: collections.Counter = collections.Counter()
    text = clean(text)

    for value in sorted({v for v in (literals or ()) if v and len(v) >= 3}, key=len, reverse=True):
        text, hits = re.subn(r"(?<![\w-])" + re.escape(value) + r"(?![\w-])", "[REDACTED:identity]", text, flags=re.I)
        counts["identity"] += hits

    for name, pattern, prefix in _RULES:
        placeholder = prefix + "[REDACTED:" + name + "]" if prefix else "[REDACTED:" + name + "]"
        text, hits = pattern.subn(placeholder, text)
        counts[name] += hits

    def conditional(name, check):
        def replace(match):
            if not check(match.group(0)):
                return match.group(0)
            counts[name] += 1
            return "[REDACTED:" + name + "]"
        return replace

    text = CARD.sub(conditional("card", lambda v: _luhn(re.sub(r"\D", "", v))), text)
    text = IPV4.sub(conditional("ipv4", lambda v: all(int(p) <= 255 for p in v.split("."))), text)

    def home(match):
        if match.group(2).lower() in SERVICE_HOMES or match.group(2).startswith("[REDACTED"):
            return match.group(0)
        counts["home-path"] += 1
        return match.group(1) + "[REDACTED:home-path]"

    text = HOME.sub(home, text)
    text = HIGH_ENTROPY.sub(conditional("high-entropy", _looks_random), text)
    return Redacted(text, {k: v for k, v in counts.items() if v})
