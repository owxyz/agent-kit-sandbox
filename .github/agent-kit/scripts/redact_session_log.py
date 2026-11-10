#!/usr/bin/env python3
"""Redact secrets from an agent session log before it is stored (P1.4).

Usage: redact_session_log.py INPUT OUTPUT    (prints the replacement count)

Pattern-based, so it is a safety net and not proof that a log is clean: keep
stored logs access-limited as well.
"""
import re
import sys

PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{10,}"),
    re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}"),
    re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}"),
    re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}"),
]
BEARER = re.compile(r"(?i)\b(authorization:\s*(?:bearer|token)\s+|bearer\s+)[A-Za-z0-9._\-]{16,}")
ASSIGNED = re.compile(
    r"(?i)\b([A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|API_?KEY)[A-Z0-9_]*)(\"?\s*[=:]\s*\"?)[^\s\"',]{8,}"
)
MARK = "[REDACTED]"


def redact(text):
    total = 0
    for pattern in PATTERNS:
        text, count = pattern.subn(MARK, text)
        total += count
    text, count = BEARER.subn(lambda m: m.group(1) + MARK, text)
    total += count
    text, count = ASSIGNED.subn(lambda m: m.group(1) + m.group(2) + MARK, text)
    return text, total + count


def main(argv):
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    with open(argv[0], encoding="utf-8", errors="replace") as handle:
        cleaned, count = redact(handle.read())
    with open(argv[1], "w", encoding="utf-8") as handle:
        handle.write(cleaned)
    print("%d replacement(s)." % count)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
