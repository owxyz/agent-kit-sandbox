"""Handling for untrusted text on the way into a prompt and out of a model.

Logs and diffs can carry instructions written by whoever controls the PR. These
helpers fence that text for the model and neutralise what the model returns
before it reaches GitHub. They reduce risk; only the code paths that ignore model
output (fixed conclusion, structured signals) are guarantees.
"""
from __future__ import annotations

import re
import secrets

from .redact import clean, redact

_LINK = re.compile(r"!?\[([^\]\n]{0,300})\]\([^)\n]{0,2000}\)")
_REF_LINK = re.compile(r"^\s*\[[^\]\n]+\]:\s*\S+.*$", re.M)
_BARE_URL = re.compile(r"(?i)\b(?:https?|ftp|file|javascript|data):[^\s)>\]]+|\bwww\.[^\s)>\]]+")


def new_nonce() -> str:
    return secrets.token_hex(8)


def fence(label: str, content: str, nonce: str) -> str:
    """Wrap `content` in a tag whose name the content's author cannot predict."""
    tag = f"untrusted_{label}_{nonce}"
    body = content.replace(nonce, "[nonce]")
    return f"<{tag}>\n{body}\n</{tag}>"


def sanitize_output(text: str, limit: int = 4000) -> str:
    """Make model or workflow-supplied text inert for a check-run body."""
    text = redact(str(text)).text
    text = _REF_LINK.sub("", text)
    text = _LINK.sub(lambda m: m.group(1), text)
    text = _BARE_URL.sub("[link removed]", text)
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    text = text.replace("@", "&#64;").strip()
    if len(text) > limit:
        text = text[:limit].rstrip() + " [truncated]"
    return text


def quote(text: str) -> str:
    """Render as a blockquote so model text cannot create page structure."""
    return "\n".join("> " + line for line in text.splitlines()) or "> (empty)"


def inline(text: str, limit: int = 200) -> str:
    """Sanitize a short value for one table cell."""
    value = re.sub(r"\s+", " ", sanitize_output(clean(str(text)), limit))
    return value.replace("|", "\\|").replace("`", "'")
