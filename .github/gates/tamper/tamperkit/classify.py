"""Decide whether a PR is an agent PR. All inputs are untrusted PR data.

Uses the same signals as kit/scripts/check_provenance.py, plus label history, so
removing an agent label cannot downgrade a PR. The patterns are copied so the
gate installs on its own; tests/test_classify.py fails if they drift from kit/.
"""
from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Set, Tuple

DEPENDENCY_BOTS = {"dependabot[bot]", "renovate[bot]"}
UNFILLED = {"", "tbd", "todo", "?", "unknown"}
TRAILER = re.compile(r"^\s*co-authored-by:\s*(?P<name>[^<\n]*)<(?P<email>[^>\n]*)>", re.I | re.M)
AGENT_EMAIL = re.compile(
    r"@anthropic\.com$|@openai\.com$|cursoragent@cursor\.com$|@aider\.chat$"
    r"|\+?(copilot|claude|codex|devin-ai-integration|gemini-code-assist|cursor)(\[bot\])?"
    r"@users\.noreply\.github\.com$",
    re.I,
)
AGENT_NAME = re.compile(r"\[bot\]\s*$", re.I)
AGENT_USED = re.compile(r"^[ \t]*[-*]?[ \t]*\**[ \t]*Agent used[ \t]*\**[ \t]*:[ \t]*\**[ \t]*(.*?)[ \t]*$", re.I | re.M)


def _is_agent_label(name: Any) -> bool:
    text = str(name or "").lower()
    return text.startswith("agent:") and len(text) > 6


def _declares_agent(body: Any) -> bool:
    text = re.sub(r"<!--.*?-->", "", str(body or ""), flags=re.S)
    match = AGENT_USED.search(text)
    value = match.group(1).strip().lower() if match else ""
    return value not in UNFILLED and value != "none"


def _has_agent_trailer(commits: Iterable[Dict[str, Any]]) -> bool:
    for commit in commits:
        message = (commit.get("commit") or {}).get("message") or ""
        for match in TRAILER.finditer(message):
            name, email = match.group("name").strip(), match.group("email").strip()
            lowered = name.lower()
            if lowered in DEPENDENCY_BOTS or lowered.startswith("github-actions"):
                continue
            if AGENT_EMAIL.search(email) or AGENT_NAME.search(name):
                return True
    return False


def parse_logins(raw: str) -> Set[str]:
    return {part.strip().lower() for part in raw.split(",") if part.strip()}


def classify(
    pr: Dict[str, Any], commits: List[Dict[str, Any]], events: List[Dict[str, Any]], agent_logins: Set[str]
) -> Tuple[str, List[str]]:
    """Return ("agent" or "human", signal names). Signal names hold no PR text."""
    author = str((pr.get("user") or {}).get("login") or "").lower()
    if author in DEPENDENCY_BOTS:
        return "human", ["dependency-bot"]
    signals = []
    if any(_is_agent_label(label.get("name")) for label in pr.get("labels") or []):
        signals.append("label")
    if any(item.get("event") == "labeled" and _is_agent_label((item.get("label") or {}).get("name")) for item in events):
        signals.append("label-history")
    if _declares_agent(pr.get("body")):
        signals.append("declared")
    if _has_agent_trailer(commits):
        signals.append("trailer")
    if author in agent_logins:
        signals.append("author")
    elif author.endswith("[bot]"):
        signals.append("bot-author")  # an App identity missing from AGENT_BOT_LOGINS still counts
    return ("agent" if signals else "human"), signals


def flatten_pages(data: Any) -> List[Dict[str, Any]]:
    """Accept a plain list or the list of pages from ``gh api --slurp``."""
    if not isinstance(data, list):
        raise ValueError("expected a list")
    items: List[Any] = []
    for entry in data:
        if isinstance(entry, list):
            items.extend(entry)
        else:
            items.append(entry)
    if not all(isinstance(item, dict) for item in items):
        raise ValueError("expected objects")
    return items
