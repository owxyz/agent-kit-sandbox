"""Trim and redact CI logs, and read the one structured fact only the log holds.

GitHub's runner prefixes every log line with a timestamp that the job's own
output cannot set, so the failing step is selected by time rather than by
`##[group]` markers, which any process can print.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

from .redact import redact

_STAMPED = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.\d+)?Z ?(.*)$")
_EXIT = re.compile(r"^##\[error\]Process completed with exit code (\d{1,3})\.\s*$")
_INTERESTING = re.compile(
    r"(?i)\b(error|fail(?:ed|ure)?|fatal|exception|traceback|panic|assert|cannot|unable|denied|not found|timed? ?out|killed)\b"
)
MAX_LINE = 2000


@dataclass(frozen=True)
class ExitCode:
    value: Optional[int]
    conflict: bool  # more than one distinct exit line: someone may be spoofing it


@dataclass
class PreparedLog:
    text: str
    total_lines: int
    kept_lines: int
    redactions: Dict[str, int] = field(default_factory=dict)


def _stamped_lines(raw: str) -> List[Tuple[Optional[str], str]]:
    lines = []
    for line in raw.split("\n"):
        match = _STAMPED.match(line.lstrip("﻿").rstrip("\r"))
        lines.append((match.group(1), match.group(2)) if match else (None, line.rstrip("\r")))
    return lines


def step_lines(raw: str, started_at: Optional[str], completed_at: Optional[str]) -> List[str]:
    """Lines inside the step's time window; the whole log if the window is unusable.

    The API gives step times to the second, so the window also catches neighbouring
    steps. It is narrowed only in directions output cannot exploit. It starts at the
    first step header within the step's first second: the runner writes the real
    header before any of the step's output, so a printed fake can only come from an
    earlier step and move the start earlier. It ends at the runner's exit line,
    which is written after the step's output.
    """
    lines = _stamped_lines(raw)
    if started_at and completed_at:
        low, high = started_at[:19], completed_at[:19]
        window = [(stamp, text) for stamp, text in lines if stamp is not None and low <= stamp <= high]
        selected = [text for _, text in window]
        if selected:
            start = next((i for i, (stamp, text) in enumerate(window) if stamp == low and text.startswith("##[group]Run ")), 0)
            ends = [i for i, text in enumerate(selected) if _EXIT.match(text.strip())]
            end = ends[-1] + 1 if ends and ends[-1] >= start else len(selected)
            return selected[start:end]
    return [text for _, text in lines]


def exit_code(raw: str, started_at: Optional[str], completed_at: Optional[str]) -> ExitCode:
    """The runner's exit line for a step.

    The runner writes its line after the step's process has exited, so the last
    match is the runner's. A process can still print lookalikes earlier, which
    `conflict` reports so P3.1 can decline to trust the value.
    """
    codes = [int(m.group(1)) for m in (_EXIT.match(l.strip()) for l in step_lines(raw, started_at, completed_at)) if m]
    if not codes:
        return ExitCode(None, False)
    return ExitCode(codes[-1], len(set(codes)) > 1)


def _trim(lines: List[str], max_lines: int, max_chars: int, tail: int = 150, context: int = 3) -> List[str]:
    deduplicated: List[str] = []
    for line in lines:
        short = line[:MAX_LINE]
        if not deduplicated or deduplicated[-1] != short:
            deduplicated.append(short)
    count = len(deduplicated)
    keep = set(range(max(0, count - tail), count))
    for index, line in enumerate(deduplicated):
        if len(keep) >= max_lines:
            break
        if _INTERESTING.search(line):
            keep.update(range(max(0, index - context), min(count, index + context + 1)))
    out: List[str] = []
    previous = -1
    for index in sorted(keep)[-max_lines:]:
        if index != previous + 1:
            out.append(f"[... {index - previous - 1} lines omitted ...]")
        out.append(deduplicated[index])
        previous = index
    while sum(len(l) + 1 for l in out) > max_chars and len(out) > 1:
        out.pop(0)
    return out


def prepare(raw: str, started_at: Optional[str], completed_at: Optional[str], literals: Iterable[str] = (),
            max_lines: int = 400, max_chars: int = 40000) -> PreparedLog:
    """Redact, trim, then redact again. Nothing unredacted leaves this function."""
    literals = list(literals)
    selected = step_lines(raw, started_at, completed_at)
    first = redact("\n".join(selected), literals)  # whole block, so multi-line keys match
    kept = _trim(first.text.split("\n"), max_lines, max_chars)
    second = redact("\n".join(kept), literals)
    counts = dict(first.counts)
    for name, value in second.counts.items():
        counts[name] = counts.get(name, 0) + value
    return PreparedLog(second.text, len(selected), len(kept), counts)
