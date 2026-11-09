"""Strict parser for unified diffs. The diff is untrusted input.

Hunk bodies are consumed by the line counts in their ``@@`` header, so content
that looks like a diff header cannot start a new file. Anything the parser does
not recognize raises ``DiffError``, which the CLI reports as a tool error.
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import List, Optional

HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)$")
_EXTENDED_HEADERS = (
    "index ", "old mode ", "new mode ", "deleted file mode ", "new file mode ",
    "similarity index ", "dissimilarity index ", "copy from ", "copy to ",
)
_ESCAPES = {
    "a": 7, "b": 8, "t": 9, "n": 10, "v": 11, "f": 12, "r": 13,
    '"': 34, "\\": 92,
}


class DiffError(Exception):
    """The diff could not be parsed completely."""


@dataclass
class Line:
    kind: str  # "+", "-" or " "
    text: str
    old_no: int
    new_no: int
    moved: bool = False
    code: str = ""
    comment: str = ""
    oversize: bool = False

    @property
    def number(self) -> int:
        return self.new_no if self.kind != "-" else self.old_no


@dataclass
class Hunk:
    section: str
    lines: List[Line] = field(default_factory=list)


@dataclass
class FileDiff:
    old_path: Optional[str] = None
    new_path: Optional[str] = None
    hunks: List[Hunk] = field(default_factory=list)
    binary: bool = False
    is_new: bool = False
    is_deleted: bool = False

    @property
    def path(self) -> str:
        return self.new_path or self.old_path or ""

    def lines(self):
        for hunk in self.hunks:
            yield from hunk.lines

    @property
    def has_removals(self) -> bool:
        return any(line.kind == "-" for line in self.lines())


def unquote_path(raw: str) -> str:
    """Decode git's C-style quoted path. Unquoted paths pass through."""
    if not (len(raw) >= 2 and raw[0] == '"' and raw[-1] == '"'):
        return raw
    out = bytearray()
    body = raw[1:-1]
    i = 0
    while i < len(body):
        char = body[i]
        if char != "\\":
            out.extend(char.encode("utf-8", "surrogateescape"))
            i += 1
            continue
        i += 1
        if i >= len(body):
            raise DiffError("bad escape at end of quoted path")
        char = body[i]
        if char in _ESCAPES:
            out.append(_ESCAPES[char])
            i += 1
        elif re.match(r"[0-7]{3}", body[i:i + 3]):
            out.append(int(body[i:i + 3], 8) & 0xFF)
            i += 3
        else:
            raise DiffError("unknown escape in quoted path")
    return out.decode("utf-8", "replace")


def _strip_prefix(path: str) -> str:
    return path[2:] if path[:2] in ("a/", "b/") else path


def _header_path(rest: str) -> Optional[str]:
    """Return the file path from a ``---`` or ``+++`` line; None for /dev/null."""
    if not rest.startswith('"'):
        rest = rest.split("\t", 1)[0]
    rest = rest.rstrip("\r")
    if rest == "/dev/null":
        return None
    return _strip_prefix(unquote_path(rest))


def _git_line_path(rest: str) -> Optional[str]:
    """Return the path from ``diff --git a/x b/x``, which is used only when no
    ``---`` line follows, as for empty or mode-only changes. Returns None if
    the two sides differ; later headers must then supply the paths."""
    rest = rest.rstrip("\r")
    quoted = re.findall(r'"(?:[^"\\]|\\.)*"', rest)
    if len(quoted) == 2:
        return _strip_prefix(unquote_path(quoted[1]))
    if len(quoted) == 1:
        token = quoted[0]
        other = rest.replace(token, "", 1).strip()
        return _strip_prefix(unquote_path(token if rest.endswith(token) else other))
    middle = (len(rest) - 1) // 2
    if len(rest) % 2 == 1 and rest[middle] == " ":
        left, right = rest[:middle], rest[middle + 1:]
        if _strip_prefix(left) == _strip_prefix(right):
            return _strip_prefix(right)
    return None


def _parse_hunk(lines: List[str], start: int, match) -> "tuple[Hunk, int]":
    old_no = int(match.group(1))
    new_no = int(match.group(3))
    old_left = int(match.group(2)) if match.group(2) is not None else 1
    new_left = int(match.group(4)) if match.group(4) is not None else 1
    hunk = Hunk(section=match.group(5).strip())
    i = start
    while old_left > 0 or new_left > 0:
        if i >= len(lines):
            raise DiffError("diff ends inside a hunk")
        line = lines[i]
        i += 1
        if line.startswith("\\"):
            continue
        kind = line[:1] or " "
        text = line[1:].rstrip("\r")
        if kind == " " and old_left > 0 and new_left > 0:
            hunk.lines.append(Line(" ", text, old_no, new_no))
            old_no += 1
            new_no += 1
            old_left -= 1
            new_left -= 1
        elif kind == "-" and old_left > 0:
            hunk.lines.append(Line("-", text, old_no, 0))
            old_no += 1
            old_left -= 1
        elif kind == "+" and new_left > 0:
            hunk.lines.append(Line("+", text, 0, new_no))
            new_no += 1
            new_left -= 1
        else:
            raise DiffError("hunk body does not match its header counts")
    return hunk, i


def parse(text: str, is_test_path=lambda path: False, max_files: int = 20000) -> List[FileDiff]:
    """Parse a unified diff into files and mark moved lines."""
    # str.splitlines also breaks on \f, \x85 and U+2028, which would let
    # content forge line starts.
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    files: List[FileDiff] = []
    current: Optional[FileDiff] = None
    in_body = False
    i = 0
    while i < len(lines):
        line = lines[i]
        i += 1
        if line.startswith("diff --git "):
            current = FileDiff()
            current.new_path = _git_line_path(line[len("diff --git "):])
            current.old_path = current.new_path
            files.append(current)
            in_body = False
            if len(files) > max_files:
                raise DiffError(f"diff has more than {max_files} files")
        elif line.startswith("--- ") and i < len(lines) and lines[i].startswith("+++ "):
            if current is None or in_body or current.hunks:
                current = FileDiff()
                files.append(current)
                in_body = False
            current.old_path = _header_path(line[4:])
            current.new_path = _header_path(lines[i][4:])
            current.is_new = current.old_path is None
            current.is_deleted = current.new_path is None
            i += 1
        elif line.startswith("@@"):
            match = HUNK_RE.match(line.rstrip("\r"))
            if not match or current is None:
                raise DiffError("malformed or orphaned hunk header")
            hunk, i = _parse_hunk(lines, i, match)
            current.hunks.append(hunk)
            in_body = True
        elif line.startswith("\\") and in_body:
            continue
        elif current is not None and not in_body:
            if line.startswith("rename from "):
                current.old_path = unquote_path(line[len("rename from "):].rstrip("\r"))
            elif line.startswith("rename to "):
                current.new_path = unquote_path(line[len("rename to "):].rstrip("\r"))
            elif line.startswith("new file mode "):
                current.is_new = True
            elif line.startswith("deleted file mode "):
                current.is_deleted = True
            elif line.startswith("Binary files "):
                current.binary = True
            elif line.startswith("GIT binary patch"):
                raise DiffError("binary patches are not supported; regenerate with --text")
            elif not line.startswith(_EXTENDED_HEADERS):
                raise DiffError("unexpected line in file header")
        elif line.strip():
            raise DiffError("unexpected line outside a hunk")
    if any(not item.path for item in files):
        raise DiffError("a file entry has no readable path")
    _mark_moved(files, is_test_path)
    return files


def _mark_moved(files: List[FileDiff], is_test_path) -> None:
    """Pair identical removed and added lines so moved code is not "new".

    Pairs stay within test files or within other files. A line moved from a
    test into production code therefore still counts as removed from the tests.
    """
    pools = defaultdict(lambda: {"+": [], "-": []})
    for diff in files:
        is_test = is_test_path(diff.path)
        for line in diff.lines():
            normalized = " ".join(line.text.split())
            if line.kind != " " and normalized:
                pools[(is_test, normalized)][line.kind].append(line)
    for pool in pools.values():
        for added, removed in zip(pool["+"], pool["-"]):
            added.moved = removed.moved = True
