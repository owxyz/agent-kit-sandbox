"""Parse a unified diff and remove comments, so justifications cannot sway the judge.

The scanner works line by line within each hunk and is deliberately simple. Files
in languages it does not know, and prose such as Markdown, are omitted rather than
shown with comments intact. It does not remove justifications placed in string
literals or identifiers. When a hunk's boundaries make comment state ambiguous it
keeps the text: showing a stray comment is better than hiding code from the judge.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field, replace
from typing import Dict, List, Optional, Tuple

_HUNK = re.compile(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@")
_TEST_PATH = re.compile(r"(?i)(^|/)(tests?|__tests__|spec)(/|$)|(^|/)test_[^/]+$|_test\.[^/]+$|\.(test|spec)\.[^/]+$")
_GENERATED = re.compile(
    r"(?i)(^|/)(vendor|third_party|node_modules|dist|build|__generated__)/|\.min\.(js|css)$|\.(lock|snap|pb\.go)$"
    r"|(^|/)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|poetry\.lock|go\.sum|cargo\.lock)$|_pb2\.py$"
)
_PREFIX = re.compile(r"^[rRbBuUfF]{0,2}$")
_STRINGS = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|`[^`]*`')
_TRIPLE = re.compile(r'"""|\'\'\'')


@dataclass(frozen=True)
class Syntax:
    line: Tuple[str, ...] = ()
    block: Tuple[Tuple[str, str], ...] = ()
    triple: bool = False
    backtick: bool = False
    char_quote: bool = False  # ' is a one-character literal, as in C or Rust
    hash_needs_space: bool = False


HASH = Syntax(line=("#",))
SHELL = Syntax(line=("#",), hash_needs_space=True)
PYTHON = Syntax(line=("#",), triple=True)
C_LIKE = Syntax(line=("//",), block=(("/*", "*/"),), char_quote=True)
SCRIPT = Syntax(line=("//",), block=(("/*", "*/"),), backtick=True)
PHP = Syntax(line=("//", "#"), block=(("/*", "*/"),))
CSS = Syntax(block=(("/*", "*/"),))
SQL = Syntax(line=("--",), block=(("/*", "*/"),))
LUA = Syntax(line=("--",), block=(("--[[", "]]"),))
MARKUP = Syntax(block=(("<!--", "-->"),))
NONE = Syntax()

_BY_EXT: Dict[str, Syntax] = {
    ".py": PYTHON, ".pyi": PYTHON,
    ".rb": HASH, ".pl": HASH, ".r": HASH, ".toml": HASH, ".ini": HASH, ".cfg": HASH,
    ".sh": SHELL, ".bash": SHELL, ".zsh": SHELL, ".yml": SHELL, ".yaml": SHELL,
    ".c": C_LIKE, ".h": C_LIKE, ".cc": C_LIKE, ".cpp": C_LIKE, ".hpp": C_LIKE, ".cs": C_LIKE, ".java": C_LIKE,
    ".go": C_LIKE, ".rs": C_LIKE, ".kt": C_LIKE, ".kts": C_LIKE, ".scala": C_LIKE, ".swift": C_LIKE,
    ".js": SCRIPT, ".jsx": SCRIPT, ".mjs": SCRIPT, ".cjs": SCRIPT, ".ts": SCRIPT, ".tsx": SCRIPT,
    ".php": PHP, ".css": CSS, ".scss": C_LIKE, ".sql": SQL, ".lua": LUA,
    ".html": MARKUP, ".xml": MARKUP, ".vue": MARKUP, ".svelte": MARKUP,
    ".json": NONE, ".csv": NONE,
}
_BY_NAME = {"makefile": SHELL, "dockerfile": SHELL, "gemfile": HASH, "rakefile": HASH}


def syntax_for(path: str) -> Optional[Syntax]:
    base = os.path.basename(path).lower()
    if base in _BY_NAME:
        return _BY_NAME[base]
    return _BY_EXT.get(os.path.splitext(base)[1])


class _Scanner:
    """Removes comments from successive lines, remembering multi-line state."""

    def __init__(self, syntax: Syntax, start_block: Optional[str] = None):
        self.syntax = syntax
        self.end: Optional[str] = start_block  # inside a comment ending with this
        self.string: Optional[str] = None  # inside a multi-line string ending with this

    def strip(self, line: str) -> str:
        syntax, out, i, n = self.syntax, [], 0, len(line)
        quote: Optional[str] = None
        while i < n:
            if self.end:
                at = line.find(self.end, i)
                if at < 0:
                    return "".join(out)
                i, self.end = at + len(self.end), None
                continue
            if self.string:
                at = line.find(self.string, i)
                if at < 0:
                    out.append(line[i:])
                    return "".join(out)
                out.append(line[i:at + len(self.string)])
                i, self.string = at + len(self.string), None
                continue
            ch = line[i]
            if quote:
                out.append(ch)
                if ch == "\\" and i + 1 < n:
                    out.append(line[i + 1])
                    i += 1
                elif ch == quote:
                    quote = None
                i += 1
                continue
            triple = line[i:i + 3]
            if syntax.triple and triple in ('"""', "'''"):
                closes = line.find(triple, i + 3)
                if _PREFIX.match("".join(out).strip()):  # a statement-position string is a docstring
                    out = []
                    if closes < 0:
                        self.end = triple
                        return ""
                    i = closes + 3
                    continue
                if closes < 0:
                    out.append(line[i:])
                    self.string = triple
                    return "".join(out)
                out.append(line[i:closes + 3])
                i = closes + 3
                continue
            block = next((b for b in syntax.block if line.startswith(b[0], i)), None)
            if block:
                i, self.end = i + len(block[0]), block[1]
                continue
            marker = next((m for m in syntax.line if line.startswith(m, i)), None)
            if marker and (not (syntax.hash_needs_space and marker == "#") or i == 0 or line[i - 1].isspace()):
                return "".join(out)
            if syntax.backtick and ch == "`":
                at = line.find("`", i + 1)
                if at < 0:
                    out.append(line[i:])
                    self.string = "`"
                    return "".join(out)
                out.append(line[i:at + 1])
                i = at + 1
                continue
            if ch == '"' or (ch == "'" and not syntax.char_quote and not syntax.hash_needs_space):
                quote = ch
            elif ch == "'" and syntax.char_quote:
                match = re.match(r"'(\\.[^']{0,8}|[^'\\])'", line[i:])
                if match:
                    out.append(match.group(0))
                    i += len(match.group(0))
                    continue
            out.append(ch)
            i += 1
        return "".join(out)


@dataclass
class Hunk:
    old_start: int
    new_start: int
    lines: List[Tuple[str, str]] = field(default_factory=list)  # (" ", "-", "+"), text


@dataclass
class FileDiff:
    path: str
    hunks: List[Hunk] = field(default_factory=list)

    @property
    def is_test(self) -> bool:
        return bool(_TEST_PATH.search(self.path))


@dataclass
class StrippedDiff:
    files: List[FileDiff]
    omitted: Dict[str, str]
    comment_lines_removed: int

    def render(self) -> str:
        return _render(self.files, " -+")

    def base_context(self) -> str:
        """The code before the change, without the change's own source edits."""
        return _render([f for f in self.files if not f.is_test], " -")

    def test_changes(self) -> str:
        """Test files as they stand after the change: the only statement of intent."""
        return _render([f for f in self.files if f.is_test], " +")


def _render(files: List[FileDiff], tags: str) -> str:
    out: List[str] = []
    for item in files:
        out.append(f"=== {item.path}")
        for hunk in item.hunks:
            out.append(f"@@ -{hunk.old_start} +{hunk.new_start} @@")
            out.extend(tag + text for tag, text in hunk.lines if tag in tags)
    return "\n".join(out)


def parse(diff: str) -> List[Tuple[str, List[Hunk], Optional[str]]]:
    files: List[Tuple[str, List[Hunk], Optional[str]]] = []
    current: Optional[List] = None
    for line in diff.split("\n"):
        if line.startswith("diff --git "):
            match = re.match(r'diff --git "?a/(.*?)"? "?b/(.*?)"?$', line)
            current = [match.group(2) if match else "unknown", [], None]
            files.append(current)  # type: ignore[arg-type]
        elif current is None:
            continue
        elif line.startswith("+++ b/"):
            current[0] = line[6:].strip().strip('"')
        elif line.startswith("--- a/") and not current[1]:
            current[0] = line[6:].strip().strip('"')
        elif line.startswith("Binary files ") or line.startswith("GIT binary patch"):
            current[2] = "binary"
        else:
            match = _HUNK.match(line)
            if match:
                current[1].append(Hunk(int(match.group(1)), int(match.group(2))))  # hunk-header context is dropped
            elif current[1] and line[:1] in (" ", "+", "-") and not line.startswith("\\"):
                current[1][-1].lines.append((line[0], line[1:]))
    return [(f[0], f[1], f[2]) for f in files]


def _opens_inside_block(hunk: Hunk, tag_filter: str, syntax: Syntax) -> Optional[str]:
    """If the first delimiter seen in a hunk is a closer, the hunk began in a comment."""
    for opener, closer in syntax.block:
        for tag, text in hunk.lines:
            if tag not in tag_filter:
                continue
            text = _STRINGS.sub("", text)  # a closer inside a string must not hide code
            at_open, at_close = text.find(opener), text.find(closer)
            if at_close >= 0 and (at_open < 0 or at_close < at_open):
                return closer
            if at_open >= 0:
                break
    return None


def _side_syntax(hunk: Hunk, tags: str, syntax: Syntax) -> Syntax:
    """An odd number of triple quotes means the hunk cut a string: keep its text."""
    count = sum(len(_TRIPLE.findall(text)) for tag, text in hunk.lines if tag in tags)
    return replace(syntax, triple=False) if syntax.triple and count % 2 else syntax


def strip_hunk(hunk: Hunk, syntax: Syntax) -> Tuple[Hunk, int]:
    old = _Scanner(_side_syntax(hunk, " -", syntax), _opens_inside_block(hunk, " -", syntax))
    new = _Scanner(_side_syntax(hunk, " +", syntax), _opens_inside_block(hunk, " +", syntax))
    result = Hunk(hunk.old_start, hunk.new_start)
    removed = 0
    for tag, text in hunk.lines:
        if tag == "-":
            kept = old.strip(text)
        elif tag == "+":
            kept = new.strip(text)
        else:
            kept = old.strip(text)
            new.strip(text)
        kept = kept.rstrip()
        if text.strip() and not kept.strip():
            removed += 1
            continue
        result.lines.append((tag, kept))
    return result, removed


def strip_comments(diff: str, max_chars: int = 120000) -> StrippedDiff:
    files: List[FileDiff] = []
    omitted: Dict[str, str] = {}
    removed = 0
    used = 0
    for path, hunks, note in parse(diff):
        if note:
            omitted[path] = note
            continue
        if _GENERATED.search(path):
            omitted[path] = "generated, vendored or lock file"
            continue
        syntax = syntax_for(path)
        if syntax is None:
            omitted[path] = "comments cannot be stripped from this file type"
            continue
        item = FileDiff(path)
        for hunk in hunks:
            stripped, count = strip_hunk(hunk, syntax)
            removed += count
            if any(tag != " " for tag, _ in stripped.lines):
                item.hunks.append(stripped)
        if not item.hunks:
            continue
        size = sum(len(text) + 1 for hunk in item.hunks for _, text in hunk.lines)
        if used + size > max_chars:
            omitted[path] = "diff size limit reached"
            continue
        used += size
        files.append(item)
    return StrippedDiff(files, omitted, removed)
