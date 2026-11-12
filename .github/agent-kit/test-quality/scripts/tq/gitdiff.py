"""Parse a zero-context git diff into per-file changed lines."""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field

from .core import ToolError, run, text

HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


@dataclass
class FileChange:
    path: str
    old_path: str = ""
    status: str = "M"  # A, M, D or R
    added: dict = field(default_factory=dict)  # new-file line -> text
    anchors: set = field(default_factory=set)  # new-file line after which lines were deleted

    @property
    def changed_lines(self):
        return set(self.added)

    @property
    def touched(self):
        return set(self.added) | self.anchors


def git(repo, *args, env=None):
    done = run(["git", "-C", repo, "-c", "core.quotepath=false"] + list(args), env=env, timeout=300)
    if done.returncode != 0:
        raise ToolError("git %s failed: %s" % (args[0], text(done.stderr).strip()))
    return done.stdout


def _path(raw, prefix):
    raw = raw.rstrip("\t")
    if raw.startswith('"'):
        raise ToolError("cannot safely parse quoted path %s" % raw)
    return raw[len(prefix):] if raw.startswith(prefix) else raw


def parse_diff(diff_text):
    files, current = {}, None
    for line in diff_text.split("\n"):
        if line.startswith("diff --git "):
            current = FileChange(path="")
            continue
        if current is None:
            continue
        if line.startswith("rename from "):
            current.old_path, current.status = line[len("rename from "):], "R"
        elif line.startswith("rename to "):
            current.path = line[len("rename to "):]
            files[current.path] = current
        elif line.startswith("new file mode"):
            current.status = "A"
        elif line.startswith("deleted file mode"):
            current.status = "D"
        elif line.startswith("--- ") and not current.path:
            if not line.startswith("--- /dev/null"):
                current.old_path = _path(line[4:], "a/")
        elif line.startswith("+++ ") and not hasattr(current, "_cursor"):
            target = line[4:]
            current.path = current.old_path if target.startswith("/dev/null") else _path(target, "b/")
            files[current.path] = current
        elif line.startswith("@@ "):
            match = HUNK.match(line)
            if not match:
                raise ToolError("cannot parse hunk header: %s" % line)
            old_count = int(match.group(2) or 1)
            new_start, new_count = int(match.group(3)), int(match.group(4) or 1)
            current._cursor = new_start
            if old_count and not new_count:  # pure deletion: git reports the line before it
                current.anchors.add(new_start)
        elif line.startswith("+") and hasattr(current, "_cursor"):
            current.added[current._cursor] = line[1:]
            current._cursor += 1
    return files


def resolve_merge_base(repo, base_sha, head_sha):
    return text(git(repo, "merge-base", base_sha, head_sha)).strip()


def changed_files(repo, merge_base, head_sha):
    output = git(repo, "diff", "--no-ext-diff", "--no-color", "-U0", "-M", "--src-prefix=a/",
                 "--dst-prefix=b/", merge_base, head_sha)
    return parse_diff(text(output))


def ignored(path, globs):
    return any(fnmatch.fnmatch(path, pattern) for pattern in globs)
