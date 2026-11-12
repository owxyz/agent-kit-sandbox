"""Build a unified diff from the GitHub API, without checking out PR code.

Used on `pull_request_target`, where the job may hold secrets. File versions are
fetched as data and diffed locally, rather than requesting GitHub's own diff,
because a server-side diff honors PR-supplied `.gitattributes`, detects renames
and can be truncated. Tree paths are never used as filesystem paths.
"""
from __future__ import annotations

import base64
import binascii
import json
import os
import re
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, Optional, Tuple

from .engine import SHA_RE, ToolError, git_env

REPO_RE = re.compile(r"^[A-Za-z0-9-]+/(?!\.{1,2}$)[A-Za-z0-9_.-]+$")
RETRY_STATUS = {500, 502, 503, 504}
ATTEMPTS = 3
REQUEST_TIMEOUT_SECONDS = 60
GIT_TIMEOUT_SECONDS = 60
Getter = Callable[[str], Any]
Entry = Tuple[str, str, int]  # sha, type, size


def api_getter(repo: str, token: str, base_url: str = "https://api.github.com") -> Getter:
    """Return a JSON GET function. Errors never include the token."""
    if not REPO_RE.match(repo):
        raise ToolError("--api-repo must be owner/name")
    if not base_url.startswith("https://"):
        raise ToolError("the API URL must use https")
    if not token:
        raise ToolError("GITHUB_TOKEN is required for --api-repo")

    def get(path: str) -> Any:
        request = urllib.request.Request(
            f"{base_url}/repos/{repo}/{path}",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"},
        )
        problem = "no response"
        for attempt in range(ATTEMPTS):
            if attempt:
                time.sleep(2 * attempt)
            try:
                with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
                    return json.load(response)
            except urllib.error.HTTPError as error:
                problem = f"HTTP {error.code}"
                if error.code not in RETRY_STATUS:
                    break
            except (urllib.error.URLError, OSError, ValueError) as error:
                problem = type(error).__name__
        raise ToolError(f"GitHub API request failed ({problem}) for {path.split('?')[0]}")

    return get


def _dict(value: Any, what: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise ToolError(f"unexpected API response for {what}")
    return value


def merge_base(get: Getter, base: str, head: str) -> str:
    sha = _dict(get(f"compare/{base}...{head}?per_page=1"), "compare").get("merge_base_commit")
    sha = sha.get("sha") if isinstance(sha, dict) else None
    if not isinstance(sha, str) or not SHA_RE.match(sha):
        raise ToolError("compare response has no merge base")
    return sha


def _tree(get: Getter, commit: str) -> Dict[str, Entry]:
    data = _dict(get(f"git/commits/{commit}"), "commit")
    tree_sha = data.get("tree", {}).get("sha") if isinstance(data.get("tree"), dict) else None
    if not isinstance(tree_sha, str) or not SHA_RE.match(tree_sha):
        raise ToolError("commit response has no tree")
    listing = _dict(get(f"git/trees/{tree_sha}?recursive=1"), "tree")
    if listing.get("truncated") is not False or not isinstance(listing.get("tree"), list):
        raise ToolError("repository tree is truncated or malformed")
    entries: Dict[str, Entry] = {}
    for item in listing["tree"]:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str) or not isinstance(item.get("sha"), str):
            raise ToolError("malformed tree entry")
        if item.get("type") in ("blob", "commit"):
            entries[item["path"]] = (item["sha"], item["type"], int(item.get("size") or 0))
    return entries


def _content(get: Getter, entry: Entry, cache: Dict[str, bytes]) -> bytes:
    sha, kind, _ = entry
    if kind == "commit":
        return f"Subproject commit {sha}\n".encode()
    if sha not in cache:
        data = _dict(get(f"git/blobs/{sha}"), "blob")
        if data.get("encoding") != "base64" or not isinstance(data.get("content"), str):
            raise ToolError("blob response is not base64")
        try:
            cache[sha] = base64.b64decode(data["content"].replace("\n", ""), validate=True)
        except (binascii.Error, ValueError) as error:
            raise ToolError("blob response is not valid base64") from error
    return cache[sha]


def _quote(path: str) -> str:
    """Return a C-quoted path, safe for a diff header whatever it contains."""
    out = []
    for byte in path.encode("utf-8", "surrogateescape"):
        if 0x20 <= byte < 0x7F and byte not in (0x22, 0x5C):
            out.append(chr(byte))
        else:
            out.append(f"\\{byte:03o}")
    return "".join(out)


def _hunks(old: Optional[bytes], new: Optional[bytes], workdir: str, env: Dict[str, str]) -> bytes:
    sides = []
    for name, content in (("old", old), ("new", new)):
        if content is None:
            sides.append(os.devnull)
            continue
        target = os.path.join(workdir, name)
        with open(target, "wb") as handle:
            handle.write(content)
        sides.append(target)
    command = [
        "git", "diff", "--no-index", "--text", "--no-ext-diff", "--no-textconv", "--no-color",
        "--unified=3", "--diff-algorithm=myers", "--", *sides,
    ]
    try:
        result = subprocess.run(
            command, cwd=workdir, env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=GIT_TIMEOUT_SECONDS
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ToolError(f"local diff failed: {type(error).__name__}") from error
    if result.returncode not in (0, 1):
        raise ToolError("local diff failed")
    output = result.stdout
    if output.startswith(b"@@ -"):
        return output
    start = output.find(b"\n@@ -")
    return output[start + 1:] if start >= 0 else b""


def build_diff(get: Getter, base: str, head: str, max_files: int, max_bytes: int) -> str:
    """Return a unified diff of two commits, using only API data."""
    if not SHA_RE.match(base) or not SHA_RE.match(head):
        raise ToolError("base and head must be full commit SHAs")
    before, after = _tree(get, base), _tree(get, head)
    changed = sorted(p for p in set(before) | set(after) if (before.get(p) or ("",))[0] != (after.get(p) or ("",))[0])
    if len(changed) > max_files:
        raise ToolError(f"PR changes {len(changed)} files; the API limit is {max_files}")
    if sum(entry[2] for path in changed for entry in (before.get(path), after.get(path)) if entry) > max_bytes:
        raise ToolError(f"changed files are larger than {max_bytes} bytes")
    cache: Dict[str, bytes] = {}
    parts = []
    total = 0
    with tempfile.TemporaryDirectory() as workdir:
        env = git_env()
        for path in changed:
            old = _content(get, before[path], cache) if path in before else None
            new = _content(get, after[path], cache) if path in after else None
            quoted = _quote(path)
            header = f'diff --git "a/{quoted}" "b/{quoted}"\n'
            if old is None:
                header += "new file mode 100644\n"
            elif new is None:
                header += "deleted file mode 100644\n"
            hunks = _hunks(old, new, workdir, env).decode("utf-8", "replace")
            if hunks:
                header += ("--- /dev/null\n" if old is None else f'--- "a/{quoted}"\n')
                header += ("+++ /dev/null\n" if new is None else f'+++ "b/{quoted}"\n')
            total += len(header) + len(hunks)
            if total > max_bytes:
                raise ToolError(f"diff is larger than {max_bytes} bytes")
            parts.append(header + hunks)
    return "".join(parts)
