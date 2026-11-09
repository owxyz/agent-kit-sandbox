"""Loads config, obtains the diff, runs rules and formats findings."""
from __future__ import annotations

import os
import re
import subprocess
import tempfile
from typing import Any, Dict, List

import yaml

from . import diffparse
from .languages import is_test_path
from .rules import REGISTRY, Context

GATE = "tamper"
MODES = {"warn", "block"}
INTENDED = {"block", "warn-then-review", "warn-over-budget"}
SHA_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
GIT_TIMEOUT_SECONDS = 300
MAX_MESSAGE_CHARS = 500
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f  ‪-‮⁦-⁩]")


class ToolError(Exception):
    """The gate could not produce a trustworthy result."""


def load_config(path: str) -> Dict[str, Any]:
    try:
        with open(path, encoding="utf-8") as handle:
            config = yaml.safe_load(handle)
    except (OSError, yaml.YAMLError) as error:
        raise ToolError(f"cannot read config: {error}") from error
    if not isinstance(config, dict) or not isinstance(config.get("rules"), dict):
        raise ToolError("config has no rules mapping")
    rules = config["rules"]
    if set(rules) != set(REGISTRY):
        missing = sorted(set(REGISTRY) - set(rules))
        unknown = sorted(set(rules) - set(REGISTRY))
        raise ToolError(f"config does not match the rule set; missing {missing}, unknown {unknown}")
    for name, entry in rules.items():
        if not isinstance(entry, dict) or entry.get("mode") not in MODES or entry.get("intended") not in INTENDED:
            raise ToolError(f"rule {name} needs mode (warn or block) and a valid intended mode")
        if not isinstance(entry.get("category"), str):
            raise ToolError(f"rule {name} needs a category")
    for section, key in (("budgets", "suppressions"), ("limits", "max_diff_bytes"), ("limits", "max_line_chars"), ("limits", "max_files"), ("limits", "max_api_files")):
        value = config.get(section, {}).get(key) if isinstance(config.get(section), dict) else None
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ToolError(f"config needs a non-negative integer {section}.{key}")
    return config


def git_env() -> Dict[str, str]:
    """Return an environment that keeps user and system git config out."""
    env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_ATTR_NOSYSTEM="1", GIT_OPTIONAL_LOCKS="0", LC_ALL="C")
    env.pop("GIT_EXTERNAL_DIFF", None)
    return env


def read_git_diff(repo: str, base: str, head: str, max_bytes: int) -> str:
    """Return the diff between two commits, read as data.

    Only full SHAs are accepted, so a ref cannot act as an option. ``--text``
    overrides ``-diff`` attributes that a PR could use to hide a file, and the
    remaining flags stop PR-controlled attributes from choosing external or
    textconv drivers.
    """
    if not SHA_RE.match(base) or not SHA_RE.match(head):
        raise ToolError("base and head must be full commit SHAs")
    env = git_env()
    command = [
        "git", "-C", repo, "-c", "core.quotepath=true", "-c", f"core.attributesFile={os.devnull}", "diff",
        "--text", "--no-ext-diff", "--no-textconv", "--no-color", "--no-renames", "--unified=3",
        "--diff-algorithm=myers", "--src-prefix=a/", "--dst-prefix=b/", base, head, "--",
    ]
    with tempfile.TemporaryFile() as stderr:
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=stderr, stdin=subprocess.DEVNULL, env=env)
        except OSError as error:
            raise ToolError(f"cannot run git: {error}") from error
        data = process.stdout.read(max_bytes + 1)
        if len(data) > max_bytes:
            process.kill()
            process.wait()
            raise ToolError(f"diff is larger than {max_bytes} bytes")
        process.stdout.close()
        try:
            code = process.wait(timeout=GIT_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired as error:
            process.kill()
            raise ToolError("git diff timed out") from error
        if code != 0:
            stderr.seek(0)
            raise ToolError("git diff failed: " + stderr.read(500).decode("utf-8", "replace"))
    return data.decode("utf-8", "replace")


def read_diff_file(path: str, max_bytes: int) -> str:
    try:
        with open(path, "rb") as handle:
            data = handle.read(max_bytes + 1)
    except OSError as error:
        raise ToolError(f"cannot read diff: {error}") from error
    if len(data) > max_bytes:
        raise ToolError(f"diff is larger than {max_bytes} bytes")
    return data.decode("utf-8", "replace")


def clean(text: str, limit: int = MAX_MESSAGE_CHARS) -> str:
    """Neutralize control and bidi characters from PR-controlled strings."""
    return _CONTROL.sub("?", str(text))[:limit]


def run(diff_text: str, config: Dict[str, Any], pr_class: str = "agent") -> List[Dict[str, Any]]:
    """Run every rule. Non-agent PRs report in warn mode only."""
    try:
        files = diffparse.parse(diff_text, is_test_path, config["limits"]["max_files"])
    except DiffError as error:
        raise ToolError(f"cannot parse diff: {error}") from error
    context = Context(files, config["budgets"]["suppressions"], config["limits"]["max_line_chars"])
    findings = []
    for name, function in REGISTRY.items():
        entry = config["rules"][name]
        mode = entry["mode"] if pr_class == "agent" else "warn"
        for hit in function(context):
            findings.append({
                "gate": GATE,
                "rule": name,
                "severity": "high" if entry["intended"] == "block" else "medium",
                "mode": mode,
                "file": clean(hit.file),
                "line": hit.line,
                "message": clean(hit.message),
            })
    findings.sort(key=lambda item: (item["file"], item["line"], item["rule"], item["message"]))
    return findings


def tool_error_finding(message: str) -> Dict[str, Any]:
    """A blocking record, so a consumer that only reads the file cannot pass."""
    return {
        "gate": GATE, "rule": "tool-error", "severity": "error", "mode": "block",
        "file": "", "line": 0, "message": clean(message),
    }


def _escape_property(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A").replace(":", "%3A").replace(",", "%2C")


def _escape_data(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def annotation(finding: Dict[str, Any]) -> str:
    """Format a GitHub annotation. PR text must not form a workflow command."""
    level = "error" if finding["mode"] == "block" else "warning"
    properties = f"title={_escape_property(finding['rule'])}"
    if finding["file"]:
        properties = f"file={_escape_property(finding['file'])},line={max(finding['line'], 1)}," + properties
    return f"::{level} {properties}::{_escape_data(finding['message'])}"


def _table_cell(text: Any) -> str:
    return re.sub(r"([\\`*_{}\[\]<>|!])", r"\\\1", str(text))


def summary_markdown(findings: List[Dict[str, Any]]) -> str:
    blocking = sum(1 for item in findings if item["mode"] == "block")
    lines = [f"## Tamper check: {len(findings)} finding(s), {blocking} blocking", ""]
    if findings:
        lines += ["| Rule | Mode | File | Line | Message |", "| --- | --- | --- | --- | --- |"]
        for item in findings:
            cells = (item["rule"], item["mode"], item["file"], item["line"], item["message"])
            lines.append("| " + " | ".join(_table_cell(cell) for cell in cells) + " |")
    return "\n".join(lines) + "\n"


DiffError = diffparse.DiffError
