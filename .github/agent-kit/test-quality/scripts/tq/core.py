"""Findings, exit codes, subprocess and config helpers shared by every gate."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import traceback
from pathlib import Path

EXIT_OK, EXIT_BLOCK, EXIT_ERROR = 0, 1, 2
GATE = "test-quality"
HARNESS_ROOT = Path(__file__).resolve().parents[2]


class ToolError(Exception):
    """The gate could not reach a verdict. Never counts as a pass."""


def finding(rule, mode, file="", line=0, message="", severity=None):
    if mode not in ("warn", "block"):
        raise ValueError("mode must be warn or block")
    return {
        "gate": GATE,
        "rule": rule,
        "severity": severity or ("high" if mode == "block" else "medium"),
        "mode": mode,
        "file": file,
        "line": line,
        "message": message,
    }


def mode_for(agent_pr):
    """Agent PRs block; human PRs warn until teams agree to block."""
    return "block" if agent_pr else "warn"


def load_config(path=None):
    cfg_path = Path(path) if path else HARNESS_ROOT / "config" / "test-quality.json"
    try:
        return json.loads(cfg_path.read_text())
    except (OSError, ValueError) as exc:
        raise ToolError("cannot read config %s: %s" % (cfg_path, exc))


def run(cmd, cwd=None, env=None, timeout=1800, stdin_bytes=None):
    """Run a command and return CompletedProcess. Missing binaries and timeouts are tool errors."""
    try:
        return subprocess.run(
            [str(c) for c in cmd], cwd=str(cwd) if cwd else None, env=env, timeout=timeout,
            input=stdin_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        raise ToolError("command not found: %s (%s)" % (cmd[0], exc))
    except subprocess.TimeoutExpired:
        raise ToolError("timed out after %ss: %s" % (timeout, " ".join(str(c) for c in cmd[:6])))


def text(data):
    return (data or b"").decode("utf-8", "replace")


def parse_bool(value):
    lowered = str(value).strip().lower()
    if lowered in ("true", "1", "yes"):
        return True
    if lowered in ("false", "0", "no"):
        return False
    raise ToolError("expected true or false, got %r" % (value,))


def common_parser(description):
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--repo", required=True, help="git checkout holding the PR head commit")
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--agent-pr", required=True, help="true or false, from pr_context.py")
    parser.add_argument("--owner-approved", default="false", help="true only from pr_context.py")
    parser.add_argument("--out", required=True, help="findings JSON path; keep outside the PR tree")
    parser.add_argument("--config", default=None)
    parser.add_argument("--python", default=sys.executable, help="interpreter holding pytest")
    parser.add_argument("--jest-bin", default=None, help="harness-pinned jest.js")
    return parser


def write_findings(path, findings):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(findings, indent=2) + "\n")


def gate_main(parser, body):
    """Run body(args) -> findings and turn the outcome into the shared exit contract."""
    args = parser.parse_args()
    try:
        findings = body(args)
        code = EXIT_BLOCK if any(f["mode"] == "block" for f in findings) else EXIT_OK
    except ToolError as exc:
        findings, code = [finding("tool-error", "block", message=str(exc), severity="critical")], EXIT_ERROR
        print("TOOL ERROR: %s" % exc, file=sys.stderr)
    except Exception as exc:  # any crash must be a tool error, never a silent pass
        traceback.print_exc()
        findings, code = [finding("tool-error", "block", message=repr(exc), severity="critical")], EXIT_ERROR
    try:
        write_findings(args.out, findings)
    except OSError as exc:
        print("cannot write findings: %s" % exc, file=sys.stderr)
        code = EXIT_ERROR
    for item in findings:
        where = "%s:%s" % (item["file"], item["line"]) if item["file"] else "-"
        print("[%s] %s %s %s" % (item["mode"], item["rule"], where, item["message"]))
    print("exit=%d findings=%d blocking=%d" % (code, len(findings), sum(f["mode"] == "block" for f in findings)))
    sys.exit(code)


def isolated_env(tmp, seed=None):
    """A minimal environment: no inherited tokens, fresh HOME and TMPDIR."""
    home, tmpdir = Path(tmp) / "home", Path(tmp) / "tmp"
    home.mkdir(parents=True, exist_ok=True)
    tmpdir.mkdir(parents=True, exist_ok=True)
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(home), "TMPDIR": str(tmpdir), "TEMP": str(tmpdir), "TMP": str(tmpdir),
        "CI": "true", "LANG": os.environ.get("LANG", "C.UTF-8"),
    }
    if seed is not None:
        env["PYTHONHASHSEED"] = str(seed % 4294967295)
    return env
