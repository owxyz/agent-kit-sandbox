"""Structured failure signals for P3.1, built without any model involvement.

Sources, most to least trustworthy:
- webhook and Jobs API fields (job, step, conclusions)
- tool: matched only against the step and job names, never against log text
- exit code: the runner's log line, which the API does not expose (see logs.py)

Step and job names come from the workflow file. A PR that edits a workflow can
change them, so P3.1 must apply the gate-violation row first.
"""
from __future__ import annotations

import re
from typing import Any, Dict, FrozenSet, List, Optional, Tuple

from . import logs

SCHEMA_VERSION = 1
FAILED = frozenset({"failure", "timed_out"})
# Ordered: the first match wins, so specific names come before generic runners.
TOOLS: Tuple[Tuple[str, str], ...] = (
    ("pytest", r"pytest|py\.test"), ("unittest", r"unittest"), ("jest", r"jest"), ("vitest", r"vitest"),
    ("mocha", r"mocha"), ("playwright", r"playwright"), ("cypress", r"cypress"),
    ("eslint", r"eslint"), ("prettier", r"prettier"), ("ruff", r"ruff"), ("flake8", r"flake8"),
    ("black", r"(?-i:black)"), ("mypy", r"mypy"), ("pyright", r"pyright"), ("tsc", r"tsc"),
    ("codeql", r"codeql"), ("semgrep", r"semgrep"), ("trivy", r"trivy"),
    ("go-test", r"go\s+test"), ("go-build", r"go\s+build"), ("golangci-lint", r"golangci-lint"),
    ("cargo", r"cargo"), ("maven", r"mvn|maven"), ("gradle", r"gradle"), ("bazel", r"bazel"), ("make", r"(?-i:make)"),
    ("docker", r"docker"), ("terraform", r"terraform"),
    ("npm", r"npm"), ("yarn", r"yarn"), ("pnpm", r"pnpm"), ("pip", r"pip3?"), ("poetry", r"poetry"),
)
_COMPILED = tuple((name, re.compile(r"(?<![\w-])(?:" + pat + r")(?![\w-])", re.I)) for name, pat in TOOLS)


def tool_from_names(step_name: str, job_name: str) -> str:
    for text in (step_name or "", job_name or ""):
        for tool, pattern in _COMPILED:
            if pattern.search(text):
                return tool
    return "unknown"


def failing_step(job: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    steps = [s for s in job.get("steps") or [] if s.get("conclusion") in FAILED]
    return steps[0] if steps else None


def job_signal(job: Dict[str, Any], raw_log: Optional[str]) -> Dict[str, Any]:
    step = failing_step(job)
    code = logs.ExitCode(None, False)
    if step and raw_log is not None:
        code = logs.exit_code(raw_log, step.get("started_at"), step.get("completed_at"))
    return {
        "job_id": job.get("id"),
        "job_name": job.get("name"),
        "conclusion": job.get("conclusion"),
        "failing_step": {"number": step.get("number"), "name": step.get("name"), "conclusion": step.get("conclusion")} if step else None,
        "tool": tool_from_names(step.get("name", "") if step else "", job.get("name", "")),
        "exit_code": code.value,
        "exit_code_source": "runner-log-line" if code.value is not None else None,
        "exit_code_conflict": code.conflict,
        "log_available": raw_log is not None,
    }


def run_signals(repo: str, run: Dict[str, Any], jobs: List[Dict[str, Any]], agent_logins: FrozenSet[str]) -> Dict[str, Any]:
    actor = (run.get("actor") or {}).get("login", "")
    return {
        "schema_version": SCHEMA_VERSION,
        "source": "structured",
        "repo": repo,
        "run_id": run.get("id"),
        "run_attempt": run.get("run_attempt", 1),
        "workflow_name": run.get("name"),
        "workflow_path": run.get("path"),
        "event": run.get("event"),
        "head_sha": run.get("head_sha"),
        "head_branch": run.get("head_branch"),
        "pr_numbers": sorted(p.get("number") for p in run.get("pull_requests") or []),
        "actor_kind": "agent" if actor in agent_logins else "human",
        "run_conclusion": run.get("conclusion"),
        "failed_jobs": jobs,
    }
