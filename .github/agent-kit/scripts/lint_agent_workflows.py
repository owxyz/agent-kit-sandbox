#!/usr/bin/env python3
"""Find workflow patterns that let PR code near secrets or agent config.

Usage: lint_agent_workflows.py PATH [PATH ...]    (exit 1 on any violation)

Rules:
  PRT001   a pull_request_target job checks out or fetches PR code
  SEC001   a job that has secrets checks out or fetches PR code
  CRED001  a PR checkout does not set persist-credentials: false
  CFG001   an agent job checks out anything but an explicit base ref
  GATE001  an agent job does not depend on the agent pre-flight
  CONC001  an agent job does not hold the one-agent-per-repo group
"""
import json
import re
import sys

from workflow_utils import as_list, find_yaml_files, jobs, load_yaml, steps, triggers

PR_REF = re.compile(
    r"pull_request\.head\.|github\.head_ref|refs/pull/|pull_request\.merge_commit_sha"
    r"|workflow_run\.head_|github\.event\.number|pull_request\.number|issue\.number",
    re.I,
)
# Values computed at run time cannot be proven to be base refs.
OPAQUE_REF = re.compile(r"\b(steps|needs|inputs)\.|github\.event\.client_payload", re.I)
BASE_REF = re.compile(
    r"github\.event\.repository\.default_branch|github\.base_ref"
    r"|pull_request\.base\.(sha|ref)|merge_group\.base_sha",
    re.I,
)
LITERAL_BASE = {"main", "master", "refs/heads/main", "refs/heads/master"}
PR_FETCH_COMMAND = re.compile(
    r"gh\s+pr\s+checkout|git\s+fetch\b.*\bpull/|refs/pull/"
    r"|git\s+(checkout|switch|fetch|pull)\b.*(github\.head_ref|GITHUB_HEAD_REF|pull_request\.head\.)",
    re.I,
)
SECRET_USE = re.compile(r"secrets\.(?!GITHUB_TOKEN\b)\w+|secrets\[|toJSON\(secrets\)", re.I)
AGENT_ACTION = re.compile(
    r"^(anthropics/claude-code|openai/codex|google-github-actions/run-gemini|cursor/)", re.I
)
AGENT_COMMAND = re.compile(
    r"(^|[\s;&|(])(claude|codex|aider|gemini|copilot|cursor-agent)\s+[-\w\"'$]"
    r"|@anthropic-ai/claude-code|@openai/codex|@google/gemini-cli|@github/copilot",
    re.M,
)
IMPLICIT_PR_EVENTS = {"pull_request", "merge_group"}
UNTRUSTED_EVENTS = {"pull_request", "pull_request_target", "issue_comment", "workflow_run"}
PREFLIGHT = "agent-preflight.yml"


def is_checkout(step):
    return str(step.get("uses", "")).lower().startswith("actions/checkout@")


def step_with(step):
    value = step.get("with")
    return value if isinstance(value, dict) else {}


def checkout_is_pr_code(step, events):
    options = step_with(step)
    ref = str(options.get("ref") or "")
    repository = str(options.get("repository") or "")
    if PR_REF.search(ref) or PR_REF.search(repository):
        return True
    if ref:
        return bool(OPAQUE_REF.search(ref) and events & UNTRUSTED_EVENTS)
    return bool(events & IMPLICIT_PR_EVENTS)


def checkout_is_explicit_base(step):
    ref = str(step_with(step).get("ref") or "").strip()
    return bool(ref) and not PR_REF.search(ref) and (bool(BASE_REF.search(ref)) or ref in LITERAL_BASE)


def job_has_secrets(job, workflow):
    env = workflow.get("env") or {}
    text = json.dumps([job, env], default=str)
    return bool(SECRET_USE.search(text)) or job.get("secrets") == "inherit"


def preflight_job_ids(workflow):
    return {
        name for name, job in jobs(workflow).items()
        if isinstance(job, dict) and PREFLIGHT in str(job.get("uses", ""))
    }


def depends_on(job_id, targets, workflow, seen=None):
    seen = seen or set()
    job = jobs(workflow).get(job_id)
    if job_id in seen or not isinstance(job, dict):
        return False
    seen.add(job_id)
    for parent in as_list(job.get("needs")):
        if parent in targets or depends_on(parent, targets, workflow, seen):
            return True
    return False


def is_agent_job(job_id, job, workflow, gates):
    if job_id in gates:
        return False
    if depends_on(job_id, gates, workflow):
        return True
    for step in steps(job):
        if AGENT_ACTION.search(str(step.get("uses", ""))):
            return True
        if AGENT_COMMAND.search(str(step.get("run", ""))):
            return True
    return False


def valid_concurrency(job):
    value = job.get("concurrency")
    group = value.get("group") if isinstance(value, dict) else value
    group = str(group or "")
    if "outputs.concurrency-group" in group:
        return True
    # A literal group is per repo only if nothing run- or PR-specific is in it.
    return "github.repository" in group and not re.search(
        r"github\.(run_id|run_number|sha|ref|head_ref|event)", group
    )


def lint_job(path, job_id, job, workflow, events, gates):
    found = []

    def add(code, message):
        found.append("%s: job %s: %s: %s" % (path, job_id, code, message))

    has_secrets = job_has_secrets(job, workflow)
    fetches_pr = False
    for step in steps(job):
        if is_checkout(step) and checkout_is_pr_code(step, events):
            fetches_pr = True
            if step_with(step).get("persist-credentials") is not False:
                add("CRED001", "PR checkout must set persist-credentials: false")
        if PR_FETCH_COMMAND.search(str(step.get("run", ""))):
            fetches_pr = True
    if fetches_pr and "pull_request_target" in events:
        add("PRT001", "pull_request_target job must not check out or fetch PR code")
    if fetches_pr and has_secrets:
        add("SEC001", "PR code must not be checked out while secrets are present")

    if is_agent_job(job_id, job, workflow, gates):
        for step in steps(job):
            if is_checkout(step) and not checkout_is_explicit_base(step):
                add("CFG001", "agent job must check out an explicit base-branch ref")
        if not depends_on(job_id, gates, workflow):
            add("GATE001", "agent job must need the %s job" % PREFLIGHT)
        if not valid_concurrency(job):
            add("CONC001", "agent job must use the pre-flight concurrency group")
    return found


def lint_file(path):
    try:
        workflow = load_yaml(path)
    except Exception as error:
        return ["%s: PARSE: %s" % (path, type(error).__name__)]
    if not isinstance(workflow, dict) or not jobs(workflow):
        return []
    events = triggers(workflow)
    gates = preflight_job_ids(workflow)
    found = []
    for job_id, job in jobs(workflow).items():
        if isinstance(job, dict):
            found.extend(lint_job(path, job_id, job, workflow, events, gates))
    return found


def main(argv):
    files = find_yaml_files(argv)
    if not files:
        print("No workflow files found.", file=sys.stderr)
        return 1
    violations = [item for path in files for item in lint_file(path)]
    for violation in violations:
        print(violation)
    print("%d file(s) checked, %d violation(s)." % (len(files), len(violations)))
    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
