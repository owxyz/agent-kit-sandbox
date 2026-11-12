#!/usr/bin/env python3
"""Lint workflows for ways to fake or dodge a required check (P2.9).

Usage: lint_check_integrity.py PATH [PATH ...] [--ruleset FILE ...] [--config FILE]
                               [--org-settings FILE] [--output FILE]

Without --ruleset or --config every job counts as required, the strict reading.
--config is config/required-checks.json: it adds INT007 and reviewed exceptions.
--org-settings takes the saved response of
GET /orgs/{org}/actions/permissions/workflow.

Rules (block unless marked):
  INT001  continue-on-error on a required job, or on one of its steps
  INT002  a job that runs PR or agent code holds checks or statuses write
  INT003  the default workflow token is not read-only
  INT004  two jobs report the same required check name
  INT007  a job can write commit statuses without being a listed writer, or on an
          event whose YAML a PR can change
  INT005  (warn) a required job can end skipped, which GitHub counts as passing
  INT006  (warn) no scanned job reports a required check
  CACHE001  a job that runs agent code or on a base-scoped event writes the cache
  CACHE002  a job runs PR code on an event that holds the base branch's cache scope
  CACHE003  (warn) a PR job saves a cache; it reaches only the PR's own scope
  CACHE004  (warn) an agent job runs in a scope that can reach main's cache
"""
import argparse
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
for candidate in ("../../../kit/scripts", "../../scripts"):
    path = os.path.normpath(os.path.join(HERE, candidate))
    if os.path.isfile(os.path.join(path, "workflow_utils.py")):
        sys.path.insert(1, path)
        break

from common import ToolError, emit, finding, load_check_config, load_json, load_required_checks, run  # noqa: E402

try:
    import yaml
    from lint_agent_workflows import (
        AGENT_ACTION, AGENT_COMMAND, PR_FETCH_COMMAND, checkout_is_pr_code, is_checkout,
    )
    from workflow_utils import as_list, find_yaml_files, jobs, load_yaml, triggers
except ImportError as error:
    print("tool error: %s (kit/scripts and PyYAML are required)" % error, file=sys.stderr)
    sys.exit(2)

BASE_SCOPED_EVENTS = {
    "pull_request_target", "workflow_run", "issue_comment", "issues",
    "discussion", "discussion_comment",
}
PR_SCOPED_EVENTS = {"pull_request", "merge_group"}
MAIN_SCOPED_EVENTS = {"workflow_dispatch", "schedule", "push", "repository_dispatch"}
# Almost any event can report a check on a commit, including a dispatch from a PR branch.
NON_REPORTING_EVENTS = {"schedule", "workflow_call"}
# GitHub reads these events' YAML from a branch the PR can change.
PR_CONTROLLED_YAML_EVENTS = {
    "pull_request", "pull_request_review", "pull_request_review_comment", "push", "workflow_dispatch",
}
TOKEN_WRITE_SCOPES = ("checks", "statuses")
CACHE_INPUT_ACTIONS = re.compile(r"^actions/setup-(node|python|java|dotnet)@", re.I)
SKIP_PROOF_IF = re.compile(r"^\s*(\$\{\{)?\s*(always\(\)|!\s*cancelled\(\))\s*(\}\})?\s*$")


class Workflow:
    def __init__(self, path):
        self.path = path
        self.data = load_yaml(path)
        if not isinstance(self.data, dict):
            raise ToolError("%s is not a workflow mapping" % path)
        with open(path, encoding="utf-8") as handle:
            self.root = yaml.compose(handle.read())
        self.events = triggers(self.data)
        self.reusable_only = self.events == {"workflow_call"}

    def line(self, *keys):
        """Best-effort source line for a key path; 1 if nothing matched."""
        node, best = self.root, 1
        for key in keys:
            if isinstance(node, yaml.MappingNode):
                for key_node, value_node in node.value:
                    if key_node.value == str(key):
                        best, node = key_node.start_mark.line + 1, value_node
                        break
                else:
                    return best
            elif isinstance(node, yaml.SequenceNode) and isinstance(key, int) and key < len(node.value):
                node = node.value[key]
                best = node.start_mark.line + 1
            else:
                return best
        return best

    def jobs(self):
        return [(k, v) for k, v in jobs(self.data).items() if isinstance(v, dict)]


def raw_steps(job):
    value = job.get("steps")
    return [(i, s) for i, s in enumerate(value) if isinstance(s, dict)] if isinstance(value, list) else []


def is_on(value):
    """continue-on-error is off only when it is literally false."""
    return value is not False and str(value).strip().lower() != "false"


def writes_status(permissions):
    if permissions == "write-all":
        return True
    return isinstance(permissions, dict) and any(permissions.get(s) == "write" for s in TOKEN_WRITE_SCOPES)


def has_any_write(permissions):
    if permissions == "write-all":
        return True
    return isinstance(permissions, dict) and "write" in permissions.values()


def uses(step):
    return str(step.get("uses", ""))


def step_with(step):
    value = step.get("with")
    return value if isinstance(value, dict) else {}


def runs_agent(job):
    for _, step in raw_steps(job):
        if AGENT_ACTION.match(uses(step)) or AGENT_COMMAND.search(str(step.get("run", ""))):
            return True
    return False


def runs_pr_code(job, events):
    for _, step in raw_steps(job):
        if is_checkout(step) and checkout_is_pr_code(step, events):
            return True
        if PR_FETCH_COMMAND.search(str(step.get("run", ""))):
            return True
        if "workflow_run" in events and uses(step).lower().startswith("actions/download-artifact@"):
            return True
    return False


def cache_write(step):
    """Return a description when the step can save to the Actions cache."""
    action = uses(step).lower()
    options = step_with(step)
    if action.startswith("actions/cache/save@"):
        return "actions/cache/save"
    if action.startswith("actions/cache@") and not is_true(options.get("lookup-only")):
        return "actions/cache"
    if CACHE_INPUT_ACTIONS.match(action) and options.get("cache") and is_on(options.get("cache")):
        return action.split("@")[0] + " with cache"
    if action.startswith("actions/setup-go@") and is_on(options.get("cache", True)):
        return "actions/setup-go, which caches by default"
    if action.startswith("ruby/setup-ruby@") and is_true(options.get("bundler-cache")):
        return "ruby/setup-ruby with bundler-cache"
    if action.startswith("gradle/actions/setup-gradle@") and not is_true(options.get("cache-read-only")):
        return "gradle/actions/setup-gradle without cache-read-only"
    if "type=gh" in str(options.get("cache-to", "")):
        return "docker cache-to type=gh"
    return None


def is_true(value):
    return value is True or str(value).strip().lower() == "true"


def display_name(job_id, job):
    return str(job.get("name") or job_id)


def matrix_values(job):
    """Return the names a matrix can produce, or None when that can't be known."""
    strategy = job.get("strategy")
    matrix = strategy.get("matrix") if isinstance(strategy, dict) else None
    if not isinstance(matrix, dict):
        return None
    found = set()
    for key, values in matrix.items():
        if key == "exclude":
            continue
        if not isinstance(values, list):
            return None  # computed at run time
        for value in values:
            found.update(str(v) for v in value.values()) if isinstance(value, dict) else found.add(str(value))
    return None if any("${{" in v for v in found) else found


def reports_context(job_id, job, context):
    display = display_name(job_id, job)
    parts = re.split(r"\$\{\{.*?\}\}", display)
    if len(parts) > 1 and not "".join(parts).strip():
        # The whole name is an expression. A matrix says what it can be; without
        # one it could be anything, including a required check's name.
        values = matrix_values(job)
        return context in values if values is not None else True
    pattern = ".+".join(re.escape(p) for p in parts)
    if re.fullmatch(pattern, context):
        return True
    if job.get("strategy") and re.fullmatch(pattern + r" \(.+\)", context):
        return True
    return bool(job.get("uses")) and bool(re.fullmatch(pattern + r" / .+", context))


class Scan:
    def __init__(self, paths, required, config=None):
        self.config = config
        # Checks posted by a step, not named after a job. Their workflow counts as required.
        self.status_workflows = {
            s["workflow"] for s in config["required"].values() if s.get("workflow")
        } if config else set()
        files = find_yaml_files(paths)
        if not files:
            raise ToolError("no workflow files found in %s" % ", ".join(paths))
        self.workflows = [Workflow(p) for p in files]
        self.by_name = {os.path.basename(w.path): w for w in self.workflows}
        self.required_contexts = required
        self.inherited_permissions = {}
        self.inherited_events = {}
        self.link_reusable_calls()
        self.required_jobs = self.find_required_jobs()

    def callee(self, job):
        target = str(job.get("uses", ""))
        return self.by_name.get(os.path.basename(target)) if target.startswith("./") else None

    def permissions(self, workflow, job):
        if "permissions" in job:
            return job["permissions"]
        if "permissions" in workflow.data:
            return workflow.data["permissions"]
        return self.inherited_permissions.get(workflow.path)

    def events(self, workflow):
        return workflow.events | self.inherited_events.get(workflow.path, set())

    def link_reusable_calls(self):
        """Pass caller events and permissions down, to a fixed point for nesting."""
        for _ in self.workflows:
            for workflow in self.workflows:
                for _, job in workflow.jobs():
                    callee = self.callee(job)
                    if callee is None:
                        continue
                    self.inherited_events.setdefault(callee.path, set()).update(self.events(workflow))
                    granted = self.permissions(workflow, job)
                    if writes_status(granted) or callee.path not in self.inherited_permissions:
                        self.inherited_permissions[callee.path] = granted

    def find_required_jobs(self):
        required = set()
        for workflow in self.workflows:
            for job_id, job in workflow.jobs():
                if self.required_contexts is None or os.path.basename(workflow.path) in self.status_workflows or (
                    not workflow.reusable_only
                    and any(reports_context(job_id, job, c) for c in self.required_contexts)
                ):
                    required.add((workflow.path, job_id))
        changed = True
        while changed:
            changed = False
            for workflow in self.workflows:
                table = dict(workflow.jobs())
                for job_id, job in workflow.jobs():
                    if (workflow.path, job_id) not in required:
                        continue
                    linked = [(workflow.path, n) for n in as_list(job.get("needs")) if n in table]
                    callee = self.callee(job)
                    if callee is not None:
                        linked += [(callee.path, n) for n, _ in callee.jobs()]
                    for item in linked:
                        if item not in required:
                            required.add(item)
                            changed = True
        return required


def check_continue_on_error(scan):
    found = []
    for wf in scan.workflows:
        for job_id, job in wf.jobs():
            if (wf.path, job_id) not in scan.required_jobs:
                continue
            if "continue-on-error" in job and is_on(job["continue-on-error"]):
                found.append(finding(
                    "INT001", "block", wf.path, wf.line("jobs", job_id, "continue-on-error"),
                    "Required job '%s' sets continue-on-error, so a failure can still report success." % job_id,
                ))
            for index, step in raw_steps(job):
                if "continue-on-error" in step and is_on(step["continue-on-error"]):
                    found.append(finding(
                        "INT001", "block", wf.path,
                        wf.line("jobs", job_id, "steps", index, "continue-on-error"),
                        "Step %d of required job '%s' sets continue-on-error." % (index + 1, job_id),
                    ))
    return found


def check_status_permission(scan):
    found = []
    for wf in scan.workflows:
        events = scan.events(wf)
        for job_id, job in wf.jobs():
            if not writes_status(scan.permissions(wf, job)):
                continue
            remote = bool(job.get("uses")) and scan.callee(job) is None
            if remote or runs_agent(job) or runs_pr_code(job, events):
                what = "calls a reusable workflow that cannot be inspected" if remote else "runs PR or agent code"
                found.append(finding(
                    "INT002", "block", wf.path, wf.line("jobs", job_id),
                    "Job '%s' %s and its token can write checks or statuses, so it could post a fake "
                    "pass under a required check's name." % (job_id, what),
                ))
    return found


def check_default_token(scan, org_settings, org_path):
    found = []
    if org_settings is not None:
        if not isinstance(org_settings, dict) or "default_workflow_permissions" not in org_settings:
            raise ToolError("%s is not an Actions workflow-permissions response" % org_path)
        if org_settings["default_workflow_permissions"] != "read":
            found.append(finding(
                "INT003", "block", org_path, 0,
                "The organization's default workflow token is '%s', not read." %
                org_settings["default_workflow_permissions"],
            ))
    for wf in scan.workflows:
        if wf.reusable_only:
            continue
        declared = wf.data.get("permissions")
        if "permissions" in wf.data and has_any_write(declared):
            found.append(finding(
                "INT003", "block", wf.path, wf.line("permissions"),
                "The workflow's default token is not read-only. Grant writes per job instead.",
            ))
        if "permissions" not in wf.data:
            bare = [job_id for job_id, job in wf.jobs() if "permissions" not in job]
            if bare:
                found.append(finding(
                    "INT003", "block", wf.path, 1,
                    "No top-level permissions, so job(s) %s fall back to the repo default token. "
                    "Add 'permissions: {}' or a read-only block." % ", ".join(bare),
                ))
    return found


def check_required_names(scan):
    found = []
    if scan.required_contexts is None:
        return found
    for context in sorted(scan.required_contexts):
        reporters = [
            (wf, job_id) for wf in scan.workflows if not wf.reusable_only and wf.events - NON_REPORTING_EVENTS
            for job_id, job in wf.jobs() if reports_context(job_id, job, context)
        ]
        if len(reporters) > 1:
            names = ", ".join("%s:%s" % (os.path.basename(w.path), j) for w, j in reporters)
            for wf, job_id in reporters:
                found.append(finding(
                    "INT004", "block", wf.path, wf.line("jobs", job_id),
                    "Required check '%s' is reported by more than one job (%s). All Actions jobs share "
                    "one app, so the pin cannot tell them apart." % (context, names),
                ))
        if not reporters:
            found.append(finding(
                "INT006", "warn", "", 0, "No scanned job reports required check '%s'." % context,
            ))
        for wf, job_id in reporters:
            job = dict(wf.jobs())[job_id]
            condition = job.get("if")
            if condition is not None and not SKIP_PROOF_IF.match(str(condition)):
                found.append(finding(
                    "INT005", "warn", wf.path, wf.line("jobs", job_id, "if"),
                    "Required job '%s' has an if: condition and can end skipped." % job_id,
                ))
    return found


def check_status_writers(scan):
    found = []
    if scan.config is None:
        return found
    scanned = {os.path.basename(wf.path) for wf in scan.workflows}
    for missing in sorted(scan.status_workflows - scanned):
        found.append(finding("INT006", "warn", "", 0, "Status workflow '%s' was not scanned." % missing))
    for wf in scan.workflows:
        for job_id, job in wf.jobs():
            permissions = scan.permissions(wf, job)
            can_write = permissions == "write-all" or (
                isinstance(permissions, dict) and permissions.get("statuses") == "write")
            if not can_write:
                continue
            controlled = sorted(scan.events(wf) & PR_CONTROLLED_YAML_EVENTS)
            if controlled:
                found.append(finding(
                    "INT007", "block", wf.path, wf.line("jobs", job_id),
                    "Job '%s' can write commit statuses on %s, where a PR controls the YAML, so being a "
                    "listed writer does not make it safe." % (job_id, controlled[0]),
                ))
            elif (os.path.basename(wf.path), job_id) not in scan.config["status_writers"]:
                found.append(finding(
                    "INT007", "block", wf.path, wf.line("jobs", job_id),
                    "Job '%s' can write commit statuses but is not a listed status writer, so it could "
                    "post a required status." % job_id,
                ))
    return found


def excepted(scan, rule, wf, job_id):
    return scan.config is not None and (rule, os.path.basename(wf.path), job_id) in scan.config["exceptions"]


def check_cache(scan):
    found = []
    for wf in scan.workflows:
        events = scan.events(wf)
        base_scoped = sorted(events & BASE_SCOPED_EVENTS)
        for job_id, job in wf.jobs():
            agent = runs_agent(job)
            if base_scoped and runs_pr_code(job, events):
                reviewed = excepted(scan, "CACHE002", wf, job_id)
                found.append(finding(
                    "CACHE002", "warn" if reviewed else "block", wf.path, wf.line("jobs", job_id),
                    "Job '%s' runs PR code on %s, which can write the base branch's cache even with "
                    "a read-only token.%s" % (job_id, base_scoped[0], " Reviewed exception." if reviewed else ""),
                ))
            if agent and events & MAIN_SCOPED_EVENTS:
                found.append(finding(
                    "CACHE004", "warn", wf.path, wf.line("jobs", job_id),
                    "Agent job '%s' runs in a scope that can reach main's cache; see the README's "
                    "known limits." % job_id,
                ))
            for index, step in raw_steps(job):
                write = cache_write(step)
                if not write:
                    continue
                line = wf.line("jobs", job_id, "steps", index)
                if agent or base_scoped:
                    why = "runs agent code" if agent else "runs on %s" % base_scoped[0]
                    found.append(finding(
                        "CACHE001", "block", wf.path, line,
                        "Job '%s' %s and saves to the cache through %s. Use actions/cache/restore." %
                        (job_id, why, write),
                    ))
                elif events & PR_SCOPED_EVENTS:
                    found.append(finding(
                        "CACHE003", "warn", wf.path, line,
                        "Job '%s' saves a cache on a PR event through %s. It reaches only the PR's scope; "
                        "prefer actions/cache/restore." % (job_id, write),
                    ))
    return found


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("paths", nargs="+")
    parser.add_argument("--ruleset", action="append", default=[])
    parser.add_argument("--config")
    parser.add_argument("--org-settings")
    parser.add_argument("--output")
    args = parser.parse_args()
    required = load_required_checks(args.ruleset) if args.ruleset else None
    config = load_check_config(args.config) if args.config else None
    if config:
        pinned = {c: s["integration_id"] for c, s in config["required"].items()}
        conflicts = sorted(c for c, app in (required or {}).items() if pinned.get(c) != app)
        if conflicts:
            raise ToolError("ruleset and config disagree on %s" % ", ".join(conflicts))
        # Checks posted by a job step are not named after a job.
        reported = {c: s["integration_id"] for c, s in config["required"].items() if not s.get("workflow")}
        required = dict(reported)
    org = load_json(args.org_settings) if args.org_settings else None
    scan = Scan(args.paths, required, config)
    findings = (
        check_continue_on_error(scan) + check_status_permission(scan)
        + check_default_token(scan, org, args.org_settings) + check_required_names(scan) + check_status_writers(scan) + check_cache(scan)
    )
    return emit(findings, args.output)


if __name__ == "__main__":
    run(main)
