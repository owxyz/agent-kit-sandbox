#!/usr/bin/env python3
"""Offline inventory of coding-agent workflows (ticket P0.1).

Scans a directory of checked-out repositories and reports each agent workflow,
its triggers, its token permissions and every secret it references. It makes
no network calls. It reports secret names only: secret values never appear in
workflow files, and literal values such as env entries are never echoed.

Usage: python3 scan_workflows.py REPOS_DIR [--format text|json] [--output FILE]
           [--all] [--agent-pattern REGEX] [--fail-on SEVERITY]
           [--credentials-seed FILE]
"""
import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone

import yamlite

SEVERITIES = ["critical", "high", "medium", "low"]

AGENT_ACTIONS = [
    (r"^anthropics/claude-code(-base)?-action\b", "claude-code"),
    (r"^openai/codex-action\b", "codex"),
    (r"^google-github-actions/run-gemini-cli\b", "gemini-cli"),
    (r"^actions/ai-inference\b", "github-models"),
    (r"^(paul-gauthier|aider-ai)/aider", "aider"),
    (r"^coderabbitai/", "coderabbit"),
    (r"^qodo-ai/pr-agent\b|^codium-ai/pr-agent\b", "pr-agent"),
]
AGENT_COMMANDS = [
    (r"@anthropic-ai/claude-code\b|(^|[\s;&|(])claude\s+(-p\b|--print\b|code\b)", "claude-code"),
    (r"@openai/codex\b|(^|[\s;&|(])codex\s+(exec|e)\b", "codex"),
    (r"@google/gemini-cli\b|(^|[\s;&|(])gemini\s+(-p\b|--prompt\b)", "gemini-cli"),
    (r"(^|[\s;&|(])aider\s+-", "aider"),
    (r"(^|[\s;&|(])cursor-agent\b", "cursor-agent"),
    (r"(^|[\s;&|(])opencode\s+run\b", "opencode"),
    (r"(^|[\s;&|(])goose\s+run\b", "goose"),
    (r"(^|[\s;&|(])gh\s+copilot\b|(^|[\s;&|(])copilot\s+-p\b", "copilot"),
]

_MODEL_KEY = re.compile(
    r"(ANTHROPIC|CLAUDE|OPENAI|GEMINI|GOOGLE_AI|MISTRAL|COHERE|OPENROUTER|DEEPSEEK|XAI|GROQ)"
    r"[A-Z0-9_]*(KEY|TOKEN)|(^|_)(LLM|MODEL|AGENT)_API_KEY$"
)
_APP_KEY = re.compile(r"APP_PRIVATE_KEY|PRIVATE_KEY_APP|^GH_APP_|^GITHUB_APP_|(^|_)APP_PEM$")
_DEPLOY_KEY = re.compile(r"DEPLOY_KEY|SSH_(PRIVATE_)?KEY")
_PAT = re.compile(
    r"(^|_)PAT($|_)|PERSONAL_ACCESS|^GH_TOKEN$|_GH_TOKEN$|_GITHUB_TOKEN$"
    r"|(^|_)(REPO|BOT|ORG|ADMIN)_TOKEN$"
)
_CLOUD_KEY = re.compile(r"^AWS_|^AZURE_|^GCP_|GOOGLE_APPLICATION_CREDENTIALS")

# A write on any of these lets a job publish, deploy, run workflows or satisfy
# a required check. The plan gives agents contents and pull requests at most,
# and no job that runs agent code gets the checks permission.
SENSITIVE_WRITE_SCOPES = {
    "actions", "attestations", "checks", "deployments", "id-token", "packages",
    "pages", "security-events", "statuses",
}

_EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}", re.S)
_SECRET_DOT = re.compile(r"(?<![\w.])secrets\.([A-Za-z_][A-Za-z0-9_]*)", re.I)
_SECRET_INDEX = re.compile(r"(?<![\w.])secrets\[\s*'([A-Za-z_][A-Za-z0-9_]*)'\s*\]", re.I)
_SECRET_DYNAMIC = re.compile(r"(?<![\w.])secrets\[\s*[^'\s]", re.I)
_SECRET_DUMP = re.compile(r"\btojson\(\s*secrets\s*\)", re.I)
_GITHUB_TOKEN = re.compile(r"(?<![\w.])github\.token\b", re.I)
_RAW_USES = re.compile(r"^\s*(?:-\s*)?uses:\s*['\"]?([^\s'\"#]+)", re.M)
_PR_HEAD = re.compile(r"github\.event\.pull_request\.head|github\.head_ref|refs/pull/", re.I)
_COMMENT_LINE = re.compile(r"^\s*#.*$", re.M)


def classify_secret(name):
    upper = name.upper()
    if upper == "GITHUB_TOKEN":
        return "github-automatic"
    if _MODEL_KEY.search(upper):
        return "model-api-key"
    if _APP_KEY.search(upper):
        return "github-app-private-key"
    if _DEPLOY_KEY.search(upper):
        return "deploy-key"
    if _PAT.search(upper):
        return "pat"
    if _CLOUD_KEY.search(upper):
        return "cloud-key"
    return "other"


class _Findings:
    """Secret references and expression-level problems found in a workflow."""

    def __init__(self):
        self.secrets = {}
        self.dynamic = set()
        self.dumps = set()

    def add_secret(self, name, where):
        self.secrets.setdefault(name.upper(), set()).add(where)

    def scan_expression(self, text, where):
        for name in _SECRET_DOT.findall(text) + _SECRET_INDEX.findall(text):
            self.add_secret(name, where)
        if _GITHUB_TOKEN.search(text):
            self.add_secret("GITHUB_TOKEN", where)
        if _SECRET_DYNAMIC.search(text):
            self.dynamic.add(where)
        if _SECRET_DUMP.search(text):
            self.dumps.add(where)

    def scan_string(self, text, where, implicit_expression=False):
        expressions = _EXPRESSION.findall(text)
        if implicit_expression and "${{" not in text:
            expressions = [text]
        for expression in expressions:
            self.scan_expression(expression, where)

    def walk(self, node, where, key=None):
        if isinstance(node, str):
            self.scan_string(node, where, key == "if")
        elif isinstance(node, dict):
            for child_key, child in node.items():
                self.walk(child, where, child_key)
        elif isinstance(node, list):
            for child in node:
                self.walk(child, where, key)


def _triggers(on_value):
    """Normalize `on:` into {event: details}."""
    if isinstance(on_value, str):
        return {on_value: None}
    if isinstance(on_value, list):
        return {str(event): None for event in on_value}
    if isinstance(on_value, dict):
        return dict(on_value)
    return {}


def _effective_permissions(job, workflow):
    if "permissions" in job:
        return job["permissions"], "job"
    if "permissions" in workflow:
        return workflow["permissions"], "workflow"
    return None, "default"


def _normalize_permissions(value):
    if isinstance(value, dict):
        return {str(k): str(v) for k, v in value.items()}
    if value is None:
        return {}
    return str(value)


def _match_agents(text, table, extra):
    labels = []
    for pattern, label in table:
        if re.search(pattern, text, re.I | re.M):
            labels.append(label)
    for pattern in extra:
        if pattern.search(text):
            labels.append("custom:" + pattern.pattern)
    return labels


def _read_text(path):
    """Read a regular file, refusing symlinks that could leave the repo."""
    if os.path.islink(path) or not os.path.isfile(path):
        return None
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def _local_action_labels(repo_path, uses, extra):
    relative = os.path.normpath(uses)
    if relative.startswith(".."):
        return []
    base = os.path.join(repo_path, relative)
    for name in ("action.yml", "action.yaml"):
        try:
            text = _read_text(os.path.join(base, name))
            document = yamlite.load(text) if text is not None else None
        except (OSError, UnicodeDecodeError, yamlite.YamlError):
            continue
        if not isinstance(document, dict):
            continue
        runs = document.get("runs")
        steps = runs.get("steps") if isinstance(runs, dict) else None
        labels = []
        for step in steps if isinstance(steps, list) else []:
            if isinstance(step, dict):
                labels += _step_labels(step, extra)
        return labels
    return []


def _step_labels(step, extra):
    labels = []
    if isinstance(step.get("uses"), str):
        labels += _match_agents(step["uses"], AGENT_ACTIONS, extra)
    if isinstance(step.get("run"), str):
        # A command in a full-line shell comment does not run.
        labels += _match_agents(_COMMENT_LINE.sub("", step["run"]), AGENT_COMMANDS, extra)
    return labels


def scan_workflow(repo_path, relative, extra_patterns):
    """Collect the raw facts for a workflow; flags are computed later."""
    record = {
        "path": relative, "name": None, "agents": set(), "triggers": {},
        "jobs": [], "findings": _Findings(), "parse_error": None,
        "local_calls": {}, "external_calls": {}, "inherit_jobs": set(),
        "head_checkout_jobs": set(), "callers": set(),
    }
    try:
        text = _read_text(os.path.join(repo_path, relative))
        if text is None:
            record["parse_error"] = "skipped: not a regular file"
            return record
    except (OSError, UnicodeDecodeError):
        record["parse_error"] = "file could not be read as UTF-8 text"
        return record
    try:
        document = yamlite.load(text)
        if not isinstance(document, dict):
            raise yamlite.YamlError(1, "workflow is not a mapping")
    except yamlite.YamlError as error:
        record["parse_error"] = str(error)
        _scan_unparsed(text, record, extra_patterns)
        return record

    record["name"] = document.get("name") if isinstance(document.get("name"), str) else None
    record["triggers"] = _triggers(document.get("on", document.get(True)))
    findings = record["findings"]
    for key, value in document.items():
        if key != "jobs":
            findings.walk(value, "(workflow)", key)

    call = record["triggers"].get("workflow_call")
    if isinstance(call, dict) and isinstance(call.get("secrets"), dict):
        for name in call["secrets"]:
            findings.add_secret(str(name), "(workflow_call input)")

    jobs = document.get("jobs")
    for job_id, job in (jobs.items() if isinstance(jobs, dict) else []):
        if not isinstance(job, dict):
            continue
        _scan_job(repo_path, str(job_id), job, document, record, extra_patterns)
    return record


def _scan_job(repo_path, job_id, job, document, record, extra_patterns):
    findings = record["findings"]
    findings.walk(job, job_id)
    permissions, source = _effective_permissions(job, document)
    record["jobs"].append({
        "id": job_id,
        "permissions": None if source == "default" else _normalize_permissions(permissions),
        "permissions_source": source,
    })
    if job.get("secrets") == "inherit":
        record["inherit_jobs"].add(job_id)
    uses = job.get("uses")
    if isinstance(uses, str):
        if uses.startswith("./"):
            record["local_calls"][os.path.normpath(uses)] = job_id
        else:
            record["external_calls"][uses] = job_id
    steps = job.get("steps")
    for step in steps if isinstance(steps, list) else []:
        if not isinstance(step, dict):
            continue
        record["agents"].update(_step_labels(step, extra_patterns))
        step_uses = step.get("uses")
        if isinstance(step_uses, str):
            if step_uses.startswith("./"):
                record["agents"].update(_local_action_labels(repo_path, step_uses, extra_patterns))
            if step_uses.lower().startswith("actions/checkout"):
                inputs = step.get("with") if isinstance(step.get("with"), dict) else {}
                checked_out = " ".join(str(inputs.get(k, "")) for k in ("ref", "repository"))
                if _PR_HEAD.search(checked_out):
                    record["head_checkout_jobs"].add(job_id)


def _scan_unparsed(text, record, extra_patterns):
    """Best effort for a file the parser rejected: secrets and agent signals."""
    uncommented = _COMMENT_LINE.sub("", text)
    record["findings"].scan_string(uncommented, "(unparsed file)")
    for uses in _RAW_USES.findall(uncommented):
        record["agents"].update(_match_agents(uses, AGENT_ACTIONS, extra_patterns))
    record["agents"].update(_match_agents(uncommented, AGENT_COMMANDS, extra_patterns))


def _propagate_calls(records):
    """Carry agent status up to callers and triggers down to called workflows."""
    by_path = {record["path"]: record for record in records}
    for record in records:
        for callee in record["local_calls"]:
            if callee in by_path:
                by_path[callee]["callers"].add(record["path"])
    for record in records:
        record["effective_triggers"] = set(record["triggers"])
    changed = True
    while changed:
        changed = False
        for record in records:
            for callee_path in record["local_calls"]:
                callee = by_path.get(callee_path)
                if callee is None:
                    continue
                new_labels = _agent_labels(callee)
                if not new_labels <= record["agents"]:
                    record["agents"] |= new_labels
                    changed = True
                missing = record["effective_triggers"] - callee["effective_triggers"]
                if missing:
                    callee["effective_triggers"] |= missing
                    changed = True


def _agent_labels(record):
    """Known agents, or a generic label when only a model API key gives it away."""
    if record["agents"]:
        return set(record["agents"])
    if any(classify_secret(name) == "model-api-key" for name in record["findings"].secrets):
        return {"unidentified-model-client"}
    return set()


def _flag(flags, code, severity, jobs, detail):
    flags.append({"code": code, "severity": severity, "jobs": sorted(jobs), "detail": detail})


def _permission_flags(record, flags):
    grouped = {}
    for job in record["jobs"]:
        permissions = job["permissions"]
        if job["permissions_source"] == "default":
            grouped.setdefault(("broad-token-undeclared", "high", ""), []).append(job["id"])
        elif permissions == "write-all":
            grouped.setdefault(("broad-token-write-all", "critical", ""), []).append(job["id"])
        elif isinstance(permissions, dict):
            for scope, level in sorted(permissions.items()):
                if level != "write":
                    continue
                if scope in SENSITIVE_WRITE_SCOPES:
                    grouped.setdefault(("broad-token-sensitive-scope", "high", scope), []).append(job["id"])
                elif scope == "contents":
                    grouped.setdefault(("broad-token-contents-write", "medium", scope), []).append(job["id"])
    details = {
        "broad-token-undeclared": "no permissions block, so the job gets the repo or org default token, which may be read-write",
        "broad-token-write-all": "permissions: write-all",
        "broad-token-sensitive-scope": "{}: write",
        "broad-token-contents-write": "{}: write on GITHUB_TOKEN reaches every unprotected branch; the plan uses a GitHub App limited by rulesets",
    }
    for (code, severity, scope), jobs in grouped.items():
        _flag(flags, code, severity, jobs, details[code].format(scope))


def _build_flags(record):
    flags = []
    if record["parse_error"]:
        _flag(flags, "parse-error", "high", [], "could not be fully parsed ({}); triggers and permissions are unknown".format(record["parse_error"]))
    _permission_flags(record, flags)
    if "pull_request_target" in record["effective_triggers"]:
        if record["head_checkout_jobs"]:
            _flag(flags, "pull-request-target", "critical", record["head_checkout_jobs"],
                  "pull_request_target job checks out PR code while base-repo secrets and token are available (banned by P0.4)")
        else:
            _flag(flags, "pull-request-target", "high", [],
                  "runs with base-repo secrets and token on events from forks and PR authors")
    findings = record["findings"]
    pats = sorted(name for name in findings.secrets if classify_secret(name) == "pat")
    for name in pats:
        _flag(flags, "pat-style-secret", "high", [w for w in findings.secrets[name] if not w.startswith("(")],
              "{} looks like a personal access token; P0.2 replaces these with GitHub App tokens".format(name))
    if record["inherit_jobs"]:
        _flag(flags, "secrets-inherit", "high", record["inherit_jobs"],
              "secrets: inherit gives the called workflow every secret the caller can read")
    if findings.dumps:
        _flag(flags, "all-secrets-exposed", "critical", [w for w in findings.dumps if not w.startswith("(")],
              "toJSON(secrets) exposes every secret to the job")
    if findings.dynamic:
        _flag(flags, "dynamic-secret-reference", "high", [w for w in findings.dynamic if not w.startswith("(")],
              "secret name is computed at run time, so this list may be incomplete")
    for uses, job_id in sorted(record["external_calls"].items()):
        _flag(flags, "external-reusable-workflow", "medium", [job_id],
              "calls a workflow outside this repo that this scan cannot see: {}".format(uses))
    flags.sort(key=lambda f: (SEVERITIES.index(f["severity"]), f["code"]))
    return flags


def _finish_record(record):
    findings = record["findings"]
    agents = _agent_labels(record)
    return {
        "path": record["path"],
        "name": record["name"],
        "is_agent": bool(agents),
        "agents": sorted(agents),
        "triggers": sorted(record["triggers"]) if not record["parse_error"] else ["unknown"],
        "effective_triggers": sorted(record["effective_triggers"]) if not record["parse_error"] else ["unknown"],
        "called_by": sorted(record["callers"]),
        "jobs": sorted(record["jobs"], key=lambda job: job["id"]),
        "secrets": [
            {"name": name, "category": classify_secret(name), "used_in": sorted(findings.secrets[name])}
            for name in sorted(findings.secrets)
        ],
        "flags": _build_flags(record),
        "parsed": record["parse_error"] is None,
    }


def discover_repos(root):
    """Return (name, path) pairs. `root` may itself be one repository."""
    if os.path.isdir(os.path.join(root, ".github", "workflows")):
        return [(os.path.basename(os.path.abspath(root)), root)]
    repos = []
    for name in sorted(os.listdir(root)):
        path = os.path.join(root, name)
        if os.path.isdir(path) and not os.path.islink(path):
            repos.append((name, path))
    return repos


def scan_repo(name, path, extra_patterns):
    directory = os.path.join(path, ".github", "workflows")
    records = []
    if os.path.isdir(directory):
        # GitHub ignores subdirectories of .github/workflows, so this does too.
        for entry in sorted(os.listdir(directory)):
            if entry.endswith((".yml", ".yaml")):
                relative = os.path.join(".github", "workflows", entry)
                records.append(scan_workflow(path, relative, extra_patterns))
    _propagate_calls(records)
    return {"repo": name, "workflows": [_finish_record(record) for record in records]}


def scan(root, extra_patterns=()):
    repos = [scan_repo(name, path, extra_patterns) for name, path in discover_repos(root)]
    return build_report(repos)


def build_report(repos):
    workflows = [w for repo in repos for w in repo["workflows"]]
    agents = [w for w in workflows if w["is_agent"]]
    counts = {severity: 0 for severity in SEVERITIES}
    for workflow in _reported(workflows):
        for flag in workflow["flags"]:
            counts[flag["severity"]] += 1
    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "summary": {
            "repos": len(repos),
            "workflows": len(workflows),
            "agent_workflows": len(agents),
            "unparsed_workflows": len([w for w in workflows if not w["parsed"]]),
            "flags_on_reported_workflows": counts,
        },
        "repos": repos,
        "credentials_to_inventory": credentials_to_inventory(repos),
    }


def _reported(workflows):
    """Agent workflows, plus any file that could not be ruled out."""
    return [w for w in workflows if w["is_agent"] or not w["parsed"]]


def credentials_to_inventory(repos):
    """Credentials on agent workflows that need an owner in the manual inventory."""
    entries = {}
    for repo in repos:
        for workflow in _reported(repo["workflows"]):
            reference = "{}:{}".format(repo["repo"], workflow["path"])
            for secret in workflow["secrets"]:
                if secret["category"] == "github-automatic":
                    continue
                entry = entries.setdefault(secret["name"], {
                    "id": secret["name"], "kind": secret["category"], "broad": "TBD", "found_in": [],
                })
                entry["found_in"].append(reference)
            broad = [f for f in workflow["flags"] if f["code"].startswith("broad-token-")]
            if broad:
                identifier = "GITHUB_TOKEN@{}".format(reference)
                entries[identifier] = {
                    "id": identifier, "kind": "workflow-token", "broad": True, "found_in": [reference],
                }
    return [entries[key] for key in sorted(entries)]


def render_seed(entries):
    """Render scan results in the manual inventory format, with TBD fields."""
    lines = [
        "# Generated by scan_workflows.py. Fill every TBD, then merge into the manual inventory.",
        "schema_version: 1",
        "security_review:",
        "  reviewer: TBD",
        "  date: TBD",
        "credentials:" + (" []" if not entries else ""),
    ]
    for entry in entries:
        broad = "true" if entry["broad"] is True else "TBD"
        lines += [
            "  - id: {}".format(json.dumps(entry["id"])),
            "    kind: {}".format(entry["kind"]),
            "    holder: TBD",
            "    owner: TBD",
            "    scope: TBD",
            "    broad: {}".format(broad),
            "    where_held: TBD",
            "    removal_date: TBD",
            "    notes: {}".format(json.dumps("Found in: " + ", ".join(sorted(set(entry["found_in"]))))),
        ]
    return "\n".join(lines) + "\n"


def render_text(report, show_all=False):
    summary = report["summary"]
    lines = [
        "Scanned {repos} repos, {workflows} workflows: {agent_workflows} agent workflows, {unparsed_workflows} unparsed.".format(**summary),
        "Flags on reported workflows: " + ", ".join(
            "{} {}".format(count, severity) for severity, count in summary["flags_on_reported_workflows"].items()),
    ]
    for repo in report["repos"]:
        workflows = repo["workflows"] if show_all else _reported(repo["workflows"])
        lines += ["", "== {} ==".format(repo["repo"])]
        if not workflows:
            lines.append("  no agent workflows")
        for workflow in workflows:
            lines.extend(_render_workflow(workflow))
    entries = report["credentials_to_inventory"]
    lines += ["", "Credentials that need an entry in the manual inventory: {}".format(len(entries))]
    for entry in entries:
        lines.append("  {} [{}] broad={}".format(entry["id"], entry["kind"], entry["broad"]))
    return "\n".join(lines) + "\n"


def _render_workflow(workflow):
    title = "AGENT" if workflow["is_agent"] else "other"
    lines = ["", "  {} {}{}".format(title, workflow["path"], " ({})".format(workflow["name"]) if workflow["name"] else "")]
    if workflow["agents"]:
        lines.append("    agents:   " + ", ".join(workflow["agents"]))
    lines.append("    triggers: " + ", ".join(workflow["effective_triggers"] or ["none"]))
    for job in workflow["jobs"]:
        permissions = job["permissions"]
        if job["permissions_source"] == "default":
            text = "undeclared (default token)"
        elif isinstance(permissions, dict):
            text = ", ".join("{}={}".format(k, v) for k, v in sorted(permissions.items())) or "none"
        else:
            text = permissions
        lines.append("    job {}: {} [from {}]".format(job["id"], text, job["permissions_source"]))
    for secret in workflow["secrets"]:
        lines.append("    secret {} [{}] in {}".format(secret["name"], secret["category"], ", ".join(secret["used_in"])))
    for flag in workflow["flags"]:
        jobs = " jobs: " + ", ".join(flag["jobs"]) if flag["jobs"] else ""
        lines.append("    FLAG {} {}: {}{}".format(flag["severity"].upper(), flag["code"], flag["detail"], jobs))
    return lines


def main(argv=None):
    parser = argparse.ArgumentParser(description="Inventory agent workflows in checked-out repositories (offline).")
    parser.add_argument("repos_dir", help="directory of checked-out repos, or a single repo")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    parser.add_argument("--output", help="write the report to this file instead of stdout")
    parser.add_argument("--all", action="store_true", help="also show workflows with no agent signal")
    parser.add_argument("--agent-pattern", action="append", default=[], metavar="REGEX",
                        help="extra regex matched against step uses/run text, for in-house agents (repeatable)")
    parser.add_argument("--fail-on", choices=SEVERITIES, help="exit 1 if a reported workflow has a flag at this severity or above")
    parser.add_argument("--credentials-seed", metavar="FILE", help="write a manual-inventory file for the credentials found; refuses to overwrite")
    args = parser.parse_args(argv)

    if not os.path.isdir(args.repos_dir):
        parser.error("not a directory: {}".format(args.repos_dir))
    try:
        patterns = [re.compile(p, re.I | re.M) for p in args.agent_pattern]
    except re.error as error:
        parser.error("invalid --agent-pattern: {}".format(error))

    report = scan(args.repos_dir, patterns)
    output = json.dumps(report, indent=2) + "\n" if args.format == "json" else render_text(report, args.all)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(output)
    else:
        sys.stdout.write(output)

    if args.credentials_seed:
        if os.path.exists(args.credentials_seed):
            parser.error("refusing to overwrite {}".format(args.credentials_seed))
        with open(args.credentials_seed, "w", encoding="utf-8") as handle:
            handle.write(render_seed(report["credentials_to_inventory"]))

    if args.fail_on:
        threshold = SEVERITIES.index(args.fail_on)
        for repo in report["repos"]:
            for workflow in _reported(repo["workflows"]):
                if any(SEVERITIES.index(flag["severity"]) <= threshold for flag in workflow["flags"]):
                    return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
