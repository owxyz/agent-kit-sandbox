"""Shared helpers: the findings contract, exit codes, ruleset loading, GitHub reads.

Exit codes for every CLI here: 0 nothing blocks, 1 a block-mode finding exists,
2 tool error. Any unexpected failure is a tool error and never a pass.
"""
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

GATE = "integrity"
ACTIONS_APP_ID = 15368
FINDING_FIELDS = ("gate", "rule", "severity", "mode", "file", "line", "message")


class ToolError(Exception):
    """The tool could not reach a verdict."""


def finding(rule, mode, file, line, message, severity=None):
    return {
        "gate": GATE,
        "rule": rule,
        "severity": severity or ("high" if mode == "block" else "medium"),
        "mode": mode,
        "file": file,
        "line": line,
        "message": message,
    }


def emit(findings, output=None):
    """Write findings as JSON and return the exit code they imply."""
    text = json.dumps(findings, indent=2, sort_keys=True) + "\n"
    if output:
        with open(output, "w", encoding="utf-8") as handle:
            handle.write(text)
    else:
        sys.stdout.write(text)
    return 1 if any(f["mode"] == "block" for f in findings) else 0


def run(main):
    """Run a CLI entry point, mapping every failure to exit code 2."""
    try:
        code = main()
    except SystemExit:
        raise
    except Exception as error:  # pylint: disable=broad-except
        print("tool error: %s" % error, file=sys.stderr)
        sys.exit(2)
    sys.exit(code)


def load_json(path):
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError) as error:
        raise ToolError("cannot read %s: %s" % (path, error))


def load_required_checks(paths):
    """Return {context: integration_id}. Every required check must be pinned."""
    required = {}
    for path in paths:
        ruleset = load_json(path)
        rules = [
            r for r in ruleset.get("rules", [])
            if isinstance(r, dict) and r.get("type") == "required_status_checks"
        ] if isinstance(ruleset, dict) else []
        if not rules:
            raise ToolError("%s has no required_status_checks rule" % path)
        for rule in rules:
            checks = (rule.get("parameters") or {}).get("required_status_checks")
            if not isinstance(checks, list) or not checks:
                raise ToolError("%s lists no required checks" % path)
            for check in checks:
                context = check.get("context") if isinstance(check, dict) else None
                app = check.get("integration_id") if isinstance(check, dict) else None
                if not isinstance(context, str) or not context:
                    raise ToolError("%s has a required check without a context" % path)
                if not isinstance(app, int) or isinstance(app, bool) or app <= 0:
                    raise ToolError("%s: %s is not pinned to an app; is its placeholder still unset?" % (path, context))
                if required.get(context, app) != app:
                    raise ToolError("%s is pinned to two different apps" % context)
                required[context] = app
    return required


def load_check_config(path):
    """Return the validated required-checks config (see config/required-checks.json)."""
    data = load_json(path)
    entries = data.get("checks") if isinstance(data, dict) else None
    if not isinstance(entries, list) or not entries:
        raise ToolError("%s lists no checks" % path)
    required = {}
    for entry in entries:
        context = entry.get("context") if isinstance(entry, dict) else None
        if not isinstance(context, str) or not context or context in required:
            raise ToolError("%s has a missing or repeated context" % path)
        app = entry.get("integration_id")
        if not isinstance(app, int) or isinstance(app, bool) or app <= 0:
            raise ToolError("%s: %s is not pinned to an app; is its placeholder still unset?" % (path, context))
        if entry.get("dedicated_app") and app == ACTIONS_APP_ID:
            raise ToolError("%s: %s needs its own App, not GitHub Actions" % (path, context))
        if entry.get("kind") not in ("check_run", "status"):
            raise ToolError("%s: %s has an unknown kind" % (path, context))
        if entry.get("queue") not in ("merge", "pr-head"):
            raise ToolError("%s: %s has an unknown queue policy" % (path, context))
        if entry["kind"] == "status" and (
                not isinstance(entry.get("creator_id"), int) or not isinstance(entry.get("workflow"), str)):
            raise ToolError("%s: status %s needs creator_id and workflow" % (path, context))
        required[context] = entry
    return {
        "required": required,
        "status_writers": {(w["workflow"], w["job"]) for w in data.get("status_writers", [])},
        "exceptions": {(x["rule"], x["workflow"], x["job"]) for x in data.get("reviewed_exceptions", [])},
    }


def queue_pr_number(ref):
    """Read the PR number from a merge queue ref. An unexpected ref is a tool error."""
    match = re.fullmatch(r"(?:refs/heads/)?gh-readonly-queue/.+/pr-(\d+)-[0-9a-f]+", ref or "")
    if not match:
        raise ToolError("not a merge queue ref: %r" % ref)
    return int(match.group(1))


def pr_head_sha(github, repo, number):
    pull = github.get_json("/repos/%s/pulls/%d" % (repo, number))
    sha = (pull.get("head") or {}).get("sha") if isinstance(pull, dict) else None
    if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ToolError("PR %d has no head SHA" % number)
    return sha


class GitHub:
    """Minimal REST client. Anything but an expected response is a tool error."""

    def __init__(self, token=None, api_url=None):
        self.token = token or os.environ.get("GITHUB_TOKEN")
        self.api_url = (api_url or os.environ.get("GITHUB_API_URL") or "https://api.github.com").rstrip("/")
        if not self.token:
            raise ToolError("no GitHub token available")

    def request(self, method, path, body=None, accept="application/vnd.github+json"):
        """Return (status, raw bytes). HTTP errors below 500 are returned, not raised."""
        data = json.dumps(body).encode("utf-8") if body is not None else None
        request = urllib.request.Request(self.api_url + path, data=data, method=method)
        request.add_header("Authorization", "Bearer %s" % self.token)
        request.add_header("Accept", accept)
        request.add_header("X-GitHub-Api-Version", "2022-11-28")
        request.add_header("User-Agent", "agent-integrity-gate")
        if data is not None:
            request.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            if error.code >= 500:
                raise ToolError("GitHub returned %d for %s" % (error.code, path))
            return error.code, error.read()
        except (urllib.error.URLError, OSError) as error:
            raise ToolError("cannot reach GitHub for %s: %s" % (path, error))

    def get_json(self, path, allow_404=False):
        status, raw = self.request("GET", path)
        if status == 404 and allow_404:
            return None
        if status != 200:
            raise ToolError("GitHub returned %d for %s" % (status, path))
        try:
            return json.loads(raw.decode("utf-8"))
        except ValueError as error:
            raise ToolError("invalid JSON from %s: %s" % (path, error))

    def get_raw(self, path):
        status, raw = self.request("GET", path, accept="application/vnd.github.raw+json")
        if status != 200:
            raise ToolError("GitHub returned %d for %s" % (status, path))
        return raw

    def list_all(self, path):
        """Follow page numbers on an endpoint that returns a bare JSON array."""
        items = []
        separator = "&" if "?" in path else "?"
        page = 1
        while True:
            batch = self.get_json("%s%sper_page=100&page=%d" % (path, separator, page))
            if not isinstance(batch, list):
                raise ToolError("expected a list from %s" % path)
            items.extend(batch)
            if len(batch) < 100:
                return items
            page += 1


def quote(value, safe=""):
    return urllib.parse.quote(str(value), safe=safe)
