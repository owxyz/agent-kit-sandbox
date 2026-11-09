#!/usr/bin/env python3
"""Validate the autonomy register (P0.13) or the manual credential inventory (P0.1).

Usage: python3 validate.py register [FILE] [--today YYYY-MM-DD] [--format text|json] [--allow-incomplete]
       python3 validate.py credentials FILE [same options]

Exit codes:
  0  valid and complete (or only incomplete, with --allow-incomplete)
  1  schema or rule errors, or a date is overdue
  2  the file could not be read or parsed
  3  valid but incomplete (TBD values remain)

Rotation dates inside the warning window are reported but do not change the
exit code. Output never repeats a field's value, in case a credential was
typed into the wrong place.
"""
import argparse
import json
import os
import re
import sys
from datetime import date, datetime, timedelta

import schemalite
import yamlite

HERE = os.path.dirname(os.path.abspath(__file__))
SCHEMAS = {
    "register": os.path.join(HERE, "schemas", "autonomy-register.schema.json"),
    "credentials": os.path.join(HERE, "schemas", "manual-credentials.schema.json"),
}
DEFAULT_FILES = {"register": os.path.join(HERE, "autonomy-register.yaml")}
SEVERITY_ORDER = ["error", "overdue", "incomplete", "due_soon"]

_CREDENTIAL_SHAPES = re.compile(
    r"gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}"
    r"|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY"
)
_CI_LOCATION = re.compile(
    r"\$\{\{|^(secrets|vars)\.|github[ _-]?actions|actions[ _-](secret|variable)|ci[ _-](variable|secret)",
    re.I,
)


class Report:
    def __init__(self):
        self.issues = []

    def add(self, category, path, message, subject=None, owner=None):
        issue = {"category": category, "path": path, "message": message}
        if subject:
            issue.update(subject=subject, owner=owner)
        self.issues.append(issue)

    def has(self, category):
        return any(issue["category"] == category for issue in self.issues)

    def exit_code(self, allow_incomplete=False):
        if self.has("error") or self.has("overdue"):
            return 1
        if self.has("incomplete") and not allow_incomplete:
            return 3
        return 0


def is_tbd(value):
    return isinstance(value, str) and value.strip().upper() == "TBD"


def parse_date(value, path, report):
    """Return a date, or None for TBD and for an invalid date (reported)."""
    if not isinstance(value, str) or is_tbd(value) or value == "N/A":
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError:
        report.add("error", path, "is not a real calendar date")
        return None


def _require_known(entry, field, path, report):
    if is_tbd(entry[field]):
        report.add("incomplete", "{}.{}".format(path, field), "is TBD")
        return False
    return True


def _scan_for_credentials(node, path, report):
    if isinstance(node, str):
        if _CREDENTIAL_SHAPES.search(node):
            report.add("error", path, "looks like a real credential; remove it and rotate that credential")
    elif isinstance(node, dict):
        for key, value in node.items():
            _scan_for_credentials(value, "{}.{}".format(path, key), report)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            _scan_for_credentials(value, "{}[{}]".format(path, index), report)


def _unique_ids(entries, path, report):
    seen = set()
    for index, entry in enumerate(entries):
        if entry["id"] in seen:
            report.add("error", "{}[{}].id".format(path, index), "duplicate id '{}'".format(entry["id"]))
        seen.add(entry["id"])


def _check_agent(agent, path, report):
    permissions = agent["token_scope"]["permissions"]
    for forbidden in ("administration", "workflows"):
        if permissions.get(forbidden, "none") != "none":
            report.add("error", "{}.token_scope.permissions.{}".format(path, forbidden),
                       "agents may not hold admin or workflow scope (P0.2)")
    if agent["level"] == "Advise":
        for scope, level in permissions.items():
            if level == "write" and scope != "checks":
                report.add("error", "{}.token_scope.permissions.{}".format(path, scope),
                           "an Advise agent may only write checks")
    metric = agent["promotion_metric"]
    for field in ("name", "target"):
        _require_known(metric, field, "{}.promotion_metric".format(path), report)


def _check_secret(secret, policy, today, path, report):
    _require_known(secret, "owner", path, report)
    if _require_known(secret, "secrets_manager_location", path, report):
        if _CI_LOCATION.search(secret["secrets_manager_location"]):
            report.add("error", "{}.secrets_manager_location".format(path),
                       "must be a secrets manager, not CI secrets or variables (P0.13)")
    interval = secret.get("rotation_days", policy["rotation_days"])
    last = parse_date(secret["last_rotated"], "{}.last_rotated".format(path), report)
    rotation = parse_date(secret["rotation_date"], "{}.rotation_date".format(path), report)
    alert = parse_date(secret["alert_date"], "{}.alert_date".format(path), report)
    _require_known(secret, "last_rotated", path, report)

    if is_tbd(secret["rotation_date"]):
        hint = ""
        if last:
            hint = "; last_rotated + {} days is {}".format(interval, last + timedelta(days=interval))
        report.add("incomplete", "{}.rotation_date".format(path), "is TBD" + hint)
    if is_tbd(secret["alert_date"]):
        hint = ""
        planned = rotation or (last + timedelta(days=interval) if last and is_tbd(secret["rotation_date"]) else None)
        if planned:
            hint = "; {} days before rotation is {}".format(
                policy["alert_days_before"], planned - timedelta(days=policy["alert_days_before"]))
        report.add("incomplete", "{}.alert_date".format(path), "is TBD" + hint)

    if last and rotation and rotation > last + timedelta(days=interval):
        report.add("error", "{}.rotation_date".format(path),
                   "is more than {} days after last_rotated".format(interval))
    if alert and rotation and alert >= rotation:
        report.add("error", "{}.alert_date".format(path), "must be before rotation_date")
    if rotation:
        days_left = (rotation - today).days
        who = {"subject": secret["id"], "owner": _display_owner(secret["owner"])}
        if days_left < 0:
            report.add("overdue", "{}.rotation_date".format(path),
                       "rotation is {} day(s) overdue".format(-days_left), **who)
        elif days_left <= policy["due_soon_days"]:
            report.add("due_soon", "{}.rotation_date".format(path),
                       "rotation is due in {} day(s)".format(days_left), **who)
        elif alert and alert <= today:
            report.add("due_soon", "{}.alert_date".format(path), "alert date has passed", **who)


def _display_owner(owner):
    """The owner on one line, withheld if a credential was typed there."""
    if _CREDENTIAL_SHAPES.search(owner):
        return "(withheld: invalid owner value)"
    return " ".join(owner.split())


def validate_register(document, today, report):
    _scan_for_credentials(document, "$", report)
    policy = document["policy"]
    agents = document["agents"]
    holders = document["other_secret_holders"]
    secrets = document["secrets"]
    _unique_ids(agents, "$.agents", report)
    _unique_ids(holders, "$.other_secret_holders", report)
    _unique_ids(secrets, "$.secrets", report)

    for index, agent in enumerate(agents):
        _check_agent(agent, "$.agents[{}]".format(index), report)
    for index, secret in enumerate(secrets):
        _check_secret(secret, policy, today, "$.secrets[{}]".format(index), report)

    required = {agent["id"]: ("github-app-private-key", "model-api-key") for agent in agents}
    for holder in holders:
        required[holder["id"]] = (
            ("webhook-secret",) if holder["type"] == "app-service"
            else ("github-app-private-key", "model-api-key")
        )
    held = set()
    for index, secret in enumerate(secrets):
        if secret["holder"] not in required:
            report.add("error", "$.secrets[{}].holder".format(index),
                       "unknown holder '{}'".format(secret["holder"]))
        held.add((secret["holder"], secret["kind"]))
    for holder, kinds in required.items():
        for kind in kinds:
            if (holder, kind) not in held:
                report.add("error", "$.secrets", "'{}' has no {} entry".format(holder, kind))


def validate_credentials(document, today, report):
    _scan_for_credentials(document, "$", report)
    review = document["security_review"]
    _require_known(review, "reviewer", "$.security_review", report)
    _require_known(review, "date", "$.security_review", report)
    parse_date(review["date"], "$.security_review.date", report)
    credentials = document["credentials"]
    _unique_ids(credentials, "$.credentials", report)
    for index, entry in enumerate(credentials):
        path = "$.credentials[{}]".format(index)
        for field in ("holder", "owner", "scope", "where_held"):
            _require_known(entry, field, path, report)
        broad = entry["broad"]
        if is_tbd(broad):
            report.add("incomplete", "{}.broad".format(path), "is TBD; check the real scope")
        elif not isinstance(broad, bool):
            report.add("error", "{}.broad".format(path), "must be true, false or TBD")
        removal = entry["removal_date"]
        when = parse_date(removal, "{}.removal_date".format(path), report)
        if broad is True and removal == "N/A":
            report.add("error", "{}.removal_date".format(path), "a broad credential needs a removal date")
        if is_tbd(removal):
            report.add("incomplete", "{}.removal_date".format(path), "is TBD")
        if broad is True and when and when < today:
            report.add("overdue", "{}.removal_date".format(path),
                       "removal is {} day(s) overdue".format((today - when).days))


VALIDATORS = {"register": validate_register, "credentials": validate_credentials}


def validate_document(kind, document, today):
    report = Report()
    with open(SCHEMAS[kind], encoding="utf-8") as handle:
        schema = json.load(handle)
    problems = schemalite.validate(document, schema)
    if problems:
        for path, message in problems:
            report.add("error", path, message)
        # Credential shapes are still worth catching in a malformed file.
        _scan_for_credentials(document, "$", report)
        return report
    VALIDATORS[kind](document, today, report)
    return report


def render_text(report, name):
    counts = {c: sum(1 for i in report.issues if i["category"] == c) for c in SEVERITY_ORDER}
    lines = ["{}: {} error, {} overdue, {} incomplete, {} due soon".format(
        name, counts["error"], counts["overdue"], counts["incomplete"], counts["due_soon"])]
    for category in SEVERITY_ORDER:
        for issue in report.issues:
            if issue["category"] == category:
                who = " [{}, owner: {}]".format(issue["subject"], issue["owner"]) if "subject" in issue else ""
                lines.append("  {}: {} {}{}".format(category.upper(), issue["path"], issue["message"], who))
    return "\n".join(lines) + "\n"


def render_alerts(report):
    """One tab-separated line per secret needing rotation, for the alert job."""
    lines = []
    for issue in report.issues:
        if "subject" in issue:
            state = "overdue" if issue["category"] == "overdue" else "due soon"
            lines.append("\t".join((state, issue["subject"], issue["owner"], issue["message"])))
    return "".join(line + "\n" for line in lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Validate the autonomy register or manual credential inventory.")
    parser.add_argument("kind", choices=sorted(VALIDATORS))
    parser.add_argument("file", nargs="?", help="defaults to autonomy-register.yaml for 'register'")
    parser.add_argument("--today", help="date to check rotations against (YYYY-MM-DD)")
    parser.add_argument("--format", choices=["text", "json", "alerts"], default="text",
                        help="alerts: one tab-separated line per secret due for rotation; other problems go to stderr")
    parser.add_argument("--allow-incomplete", action="store_true",
                        help="exit 0 when the only problems are TBD values, for use during rollout")
    args = parser.parse_args(argv)

    path = args.file or DEFAULT_FILES.get(args.kind)
    if not path:
        parser.error("a file is required for '{}'".format(args.kind))
    try:
        today = datetime.strptime(args.today, "%Y-%m-%d").date() if args.today else date.today()
    except ValueError:
        parser.error("--today must be YYYY-MM-DD")
    try:
        with open(path, encoding="utf-8") as handle:
            document = yamlite.load(handle.read())
    except (OSError, UnicodeDecodeError) as error:
        print("{}: cannot read file: {}".format(path, type(error).__name__), file=sys.stderr)
        return 2
    except yamlite.YamlError as error:
        print("{}: invalid YAML at {}".format(path, error), file=sys.stderr)
        return 2

    report = validate_document(args.kind, document, today)
    code = report.exit_code(args.allow_incomplete)
    if args.format == "json":
        print(json.dumps({"file": path, "exit_code": code, "issues": report.issues}, indent=2))
    elif args.format == "alerts":
        sys.stdout.write(render_alerts(report))
        for issue in report.issues:
            if issue["category"] == "error":
                print("ERROR: {} {}".format(issue["path"], issue["message"]), file=sys.stderr)
    else:
        sys.stdout.write(render_text(report, path))
    return code


if __name__ == "__main__":
    sys.exit(main())
