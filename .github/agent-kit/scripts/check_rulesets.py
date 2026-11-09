#!/usr/bin/env python3
"""Validate the main-branch ruleset JSON (P0.3, P2.1, P4.3, P4.4).

Usage: check_rulesets.py RULESET.json [RULESET.json ...]

Files are validated together, because the merge queue ships as its own ruleset.
"""
import json
import sys

REQUIRED_PULL_REQUEST = {
    "dismiss_stale_reviews_on_push": True,
    "require_code_owner_review": True,
    "require_last_push_approval": True,
}
MERGE_QUEUE_RANGES = {
    "check_response_timeout_minutes": (1, 360),
    "max_entries_to_build": (0, 100),
    "max_entries_to_merge": (0, 100),
    "min_entries_to_merge": (0, 100),
    "min_entries_to_merge_wait_minutes": (0, 360),
}
REQUIRED_TYPES = {"pull_request", "required_status_checks", "non_fast_forward", "deletion", "merge_queue"}


def check_header(name, ruleset):
    problems = []
    if ruleset.get("enforcement") != "active":
        problems.append("%s: enforcement must be active" % name)
    if ruleset.get("target") != "branch":
        problems.append("%s: target must be branch" % name)
    if ruleset.get("bypass_actors") != []:
        problems.append("%s: bypass_actors must be empty" % name)
    include = ((ruleset.get("conditions") or {}).get("ref_name") or {}).get("include")
    if include != ["refs/heads/main"]:
        problems.append("%s: must target only refs/heads/main" % name)
    return problems


def check_pull_request(name, parameters):
    problems = []
    for key, expected in REQUIRED_PULL_REQUEST.items():
        if parameters.get(key) is not expected:
            problems.append("%s: pull_request.%s must be %s" % (name, key, expected))
    if not isinstance(parameters.get("required_approving_review_count"), int) \
            or parameters["required_approving_review_count"] < 1:
        problems.append("%s: at least one approval is required" % name)
    if not isinstance(parameters.get("required_review_thread_resolution"), bool):
        problems.append("%s: required_review_thread_resolution must be set" % name)
    return problems


def check_merge_queue(name, parameters):
    problems = []
    for key, (low, high) in MERGE_QUEUE_RANGES.items():
        value = parameters.get(key)
        if not isinstance(value, int) or not low <= value <= high:
            problems.append("%s: merge_queue.%s must be %d-%d" % (name, key, low, high))
    if parameters.get("grouping_strategy") not in ("ALLGREEN", "HEADGREEN"):
        problems.append("%s: merge_queue.grouping_strategy is invalid" % name)
    if parameters.get("merge_method") not in ("MERGE", "SQUASH", "REBASE"):
        problems.append("%s: merge_queue.merge_method is invalid" % name)
    return problems


def check(paths):
    problems, seen = [], set()
    for path in paths:
        try:
            with open(path, encoding="utf-8") as handle:
                ruleset = json.load(handle)
        except (OSError, ValueError) as error:
            problems.append("%s: unreadable: %s" % (path, type(error).__name__))
            continue
        problems.extend(check_header(path, ruleset))
        for rule in ruleset.get("rules", []):
            kind = rule.get("type")
            seen.add(kind)
            parameters = rule.get("parameters") or {}
            if kind == "pull_request":
                problems.extend(check_pull_request(path, parameters))
            elif kind == "merge_queue":
                problems.extend(check_merge_queue(path, parameters))
            elif kind == "required_status_checks" and not parameters.get("required_status_checks"):
                problems.append("%s: no required status checks listed" % path)
    for kind in sorted(REQUIRED_TYPES - seen):
        problems.append("missing rule type: %s" % kind)
    return problems


def main(argv):
    problems = check(argv)
    for problem in problems:
        print(problem)
    print("%d ruleset file(s) checked, %d problem(s)." % (len(argv), len(problems)))
    return 1 if problems or not argv else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
