#!/usr/bin/env python3
"""Require a real, pinned success for every required check (P2.9).

Usage: verify_required_checks.py (--config FILE | --ruleset FILE ...) --sha SHA
           (--saved FILE [--saved-statuses FILE] [--pr-head-sha SHA]
            | --repo OWNER/NAME [--wait SECONDS] [--queue-ref REF])
           [--exclude CONTEXT ...] [--output FILE]

GitHub's own required-check gate accepts skipped and neutral results. This
verifier does not: only a pinned success passes. --sha is the commit under test.
In the merge queue, --queue-ref (or --pr-head-sha) makes checks with queue policy
"pr-head" count on the PR's head commit instead, because those gates do not
really run on the merge commit.

--saved-statuses is {"<sha>": [status objects]}, from /commits/<sha>/statuses.

Rules (all block):
  CHK001  a required check ended, or is still, in anything but success
  CHK002  a required check has no result from its pinned identity on this commit
  CHK003  another identity reported under a required check's name
"""
import argparse
import re
import sys
import time

from common import (
    GitHub, ToolError, emit, finding, load_check_config, load_json, load_required_checks,
    pr_head_sha, queue_pr_number, quote, run,
)

FULL_SHA = r"[0-9a-f]{40}"


def extract_runs(data):
    """Accept an API response, a bare list of runs, or a list of response pages."""
    if isinstance(data, dict):
        data = data.get("check_runs")
    if not isinstance(data, list):
        raise ToolError("expected a check_runs list")
    runs = []
    for item in data:
        if isinstance(item, dict) and isinstance(item.get("check_runs"), list):
            runs.extend(item["check_runs"])
        elif isinstance(item, dict) and "name" in item:
            runs.append(item)
        else:
            raise ToolError("malformed check run entry: %r" % (item,))
    return runs


def fetch_runs(github, repo, sha):
    runs, page = [], 1
    while True:
        body = github.get_json(
            "/repos/%s/commits/%s/check-runs?filter=latest&per_page=100&page=%d" % (repo, quote(sha), page)
        )
        if not isinstance(body, dict) or not isinstance(body.get("check_runs"), list):
            raise ToolError("unexpected check-runs response")
        runs.extend(body["check_runs"])
        total = body.get("total_count")
        if not isinstance(total, int):
            raise ToolError("check-runs response has no total_count")
        if len(runs) >= total:
            return runs
        if not body["check_runs"]:
            raise ToolError("check-runs ended early: %d of %d" % (len(runs), total))
        page += 1


def app_id(check_run):
    app = check_run.get("app")
    return app.get("id") if isinstance(app, dict) else None


def passed(check_run):
    return check_run.get("status") == "completed" and check_run.get("conclusion") == "success"


def latest_suite(pinned):
    """Keep the newest check suite: a later event on one commit supersedes an earlier one."""
    suites = {}
    for check_run in pinned:
        suite = check_run.get("check_suite")
        suites.setdefault(suite.get("id") if isinstance(suite, dict) else None, []).append(check_run)
    return max(suites.values(), key=lambda group: max(r.get("id") or 0 for r in group))


def current_runs(spec, pinned):
    """Only a dedicated App can post its check, so its newest post is the result."""
    if spec.get("dedicated_app"):
        return [max(pinned, key=lambda r: r.get("id") or 0)]
    return latest_suite(pinned)


def target_sha(spec, sha, pr_head):
    return pr_head if pr_head and spec["queue"] == "pr-head" else sha


def creator_id(status):
    creator = status.get("creator")
    return creator.get("id") if isinstance(creator, dict) else None


def evaluate_check_run(context, spec, runs, commit, source):
    app, found = spec["integration_id"], []
    named = [r for r in runs if r.get("head_sha") == commit and r.get("name") == context]
    for check_run in named:
        if app_id(check_run) != app:
            found.append(finding(
                "CHK003", "block", source, 0,
                "App %s reported '%s', which is pinned to app %d." % (app_id(check_run), context, app),
            ))
    pinned = [r for r in named if app_id(r) == app]
    if not pinned:
        found.append(finding(
            "CHK002", "block", source, 0, "Required check '%s' has no run from app %d on %s." % (context, app, commit),
        ))
        return found
    for check_run in current_runs(spec, pinned):
        if not passed(check_run):
            state = check_run.get("conclusion") or check_run.get("status") or "unknown"
            found.append(finding(
                "CHK001", "block", source, 0, "Required check '%s' is '%s' on %s; only success passes." % (context, state, commit),
            ))
    return found


def statuses_named(context, statuses, commit):
    return [s for s in statuses.get(commit, []) if isinstance(s, dict) and s.get("context") == context]


def latest_status(entries):
    return max(entries, key=lambda s: s.get("id") or 0)


def evaluate_status(context, spec, statuses, commit, source):
    found = []
    named = statuses_named(context, statuses, commit)
    foreign = [s for s in named if creator_id(s) != spec["creator_id"]]
    for status in foreign:
        found.append(finding(
            "CHK003", "block", source, 0,
            "User %s posted status '%s', which is pinned to %d." % (creator_id(status), context, spec["creator_id"]),
        ))
    pinned = [s for s in named if creator_id(s) == spec["creator_id"]]
    if not pinned:
        found.append(finding(
            "CHK002", "block", source, 0, "Required status '%s' has no pinned result on %s." % (context, commit),
        ))
    elif latest_status(pinned).get("state") != "success":
        found.append(finding(
            "CHK001", "block", source, 0,
            "Required status '%s' is '%s' on %s; only success passes." % (context, latest_status(pinned).get("state"), commit),
        ))
    return found


def evaluate(required, runs, statuses, sha, pr_head, source):
    found = []
    for context, spec in sorted(required.items()):
        commit = target_sha(spec, sha, pr_head)
        check = evaluate_status if spec["kind"] == "status" else evaluate_check_run
        found += check(context, spec, statuses if spec["kind"] == "status" else runs, commit, source)
    return found


def still_pending(required, runs, statuses, sha, pr_head):
    for context, spec in required.items():
        commit = target_sha(spec, sha, pr_head)
        if spec["kind"] == "status":
            pinned = [s for s in statuses_named(context, statuses, commit) if creator_id(s) == spec["creator_id"]]
            if not pinned or latest_status(pinned).get("state") == "pending":
                return True
            continue
        pinned = [r for r in runs if r.get("head_sha") == commit and r.get("name") == context
                  and app_id(r) == spec["integration_id"]]
        if not pinned or any(r.get("status") != "completed" for r in current_runs(spec, pinned)):
            return True
    return False


def load_saved_statuses(path):
    if not path:
        return {}
    data = load_json(path)
    if not isinstance(data, dict) or not all(isinstance(v, list) for v in data.values()):
        raise ToolError("saved statuses must map each commit SHA to a list")
    return data


def required_from(args):
    if args.config:
        required = load_check_config(args.config)["required"]
    else:
        required = {
            context: {"kind": "check_run", "integration_id": app, "queue": "merge"}
            for context, app in load_required_checks(args.ruleset).items()
        }
    required = {c: s for c, s in required.items() if c not in args.exclude}
    if not required:
        raise ToolError("no required checks left to verify")
    return required


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    definition = parser.add_mutually_exclusive_group(required=True)
    definition.add_argument("--config")
    definition.add_argument("--ruleset", action="append")
    parser.add_argument("--sha", required=True)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--saved")
    source.add_argument("--repo")
    parser.add_argument("--saved-statuses")
    parser.add_argument("--pr-head-sha", help="saved only: the PR head in the merge queue")
    parser.add_argument("--queue-ref", help="live only: the merge queue ref naming the PR")
    parser.add_argument("--wait", type=int, default=0, help="live only: seconds to wait for pending checks")
    parser.add_argument("--poll-interval", type=float, default=20)
    parser.add_argument("--exclude", action="append", default=[], help="skip this context, for the verifier's own job")
    parser.add_argument("--output")
    args = parser.parse_args()
    for value in (args.sha, args.pr_head_sha):
        if value is not None and not re.fullmatch(FULL_SHA, value):
            raise ToolError("commit SHAs must be full 40-character SHAs")
    required = required_from(args)

    if args.saved:
        runs, statuses = extract_runs(load_json(args.saved)), load_saved_statuses(args.saved_statuses)
        return emit(evaluate(required, runs, statuses, args.sha, args.pr_head_sha, args.saved), args.output)

    if not re.fullmatch(r"[\w.-]+/[\w.-]+", args.repo):
        raise ToolError("--repo must be owner/name")
    github = GitHub()
    pr_head = pr_head_sha(github, args.repo, queue_pr_number(args.queue_ref)) if args.queue_ref else None
    commits = sorted({target_sha(spec, args.sha, pr_head) for spec in required.values()})
    wants_statuses = any(spec["kind"] == "status" for spec in required.values())
    deadline = time.monotonic() + args.wait
    while True:
        runs = [r for commit in commits for r in fetch_runs(github, args.repo, commit)]
        statuses = {
            commit: github.list_all("/repos/%s/commits/%s/statuses" % (args.repo, quote(commit)))
            for commit in commits
        } if wants_statuses else {}
        if not still_pending(required, runs, statuses, args.sha, pr_head) or time.monotonic() >= deadline:
            source_name = "%s@%s" % (args.repo, args.sha)
            return emit(evaluate(required, runs, statuses, args.sha, pr_head, source_name), args.output)
        print("waiting for required checks...", file=sys.stderr)
        time.sleep(args.poll_interval)


if __name__ == "__main__":
    run(main)
