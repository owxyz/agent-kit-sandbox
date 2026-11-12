#!/usr/bin/env python3
"""Trusted job only: derive agent, bug-fix and owner-approval facts. Never runs PR code."""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
from pathlib import Path

from tq.context import bug_fix_signals, owner_approved
from tq.core import EXIT_ERROR, ToolError

PER_PAGE, MAX_PAGES = 100, 5


def api_get(path, token, api_url):
    request = urllib.request.Request(api_url.rstrip("/") + path, headers={
        "Authorization": "Bearer %s" % token, "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "test-quality-gate"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode())
    except (OSError, ValueError) as exc:
        raise ToolError("GitHub API failed for %s: %s" % (path, exc))


def paged(path, token, api_url):
    items = []
    for page in range(1, MAX_PAGES + 1):
        batch = api_get("%s?per_page=%d&page=%d" % (path, PER_PAGE, page), token, api_url)
        items += batch
        if len(batch) < PER_PAGE:
            return items
    return items


def split_list(value):
    return [item.strip() for item in (value or "").split(",") if item.strip()]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--event", required=True)
    parser.add_argument("--kit-scripts", required=True, help="directory holding kit's check_provenance.py")
    parser.add_argument("--agent-logins", default="")
    parser.add_argument("--owners", default="", help="comma-separated logins who may approve exclusions")
    parser.add_argument("--github-output", default=None)
    args = parser.parse_args()
    try:
        token, api_url = os.environ["GITHUB_TOKEN"], os.environ.get("GITHUB_API_URL", "https://api.github.com")
        sys.path.insert(0, args.kit_scripts)
        import check_provenance  # the same agent-PR rule as the provenance check

        event = json.loads(Path(args.event).read_text())
        number = event["pull_request"]["number"]
        repo = event["repository"]["full_name"]
        base = "/repos/%s/pulls/%d" % (repo, number)
        pull = api_get(base, token, api_url)
        commits, reviews = paged(base + "/commits", token, api_url), paged(base + "/reviews", token, api_url)
        logins = {x.lower() for x in split_list(args.agent_logins)}
        agent = check_provenance.evaluate(pull, commits, logins)[2]
        signals = bug_fix_signals(pull)
        head_sha = pull["head"]["sha"]
        values = {
            "agent_pr": str(bool(agent)).lower(),
            "bug_fix": str(bool(signals)).lower(),
            "bug_fix_signals": ",".join(signals),
            "owner_approved": str(owner_approved(reviews, split_list(args.owners), head_sha)).lower(),
            "head_sha": head_sha,
            "base_sha": pull["base"]["sha"],
        }
    except (ToolError, KeyError, TypeError, ValueError, OSError, ImportError) as exc:
        print("TOOL ERROR: %r" % (exc,), file=sys.stderr)
        sys.exit(EXIT_ERROR)
    for key, value in values.items():
        print("%s=%s" % (key, value))
    if args.github_output:
        with open(args.github_output, "a") as handle:
            for key, value in values.items():
                handle.write("%s=%s\n" % (key, value))


if __name__ == "__main__":
    main()
