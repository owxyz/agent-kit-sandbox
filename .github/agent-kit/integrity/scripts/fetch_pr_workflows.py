#!/usr/bin/env python3
"""Download a PR's workflow files as data, with no checkout (P2.9).

Usage: fetch_pr_workflows.py --repo OWNER/NAME --sha SHA --dest DIR

Files land in DIR/.github/workflows, so paths in findings match CODEOWNERS once
DIR/ is stripped. Nothing from the PR is ever executed.
"""
import argparse
import os

from common import GitHub, ToolError, quote, run

WORKFLOW_DIR = ".github/workflows"


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo", required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--dest", required=True)
    args = parser.parse_args()
    github = GitHub()
    listing = github.get_json("/repos/%s/contents/%s?ref=%s" % (args.repo, WORKFLOW_DIR, quote(args.sha)))
    if not isinstance(listing, list):
        raise ToolError("%s is not a directory at %s" % (WORKFLOW_DIR, args.sha))
    target = os.path.join(args.dest, WORKFLOW_DIR)
    os.makedirs(target, exist_ok=True)
    for item in listing:
        name = str(item.get("name", ""))
        if item.get("type") != "file" or not name.endswith((".yml", ".yaml")):
            continue
        if os.path.basename(name) != name:
            raise ToolError("unsafe file name from API: %r" % name)
        raw = github.get_raw("/repos/%s/contents/%s/%s?ref=%s" % (args.repo, WORKFLOW_DIR, quote(name), quote(args.sha)))
        with open(os.path.join(target, name), "wb") as handle:
            handle.write(raw)
    return 0


if __name__ == "__main__":
    run(main)
