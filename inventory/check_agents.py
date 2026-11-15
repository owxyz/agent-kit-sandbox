#!/usr/bin/env python3
"""Fail a PR that adds an agent missing from the autonomy register (R2.6, P0.13).

Scans the workflows of the base checkout and the PR head with scan_workflows.py, as data, and compares the
agents it finds with the ids in the register (agents and other_secret_holders). An agent the PR adds to a
workflow, and that the register doesn't list, fails the check. Agents already on the base branch are reported
but don't fail, so one unregistered workflow doesn't hold every later PR.

Usage: python3 check_agents.py --register REGISTER --base BASE_DIR --head HEAD_DIR [--summary FILE]

Exit 0 pass, 1 an unregistered agent was added, 2 tool error (wins over a fail).
"""
import argparse
import os
import sys

import scan_workflows
import yamlite

EXIT_OK, EXIT_FAIL, EXIT_TOOL_ERROR = 0, 1, 2


def register_ids(path):
    with open(path, encoding="utf-8") as handle:
        document = yamlite.load(handle.read())
    ids = set()
    for section in ("agents", "other_secret_holders"):
        entries = document.get(section)
        if not isinstance(entries, list):
            raise ValueError("register has no {} list".format(section))
        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(entry.get("id"), str) or not entry["id"]:
                raise ValueError("an entry in {} has no id".format(section))
            ids.add(entry["id"])
    return ids


def agent_uses(root):
    """{(workflow path, agent label)} for every agent the scanner finds in root's workflows."""
    report = scan_workflows.scan_repo(os.path.basename(os.path.abspath(root)), root, ())
    uses = set()
    for workflow in report["workflows"]:
        # A workflow that doesn't parse is still scanned as text by scan_workflows, so its agents count.
        for label in workflow.get("agents") or ():
            uses.add((workflow["path"], label))
    return uses


def evaluate(registered, base, head):
    added = sorted(head - base)
    failures = [(path, label) for path, label in added if label not in registered]
    existing = sorted((path, label) for path, label in head & base if label not in registered)
    return failures, existing, added


def render(failures, existing, added, registered):
    lines = ["## Agent register check", ""]
    if failures:
        lines.append("**Failed:** this PR adds agents that aren't in the autonomy register. Register each one "
                     "first, through a reviewed change to the register (P0.13), then rerun this check.")
        lines.append("")
        lines += ["- `{}` in `{}`".format(label, path) for path, label in failures]
    else:
        lines.append("Passed: every agent this PR adds is in the register." if added
                     else "Passed: this PR adds no agent to a workflow.")
    if existing:
        lines += ["", "Already on the base branch and not registered (reported, not failed):", ""]
        lines += ["- `{}` in `{}`".format(label, path) for path, label in existing]
    lines += ["", "Registered ids: " + ", ".join("`{}`".format(i) for i in sorted(registered))]
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--register", required=True, help="autonomy-register.yaml, from the base branch")
    parser.add_argument("--base", required=True, help="checkout of the base commit")
    parser.add_argument("--head", required=True, help="checkout of the PR head, read as data")
    parser.add_argument("--summary", help="append the Markdown report here, e.g. $GITHUB_STEP_SUMMARY")
    args = parser.parse_args(argv)
    try:
        registered = register_ids(args.register)
        base, head = agent_uses(args.base), agent_uses(args.head)
    except (OSError, ValueError) as error:  # yamlite.YamlError is a ValueError
        print("TOOL ERROR: {}".format(error), file=sys.stderr)
        return EXIT_TOOL_ERROR
    failures, existing, added = evaluate(registered, base, head)
    text = render(failures, existing, added, registered)
    sys.stdout.write(text)
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as handle:
            handle.write(text)
    for path, label in failures:
        print("::error file={}::agent '{}' is not in the autonomy register".format(path, label))
    return EXIT_FAIL if failures else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
