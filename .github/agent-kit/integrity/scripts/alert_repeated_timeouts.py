#!/usr/bin/env python3
"""Alert when a check keeps timing out on agent PRs (catalogue: denial of evaluation).

Usage: alert_repeated_timeouts.py HISTORY.json [--threshold N] [--output FILE]

HISTORY.json is a list of {"pr": 12, "labels": ["agent:x"], "check_runs": [...]}.
A finding (CHK004, warn) is raised for each check name that timed out on at
least N distinct agent PRs. Default N is 3.
"""
import argparse

from common import ToolError, emit, finding, load_json, run


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("history")
    parser.add_argument("--threshold", type=int, default=3)
    parser.add_argument("--output")
    args = parser.parse_args()
    history = load_json(args.history)
    if not isinstance(history, list):
        raise ToolError("history must be a list of PR records")
    timed_out = {}
    for record in history:
        if not isinstance(record, dict) or not isinstance(record.get("check_runs"), list):
            raise ToolError("malformed PR record: %r" % (record,))
        if not any(str(label).startswith("agent:") for label in record.get("labels", [])):
            continue
        for check in record["check_runs"]:
            if isinstance(check, dict) and check.get("conclusion") == "timed_out":
                timed_out.setdefault(str(check.get("name")), set()).add(record.get("pr"))
    findings = [
        finding(
            "CHK004", "warn", args.history, 0,
            "Check '%s' timed out on %d agent PRs: %s." % (name, len(prs), ", ".join(map(str, sorted(prs)))),
        )
        for name, prs in sorted(timed_out.items()) if len(prs) >= args.threshold
    ]
    return emit(findings, args.output)


if __name__ == "__main__":
    run(main)
