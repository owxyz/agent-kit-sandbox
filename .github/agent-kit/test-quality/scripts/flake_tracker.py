#!/usr/bin/env python3
"""Track flake rates for existing tests on the default branch and propose quarantine changes.

A failure is flaky only when the same test also passed on the same commit. A test that fails
every run on a commit is broken, not flaky, and is left out of its rate.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path

from tq.adapters import make_adapters
from tq.core import EXIT_ERROR, ToolError, load_config
from tq.workspace import Workspace, require_full_sha


def _read(path, default):
    path = Path(path)
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text())
    except ValueError as exc:
        raise ToolError("cannot parse %s: %s" % (path, exc))


def _write(path, data):
    Path(path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def measure(args):
    require_full_sha(args.sha, "--sha")
    cfg = load_config(args.config)
    runs, tests = args.runs or cfg["flake"]["runs_per_commit"], {}
    with Workspace(args.repo, args.sha, args.sha) as ws:
        for adapter in make_adapters(cfg, args.python, args.jest_bin, ws.base_harness_tree()):
            if not adapter.detect(ws.pr_tree()):
                continue
            for number in range(runs):
                seed = 1000 + number
                result = adapter.run(ws.pr_tree(), ws.scratch("measure"), seed)
                for test_id, outcome in result.outcomes.items():
                    if outcome["status"] == "skipped":
                        continue
                    entry = tests.setdefault(test_id, {"runs": 0, "failures": 0})
                    entry["runs"] += 1
                    entry["failures"] += outcome["status"] == "failed"
                for path in result.load_errors:
                    print("load error during measurement: %s" % path, file=sys.stderr)
    _write(args.out, {"sha": args.sha, "tests": tests})
    print("measured %d tests x %d runs at %s" % (len(tests), runs, args.sha))


def record(args):
    cfg = load_config(args.config)
    database = _read(args.db, {"version": 1, "commits": []})
    sample = _read(args.results, None)
    if sample is None:
        raise ToolError("missing results file %s" % args.results)
    commits = [c for c in database["commits"] if c["sha"] != sample["sha"]] + [sample]
    database["commits"] = commits[-cfg["flake"]["window_commits"]:]
    _write(args.db, database)
    print("flake history holds %d commits" % len(database["commits"]))


def rates(database):
    totals = {}
    for commit in database["commits"]:
        for test_id, entry in commit["tests"].items():
            item = totals.setdefault(test_id, {"runs": 0, "flaky_failures": 0})
            if entry["failures"] == entry["runs"]:
                continue  # consistently failing on this commit: broken, not flaky
            item["runs"] += entry["runs"]
            item["flaky_failures"] += entry["failures"]
    for item in totals.values():
        item["rate"] = round(item["flaky_failures"] / item["runs"], 4) if item["runs"] else 0.0
    return totals


def report(args):
    table = rates(_read(args.db, {"version": 1, "commits": []}))
    print(json.dumps(table, indent=2, sort_keys=True))


def quarantine(args):
    cfg, today = load_config(args.config)["flake"], dt.date.today()
    table = rates(_read(args.db, {"version": 1, "commits": []}))
    data = _read(args.quarantine, {"version": 1, "tests": []})
    current = {entry["id"] for entry in data["tests"]}
    kept = []
    for entry in data["tests"]:
        stats = table.get(entry["id"])
        if stats and stats["runs"] >= cfg["min_runs"] and stats["rate"] == 0:
            print("RELEASE %s (no flakes in %d runs)" % (entry["id"], stats["runs"]))
        else:
            kept.append(entry)
    for test_id, stats in sorted(table.items()):
        if test_id not in current and stats["runs"] >= cfg["min_runs"] and stats["rate"] >= cfg["threshold"]:
            print("QUARANTINE %s (rate %.2f%% over %d runs)" % (test_id, 100 * stats["rate"], stats["runs"]))
            kept.append({"id": test_id, "reason": "flake rate %.4f over %d runs" % (stats["rate"], stats["runs"]),
                         "flake_rate": stats["rate"], "added": today.isoformat(),
                         "expires": (today + dt.timedelta(days=cfg["quarantine_days"])).isoformat(),
                         "owner": "unassigned"})
    data["tests"] = kept
    if args.write:
        _write(args.quarantine, data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=None)
    sub = parser.add_subparsers(dest="command", required=True)
    cmd = sub.add_parser("measure")
    cmd.add_argument("--repo", required=True)
    cmd.add_argument("--sha", required=True)
    cmd.add_argument("--runs", type=int, default=0)
    cmd.add_argument("--out", required=True)
    cmd.add_argument("--python", default=sys.executable)
    cmd.add_argument("--jest-bin", default=None)
    cmd.set_defaults(func=measure)
    cmd = sub.add_parser("record")
    cmd.add_argument("--db", required=True)
    cmd.add_argument("--results", required=True)
    cmd.set_defaults(func=record)
    cmd = sub.add_parser("report")
    cmd.add_argument("--db", required=True)
    cmd.set_defaults(func=report)
    cmd = sub.add_parser("quarantine")
    cmd.add_argument("--db", required=True)
    cmd.add_argument("--quarantine", required=True)
    cmd.add_argument("--write", action="store_true", help="update the file so an owner can open a PR")
    cmd.set_defaults(func=quarantine)
    args = parser.parse_args()
    try:
        args.func(args)
    except (ToolError, KeyError, OSError) as exc:
        print("TOOL ERROR: %r" % (exc,), file=sys.stderr)
        sys.exit(EXIT_ERROR)


if __name__ == "__main__":
    main()
