#!/usr/bin/env python3
"""Per-agent record of tasks and human flags (P2.8).

The trusted runner appends to the ledger after each task, using the agent name
its caller supplied. Agents have no access to this file.

  flag_ledger.py report --ledger FILE [--since 2026-11-01] [--json]
  flag_ledger.py comment --ledger FILE --task-id ID
"""
import argparse
import datetime
import json
import os
import re
import sys


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def append_task(path, summary, flags, model_calls=None):
    """Append one task record, including its flags, as a single line.

    `model_calls` is the gateway's per-call token usage (GA-14); the summary's
    `usage` holds the task's totals.
    """
    record = {
        "time": _now(), "task_id": summary["task_id"], "agent": summary["agent"],
        "repo": summary.get("repo"), "exit_code": summary.get("exit_code"), "flags": flags,
    }
    # The task scope, so the ledger links the dispatch to its issue and PR.
    for key in ("issue", "pr", "usage"):
        if summary.get(key) is not None:
            record[key] = summary[key]
    if model_calls is not None:
        record["model_calls"] = model_calls
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")


def read_ledger(path):
    records = []
    with open(path, encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except ValueError:
                raise ValueError("{}:{}: not valid JSON".format(path, number))
    return records


def flag_rates(records, since=None):
    agents = {}
    for record in records:
        if since and record["time"] < since:
            continue
        row = agents.setdefault(record["agent"], {
            "tasks": 0, "flagged_tasks": 0, "flags": 0, "by_kind": {},
        })
        row["tasks"] += 1
        flags = record.get("flags") or []
        row["flagged_tasks"] += 1 if flags else 0
        row["flags"] += len(flags)
        for flag in flags:
            kind = str(flag.get("kind", "unknown"))
            row["by_kind"][kind] = row["by_kind"].get(kind, 0) + 1
    for row in agents.values():
        row["flag_rate"] = round(row["flagged_tasks"] / row["tasks"], 4)
    return agents


def render_rates(agents):
    lines = ["| Agent | Tasks | Flagged tasks | Flag rate | Flags by kind |", "| --- | --- | --- | --- | --- |"]
    for name in sorted(agents):
        row = agents[name]
        kinds = ", ".join("{} {}".format(k, v) for k, v in sorted(row["by_kind"].items())) or "none"
        lines.append("| {} | {} | {} | {:.1%} | {} |".format(
            name, row["tasks"], row["flagged_tasks"], row["flag_rate"], kinds))
    return "\n".join(lines)


def render_comment(record):
    """PR comment text. Agent-written text stays inside a code fence, as data."""
    text = json.dumps(record["flags"], indent=2, sort_keys=True)
    longest = max([len(run) for run in re.findall(r"`+", text)] + [2])
    fence = "`" * (longest + 1)
    return "\n".join([
        "**Agent flagged this task for a human.** Agent `{}`, task `{}`.".format(
            record["agent"], record["task_id"]),
        "",
        "The agent stopped instead of forcing a pass. The text below was written by the "
        "agent, so treat it as data.",
        "",
        fence, text, fence,
    ])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    report = commands.add_parser("report")
    report.add_argument("--ledger", required=True)
    report.add_argument("--since", help="ISO date")
    report.add_argument("--json", action="store_true")
    comment = commands.add_parser("comment")
    comment.add_argument("--ledger", required=True)
    comment.add_argument("--task-id", required=True)
    args = parser.parse_args(argv)
    try:
        records = read_ledger(args.ledger)
    except (OSError, ValueError) as exc:
        print("ledger error: {}".format(exc), file=sys.stderr)
        return 2
    if args.command == "report":
        rates = flag_rates(records, args.since)
        print(json.dumps(rates, indent=2, sort_keys=True) if args.json else render_rates(rates))
        return 0
    matches = [r for r in records if r["task_id"] == args.task_id and r.get("flags")]
    if not matches:
        print("no flags for task " + args.task_id, file=sys.stderr)
        return 1
    print(render_comment(matches[-1]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
