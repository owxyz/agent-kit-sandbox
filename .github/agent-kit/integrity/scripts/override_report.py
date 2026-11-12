#!/usr/bin/env python3
"""Weekly override rate per gate, from the audit log (P2.7).

Usage: override_report.py (--audit-file PATH | --audit-repo OWNER/NAME)
           [--week YYYY-Www] [--tune-min N] [--output-md FILE] [--output-json FILE]

Rate = overridden / blocked, counting distinct (repo, PR, commit, gate), so
re-runs do not inflate it. Default week is the last complete ISO week. A gate is
marked for tuning when its rate rose from a prior week that had blocks and it
saw at least N blocks this week (default 3).
"""
import argparse
import datetime
import json
import re
import sys

from audit_log import GENESIS, add_store_arguments, parse_chain, store_from
from common import ToolError, run


def week_bounds(label):
    match = re.fullmatch(r"(\d{4})-W(\d{2})", label)
    if not match:
        raise ToolError("--week must look like 2026-W45")
    try:
        start = datetime.date.fromisocalendar(int(match.group(1)), int(match.group(2)), 1)
    except ValueError as error:
        raise ToolError("invalid week: %s" % error)
    return start, start + datetime.timedelta(days=7)


def label_for(day):
    year, week, _ = day.isocalendar()
    return "%d-W%02d" % (year, week)


def in_week(entry, start, end):
    try:
        day = datetime.datetime.strptime(entry["ts"], "%Y-%m-%dT%H:%M:%SZ").date()
    except (KeyError, ValueError) as error:
        raise ToolError("audit entry %s has a bad timestamp: %s" % (entry.get("seq"), error))
    return start <= day < end


def key(entry):
    return (entry["repo"], entry["pr"], entry["sha"], entry["gate"])


def tally(entries):
    gates = {}
    for entry in entries:
        slot = gates.setdefault(entry["gate"], {"blocked": set(), "overridden": set(), "rejected": 0})
        if entry["event"] == "override_rejected":
            slot["rejected"] += 1
            continue
        slot["blocked"].add(key(entry))
        if entry["event"] == "override":
            slot["overridden"].add(key(entry))
    return gates


def rate(slot):
    return round(len(slot["overridden"]) / len(slot["blocked"]), 4) if slot and slot["blocked"] else None


def build(entries, week, tune_min):
    start, end = week_bounds(week)
    previous_start = start - datetime.timedelta(days=7)
    current_entries = [e for e in entries if in_week(e, start, end)]
    current = tally(current_entries)
    previous = tally([e for e in entries if in_week(e, previous_start, start)])
    rows = []
    for gate in sorted(set(current) | set(previous)):
        now_slot, before_slot = current.get(gate), previous.get(gate)
        now_rate, before_rate = rate(now_slot), rate(before_slot)
        blocked = len(now_slot["blocked"]) if now_slot else 0
        rising = now_rate is not None and before_rate is not None and now_rate > before_rate
        rows.append({
            "gate": gate, "blocked": blocked,
            "overridden": len(now_slot["overridden"]) if now_slot else 0,
            "rejected_attempts": now_slot["rejected"] if now_slot else 0,
            "override_rate": now_rate, "previous_rate": before_rate,
            "rising": rising, "needs_tuning": rising and blocked >= tune_min,
        })
    overrides = [e for e in current_entries if e["event"] == "override"]
    return {
        "week": week, "gates": rows,
        "overrides": [
            {k: e.get(k) for k in ("gate", "repo", "pr", "sha", "actor", "reason", "rules", "agent_pr", "comment_url")}
            for e in overrides
        ],
        "log_head": {
            "seq": len(entries), "hash": entries[-1]["entry_hash"] if entries else GENESIS,
        },
    }


def percent(value):
    return "n/a" if value is None else "%.0f%%" % (value * 100)


def safe(value):
    """Keep free text from breaking the table or pinging people."""
    return re.sub(r"\s+", " ", str(value)).replace("|", "\\|").replace("@", "@​")


def markdown(report):
    lines = [
        "# Gate override report: %s" % report["week"], "",
        "| Gate | Blocked | Overridden | Rate | Previous | Rejected attempts | Status |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in report["gates"]:
        status = "**needs tuning**" if row["needs_tuning"] else ("rising" if row["rising"] else "ok")
        lines.append("| %s | %d | %d | %s | %s | %d | %s |" % (
            safe(row["gate"]), row["blocked"], row["overridden"], percent(row["override_rate"]),
            percent(row["previous_rate"]), row["rejected_attempts"], status,
        ))
    if not report["gates"]:
        lines.append("| none | 0 | 0 | n/a | n/a | 0 | ok |")
    lines += ["", "## Overrides to review", ""]
    lines += ["- %s on %s#%s (`%s`) by %s: %s" % (
        safe(o["gate"]), safe(o["repo"]), o["pr"], str(o["sha"])[:12], safe(o["actor"]), safe(o["reason"]),
    ) for o in report["overrides"]] or ["None this week."]
    lines += ["", "Log head: `%d:%s`" % (report["log_head"]["seq"], report["log_head"]["hash"]), ""]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    add_store_arguments(parser)
    parser.add_argument("--week")
    parser.add_argument("--tune-min", type=int, default=3)
    parser.add_argument("--output-md")
    parser.add_argument("--output-json")
    args = parser.parse_args()
    today = datetime.datetime.now(datetime.timezone.utc).date()
    week = args.week or label_for(today - datetime.timedelta(days=7))
    report = build(parse_chain(store_from(args).read()[0]), week, args.tune_min)
    text = markdown(report)
    if args.output_md:
        with open(args.output_md, "w", encoding="utf-8") as handle:
            handle.write(text)
    else:
        sys.stdout.write(text)
    if args.output_json:
        with open(args.output_json, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, sort_keys=True)
    return 0


if __name__ == "__main__":
    run(main)
