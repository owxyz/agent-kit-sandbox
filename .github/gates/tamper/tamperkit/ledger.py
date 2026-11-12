"""Append-only record of reviewer verdicts, and per-rule false-positive rates.

One JSON object per line, keyed by (repo, pr, rule). The newest row for a key
wins, so a verdict is corrected by appending. Rates are per flagged PR, as the
plan's exit gate defines them.
"""
from __future__ import annotations

import datetime
import json
import os
from typing import Any, Dict, List, Tuple

PENDING = "pending"
FALSE_POSITIVE = "false_positive"
CONFIRMED_HACK = "confirmed_hack"
VERDICTS = {PENDING, FALSE_POSITIVE, CONFIRMED_HACK}
_FIELDS = ("repo", "pr", "rule", "verdict", "by", "note", "at")


class LedgerError(Exception):
    pass


Key = Tuple[str, int, str]


def read(path: str) -> Dict[Key, Dict[str, Any]]:
    """Return the latest row per key. A corrupt row stops the report."""
    latest: Dict[Key, Dict[str, Any]] = {}
    if not os.path.exists(path):
        return latest
    with open(path, encoding="utf-8") as handle:
        for number, raw in enumerate(handle, 1):
            if not raw.strip():
                continue
            try:
                row = json.loads(raw)
            except ValueError as error:
                raise LedgerError(f"{path}:{number}: not JSON") from error
            if (
                not isinstance(row, dict) or set(row) != set(_FIELDS) or row["verdict"] not in VERDICTS
                or not isinstance(row["pr"], int) or isinstance(row["pr"], bool)
                or not isinstance(row["repo"], str) or not isinstance(row["rule"], str)
            ):
                raise LedgerError(f"{path}:{number}: invalid row")
            latest[(row["repo"], row["pr"], row["rule"])] = row
    return latest


def append(path: str, repo: str, pr: int, rule: str, verdict: str, by: str, note: str = "") -> None:
    if verdict not in VERDICTS:
        raise LedgerError(f"unknown verdict {verdict}")
    if not repo or pr <= 0 or not by:
        raise LedgerError("repo, a positive PR number and a reviewer are required")
    row = {
        "repo": repo, "pr": pr, "rule": rule, "verdict": verdict, "by": by, "note": note,
        "at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, sort_keys=True) + "\n")


def ingest(path: str, repo: str, pr: int, findings: List[Dict[str, Any]], known_rules) -> int:
    """Record each flagged rule on a PR as pending, keeping existing verdicts."""
    existing = read(path)
    if not isinstance(findings, list) or not all(isinstance(item, dict) for item in findings):
        raise LedgerError("findings must be a list of objects")
    rules = sorted({str(item.get("rule")) for item in findings})
    if "tool-error" in rules:
        raise LedgerError("findings record a tool error; nothing was evaluated")
    unknown = [rule for rule in rules if rule not in known_rules]
    if unknown:
        raise LedgerError(f"unknown rules in findings: {unknown}")
    added = 0
    for rule in rules:
        if (repo, pr, rule) not in existing:
            append(path, repo, pr, rule, PENDING, "tamper-check", "flagged, awaiting review")
            added += 1
    return added


def report(rows: Dict[Key, Dict[str, Any]], config: Dict[str, Any]) -> List[Dict[str, Any]]:
    bar = config["promotion"]["false_positive_bar"]
    minimum = config["promotion"]["min_judged_prs"]
    results = []
    for rule, entry in config["rules"].items():
        verdicts = [row["verdict"] for key, row in rows.items() if key[2] == rule]
        false_positives = verdicts.count(FALSE_POSITIVE)
        hacks = verdicts.count(CONFIRMED_HACK)
        pending = verdicts.count(PENDING)
        judged = false_positives + hacks
        rate = false_positives / judged if judged else None
        if not verdicts:
            status = "no-data"
        elif pending:
            status = "needs-review"
        elif judged < minimum:
            status = "insufficient-sample"
        else:
            status = "meets-bar" if rate < bar else "over-bar"
        results.append({
            "rule": rule, "category": entry["category"], "mode": entry["mode"], "intended": entry["intended"],
            "flagged_prs": len(verdicts), "false_positives": false_positives, "confirmed_hacks": hacks,
            "pending": pending, "false_positive_rate": rate, "status": status,
        })
    return results


def format_table(results: List[Dict[str, Any]], bar: float) -> str:
    header = f"False-positive report (bar: under {bar:.0%} of judged flagged PRs)"
    columns = f"{'rule':<30}{'mode':<7}{'intended':<18}{'flagged':>8}{'FP':>5}{'hack':>6}{'pend':>6}{'FP rate':>9}  status"
    lines = [header, columns]
    for item in results:
        rate = "-" if item["false_positive_rate"] is None else f"{item['false_positive_rate']:.1%}"
        lines.append(
            f"{item['rule']:<30}{item['mode']:<7}{item['intended']:<18}{item['flagged_prs']:>8}"
            f"{item['false_positives']:>5}{item['confirmed_hacks']:>6}{item['pending']:>6}{rate:>9}  {item['status']}"
        )
    return "\n".join(lines)
