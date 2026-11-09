#!/usr/bin/env python3
"""Record tamper-rule verdicts and report false-positive rates per rule.

Exit codes: 0 ok, 1 --enforce found a blocking rule not at `meets-bar`, 2 error.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from tamperkit import engine, ledger

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_LEDGER = os.path.join(HERE, "ledger", "verdicts.jsonl")
DEFAULT_CONFIG = os.path.join(HERE, "rules.yml")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", default=DEFAULT_LEDGER)
    parser.add_argument("--config", default=DEFAULT_CONFIG)
    commands = parser.add_subparsers(dest="command", required=True)

    record = commands.add_parser("record", help="Record a reviewer's verdict")
    record.add_argument("--repo", required=True)
    record.add_argument("--pr", type=int, required=True)
    record.add_argument("--rule", required=True)
    record.add_argument("--verdict", required=True, choices=(ledger.FALSE_POSITIVE, ledger.CONFIRMED_HACK))
    record.add_argument("--by", required=True, help="Reviewer")
    record.add_argument("--note", default="")

    ingest = commands.add_parser("ingest", help="Record a findings file as pending reviews")
    ingest.add_argument("--repo", required=True)
    ingest.add_argument("--pr", type=int, required=True)
    ingest.add_argument("--findings", required=True)

    report = commands.add_parser("report", help="Per-rule false-positive report")
    report.add_argument("--json", action="store_true")
    report.add_argument("--enforce", action="store_true", help="Fail if a block-mode rule is not at meets-bar")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        config = engine.load_config(args.config)
        if not isinstance(config.get("promotion"), dict):
            raise ledger.LedgerError("config has no promotion section")
        if args.command == "record":
            if args.rule not in config["rules"]:
                raise ledger.LedgerError(f"unknown rule {args.rule}")
            ledger.append(args.ledger, args.repo, args.pr, args.rule, args.verdict, args.by, args.note)
            return 0
        if args.command == "ingest":
            with open(args.findings, encoding="utf-8") as handle:
                findings = json.load(handle)
            print(f"added {ledger.ingest(args.ledger, args.repo, args.pr, findings, config['rules'])} pending row(s)")
            return 0
        results = ledger.report(ledger.read(args.ledger), config)
        if args.json:
            print(json.dumps(results, indent=2))
        else:
            print(ledger.format_table(results, config["promotion"]["false_positive_bar"]))
        if args.enforce:
            failing = [item["rule"] for item in results if item["mode"] == "block" and item["status"] != "meets-bar"]
            if failing:
                print("blocking without meeting the bar: " + ", ".join(failing), file=sys.stderr)
                return 1
        return 0
    except (engine.ToolError, ledger.LedgerError, OSError, ValueError) as error:
        print(f"tamper-ledger: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
