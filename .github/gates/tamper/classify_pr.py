#!/usr/bin/env python3
"""Print `agent` or `human` for a PR. Any failure prints `agent` (fail closed).

Standard library only, so it can run before dependencies are installed.
"""
from __future__ import annotations

import argparse
import json
import sys

from tamperkit import classify


def load(path: str):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pr", required=True, help="JSON from GET /repos/{repo}/pulls/{number}")
    parser.add_argument("--commits", required=True, help="JSON from .../pulls/{number}/commits")
    parser.add_argument("--events", required=True, help="JSON from .../issues/{number}/events")
    parser.add_argument("--agent-logins", default="", help="Comma-separated agent logins")
    args = parser.parse_args(argv)
    try:
        pr = load(args.pr)
        if not isinstance(pr, dict):
            raise ValueError("expected an object")
        result, signals = classify.classify(
            pr,
            classify.flatten_pages(load(args.commits)),
            classify.flatten_pages(load(args.events)),
            classify.parse_logins(args.agent_logins),
        )
    except Exception as error:  # A failed lookup must never lower the PR's class.
        print(f"classify: {type(error).__name__}; treating as agent", file=sys.stderr)
        print("agent")
        return 0
    print("classify: signals " + (",".join(signals) or "none"), file=sys.stderr)
    print(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
