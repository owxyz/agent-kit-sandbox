#!/usr/bin/env python3
"""Tamper-check CLI (ticket P2.2).

Exit codes: 0 nothing blocks, 1 a block-mode finding exists, 2 tool error.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from tamperkit import apidiff, engine

DEFAULT_CONFIG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules.yml")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=DEFAULT_CONFIG, help="Rule modes; always read from the base branch")
    parser.add_argument("--diff", help="Unified diff file")
    parser.add_argument("--allow-empty", action="store_true", help="Accept an empty --diff file")
    parser.add_argument("--repo", help="Git repo holding --base and --head; files are not executed")
    parser.add_argument("--api-repo", help="owner/name; read both commits through the API, using GITHUB_TOKEN")
    parser.add_argument("--merge-base", action="store_true", help="With --api-repo, diff from the merge base of --base and --head")
    parser.add_argument("--base", help="Full base commit SHA")
    parser.add_argument("--head", help="Full head commit SHA")
    parser.add_argument("--pr-class", choices=("agent", "human"), default="agent",
                        help="human reports every finding as warn; agent is the fail-closed default")
    parser.add_argument("--output", help="Write findings JSON here (default stdout)")
    parser.add_argument("--annotate", action="store_true", help="Print GitHub annotations")
    parser.add_argument("--summary", help="Append a Markdown summary to this file")
    return parser


def collect(args: argparse.Namespace) -> list:
    config = engine.load_config(args.config)
    max_bytes = config["limits"]["max_diff_bytes"]
    if sum(bool(item) for item in (args.diff, args.repo, args.api_repo)) != 1:
        raise engine.ToolError("give exactly one of --diff, --repo or --api-repo")
    if args.diff:
        text = engine.read_diff_file(args.diff, max_bytes)
        if not text.strip() and not args.allow_empty:
            raise engine.ToolError("diff file is empty; pass --allow-empty if that is expected")
    else:
        if not args.base or not args.head:
            raise engine.ToolError("--repo and --api-repo need --base and --head")
        if not engine.SHA_RE.match(args.base) or not engine.SHA_RE.match(args.head):
            raise engine.ToolError("base and head must be full commit SHAs")
        if args.repo:
            text = engine.read_git_diff(args.repo, args.base, args.head, max_bytes)
        else:
            get = apidiff.api_getter(
                args.api_repo, os.environ.get("GITHUB_TOKEN", ""), os.environ.get("GITHUB_API_URL", "https://api.github.com")
            )
            base = apidiff.merge_base(get, args.base, args.head) if args.merge_base else args.base
            text = apidiff.build_diff(get, base, args.head, config["limits"]["max_api_files"], max_bytes)
    return engine.run(text, config, args.pr_class)


def emit(args: argparse.Namespace, findings: list) -> None:
    payload = json.dumps(findings, indent=2, ensure_ascii=True) + "\n"
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(payload)
    else:
        sys.stdout.write(payload)
    if args.annotate:
        for finding in findings:
            print(engine.annotation(finding), file=sys.stdout if args.output else sys.stderr)
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as handle:
            handle.write(engine.summary_markdown(findings))


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        findings = collect(args)
        status = 1 if any(item["mode"] == "block" for item in findings) else 0
    except engine.ToolError as error:
        findings = [engine.tool_error_finding(str(error))]
        status = 2
    except Exception as error:  # A crash must never read as a pass.
        findings = [engine.tool_error_finding(f"internal error: {type(error).__name__}: {error}")]
        status = 2
    try:
        emit(args, findings)
    except OSError as error:
        print(f"tamper-check: cannot write results: {error}", file=sys.stderr)
        return 2
    return status


if __name__ == "__main__":
    sys.exit(main())
