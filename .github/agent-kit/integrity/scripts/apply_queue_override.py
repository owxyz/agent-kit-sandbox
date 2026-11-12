#!/usr/bin/env python3
"""Decide a gate's merge-queue result from overrides already audited on the PR (P2.7).

Usage: apply_queue_override.py --gate NAME --findings FILE --gate-exit N
           --repo OWNER/NAME --queue-ref REF
           (--audit-file PATH | --audit-repo OWNER/NAME)
           [--path-prefix P ...] [--output FILE]

Nobody can comment on a merge commit, so the queue honors only an override the
audit log recorded for the PR's current head. It covers a finding only if that
override listed the finding's rule and file, so anything new from the merge
still blocks. This script reads the log and never writes it.
"""
import argparse

from apply_override import load_findings, strip_prefix
from audit_log import add_store_arguments, parse_chain, store_from
from common import GitHub, ToolError, emit, pr_head_sha, queue_pr_number, run


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--gate", required=True)
    parser.add_argument("--findings", required=True)
    parser.add_argument("--gate-exit", type=int, required=True)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--queue-ref", required=True)
    parser.add_argument("--path-prefix", action="append", default=[])
    parser.add_argument("--output")
    add_store_arguments(parser)
    args = parser.parse_args()

    if args.gate_exit not in (0, 1):
        raise ToolError("gate exited %d; a tool error cannot be overridden" % args.gate_exit)
    findings = load_findings(args.findings, args.gate)
    blocks = [f for f in findings if f["mode"] == "block"]
    if bool(blocks) != (args.gate_exit == 1):
        raise ToolError("gate exit %d disagrees with its findings" % args.gate_exit)
    if not blocks:
        return emit(findings, args.output)

    number = queue_pr_number(args.queue_ref)
    head = pr_head_sha(GitHub(), args.repo, number)
    overrides = [
        e for e in parse_chain(store_from(args).read(allow_missing=True)[0])
        if e.get("event") == "override" and e.get("repo") == args.repo and e.get("pr") == number
        and e.get("sha") == head and e.get("gate") == args.gate
    ]

    def covering(item):
        path = strip_prefix(str(item["file"]), args.path_prefix)
        for entry in overrides:
            if item["rule"] in entry.get("rules", []) and path in entry.get("files", []):
                return entry
        return None

    decided = []
    for item in findings:
        entry = covering(item) if item["mode"] == "block" else None
        decided.append(
            dict(item, mode="warn", message="[overridden on PR by @%s] %s" % (entry["actor"], item["message"]))
            if entry else item
        )
    return emit(decided, args.output)


if __name__ == "__main__":
    run(main)
