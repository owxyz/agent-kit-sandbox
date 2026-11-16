#!/usr/bin/env python3
"""flag-for-human: stop and ask a person instead of forcing a pass (P2.8).

Agents call this when the spec and the tests conflict. The flag goes to the
gateway outside the sandbox, so the agent can't edit or delete the record.
"""
import argparse
import json
import os
import sys
import urllib.error
import urllib.request

KINDS = ("spec-test-conflict", "spec-unclear", "blocked-other")


def build_parser():
    parser = argparse.ArgumentParser(prog="flag-for-human", description=__doc__.splitlines()[0])
    parser.add_argument("--kind", choices=KINDS, default="spec-test-conflict")
    parser.add_argument("--summary", required=True, help="One line: what conflicts")
    parser.add_argument("--spec", help="Where the spec says it (issue, doc, quote)")
    parser.add_argument("--test", help="The test that disagrees, e.g. tests/test_x.py::test_y")
    parser.add_argument("--detail", default="", help="What you tried and what you need decided")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.kind == "spec-test-conflict" and not (args.spec and args.test):
        parser.error("spec-test-conflict needs both --spec and --test")
    url = os.environ.get("FLAG_FOR_HUMAN_URL")
    if not url:
        print("flag-for-human: FLAG_FOR_HUMAN_URL is not set; this only works in the sandbox. "
              "Stop and report the conflict in your final message.", file=sys.stderr)
        return 2
    flag = {"kind": args.kind, "summary": args.summary, "spec": args.spec or "",
            "test": args.test or "", "detail": args.detail}
    request = urllib.request.Request(
        url, data=json.dumps(flag).encode(), method="POST",
        headers={"Content-Type": "application/json"},
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=30):
            pass
    except (urllib.error.URLError, OSError) as exc:
        print("flag-for-human: could not record the flag ({}). Stop and report the conflict "
              "in your final message.".format(exc), file=sys.stderr)
        return 2
    print("Flag recorded. A human will decide. Stop now: do not change the test or the "
          "code to force a pass.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
