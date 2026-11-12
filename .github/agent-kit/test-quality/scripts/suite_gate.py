#!/usr/bin/env python3
"""P2.4 suites: the blocking suite excludes quarantined tests; the quarantine suite never blocks."""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

from tq.adapters import make_adapters
from tq.core import ToolError, common_parser, finding, gate_main, load_config, parse_bool
from tq.workspace import Workspace, require_full_sha

RULE = "P2.4/"


def load_quarantine(path, today=None):
    """Return (active ids, findings). An expired entry is back in the blocking suite."""
    today = today or dt.date.today()
    try:
        data = json.loads(Path(path).read_text())
    except (OSError, ValueError) as exc:
        raise ToolError("cannot read quarantine list %s: %s" % (path, exc))
    active, findings = [], []
    for entry in data.get("tests", []):
        try:
            expired = dt.date.fromisoformat(entry["expires"]) < today
            test_id = entry["id"]
        except (KeyError, ValueError, TypeError) as exc:
            raise ToolError("bad quarantine entry %r: %s" % (entry, exc))
        if expired:
            findings.append(finding(RULE + "quarantine-expired", "warn", test_id.split("::", 1)[0], 0,
                                    "%s is past its quarantine date and blocks again" % test_id))
        else:
            active.append(test_id)
    return active, findings


def body(args):
    require_full_sha(args.base_sha, "--base-sha")
    require_full_sha(args.head_sha, "--head-sha")
    cfg = load_config(args.config)
    active, findings = load_quarantine(args.quarantine)
    quarantine_suite = args.suite == "quarantine"
    with Workspace(args.repo, args.base_sha, args.head_sha, parse_bool(args.owner_approved)) as ws:
        for adapter in make_adapters(cfg, args.python, args.jest_bin, ws.base_harness_tree()):
            tree = ws.pr_tree()
            if not adapter.detect(tree):
                continue
            mine = [t for t in active if adapter.owns(t.split("::", 1)[0])]
            if quarantine_suite and not mine:
                continue
            result = adapter.run(tree, ws.scratch("suite"), 1, deselect=() if quarantine_suite else mine,
                                 only=mine if quarantine_suite else ())
            mode = "warn" if quarantine_suite else "block"
            for test_id, outcome in sorted(result.outcomes.items()):
                if outcome["status"] == "failed":
                    findings.append(finding(RULE + "suite-test-failed", mode, test_id.split("::", 1)[0], 0,
                                            "%s failed in the %s suite" % (test_id, args.suite)))
            for path, reason in sorted(result.load_errors.items()):
                findings.append(finding(RULE + "test-file-failed-to-load", mode, path.split("::", 1)[0], 0, reason[:500]))
    return findings


if __name__ == "__main__":
    parser = common_parser(__doc__)
    parser.add_argument("--suite", choices=("blocking", "quarantine"), required=True)
    parser.add_argument("--quarantine", required=True, help="base-branch quarantine.json")
    gate_main(parser, body)
