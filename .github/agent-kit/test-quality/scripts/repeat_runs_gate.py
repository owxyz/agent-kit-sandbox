#!/usr/bin/env python3
"""P2.4 repeat runs: every new or modified test, N isolated randomized runs, no retries."""
from __future__ import annotations

import hashlib

from tq.adapters import make_adapters
from tq.core import ToolError, common_parser, finding, gate_main, load_config, parse_bool
from tq.gitdiff import ignored
from tq.workspace import Workspace, require_full_sha

RULE = "P2.4/"
MODE = "block"  # the ticket says any failure blocks the PR, so this applies to human PRs too


def seed_for(head_sha, round_number):
    """Reproducible per commit, so a failing round can be replayed."""
    return int(hashlib.sha256(("%s:%d" % (head_sha, round_number)).encode()).hexdigest(), 16) % 2147483647


def body(args):
    require_full_sha(args.base_sha, "--base-sha")
    require_full_sha(args.head_sha, "--head-sha")
    cfg = load_config(args.config)
    parse_bool(args.agent_pr)  # validated for a uniform CLI; this gate blocks everyone
    runs, findings = cfg["repeat_runs"], []
    with Workspace(args.repo, args.base_sha, args.head_sha, parse_bool(args.owner_approved)) as ws:
        for adapter in make_adapters(cfg, args.python, args.jest_bin, ws.base_harness_tree()):
            if not any(adapter.owns(p) and adapter.is_test_path(p) for p in ws.changes):
                continue
            for path, change in sorted(ws.changes.items()):
                if change.status == "D" or not adapter.owns(path) or not adapter.is_test_path(path):
                    continue
                for line, content in sorted(change.added.items()):
                    if adapter.retry_re.search(content):
                        findings.append(finding(RULE + "retry-in-test", MODE, path, line,
                                                "retries never count as a pass; remove the retry"))
            changed = adapter.changed_tests(ws, ws.scratch("discover"))
            for path, reason in sorted(changed.load_errors.items()):
                findings.append(finding(RULE + "test-file-failed-to-load", MODE, path, 0, reason[:500]))
            wanted = {t for t in changed.wanted if not ignored(t.split("::", 1)[0], cfg["ignore_globs"])}
            if not wanted:
                continue
            print("%s: %d test(s) x %d runs" % (adapter.name, len(wanted), runs))
            fails, skips, retried, load_fails = {}, {}, {}, {}
            for number in range(1, runs + 1):
                seed = seed_for(args.head_sha, number)
                tree, scratch = ws.pr_tree(), ws.scratch("round")
                result = adapter.run(tree, scratch, seed, changed=changed)
                for test_id in wanted:
                    status = result.status(test_id)
                    if status == "failed":
                        fails.setdefault(test_id, []).append(seed)
                    elif status == "skipped":
                        skips[test_id] = skips.get(test_id, 0) + 1
                    elif status == "load_error":
                        load_fails.setdefault(test_id.split("::", 1)[0], []).append(seed)
                    elif status == "not_run":
                        raise ToolError("%s reported no result in run %d (seed %d); a crash or exit is "
                                        "not a pass" % (test_id, number, seed))
                    if any(o.get("invocations", 1) > 1 for o in result.matching(test_id)):
                        retried[test_id] = True
            for test_id in sorted(wanted):
                file_part = test_id.split("::", 1)[0]
                line = changed.lines.get(test_id, 0)
                if test_id in fails:
                    seeds = fails[test_id]
                    kind = "test-always-fails" if len(seeds) == runs else "flaky-test"
                    findings.append(finding(RULE + kind, MODE, file_part, line, "%s failed %d of %d runs (seeds %s)"
                                            % (test_id, len(seeds), runs, ",".join(map(str, seeds[:5])))))
                if test_id in retried:
                    findings.append(finding(RULE + "test-retried", MODE, file_part, line,
                                            "%s was retried by the runner; retries never count" % test_id))
                if skips.get(test_id) == runs and (adapter.granularity == "test" or test_id in changed.new):
                    findings.append(finding(RULE + "test-never-ran", MODE, file_part, line,
                                            "%s was skipped in every run; a skip is not a pass" % test_id))
            for file_part, seeds in sorted(load_fails.items()):
                findings.append(finding(RULE + "test-file-failed-to-load", MODE, file_part, 0,
                                        "failed to load in %d run(s)" % len(set(seeds))))
    return findings


if __name__ == "__main__":
    gate_main(common_parser(__doc__), body)
