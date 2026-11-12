#!/usr/bin/env python3
"""P2.11: every new test also runs against the base code; bug-fix tests must fail there."""
from __future__ import annotations

from tq.adapters import make_adapters
from tq.core import common_parser, finding, gate_main, load_config, mode_for, parse_bool
from tq.workspace import Workspace, require_full_sha

RULE = "P2.11/"
SEED = 20240229


def body(args):
    require_full_sha(args.base_sha, "--base-sha")
    require_full_sha(args.head_sha, "--head-sha")
    cfg = load_config(args.config)
    mode, bug_fix = mode_for(parse_bool(args.agent_pr)), parse_bool(args.bug_fix)
    findings, any_new = [], False
    with Workspace(args.repo, args.base_sha, args.head_sha, parse_bool(args.owner_approved)) as ws:
        for adapter in make_adapters(cfg, args.python, args.jest_bin, ws.base_harness_tree()):
            if not any(adapter.owns(p) and adapter.is_test_path(p) for p in ws.changes):
                continue
            changed = adapter.changed_tests(ws, ws.scratch("discover"))
            for path, reason in sorted(changed.load_errors.items()):
                findings.append(finding(RULE + "new-test-not-passing-on-pr", mode, path, 0, reason[:500]))
            if not changed.new:
                continue
            any_new = True
            pr_result = adapter.run(ws.pr_tree(), ws.scratch("pr"), SEED, changed=changed)
            base_result = adapter.run(ws.base_tree_with_tests(adapter.is_test_path), ws.scratch("base"),
                                      SEED, changed=changed)
            for test_id in sorted(changed.new):
                on_pr, on_base = pr_result.status(test_id), base_result.status(test_id)
                file_part, line = test_id.split("::", 1)[0], changed.lines.get(test_id, 0)
                print("%s: base=%s pr=%s" % (test_id, on_base, on_pr))
                if on_pr != "passed":
                    findings.append(finding(RULE + "new-test-not-passing-on-pr", mode, file_part, line,
                                            "%s is %s on the PR" % (test_id, on_pr)))
                    continue
                if on_base == "passed":
                    if bug_fix:
                        findings.append(finding(RULE + "bugfix-test-passes-on-base", mode, file_part, line,
                                                "%s passes without the fix, so it does not prove it" % test_id))
                    else:
                        findings.append(finding(RULE + "new-test-passes-on-base", "warn", file_part, line,
                                                "%s passes on base too; it may not exercise the change" % test_id))
                elif on_base == "load_error" and bug_fix:
                    findings.append(finding(RULE + "base-failed-to-load", "warn", file_part, line,
                                            "%s could not load on base, which is weaker evidence than an "
                                            "assertion failure" % test_id))
                elif on_base in ("skipped", "not_run") and bug_fix:
                    findings.append(finding(RULE + "bugfix-test-not-run-on-base", mode, file_part, line,
                                            "%s is %s on base, so failure before the fix is unproven"
                                            % (test_id, on_base)))
    if bug_fix and not any_new:
        findings.append(finding(RULE + "bugfix-without-new-test", "warn", "", 0,
                                "PR is classified as a bug fix but adds no new test"))
    return findings


if __name__ == "__main__":
    parser = common_parser(__doc__)
    parser.add_argument("--bug-fix", required=True, help="true or false, from pr_context.py")
    gate_main(parser, body)
