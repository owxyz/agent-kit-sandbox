#!/usr/bin/env python3
"""P2.3 changed-code gate: branch coverage, error paths and new coverage exclusions."""
from __future__ import annotations

from tq.adapters import make_adapters, unsupported_paths
from tq.core import common_parser, finding, gate_main, load_config, mode_for, parse_bool
from tq.errorsites import inside
from tq.gitdiff import ignored
from tq.workspace import Workspace, require_full_sha

RULE = "P2.3/"


def _exclusions(adapter, sources, mode, approved):
    found = []
    for path, change in sources.items():
        for line, content in sorted(change.added.items()):
            if adapter.exclusion_re.search(content):
                if approved:
                    print("exclusion approved by owner: %s:%d" % (path, line))
                else:
                    found.append(finding(RULE + "new-coverage-exclusion", mode, path, line,
                                         "new coverage-exclusion comment needs owner approval"))
    return found


def _error_paths(adapter, path, change, cov, source, mode):
    found, changed = [], change.changed_lines
    for site in adapter.error_sites(source):
        if not changed & set(range(site.span[0], site.span[1] + 1)):
            continue
        if site.line in cov.excluded:
            continue
        points = [executed for point, executed in cov.points.items() if inside(point, site.probe)]
        if not points:
            found.append(finding(RULE + "error-path-unverifiable", "warn", path, site.line,
                                 "%s has no instrumented statement, so execution cannot be proven" % site.kind))
        elif not any(points):
            found.append(finding(RULE + "error-path-unexecuted", mode, path, site.line,
                                 "changed %s was not run by any test" % site.kind))
    return found


def body(args):
    require_full_sha(args.base_sha, "--base-sha")
    require_full_sha(args.head_sha, "--head-sha")
    cfg = load_config(args.config)
    mode, approved = mode_for(parse_bool(args.agent_pr)), parse_bool(args.owner_approved)
    threshold, findings = cfg["branch_threshold_percent"], []
    with Workspace(args.repo, args.base_sha, args.head_sha, approved) as ws:
        adapters = make_adapters(cfg, args.python, args.jest_bin, ws.base_harness_tree())
        live = {p: c for p, c in ws.changes.items() if c.status != "D" and not ignored(p, cfg["ignore_globs"])}
        for path in unsupported_paths(live, adapters):
            findings.append(finding(RULE + "no-language-adapter", "warn", path, 0,
                                    "changed file has no test-quality adapter, so it was not measured"))
        total = covered = 0
        uncovered, unexecuted = [], []
        for adapter in adapters:
            sources = {p: c for p, c in live.items() if adapter.is_source_path(p) and c.added}
            if not sources:
                continue
            findings += _exclusions(adapter, sources, mode, approved)
            report, tests_failed = adapter.coverage(ws.pr_tree(), sources, ws.scratch("cov"))
            if tests_failed:
                findings.append(finding(RULE + "tests-failed-during-coverage", mode, "", 0,
                                        "%s tests failed, so coverage from this run is not trustworthy" % adapter.name))
            for path, change in sorted(sources.items()):
                cov = report.get(path)
                if cov is None:
                    findings.append(finding(RULE + "file-not-measured", mode, path, 0,
                                            "changed source file is missing from the coverage report"))
                    continue
                if cov.parse_error:
                    findings.append(finding(RULE + "source-unparseable", mode, path, 0, cov.parse_error))
                    continue
                for branch in cov.branches:
                    if branch.lines & change.changed_lines:
                        total += branch.total
                        covered += branch.covered
                        if branch.covered < branch.total:
                            uncovered.append((path, branch))
                unexecuted += [(path, line) for (line, _col), hit in sorted(cov.points.items())
                               if not hit and line in change.changed_lines]
                findings += _error_paths(adapter, path, change, cov, ws.show(ws.head_sha, path), mode)
    percent = 100.0 * covered / total if total else 100.0
    print("changed branches: %d/%d (%.1f%%), threshold %d%%" % (covered, total, percent, threshold))
    if total and percent < threshold:
        findings.append(finding(RULE + "branch-coverage-below-threshold", mode, "", 0,
                                "%d of %d changed branches ran (%.1f%%); at least %d%% is required"
                                % (covered, total, percent, threshold)))
        for path, branch in uncovered:
            findings.append(finding(RULE + "uncovered-branch", mode, path, branch.line,
                                    "%d of %d outcomes ran" % (branch.covered, branch.total)))
    if unexecuted:
        # With no changed branches the threshold is vacuous, so unrun straight-line code must not pass.
        line_mode = mode if not total else "warn"
        for path, line in sorted(set(unexecuted)):
            findings.append(finding(RULE + "unexecuted-changed-line", line_mode, path, line,
                                    "changed line was not run by any test"))
    return findings


if __name__ == "__main__":
    gate_main(common_parser(__doc__), body)
