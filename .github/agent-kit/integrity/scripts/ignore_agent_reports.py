#!/usr/bin/env python3
"""Delete report and coverage files from a PR checkout before CI computes its own (P2.9).

Usage: ignore_agent_reports.py ROOT [--keep GLOB ...] [--output FILE]

Each removal is a warn finding (ART001). The file can no longer affect the
result, so nothing blocks. --keep exempts paths such as real test fixtures; set
it in the base-branch workflow, never from anything in the PR.
"""
import argparse
import fnmatch
import os
import shutil

from common import ToolError, emit, finding, run

REPORT_FILES = (
    ".coverage", ".coverage.*", "coverage.xml", "coverage.json", "coverage-final.json",
    "coverage-summary.json", "cobertura*.xml", "clover.xml", "jacoco*.xml", "lcov.info", "*.lcov",
    "junit*.xml", "TEST-*.xml", "test-results*.xml", "test-report*.xml", "test-results*.json",
    "pytest-report*", "*.trx", "*.sarif",
)
REPORT_DIRS = ("htmlcov", ".nyc_output", "test-results", "test-reports", "surefire-reports")
SKIP_DIRS = {".git"}


def matches(name, patterns):
    return any(fnmatch.fnmatchcase(name, p) for p in patterns)


def remove(path):
    if os.path.isdir(path) and not os.path.islink(path):
        shutil.rmtree(path)
    else:
        os.remove(path)


def purge(root, keep):
    removed = []
    for current, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for names, patterns in ((list(dirs), REPORT_DIRS), (files, REPORT_FILES)):
            for name in names:
                relative = os.path.relpath(os.path.join(current, name), root)
                # A symlink to a directory is listed under dirs, whatever its name.
                link = os.path.islink(os.path.join(current, name))
                named = matches(name, patterns) or (link and matches(name, REPORT_FILES))
                if not named or matches(relative, keep):
                    continue
                remove(os.path.join(current, name))
                removed.append(relative)
                if name in dirs:
                    dirs.remove(name)
    return sorted(removed)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("root")
    parser.add_argument("--keep", action="append", default=[])
    parser.add_argument("--output")
    args = parser.parse_args()
    if not os.path.isdir(args.root):
        raise ToolError("%s is not a directory" % args.root)
    return emit([
        finding("ART001", "warn", path, 0, "Removed a report or coverage file supplied by the PR; CI computes its own.")
        for path in purge(args.root, args.keep)
    ], args.output)


if __name__ == "__main__":
    run(main)
