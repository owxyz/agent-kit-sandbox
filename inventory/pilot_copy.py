#!/usr/bin/env python3
"""Install, or check, the copy of the register and its checker on a repo that uses agents (R2.6).

The master register lives here, in inventory/. A repo that runs the agent register check, such as the pilot,
holds a copy at .github/agent-kit/inventory/ so its workflow needs no token for this private repo. The copy
is always these exact files; change them here and re-run this script, never on the target.

On a new repo, merge the copy in its own PR before adding templates/agent-register-check.yml: the check
runs the checker from the base branch, so the PR that installs it can't check itself.

  python3 inventory/pilot_copy.py TARGET_REPO_DIR            # write the copy
  python3 inventory/pilot_copy.py TARGET_REPO_DIR --check    # exit 1 if it differs from the master

Exit 0 in step, 1 drifted (with --check), 2 tool error.
"""
import argparse
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEST = os.path.join(".github", "agent-kit", "inventory")
FILES = (
    "autonomy-register.yaml",
    "check_agents.py",
    "scan_workflows.py",
    "schemalite.py",
    "validate.py",
    "yamlite.py",
    os.path.join("schemas", "autonomy-register.schema.json"),
    os.path.join("schemas", "manual-credentials.schema.json"),
)


def _read(path):
    with open(path, "rb") as handle:
        return handle.read()


def drift(target):
    """Paths under the copy that are missing, different or extra."""
    root = os.path.join(target, DEST)
    problems = []
    for name in FILES:
        copied = os.path.join(root, name)
        if not os.path.isfile(copied) or os.path.islink(copied):
            problems.append("missing: " + name)
        elif _read(copied) != _read(os.path.join(HERE, name)):
            problems.append("differs: " + name)
    if os.path.isdir(root):
        wanted = set(FILES)
        for folder, _dirs, names in os.walk(root):
            for name in names:
                relative = os.path.relpath(os.path.join(folder, name), root)
                if relative not in wanted and "__pycache__" not in relative.split(os.sep):
                    problems.append("extra: " + relative)
    return sorted(problems)


def install(target):
    root = os.path.join(target, DEST)
    for name in FILES:
        destination = os.path.join(root, name)
        os.makedirs(os.path.dirname(destination), exist_ok=True)
        shutil.copyfile(os.path.join(HERE, name), destination)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("target", help="checkout of the repo that holds the copy")
    parser.add_argument("--check", action="store_true", help="only compare; don't write")
    args = parser.parse_args(argv)
    if not os.path.isdir(os.path.join(args.target, ".git")) and not os.path.isfile(os.path.join(args.target, ".git")):
        print("TOOL ERROR: {} is not a git checkout".format(args.target), file=sys.stderr)
        return 2
    try:
        if not args.check:
            install(args.target)
        problems = drift(args.target)
    except OSError as error:
        print("TOOL ERROR: {}".format(error), file=sys.stderr)
        return 2
    for problem in problems:
        print(problem)
    if problems:
        return 1
    print("in step: {} files at {}".format(len(FILES), DEST))
    return 0


if __name__ == "__main__":
    sys.exit(main())
