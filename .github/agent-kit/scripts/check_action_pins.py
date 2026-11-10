#!/usr/bin/env python3
"""Require immutable pins for actions and exact versions for agent tooling.

Usage: check_action_pins.py PATH [PATH ...]    (exit 1 on any violation)

Paths are searched for workflow YAML, composite actions, and agent-tools
package.json manifests.

  PIN001  an action or reusable workflow is not pinned to a full commit SHA
  PIN002  a docker action is not pinned to a digest
  VER001  a command installs or runs a package without an exact version
  VER002  a remote script is piped straight into a shell
  VER003  an agent-tools manifest dependency is not an exact version
"""
import json
import os
import re
import shlex
import sys

from workflow_utils import find_yaml_files, jobs, load_yaml, steps

FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
ZERO_SHA = "0" * 40
NPM_PINNED = re.compile(r"^(@[^/@\s]+/)?[^/@\s]+@(\d+\.\d+\.\d+\S*|\$\S+)$")
PIP_PINNED = re.compile(r"^[A-Za-z0-9_.\-\[\],]+(==\d\S*|==\$\S+|@\d+\.\d+\S*)$")
EXACT_SEMVER = re.compile(r"^\d+\.\d+\.\d+([-+][0-9A-Za-z.\-+]+)?$")
PIPE_TO_SHELL = re.compile(r"\b(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(ba|z|da)?sh\b")
SHELL_SEPARATORS = {"&&", "||", ";", "|", "&"}
# (command words, kind) for commands that fetch and install or run a package.
INSTALLERS = [
    (("npm", "install"), "npm"), (("npm", "i"), "npm"), (("npm", "add"), "npm"),
    (("pnpm", "add"), "npm"), (("pnpm", "dlx"), "npm"), (("yarn", "add"), "npm"),
    (("yarn", "dlx"), "npm"), (("npx",), "npm"), (("bunx",), "npm"),
    (("pip", "install"), "pip"), (("pip3", "install"), "pip"),
    (("pipx", "install"), "pip"), (("pipx", "run"), "pip"),
    (("uvx",), "pip"), (("uv", "tool", "install"), "pip"), (("uv", "tool", "run"), "pip"),
]
FLAGS_WITH_VALUE = {"-r", "--requirement", "-c", "--constraint", "-e", "--editable",
                    "-t", "--target", "--prefix", "-i", "--index-url", "--python"}


def check_uses(path, where, value):
    value = str(value)
    if value.startswith("./"):
        return []
    if value.startswith("docker://"):
        if "@sha256:" in value:
            return []
        return ["%s: %s: PIN002: docker action needs a digest: %s" % (path, where, value)]
    ref = value.rpartition("@")[2] if "@" in value else ""
    if FULL_SHA.match(ref) and ref != ZERO_SHA:
        return []
    return ["%s: %s: PIN001: not pinned to a full commit SHA: %s" % (path, where, value)]


def tokenize(line):
    try:
        lexer = shlex.shlex(line, posix=True, punctuation_chars=";&|")
        lexer.whitespace_split = True
        lexer.commenters = "#"
        return list(lexer)
    except ValueError:
        return line.split()


def package_arguments(tokens):
    """Yield (kind, package) for every installer invocation in the tokens."""
    index = 0
    while index < len(tokens):
        for words, kind in INSTALLERS:
            if tuple(tokens[index:index + len(words)]) != words:
                continue
            position = index + len(words)
            runner = len(words) == 1 or words[-1] in ("dlx", "run")
            while position < len(tokens) and tokens[position] not in SHELL_SEPARATORS:
                token = tokens[position]
                position += 1
                if token in FLAGS_WITH_VALUE:
                    position += 1
                elif not token.startswith(("-", ".", "/")) and not token.endswith((".txt", ".whl")):
                    yield kind, token
                    if runner:
                        break  # Later tokens are the tool's own arguments.
            index = position - 1
            break
        index += 1


def check_run(path, where, script):
    found = []
    joined = re.sub(r"\\\n", " ", str(script))
    if PIPE_TO_SHELL.search(joined):
        found.append("%s: %s: VER002: remote script piped into a shell" % (path, where))
    for line in joined.splitlines():
        for kind, package in package_arguments(tokenize(line)):
            pinned = NPM_PINNED if kind == "npm" else PIP_PINNED
            if not pinned.match(package):
                found.append("%s: %s: VER001: no exact version: %s" % (path, where, package))
    return found


def check_workflow(path):
    try:
        document = load_yaml(path)
    except Exception as error:
        return ["%s: PARSE: %s" % (path, type(error).__name__)]
    if not isinstance(document, dict):
        return []
    found = []
    for job_id, job in jobs(document).items():
        if not isinstance(job, dict):
            continue
        if job.get("uses"):
            found.extend(check_uses(path, "job " + job_id, job["uses"]))
        for number, step in enumerate(steps(job), 1):
            where = "job %s step %d" % (job_id, number)
            if step.get("uses"):
                found.extend(check_uses(path, where, step["uses"]))
            if step.get("run"):
                found.extend(check_run(path, where, step["run"]))
    runs = document.get("runs")
    if isinstance(runs, dict):
        for number, step in enumerate(steps(runs), 1):
            where = "composite step %d" % number
            if step.get("uses"):
                found.extend(check_uses(path, where, step["uses"]))
            if step.get("run"):
                found.extend(check_run(path, where, step["run"]))
    return found


def check_manifest(path):
    try:
        with open(path, encoding="utf-8") as handle:
            manifest = json.load(handle)
    except Exception as error:
        return ["%s: PARSE: %s" % (path, type(error).__name__)]
    found = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, version in (manifest.get(section) or {}).items():
            if not EXACT_SEMVER.match(str(version)):
                found.append("%s: VER003: %s is not an exact version: %s" % (path, name, version))
    return found


def find_manifests(paths):
    manifests = []
    for path in paths:
        if os.path.isfile(path):
            continue
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in (".git", "node_modules")]
            if os.path.basename(root) == "agent-tools" and "package.json" in files:
                manifests.append(os.path.join(root, "package.json"))
    return sorted(manifests)


def main(argv):
    files = find_yaml_files(argv)
    manifests = find_manifests(argv)
    if not files and not manifests:
        print("No files found.", file=sys.stderr)
        return 1
    violations = [v for path in files for v in check_workflow(path)]
    violations += [v for path in manifests for v in check_manifest(path)]
    for violation in violations:
        print(violation)
    print("%d file(s) checked, %d violation(s)."
          % (len(files) + len(manifests), len(violations)))
    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
