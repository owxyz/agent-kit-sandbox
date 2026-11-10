#!/usr/bin/env python3
"""Copy agent context, prompts and MCP config out of a base commit (P0.4).

Usage: load_agent_config.py --repo . --base-ref REF --dest NEW_DIR

Reads git objects only, so the working tree and any PR branch have no effect.
Symlinks are skipped, because a link could point outside the base commit.
Writes manifest.json listing the base commit and every file copied.
"""
import argparse
import fnmatch
import json
import os
import subprocess
import sys

ANY_DEPTH_NAMES = {"AGENTS.md", "AGENTS.override.md", "AGENT.md", "CLAUDE.md", "CLAUDE.local.md",
                   "GEMINI.md", ".cursorrules", ".mcp.json"}
PATH_PATTERNS = (
    ".github/copilot-instructions.md",
    ".github/instructions/*",
    ".github/prompts/*",
    ".github/agents/*",
    ".github/agent-kit/prompts/*",
    ".github/agent-kit/approved-mcp-servers.json",
    ".claude/*",
    ".cursor/*",
    ".codex/*",
    ".gemini/*",
    ".vscode/mcp.json",
)
SYMLINK_MODE = "120000"
REGULAR_MODES = ("100644", "100755")


def is_agent_config(path):
    if os.path.basename(path) in ANY_DEPTH_NAMES:
        return True
    return any(fnmatch.fnmatch(path, pattern) for pattern in PATH_PATTERNS)


def git(repo, *args):
    return subprocess.run(["git", "-C", repo] + list(args), check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout


def list_tree(repo, commit):
    """Yield (mode, object id, path) for each blob in the commit."""
    for record in git(repo, "ls-tree", "-r", "-z", "--full-tree", commit).split(b"\0"):
        if record:
            meta, path = record.split(b"\t", 1)
            mode, _kind, object_id = meta.decode().split()
            yield mode, object_id, path.decode("utf-8", "surrogateescape")


def load(repo, base_ref, dest):
    commit = git(repo, "rev-parse", "--verify", base_ref + "^{commit}").decode().strip()
    os.makedirs(dest, exist_ok=True)
    if os.listdir(dest):
        raise ValueError("destination must be empty")
    copied, skipped = [], []
    root = os.path.realpath(dest)
    for mode, object_id, path in list_tree(repo, commit):
        if not is_agent_config(path):
            continue
        if mode == SYMLINK_MODE or mode not in REGULAR_MODES:
            skipped.append(path)
            continue
        target = os.path.realpath(os.path.join(root, path))
        if not target.startswith(root + os.sep):
            skipped.append(path)
            continue
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "wb") as handle:
            handle.write(git(repo, "cat-file", "blob", object_id))
        copied.append(path)
    manifest = {"base_commit": commit, "files": copied, "skipped": skipped}
    with open(os.path.join(root, "manifest.json"), "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=".")
    parser.add_argument("--base-ref", required=True)
    parser.add_argument("--dest", required=True)
    args = parser.parse_args()
    try:
        manifest = load(args.repo, args.base_ref, args.dest)
    except (subprocess.CalledProcessError, ValueError, OSError) as error:
        print("Could not load agent config: %s" % type(error).__name__, file=sys.stderr)
        return 1
    print("Loaded %d file(s) from %s; skipped %d."
          % (len(manifest["files"]), manifest["base_commit"], len(manifest["skipped"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
