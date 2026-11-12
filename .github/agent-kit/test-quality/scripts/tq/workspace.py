"""Throwaway source trees built from git objects, so nothing untracked is ever measured."""
from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

from .core import ToolError, run, text
from .gitdiff import changed_files, git, resolve_merge_base

HARNESS_FILES = {"conftest.py"}


class Workspace:
    """Exports commits with a private index, which ignores export-ignore in .gitattributes."""

    def __init__(self, repo, base_sha, head_sha, harness_approved=False):
        self.repo = str(Path(repo).resolve())
        self.base_sha, self.head_sha = base_sha, head_sha
        self.harness_approved = harness_approved
        self.merge_base = resolve_merge_base(self.repo, base_sha, head_sha)
        self.changes = changed_files(self.repo, self.merge_base, head_sha)
        self.tmp = Path(os.path.realpath(tempfile.mkdtemp(prefix="tq-")))
        self._count = 0
        self._cache = {}

    def close(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()

    def scratch(self, name="s"):
        self._count += 1
        path = self.tmp / ("%s-%d" % (name, self._count))
        path.mkdir(parents=True)
        return path

    def _export(self, rev):
        if rev not in self._cache:
            dest = self.scratch("export")
            index = self.tmp / ("index-%s" % rev)
            env = dict(os.environ, GIT_INDEX_FILE=str(index))
            git(self.repo, "read-tree", rev, env=env)
            git(self.repo, "checkout-index", "-a", "--prefix=%s/" % dest, env=env)
            self._cache[rev] = dest
        return self._cache[rev]

    def show(self, rev, path):
        """Return a file's text at a revision, or None when it is absent there."""
        done = run(["git", "-C", self.repo, "-c", "core.quotepath=false", "show", "%s:%s" % (rev, path)])
        return text(done.stdout) if done.returncode == 0 else None

    def base_harness_tree(self):
        return self._export(self.base_sha)

    def _copy(self, source):
        dest = self.scratch("tree") / "repo"
        shutil.copytree(source, dest, symlinks=True)
        return Path(os.path.realpath(dest))

    def _overlay_harness(self, tree):
        """conftest.py runs inside pytest, so it comes from the base branch unless an owner approved."""
        if self.harness_approved:
            return
        base = self.base_harness_tree()
        for found in list(tree.rglob("conftest.py")):
            rel = found.relative_to(tree)
            if (base / rel).is_file():
                shutil.copy2(base / rel, found)
            else:
                found.unlink()
        for found in base.rglob("conftest.py"):
            rel = found.relative_to(base)
            if not (tree / rel).exists():
                (tree / rel).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(found, tree / rel)

    def _link_deps(self, tree):
        modules = Path(self.repo) / "node_modules"
        if modules.is_dir() and not (tree / "node_modules").exists():
            (tree / "node_modules").symlink_to(modules, target_is_directory=True)

    def pr_tree(self):
        tree = self._copy(self._export(self.head_sha))
        self._overlay_harness(tree)
        self._link_deps(tree)
        return tree

    def base_tree_with_tests(self, is_test_path):
        """The code as it was before the PR, plus the PR's versions of its test files."""
        tree = self._copy(self._export(self.merge_base))
        head = self._export(self.head_sha)
        for path, change in self.changes.items():
            if change.status != "D" and is_test_path(path) and Path(path).name not in HARNESS_FILES:
                (tree / path).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(head / path, tree / path)
        self._overlay_harness(tree)
        self._link_deps(tree)
        return tree

    def merge_base_tree(self):
        tree = self._copy(self._export(self.merge_base))
        self._overlay_harness(tree)
        self._link_deps(tree)
        return tree


def require_full_sha(value, name):
    if len(value) != 40 or set(value) - set("0123456789abcdef"):
        raise ToolError("%s must be a full commit SHA, got %r" % (name, value))
