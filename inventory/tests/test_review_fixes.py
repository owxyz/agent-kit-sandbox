"""Regression tests for the review findings on the inventory tooling."""
import contextlib
import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import scan_workflows as scanner  # noqa: E402
import validate  # noqa: E402
import yamlite  # noqa: E402

PRT = "on: pull_request_target\npermissions: {}\njobs:\n  a:\n    runs-on: x\n    steps:\n"


def write(root, relative, text):
    path = os.path.join(root, relative)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as handle:
        handle.write(text)
    return path


def prt_severity(steps):
    with tempfile.TemporaryDirectory() as root:
        write(root, ".github/workflows/w.yml", PRT + steps)
        workflow = scanner.scan(root)["repos"][0]["workflows"][0]
    return {f["code"]: f["severity"] for f in workflow["flags"]}["pull-request-target"]


class PullRequestCodeTests(unittest.TestCase):
    def test_merge_commit_checkout_is_critical(self):
        self.assertEqual(prt_severity(
            "      - uses: actions/checkout@v4\n        with:\n"
            "          ref: ${{ github.event.pull_request.merge_commit_sha }}\n"), "critical")

    def test_shell_checkout_of_pr_is_critical(self):
        for run in ("gh pr checkout ${{ github.event.number }}",
                    "git fetch origin pull/${{ github.event.number }}/head",
                    "git checkout ${{ github.head_ref }}"):
            with self.subTest(run=run):
                self.assertEqual(prt_severity("      - run: " + run + "\n"), "critical")

    def test_commented_or_unrelated_commands_stay_high(self):
        self.assertEqual(prt_severity("      - run: |\n          # gh pr checkout 1\n          echo hi\n"), "high")
        self.assertEqual(prt_severity("      - run: echo \"${{ github.head_ref }}\"\n"), "high")


class SymlinkTests(unittest.TestCase):
    def test_symlinked_repo_folder_is_scanned(self):
        with tempfile.TemporaryDirectory() as root:
            write(root, "real/r/.github/workflows/w.yml",
                  "on: push\npermissions: {}\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: claude -p hi\n")
            os.makedirs(os.path.join(root, "repos"))
            os.symlink(os.path.join(root, "real", "r"), os.path.join(root, "repos", "r"))
            report = scanner.scan(os.path.join(root, "repos"))
        self.assertEqual(report["summary"]["agent_workflows"], 1)

    def test_symlinked_workflows_folder_is_reported_not_read(self):
        with tempfile.TemporaryDirectory() as root:
            write(root, "elsewhere/w.yml", "on: push\njobs: {}\n# ${{ secrets.OUTSIDE }}\n")
            os.makedirs(os.path.join(root, "r", ".github"))
            os.symlink(os.path.join(root, "elsewhere"), os.path.join(root, "r", ".github", "workflows"))
            workflows = scanner.scan(os.path.join(root, "r"))["repos"][0]["workflows"]
        self.assertEqual(len(workflows), 1)
        self.assertFalse(workflows[0]["parsed"])
        self.assertEqual(workflows[0]["secrets"], [])
        self.assertIn("symlink", workflows[0]["flags"][0]["detail"])


class YamlDocumentTests(unittest.TestCase):
    def test_end_marker_after_mapping(self):
        self.assertEqual(yamlite.load("a: 1\nb:\n  c: 2\n...\n"), {"a": 1, "b": {"c": 2}})

    def test_second_document_after_mapping_is_named(self):
        with self.assertRaises(yamlite.YamlError) as caught:
            yamlite.load("a: 1\n---\nb: 2\n")
        self.assertIn("multiple YAML documents", caught.exception.reason)

    def test_folded_scalar_keeps_more_indented_lines(self):
        self.assertEqual(yamlite.load("a: >\n  x\n    y\n  z\n"), {"a": "x\n  y\nz\n"})
        self.assertEqual(yamlite.load("a: >\n  one\n  two\n\n  three\n"), {"a": "one two\nthree\n"})


class AlertFieldTests(unittest.TestCase):
    def test_blank_owner_is_incomplete(self):
        report = validate.Report()
        self.assertFalse(validate._require_known({"owner": "   "}, "owner", "$", report))
        self.assertEqual(report.issues[0]["message"], "is blank")

    def test_alert_owner_is_never_empty(self):
        self.assertEqual(validate._display_owner("   "), "(none)")


class SeedTests(unittest.TestCase):
    def test_existing_seed_refused_before_any_output(self):
        with tempfile.TemporaryDirectory() as root:
            seed = write(root, "seed.yaml", "kept\n")
            out = io.StringIO()
            with self.assertRaises(SystemExit), contextlib.redirect_stdout(out), \
                    contextlib.redirect_stderr(io.StringIO()):
                scanner.main([root, "--credentials-seed", seed])
            with open(seed) as handle:
                self.assertEqual(handle.read(), "kept\n")
        self.assertEqual(out.getvalue(), "")


@unittest.skipUnless(shutil.which("bash"), "needs bash")
class FetchScriptTests(unittest.TestCase):
    STUB = """#!/bin/bash
# Stand-in for gh: no network. Clone drains stdin, as a credential prompt might.
case "$1 $2" in
  "repo list") printf 'org/one\\norg/two\\n' ;;
  "repo clone") cat > /dev/null; mkdir -p "$4" ;;
  *) exit 0 ;;
esac
"""

    def test_every_repo_is_cloned_when_a_command_reads_stdin(self):
        with tempfile.TemporaryDirectory() as root:
            stub = write(root, "bin/gh", self.STUB)
            os.chmod(stub, 0o755)
            env = dict(os.environ, PATH=os.path.join(root, "bin") + os.pathsep + os.environ["PATH"])
            subprocess.run(["bash", os.path.join(ROOT, "fetch_inventory.sh"), "org", os.path.join(root, "out")],
                           env=env, check=True, stdout=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
            self.assertEqual(sorted(os.listdir(os.path.join(root, "out", "repos"))), ["one", "two"])


if __name__ == "__main__":
    unittest.main()
