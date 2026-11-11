"""Regression tests for the second review of the inventory tooling."""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import scan_workflows as scanner  # noqa: E402
import yamlite  # noqa: E402

PRT = "on: pull_request_target\npermissions: {}\njobs:\n  a:\n    runs-on: x\n"


def write(root, relative, text):
    path = os.path.join(root, relative)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as handle:
        handle.write(text)
    return path


def scan_one(text, extra=None):
    with tempfile.TemporaryDirectory() as root:
        write(root, ".github/workflows/w.yml", text)
        if extra:
            extra(root)
        return scanner.scan(root)["repos"][0]["workflows"][0]


def prt_flag(job_body):
    workflow = scan_one(PRT + job_body)
    return {f["code"]: f for f in workflow["flags"]}["pull-request-target"]


def checkout(ref=None, repository=None):
    lines = "    steps:\n      - uses: actions/checkout@v4\n"
    inputs = {k: v for k, v in (("ref", ref), ("repository", repository)) if v is not None}
    if inputs:
        lines += "        with:\n" + "".join("          {}: {}\n".format(k, v) for k, v in inputs.items())
    return lines


class EnvIndirectionTests(unittest.TestCase):
    def test_job_env_carrying_pr_ref_into_git_is_critical(self):
        flag = prt_flag("    env:\n      HEAD_REF: ${{ github.head_ref }}\n    steps:\n"
                        "      - run: git fetch origin \"$HEAD_REF\" && git checkout FETCH_HEAD\n")
        self.assertEqual(flag["severity"], "critical")

    def test_step_and_workflow_env_are_tracked(self):
        step = prt_flag("    steps:\n      - run: git checkout ${PR_SHA}\n"
                        "        env:\n          PR_SHA: ${{ github.event.pull_request.head.sha }}\n")
        self.assertEqual(step["severity"], "critical")
        top = scan_one("on: pull_request_target\npermissions: {}\nenv:\n  N: ${{ github.event.number }}\n"
                       "jobs:\n  a:\n    runs-on: x\n    steps:\n      - run: git fetch origin refs/heads/main $N\n")
        self.assertEqual({f["code"]: f["severity"] for f in top["flags"]}["pull-request-target"], "critical")

    def test_untainted_env_in_git_stays_high(self):
        flag = prt_flag("    env:\n      BRANCH: main\n    steps:\n      - run: git fetch origin \"$BRANCH\"\n")
        self.assertEqual(flag["severity"], "high")


class CheckoutAllowlistTests(unittest.TestCase):
    def test_base_refs_stay_high(self):
        for ref in (None, "main", "${{ github.event.pull_request.base.sha }}",
                    "${{ github.event.pull_request.base.sha || github.event.merge_group.base_sha }}",
                    "${{ github.event.repository.default_branch }}"):
            with self.subTest(ref=ref):
                self.assertEqual(prt_flag(checkout(ref=ref))["severity"], "high")

    def test_unprovable_refs_are_critical(self):
        for ref in ("${{ env.PR_SHA }}", "${{ inputs.ref }}", "${{ steps.pr.outputs.sha }}",
                    "refs/heads/${{ github.event.pull_request.title }}"):
            with self.subTest(ref=ref):
                flag = prt_flag(checkout(ref=ref))
                self.assertEqual(flag["severity"], "critical")
                self.assertIn("cannot prove", flag["detail"])

    def test_other_repository_is_critical(self):
        self.assertEqual(prt_flag(checkout(repository="${{ env.FORK }}"))["severity"], "critical")
        self.assertEqual(prt_flag(checkout(repository="${{ github.repository }}"))["severity"], "high")


class CommandSplitTests(unittest.TestCase):
    def test_pr_expression_in_another_command_stays_high(self):
        flag = prt_flag("    steps:\n      - run: git fetch origin main && echo \"${{ github.head_ref }}\"\n")
        self.assertEqual(flag["severity"], "high")

    def test_backslash_continued_fetch_is_critical(self):
        flag = prt_flag("    steps:\n      - run: |\n          git fetch origin \\\n            pull/1/head\n")
        self.assertEqual(flag["severity"], "critical")


class LocalActionTests(unittest.TestCase):
    STEP = ("on: push\npermissions: {}\njobs:\n  a:\n    runs-on: x\n    steps:\n"
            "      - uses: ./.github/actions/x\n")

    def test_symlinked_actions_folder_is_not_read(self):
        def link(root):
            write(root, "elsewhere/x/action.yml", "runs:\n  using: composite\n  steps:\n    - run: claude -p hi\n      shell: bash\n")
            os.symlink(os.path.join(root, "elsewhere"), os.path.join(root, ".github", "actions"))
        workflow = scan_one(self.STEP, link)
        self.assertFalse(workflow["is_agent"])
        self.assertIn("local-action-not-read", [f["code"] for f in workflow["flags"]])

    def test_missing_action_is_flagged(self):
        workflow = scan_one(self.STEP)
        self.assertIn("local-action-not-read", [f["code"] for f in workflow["flags"]])


class FoldTests(unittest.TestCase):
    def test_blank_lines_next_to_indented_lines_are_kept(self):
        self.assertEqual(yamlite.load("a: >\n  x\n\n    y\n\n  z\n"), {"a": "x\n\n  y\n\nz\n"})

    def test_leading_blank_line_is_kept(self):
        self.assertEqual(yamlite.load("a: >\n\n  x\n"), {"a": "\nx\n"})


@unittest.skipUnless(shutil.which("bash") and shutil.which("python3"), "needs bash")
class AlertJobTests(unittest.TestCase):
    """Run the alert job's script against a stand-in for gh; nothing reaches GitHub."""

    STUB = """#!/bin/bash
case "$1 $2" in
  "issue list") echo list >> "$STUB/calls"; [ -f "$STUB/list_fails" ] && exit 1; cat "$STUB/existing" ;;
  "issue create")
    shift 2
    while [ $# -gt 0 ]; do [ "$1" = --title ] && title=$2; shift; done
    case "$title" in *first*) exit 1 ;; esac
    echo "$title" >> "$STUB/created" ;;
esac
"""
    VALIDATOR = """import sys
print("due soon\\tfirst-key\\t@a\\trotation is due in 3 day(s)")
print("overdue\\tsecond-key\\t@b\\trotation is 2 day(s) overdue")
sys.exit(1)
"""

    def run_job(self, root, list_fails=False):
        with open(os.path.join(ROOT, "templates", "register-check.yml")) as handle:
            job = yamlite.load(handle.read())["jobs"]["rotation-alert"]
        write(root, "w/inventory/validate.py", self.VALIDATOR)
        os.chmod(write(root, "bin/gh", self.STUB), 0o755)
        write(root, "existing", "")
        if list_fails:
            write(root, "list_fails", "")
        env = dict(os.environ, STUB=root, PATH=os.path.join(root, "bin") + os.pathsep + os.environ["PATH"])
        result = subprocess.run(["bash", "-e", "-c", job["steps"][1]["run"]], cwd=os.path.join(root, "w"),
                                env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL)
        created = os.path.join(root, "created")
        with open(created) if os.path.exists(created) else open(os.devnull) as handle:
            titles = handle.read().splitlines()
        with open(os.path.join(root, "calls")) if os.path.exists(os.path.join(root, "calls")) else open(os.devnull) as handle:
            calls = handle.read().splitlines()
        return result.returncode, titles, calls

    def test_one_list_call_and_a_failed_create_does_not_stop_later_alerts(self):
        with tempfile.TemporaryDirectory() as root:
            code, titles, calls = self.run_job(root)
        self.assertEqual(calls, ["list"])
        self.assertEqual(titles, ["Agent secret rotation overdue: second-key"])
        self.assertEqual(code, 1)

    def test_failed_list_creates_nothing(self):
        with tempfile.TemporaryDirectory() as root:
            code, titles, _ = self.run_job(root, list_fails=True)
        self.assertNotEqual(code, 0)
        self.assertEqual(titles, [])


if __name__ == "__main__":
    unittest.main()
