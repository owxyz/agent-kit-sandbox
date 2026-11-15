"""R2.6: the agent register check, external agents in the register, and the copy installed on a repo."""
import contextlib
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import date

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
import check_agents  # noqa: E402
import pilot_copy  # noqa: E402
import validate  # noqa: E402
import yamlite  # noqa: E402

REGISTER = os.path.join(ROOT, "autonomy-register.yaml")
TEMPLATE = os.path.join(ROOT, "templates", "agent-register-check.yml")

PLAIN = "name: ci\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make test\n"


def workflow_with(step):
    return ("name: agent\non: [workflow_dispatch]\npermissions: {}\njobs:\n  run:\n    runs-on: ubuntu-latest\n"
            "    permissions:\n      contents: read\n    steps:\n" + step)


CODEX = workflow_with("      - uses: openai/codex-action@0123456789abcdef0123456789abcdef01234567\n")
CLAUDE = workflow_with("      - uses: anthropics/claude-code-action@0123456789abcdef0123456789abcdef01234567\n")
CURSOR_CLI = workflow_with("      - run: cursor-agent -p 'fix the bug'\n")
GEMINI_CLI = workflow_with("      - run: npx @google/gemini-cli -p 'review'\n")


class Repos(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="agents-check-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def repo(self, name, workflows):
        root = os.path.join(self.tmp, name)
        folder = os.path.join(root, ".github", "workflows")
        os.makedirs(folder)
        for filename, text in workflows.items():
            with open(os.path.join(folder, filename), "w") as handle:
                handle.write(text)
        return root

    def run_check(self, base, head, register=REGISTER):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = check_agents.main(["--register", register, "--base", self.repo("base", base),
                                      "--head", self.repo("head", head)])
        return code, out.getvalue()


class CheckAgents(Repos):
    def test_adding_an_unregistered_agent_fails(self):
        code, out = self.run_check({"ci.yml": PLAIN}, {"ci.yml": PLAIN, "codex.yml": CODEX})
        self.assertEqual(code, 1)
        self.assertIn("`codex` in `.github/workflows/codex.yml`", out)
        self.assertIn("::error file=.github/workflows/codex.yml::agent 'codex'", out)

    def test_adding_a_registered_agent_passes(self):
        code, out = self.run_check({"ci.yml": PLAIN}, {"ci.yml": PLAIN, "claude.yml": CLAUDE})
        self.assertEqual(code, 0, out)
        self.assertIn("every agent this PR adds is in the register", out)

    def test_cursor_is_registered(self):
        code, out = self.run_check({}, {"cursor.yml": CURSOR_CLI})
        self.assertEqual(code, 0, out)

    def test_an_agent_in_a_run_step_counts(self):
        code, out = self.run_check({}, {"gemini.yml": GEMINI_CLI})
        self.assertEqual(code, 1)
        self.assertIn("gemini-cli", out)

    def test_agent_already_on_base_is_reported_not_failed(self):
        code, out = self.run_check({"codex.yml": CODEX}, {"codex.yml": CODEX, "ci.yml": PLAIN})
        self.assertEqual(code, 0, out)
        self.assertIn("Already on the base branch and not registered", out)

    def test_copying_an_unregistered_agent_into_a_new_workflow_fails(self):
        code, out = self.run_check({"codex.yml": CODEX}, {"codex.yml": CODEX, "codex2.yml": CODEX})
        self.assertEqual(code, 1)
        self.assertIn("codex2.yml", out)

    def test_no_agent_change_passes(self):
        code, out = self.run_check({"ci.yml": PLAIN}, {"ci.yml": PLAIN + "# comment\n"})
        self.assertEqual(code, 0, out)
        self.assertIn("adds no agent", out)

    def test_unreadable_register_is_a_tool_error(self):
        code, _ = self.run_check({}, {"codex.yml": CODEX}, register=os.path.join(self.tmp, "missing.yaml"))
        self.assertEqual(code, 2)

    def test_register_without_ids_is_a_tool_error(self):
        broken = os.path.join(self.tmp, "broken.yaml")
        with open(broken, "w") as handle:
            handle.write("schema_version: 1\nagents:\n  - job: no id\nother_secret_holders: []\n")
        code, _ = self.run_check({}, {"codex.yml": CODEX}, register=broken)
        self.assertEqual(code, 2)

    def test_unparsable_workflow_is_still_scanned(self):
        code, out = self.run_check({}, {"bad.yml": CODEX + "  : [\n"})
        self.assertEqual(code, 1, out)


class ExternalAgents(unittest.TestCase):
    def setUp(self):
        with open(REGISTER) as handle:
            self.document = yamlite.load(handle.read())

    def check(self, document):
        report = validate.Report()
        validate.validate_register(document, date(2026, 11, 14), report)
        return [issue["message"] for issue in report.issues if issue["category"] == "error"]

    def test_cursor_and_claude_web_are_registered_as_external(self):
        kinds = {h["id"]: h["type"] for h in self.document["other_secret_holders"]}
        self.assertEqual(kinds["cursor-agent"], "external-agent")
        self.assertEqual(kinds["claude-code-web"], "external-agent")
        self.assertEqual(kinds["claude-code"], "coding-agent")

    def test_external_agents_need_no_secrets(self):
        self.assertEqual(self.check(self.document), [])

    def test_an_external_agent_holding_a_key_is_an_error(self):
        self.document["secrets"].append(dict(self.document["secrets"][0], id="cursor-key", holder="cursor-agent"))
        self.assertTrue(any("external agent" in m for m in self.check(self.document)))

    def test_no_email_in_external_entries(self):
        # The register is also published on the public sandbox.
        for holder in self.document["other_secret_holders"]:
            self.assertNotRegex(holder["description"], r"@[\w.-]+\.\w+", holder["id"])


class PilotCopy(Repos):
    def target(self):
        root = os.path.join(self.tmp, "target")
        os.makedirs(root)
        subprocess.run(["git", "init", "-q", root], check=True)
        return root

    def quiet(self, *argv):
        with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()):
            code = pilot_copy.main(list(argv))
        return code, out.getvalue()

    def test_install_then_check_is_in_step(self):
        target = self.target()
        self.assertEqual(self.quiet(target)[0], 0)
        self.assertEqual(self.quiet(target, "--check")[0], 0)

    def test_check_reports_a_changed_file(self):
        target = self.target()
        self.quiet(target)
        with open(os.path.join(target, pilot_copy.DEST, "autonomy-register.yaml"), "a") as handle:
            handle.write("# edited on the target\n")
        code, out = self.quiet(target, "--check")
        self.assertEqual(code, 1)
        self.assertIn("differs: autonomy-register.yaml", out)

    def test_check_reports_missing_and_extra_files(self):
        target = self.target()
        self.quiet(target)
        os.remove(os.path.join(target, pilot_copy.DEST, "check_agents.py"))
        with open(os.path.join(target, pilot_copy.DEST, "local.py"), "w") as handle:
            handle.write("x = 1\n")
        code, out = self.quiet(target, "--check")
        self.assertEqual(code, 1)
        self.assertIn("missing: check_agents.py", out)
        self.assertIn("extra: local.py", out)

    def test_target_must_be_a_git_checkout(self):
        self.assertEqual(self.quiet(self.tmp)[0], 2)

    def test_installed_copy_runs_the_check(self):
        target = self.target()
        self.quiet(target)
        copy = os.path.join(target, pilot_copy.DEST)
        head = self.repo("head", {"codex.yml": CODEX})
        base = self.repo("base", {})
        done = subprocess.run([sys.executable, os.path.join(copy, "check_agents.py"), "--register",
                               os.path.join(copy, "autonomy-register.yaml"), "--base", base, "--head", head],
                              capture_output=True, text=True)
        self.assertEqual(done.returncode, 1, done.stderr)
        done = subprocess.run([sys.executable, os.path.join(copy, "validate.py"), "register",
                               os.path.join(copy, "autonomy-register.yaml"), "--allow-incomplete"],
                              capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)


class Template(unittest.TestCase):
    def setUp(self):
        with open(TEMPLATE) as handle:
            self.text = handle.read()

    def test_actions_are_pinned(self):
        uses = re.findall(r"uses:\s*(\S+)", self.text)
        self.assertTrue(uses)
        for ref in uses:
            self.assertRegex(ref, r"@[0-9a-f]{40}$")

    def test_scripts_and_register_come_from_the_base_branch(self):
        for name in ("check_agents.py", "validate.py", "autonomy-register.yaml"):
            self.assertIn(".trusted/" + pilot_copy.DEST + "/" + name, self.text)
        self.assertIn("ref: ${{ github.event.pull_request.base.sha }}", self.text)
        self.assertNotIn("pull_request_target", self.text)
        self.assertNotIn("secrets.", self.text)

    def test_every_installed_file_is_in_the_copy(self):
        for name in ("check_agents.py", "validate.py", "autonomy-register.yaml"):
            self.assertIn(name, pilot_copy.FILES)


if __name__ == "__main__":
    unittest.main()
