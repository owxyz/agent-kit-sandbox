"""The patch applies to kit's current files, and the docs match what is built."""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

from helpers import LIMITS, METRICS, NOW, REPO, ROOT, FakeGitHub, Workspace, store_module

import check_limits
from agentmetrics import costs

try:
    import yaml
except ImportError:
    yaml = None

GUIDE = (LIMITS / "docs" / "pilot-team-guide.md").read_text()
ANNOUNCE = (LIMITS / "docs" / "announcement-draft.md").read_text()
AGENDA = (LIMITS / "docs" / "office-hours-agenda.md").read_text()
README = (LIMITS / "README.md").read_text()
PATCH = LIMITS / "integration" / "agent-preflight.patch"


class Patched(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.workflows = os.path.join(cls.tmp.name, ".github", "workflows")
        os.makedirs(cls.workflows)
        for name in ("agent-preflight.yml", "agent-run.example.yml"):
            shutil.copy(ROOT / "kit" / "workflows" / name, cls.workflows)
        with open(PATCH) as patch:
            cls.done = subprocess.run(["patch", "-p1", "-d", cls.workflows], stdin=patch, capture_output=True, text=True)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def load(self, name):
        with open(os.path.join(self.workflows, name)) as handle:
            return yaml.safe_load(handle)

    def test_patch_applies_cleanly_to_current_kit(self):
        self.assertEqual(self.done.returncode, 0, self.done.stdout + self.done.stderr)
        self.assertNotIn("fuzz", self.done.stdout)

    @unittest.skipUnless(shutil.which("actionlint"), "actionlint not installed")
    def test_actionlint_accepts_patched_workflows(self):
        done = subprocess.run(["actionlint", "agent-preflight.yml", "agent-run.example.yml"], cwd=self.workflows, capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)

    @unittest.skipUnless(yaml, "PyYAML not installed")
    def test_kit_linters_accept_patched_workflows(self):
        for script in ("lint_agent_workflows.py", "check_action_pins.py"):
            done = subprocess.run([sys.executable, "-B", str(ROOT / "kit" / "scripts" / script), self.workflows], capture_output=True, text=True)
            self.assertEqual(done.returncode, 0, script + done.stdout + done.stderr)

    @unittest.skipUnless(yaml, "PyYAML not installed")
    def test_outputs_come_from_the_limits_step_and_it_runs_last(self):
        job = self.load("agent-preflight.yml")["jobs"]["gate"]
        self.assertEqual(job["outputs"]["allowed"], "${{ steps.limits.outputs.allowed }}")
        self.assertEqual(job["steps"][-1]["id"], "limits")
        self.assertEqual(job["steps"][0]["id"], "decision")
        self.assertEqual(job["permissions"]["actions"], "read")
        self.assertNotIn("if", job["steps"][-1], "the step must not run after an earlier failure")

    @unittest.skipUnless(yaml, "PyYAML not installed")
    def test_limits_code_comes_from_the_default_branch(self):
        checkout = self.load("agent-preflight.yml")["jobs"]["gate"]["steps"][1]
        self.assertEqual(checkout["with"]["ref"], "${{ github.event.repository.default_branch }}")
        self.assertIs(checkout["with"]["persist-credentials"], False)

    def test_restore_picks_the_newest_store(self):
        # Live proof, 2026-11-10: the artifact list isn't ordered by age, so
        # per_page=1 restored an older store and a spent budget passed.
        text = PATCH.read_text()
        self.assertNotIn("per_page=1\"", text)
        self.assertNotIn(".artifacts[0]", text)
        self.assertIn("sort | tail -n 1", text)

    def test_checkout_pin_is_kits_existing_pin(self):
        kit = (ROOT / "kit" / "workflows" / "agent-run.example.yml").read_text()
        pins = set(re.findall(r"actions/checkout@([0-9a-f]{40})", PATCH.read_text()))
        self.assertEqual(len(pins), 1)
        self.assertIn(pins.pop(), kit)


class RealCostImport(unittest.TestCase):
    def test_usage_imported_by_metrics_is_what_the_budget_reads(self):
        ws = Workspace(used=None)
        self.addCleanup(ws.close)
        path = os.path.join(ws.dir, "usage.csv")
        with open(path, "w") as handle:
            handle.write("record_id,date,agent,input_tokens,output_tokens,source\n")
            handle.write("a,%s,claude,700,300,provider-export\n" % NOW.date().isoformat())
        costs.import_costs(ws.conn, path)
        with FakeGitHub() as gh:
            gh.state.add_run(500)
            logs = []
            code = check_limits.main(["--config", ws.config, "--db", ws.db, "--agent", "claude"],
                                     env={"GITHUB_API_URL": gh.url, "GITHUB_TOKEN": "t", "GITHUB_REPOSITORY": REPO, "GITHUB_RUN_ID": "500"},
                                     log=logs.append, metrics=METRICS, now=NOW, sleep=lambda _: None)
        self.assertEqual(code, 1)
        self.assertTrue(any('"rule": "budget_spent"' in line for line in logs))


class DocsMatchBuild(unittest.TestCase):
    def test_rule_count_and_warn_only_claim(self):
        text = (ROOT / "gates" / "tamper" / "rules.yml").read_text()
        modes = re.findall(r"^  [a-z-]+:\s+\{mode: (\w+),", text, re.M)
        self.assertEqual(len(modes), 25)
        self.assertEqual(set(modes), {"warn"})
        self.assertIn("all 25 rules ship in warn mode", GUIDE)

    def test_override_claims_match_wired_gates(self):
        wired = set()
        for path in (ROOT / "gates").glob("*/workflows/*.yml"):
            wired.update(re.findall(r"apply_override\.py\s+--gate (\w+)", path.read_text()))
        self.assertEqual(wired, {"tamper", "integrity"})
        self.assertIn("**Available for:** `tamper` and `integrity`", GUIDE)

    def test_override_thresholds_match_code(self):
        code = (ROOT / "gates" / "integrity" / "scripts" / "apply_override.py").read_text()
        self.assertIn("MIN_REASON_CHARS = 20", code)
        self.assertIn("MIN_REASON_WORDS = 3", code)
        self.assertIn("if len(sha) < 7", code)
        self.assertIn("at least 20 characters and 3 words", GUIDE)
        self.assertIn("first 7 characters", GUIDE)

    def test_repeat_runs_really_block_humans_and_coverage_does_not(self):
        scripts = ROOT / "gates" / "test-quality" / "scripts"
        self.assertIn('MODE = "block"', (scripts / "repeat_runs_gate.py").read_text())
        self.assertIn("mode_for", (scripts / "coverage_gate.py").read_text())

    def test_handoffs_are_described_as_not_built(self):
        for root in ("kit", "gates"):
            hits = subprocess.run(["grep", "-rIil", "--exclude-dir=tests", "handoff", str(ROOT / root)], capture_output=True, text=True)
            self.assertEqual(hits.stdout, "", "a handoff now exists; update the guide")
        self.assertIn("isn't part of the gates today", GUIDE)

    def test_unproven_items_are_marked(self):
        self.assertGreaterEqual(GUIDE.count("Not proven"), 8)
        self.assertIn("Still being proven", ANNOUNCE)
        self.assertIn("What to say isn't proven", AGENDA)

    def test_drafts_say_they_were_not_sent_or_held(self):
        self.assertIn("NOT SENT", ANNOUNCE)
        self.assertIn("No session has been scheduled or held", AGENDA)

    def test_guide_review_queue_and_alert_match_config(self):
        data = json.loads((LIMITS / "config" / "limits.json").read_text())
        self.assertEqual((data["review_queue"]["max_waiting_prs"], data["budget"]["alert_percent"]), (3, 80))
        self.assertIn("3 PRs waiting", GUIDE)
        self.assertIn("80%", GUIDE)

    def test_readme_maps_every_ticket_criterion(self):
        for phrase in ("per-repo cap", "conflict rate stays under target", "alerts at 80%", "3 of its PRs wait", "announced to pilot teams", "overrides and handoffs", "Office hours are held"):
            self.assertIn(phrase, README)

    def test_readme_files_exist(self):
        for path in re.findall(r"`((?:scripts|config|integration|docs)/[\w./-]+\.\w+)`", README):
            self.assertTrue((LIMITS / path).exists(), path)


if __name__ == "__main__":
    unittest.main()
