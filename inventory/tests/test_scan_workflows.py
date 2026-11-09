import ast
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
import scan_workflows as scanner  # noqa: E402
import validate  # noqa: E402
import yamlite  # noqa: E402

FIXTURES = os.path.join(HERE, "fixtures", "repos")
ALPHA = ".github/workflows/"


def run_cli(*args):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = scanner.main(list(args))
    return code, out.getvalue()


def write(root, relative, text):
    path = os.path.join(root, relative)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as handle:
        handle.write(text)
    return path


class FixtureScanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = scanner.scan(FIXTURES)

    def workflow(self, repo, name):
        for item in self.report["repos"]:
            if item["repo"] == repo:
                for workflow in item["workflows"]:
                    if workflow["path"] == ALPHA + name:
                        return workflow
        self.fail("missing workflow " + name)

    def codes(self, workflow):
        return {flag["code"]: flag for flag in workflow["flags"]}

    def secrets(self, workflow):
        return {secret["name"]: secret["category"] for secret in workflow["secrets"]}

    def test_summary_counts(self):
        summary = self.report["summary"]
        self.assertEqual((summary["repos"], summary["workflows"], summary["agent_workflows"], summary["unparsed_workflows"]),
                         (3, 8, 6, 1))

    def test_agent_action_trigger_permissions_secrets(self):
        workflow = self.workflow("alpha-service", "claude-agent.yml")
        self.assertTrue(workflow["is_agent"])
        self.assertEqual(workflow["agents"], ["claude-code"])
        self.assertEqual(workflow["triggers"], ["issue_comment", "pull_request"])
        self.assertEqual(workflow["jobs"][0]["permissions"], {"contents": "write", "pull-requests": "write"})
        self.assertEqual(self.secrets(workflow), {
            "ANTHROPIC_API_KEY": "model-api-key", "ORG_GH_PAT": "pat", "GITHUB_TOKEN": "github-automatic"})
        codes = self.codes(workflow)
        self.assertIn("pat-style-secret", codes)
        self.assertEqual(codes["broad-token-contents-write"]["severity"], "medium")

    def test_non_agent_has_no_false_positives(self):
        workflow = self.workflow("alpha-service", "ci.yml")
        self.assertFalse(workflow["is_agent"])
        self.assertEqual(workflow["secrets"], [])

    def test_non_agent_secret_is_not_reported_as_followup(self):
        names = [entry["id"] for entry in self.report["credentials_to_inventory"]]
        self.assertNotIn("DOCS_UPLOAD_TOKEN", names)
        self.assertEqual(self.workflow("gamma-docs", "docs.yml")["jobs"][0]["permissions"], {})

    def test_pull_request_target_running_pr_code_is_critical(self):
        workflow = self.workflow("alpha-service", "prt-agent.yaml")
        codes = self.codes(workflow)
        self.assertEqual(codes["pull-request-target"]["severity"], "critical")
        self.assertEqual(codes["pull-request-target"]["jobs"], ["fix"])
        self.assertIn("broad-token-write-all", codes)
        self.assertIn("all-secrets-exposed", codes)
        self.assertIn("dynamic-secret-reference", codes)
        self.assertEqual(workflow["jobs"][0]["permissions"], "write-all")
        self.assertEqual(self.secrets(workflow), {"OPENAI_API_KEY": "model-api-key", "DEPLOY_SSH_KEY": "deploy-key"})

    def test_reusable_workflow_propagation(self):
        caller = self.workflow("beta-service", "caller.yml")
        callee = self.workflow("beta-service", "agent-reusable.yml")
        self.assertTrue(caller["is_agent"])
        self.assertEqual(caller["agents"], ["claude-code"])
        self.assertIn("secrets-inherit", self.codes(caller))
        self.assertIn("external-reusable-workflow", self.codes(caller))
        self.assertIn("broad-token-undeclared", self.codes(caller))
        self.assertEqual(callee["called_by"], [ALPHA + "caller.yml"])
        self.assertIn("pull_request_target", callee["effective_triggers"])
        self.assertEqual(self.codes(callee)["pull-request-target"]["severity"], "high")
        self.assertIn("broad-token-sensitive-scope", self.codes(callee))
        self.assertEqual(self.secrets(callee)["RELEASE_APP_PRIVATE_KEY"], "github-app-private-key")

    def test_local_composite_action_is_an_agent(self):
        workflow = self.workflow("beta-service", "composite.yml")
        self.assertEqual(workflow["agents"], ["claude-code"])
        self.assertEqual(workflow["triggers"], ["schedule"])
        self.assertIn("broad-token-undeclared", self.codes(workflow))

    def test_unparseable_file_is_reported_with_text_fallback(self):
        workflow = self.workflow("beta-service", "broken.yml")
        self.assertFalse(workflow["parsed"])
        self.assertEqual(workflow["triggers"], ["unknown"])
        self.assertEqual(workflow["agents"], ["gemini-cli"])
        self.assertIn("GEMINI_API_KEY", self.secrets(workflow))
        self.assertIn("parse-error", self.codes(workflow))

    def test_literal_values_are_never_output(self):
        for args in ([FIXTURES], [FIXTURES, "--format", "json"], [FIXTURES, "--all"]):
            _, output = run_cli(*args)
            self.assertNotIn("FAKE_LITERAL_VALUE_DO_NOT_PRINT", output)


class BehaviourTests(unittest.TestCase):
    def test_classify_secret(self):
        cases = {
            "GITHUB_TOKEN": "github-automatic", "gh_pat": "pat", "AGENT_PAT_2": "pat",
            "GH_TOKEN": "pat", "BOT_TOKEN": "pat", "PATH_PREFIX": "other", "SPATIAL_KEY": "other",
            "PATCH_TOKEN": "other", "OPENAI_API_KEY": "model-api-key", "CLAUDE_CODE_OAUTH_TOKEN": "model-api-key",
            "BOT_APP_PRIVATE_KEY": "github-app-private-key", "PROD_DEPLOY_KEY": "deploy-key",
            "AWS_SECRET_ACCESS_KEY": "cloud-key", "NPM_PUBLISH": "other",
        }
        for name, expected in cases.items():
            self.assertEqual(scanner.classify_secret(name), expected, name)

    def test_secret_expression_forms(self):
        findings = scanner._Findings()
        findings.scan_string("${{secrets.A}} ${{ secrets['B'] }} ${{ x || SECRETS.c }} secrets.NOT_IN_EXPRESSION", "j")
        findings.scan_string("secrets.D != ''", "j", implicit_expression=True)
        self.assertEqual(set(findings.secrets), {"A", "B", "C", "D"})

    def test_job_permissions_override_workflow(self):
        with tempfile.TemporaryDirectory() as root:
            write(root, "r/.github/workflows/w.yml",
                  "on: push\npermissions: write-all\njobs:\n  a:\n    permissions:\n      contents: read\n"
                  "    runs-on: x\n    steps:\n      - run: claude -p hi\n")
            workflow = scanner.scan(root)["repos"][0]["workflows"][0]
        self.assertEqual(workflow["jobs"][0]["permissions_source"], "job")
        self.assertEqual(workflow["flags"], [])

    def test_trigger_forms(self):
        self.assertEqual(list(scanner._triggers("push")), ["push"])
        self.assertEqual(list(scanner._triggers(["push", "issues"])), ["push", "issues"])
        self.assertEqual(list(scanner._triggers({"push": None})), ["push"])

    def test_commented_command_is_not_an_agent(self):
        with tempfile.TemporaryDirectory() as root:
            write(root, ".github/workflows/w.yml",
                  "on: push\npermissions: {}\njobs:\n  a:\n    runs-on: x\n    steps:\n"
                  "      - run: |\n          # claude -p hello\n          echo done\n")
            workflow = scanner.scan(root)["repos"][0]["workflows"][0]
        self.assertFalse(workflow["is_agent"])

    def test_command_after_a_comment_still_counts(self):
        with tempfile.TemporaryDirectory() as root:
            write(root, ".github/workflows/w.yml",
                  "on: push\npermissions: {}\njobs:\n  a:\n    runs-on: x\n    steps:\n"
                  "      - run: |\n          # run the agent\n          claude -p hello\n")
            workflow = scanner.scan(root)["repos"][0]["workflows"][0]
        self.assertEqual(workflow["agents"], ["claude-code"])

    def test_generic_agent_key_marks_agent_and_is_inventoried(self):
        self.assertEqual(scanner.classify_secret("AGENT_API_KEY"), "model-api-key")
        with tempfile.TemporaryDirectory() as root:
            write(root, ".github/workflows/w.yml",
                  "on: push\npermissions: {}\njobs:\n  a:\n    runs-on: x\n    steps:\n"
                  "      - run: ./bot\n        env:\n          K: ${{ secrets.AGENT_API_KEY }}\n")
            report = scanner.scan(root)
        self.assertEqual(report["repos"][0]["workflows"][0]["agents"], ["unidentified-model-client"])
        self.assertEqual([e["id"] for e in report["credentials_to_inventory"]], ["AGENT_API_KEY"])

    def test_other_secret_on_agent_workflow_is_inventoried(self):
        with tempfile.TemporaryDirectory() as root:
            write(root, ".github/workflows/w.yml",
                  "on: push\npermissions: {}\njobs:\n  a:\n    runs-on: x\n    steps:\n"
                  "      - run: claude -p hi\n        env:\n          K: ${{ secrets.DOCS_UPLOAD }}\n")
            entries = scanner.scan(root)["credentials_to_inventory"]
        self.assertEqual([(e["id"], e["kind"]) for e in entries], [("DOCS_UPLOAD", "other")])

    def test_agent_pattern_option(self):
        with tempfile.TemporaryDirectory() as root:
            write(root, ".github/workflows/w.yml",
                  "on: push\npermissions: {}\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: ./our-bot go\n")
            self.assertIn("no agent workflows", run_cli(root)[1])
            self.assertIn("AGENT", run_cli(root, "--agent-pattern", "our-bot")[1])

    def test_symlinked_workflow_is_not_followed(self):
        with tempfile.TemporaryDirectory() as root:
            outside = write(root, "outside.yml", "on: push\njobs: {}\n# ${{ secrets.OUTSIDE }}\n")
            link = os.path.join(root, "r", ".github", "workflows", "w.yml")
            os.makedirs(os.path.dirname(link))
            os.symlink(outside, link)
            workflow = scanner.scan(os.path.join(root, "r"))["repos"][0]["workflows"][0]
        self.assertFalse(workflow["parsed"])
        self.assertEqual(workflow["secrets"], [])

    def test_workflow_subdirectories_are_ignored(self):
        with tempfile.TemporaryDirectory() as root:
            write(root, "r/.github/workflows/sub/w.yml", "on: push\njobs: {}\n")
            self.assertEqual(scanner.scan(root)["summary"]["workflows"], 0)

    def test_fail_on_exit_code(self):
        self.assertEqual(run_cli(FIXTURES, "--fail-on", "critical")[0], 1)
        with tempfile.TemporaryDirectory() as root:
            write(root, ".github/workflows/w.yml", "on: push\npermissions: {}\njobs: {}\n")
            self.assertEqual(run_cli(root, "--fail-on", "low")[0], 0)

    def test_json_output_is_valid(self):
        self.assertEqual(json.loads(run_cli(FIXTURES, "--format", "json")[1])["schema_version"], 1)

    def test_seed_passes_schema_and_is_incomplete(self):
        with tempfile.TemporaryDirectory() as root:
            seed = os.path.join(root, "seed.yaml")
            self.assertEqual(run_cli(FIXTURES, "--credentials-seed", seed)[0], 0)
            with open(seed) as handle:
                document = yamlite.load(handle.read())
            report = validate.validate_document("credentials", document, __import__("datetime").date(2026, 11, 8))
            self.assertFalse(report.has("error"))
            self.assertTrue(report.has("incomplete"))
            ids = {entry["id"]: entry for entry in document["credentials"]}
            self.assertEqual(ids["ORG_GH_PAT"]["kind"], "pat")
            with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
                run_cli(FIXTURES, "--credentials-seed", seed)

    def test_no_network_or_subprocess_imports(self):
        banned = {"socket", "subprocess", "urllib", "http", "requests", "ftplib", "ssl"}
        for name in ("scan_workflows.py", "validate.py", "yamlite.py", "schemalite.py"):
            with open(os.path.join(ROOT, name)) as handle:
                tree = ast.parse(handle.read())
            imported = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.update(alias.name.split(".")[0] for alias in node.names)
                elif isinstance(node, ast.ImportFrom):
                    imported.add((node.module or "").split(".")[0])
            self.assertEqual(imported & banned, set(), name)


if __name__ == "__main__":
    unittest.main()
