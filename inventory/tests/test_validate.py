import contextlib
import copy
import io
import json
import os
import sys
import tempfile
import unittest
from datetime import date

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
import schemalite  # noqa: E402
import validate  # noqa: E402
import yamlite  # noqa: E402

TODAY = date(2026, 11, 8)
REGISTER = os.path.join(ROOT, "autonomy-register.yaml")
TEMPLATE = os.path.join(ROOT, "manual-credentials.template.yaml")
FAKE_TOKEN = "ghp_" + "a1" * 18


def load(path):
    with open(path) as handle:
        return yamlite.load(handle.read())


def complete_register():
    document = load(REGISTER)
    for agent in document["agents"]:
        for field in ("name", "target"):
            if agent["promotion_metric"][field] == "TBD":
                agent["promotion_metric"][field] = "filled in"
    for secret in document["secrets"]:
        secret.update(owner="platform-team", secrets_manager_location="vault:kv/agents/" + secret["id"],
                      last_rotated="2026-10-01", rotation_date="2026-12-30", alert_date="2026-12-16")
    return document


def complete_credentials():
    return {
        "schema_version": 1,
        "security_review": {"reviewer": "sec-team", "date": "2026-11-01"},
        "credentials": [{
            "id": "bot-pat", "kind": "pat", "holder": "bot", "owner": "platform-team",
            "scope": "classic repo", "broad": True, "where_held": "org secret", "removal_date": "2026-12-01",
        }, {
            "id": "docs-key", "kind": "deploy-key", "holder": "docs", "owner": "docs-team",
            "scope": "read-only", "broad": False, "where_held": "repo", "removal_date": "N/A",
        }],
    }


def categories(report):
    return {issue["category"] for issue in report.issues}


def paths(report, category):
    return [issue["path"] for issue in report.issues if issue["category"] == category]


class RegisterContentTests(unittest.TestCase):
    def test_starting_levels_match_plan(self):
        levels = {agent["id"]: agent["level"] for agent in load(REGISTER)["agents"]}
        self.assertEqual(levels, {
            "diagnosis": "Advise", "review": "Advise", "llm-judge": "Advise",
            "narrow-repair": "Act with gates", "broad-repair": "Suggest", "dependency-repair": "Suggest",
        })

    def test_policy_default_is_90_days(self):
        self.assertEqual(load(REGISTER)["policy"]["rotation_days"], 90)

    def test_shipped_register_is_valid_but_incomplete(self):
        report = validate.validate_document("register", load(REGISTER), TODAY)
        self.assertEqual(categories(report), {"incomplete"})
        self.assertEqual(report.exit_code(), 3)
        self.assertEqual(report.exit_code(allow_incomplete=True), 0)
        self.assertIn("$.secrets[0].owner", paths(report, "incomplete"))
        self.assertIn("$.secrets[0].secrets_manager_location", paths(report, "incomplete"))
        self.assertIn("$.agents[2].promotion_metric.target", paths(report, "incomplete"))

    def test_shipped_template_is_valid_but_incomplete(self):
        report = validate.validate_document("credentials", load(TEMPLATE), TODAY)
        self.assertEqual(categories(report), {"incomplete"})
        kinds = {entry["kind"] for entry in load(TEMPLATE)["credentials"]}
        self.assertEqual(kinds, {"pat", "deploy-key", "github-app-private-key", "model-api-key"})


class RegisterRuleTests(unittest.TestCase):
    def check(self, document):
        return validate.validate_document("register", document, TODAY)

    def test_complete_register_is_clean(self):
        report = self.check(complete_register())
        self.assertEqual(report.issues, [])
        self.assertEqual(report.exit_code(), 0)

    def test_schema_errors(self):
        document = complete_register()
        del document["agents"][0]["promotion_metric"]
        document["agents"][1]["level"] = "Autonomous"
        document["secrets"][0]["surprise"] = "x"
        report = self.check(document)
        messages = " ".join(issue["message"] for issue in report.issues)
        self.assertIn("promotion_metric", messages)
        self.assertIn("must be one of", messages)
        self.assertIn("unknown field 'surprise'", messages)
        self.assertEqual(report.exit_code(), 1)

    def test_overdue(self):
        document = complete_register()
        document["secrets"][0].update(last_rotated="2026-08-01", rotation_date="2026-11-01", alert_date="2026-10-20")
        report = self.check(document)
        self.assertEqual(paths(report, "overdue"), ["$.secrets[0].rotation_date"])
        self.assertEqual(report.exit_code(), 1)

    def test_due_soon_warns_without_failing(self):
        document = complete_register()
        document["secrets"][0].update(last_rotated="2026-09-01", rotation_date="2026-11-20", alert_date="2026-11-06")
        report = self.check(document)
        self.assertEqual(paths(report, "due_soon"), ["$.secrets[0].rotation_date"])
        self.assertEqual(report.exit_code(), 0)

    def test_due_today_is_due_soon_not_overdue(self):
        document = complete_register()
        document["secrets"][0].update(last_rotated="2026-09-01", rotation_date="2026-11-08", alert_date="2026-11-01")
        report = self.check(document)
        self.assertEqual(paths(report, "overdue"), [])
        self.assertEqual(len(paths(report, "due_soon")), 1)

    def test_passed_alert_date_warns(self):
        document = complete_register()
        document["secrets"][0].update(alert_date="2026-11-01")
        self.assertEqual(paths(self.check(document), "due_soon"), ["$.secrets[0].alert_date"])

    def test_rotation_beyond_interval(self):
        document = complete_register()
        document["secrets"][0]["rotation_date"] = "2026-12-31"
        self.assertEqual(self.check(document).exit_code(), 1)
        document["secrets"][0]["rotation_days"] = 120
        self.assertEqual(self.check(document).exit_code(), 0)

    def test_alert_must_precede_rotation(self):
        document = complete_register()
        document["secrets"][0]["alert_date"] = "2026-12-30"
        self.assertIn("$.secrets[0].alert_date", paths(self.check(document), "error"))

    def test_invalid_calendar_date(self):
        document = complete_register()
        document["secrets"][0]["rotation_date"] = "2026-02-31"
        self.assertIn("$.secrets[0].rotation_date", paths(self.check(document), "error"))

    def test_tbd_date_gives_90_day_hint(self):
        document = complete_register()
        document["secrets"][0]["rotation_date"] = "TBD"
        messages = [i["message"] for i in self.check(document).issues if i["category"] == "incomplete"]
        self.assertTrue(any("2026-12-30" in message for message in messages), messages)

    def test_ci_location_rejected(self):
        for location in ("secrets.AGENT_KEY", "GitHub Actions secret", "${{ secrets.X }}", "CI variable"):
            document = complete_register()
            document["secrets"][0]["secrets_manager_location"] = location
            self.assertIn("$.secrets[0].secrets_manager_location", paths(self.check(document), "error"), location)

    def test_advise_agent_cannot_write_contents(self):
        document = complete_register()
        document["agents"][0]["token_scope"]["permissions"]["contents"] = "write"
        self.assertEqual(self.check(document).exit_code(), 1)

    def test_admin_and_workflow_scope_rejected(self):
        for scope in ("administration", "workflows"):
            document = complete_register()
            document["agents"][3]["token_scope"]["permissions"][scope] = "write"
            self.assertEqual(self.check(document).exit_code(), 1, scope)

    def test_missing_model_key_entry(self):
        document = complete_register()
        document["secrets"] = [s for s in document["secrets"] if s["id"] != "review-model-key"]
        messages = " ".join(i["message"] for i in self.check(document).issues)
        self.assertIn("'review' has no model-api-key entry", messages)

    def test_webhook_secret_required(self):
        document = complete_register()
        document["secrets"] = [s for s in document["secrets"] if s["kind"] != "webhook-secret"]
        self.assertEqual(self.check(document).exit_code(), 1)

    def test_unknown_holder_and_duplicate_id(self):
        document = complete_register()
        document["secrets"].append(dict(document["secrets"][0], holder="ghost"))
        report = self.check(document)
        messages = " ".join(i["message"] for i in report.issues)
        self.assertIn("unknown holder", messages)
        self.assertIn("duplicate id", messages)

    def test_credential_shaped_value_rejected_and_not_echoed(self):
        document = complete_register()
        document["secrets"][0]["owner"] = FAKE_TOKEN
        report = self.check(document)
        self.assertEqual(report.exit_code(), 1)
        self.assertNotIn(FAKE_TOKEN, json.dumps(report.issues))


class AlertTests(unittest.TestCase):
    def due(self, owner="@org/platform"):
        document = complete_register()
        document["secrets"][0].update(owner=owner, last_rotated="2026-09-01",
                                      rotation_date="2026-11-20", alert_date="2026-11-06")
        document["secrets"][1].update(last_rotated="2026-08-01", rotation_date="2026-11-01",
                                      alert_date="2026-10-20")
        return validate.validate_document("register", document, TODAY)

    def test_one_line_per_secret_with_owner(self):
        lines = validate.render_alerts(self.due()).splitlines()
        self.assertEqual(lines[0].split("\t"),
                         ["due soon", "diagnosis-app-key", "@org/platform", "rotation is due in 12 day(s)"])
        self.assertEqual(lines[1].split("\t")[:2], ["overdue", "diagnosis-model-key"])
        self.assertEqual(len(lines), 2)

    def test_no_alerts_when_nothing_is_due(self):
        report = validate.validate_document("register", complete_register(), TODAY)
        self.assertEqual(validate.render_alerts(report), "")

    def test_credential_in_owner_is_withheld(self):
        self.assertNotIn(FAKE_TOKEN, validate.render_alerts(self.due(owner=FAKE_TOKEN)))

    def test_both_date_hints_appear_in_one_pass(self):
        document = complete_register()
        document["secrets"][0].update(rotation_date="TBD", alert_date="TBD")
        messages = " ".join(i["message"] for i in validate.validate_document("register", document, TODAY).issues)
        self.assertIn("is 2026-12-30", messages)
        self.assertIn("is 2026-12-16", messages)


class CredentialRuleTests(unittest.TestCase):
    def check(self, document):
        return validate.validate_document("credentials", document, TODAY)

    def test_complete_is_clean(self):
        self.assertEqual(self.check(complete_credentials()).issues, [])

    def test_broad_needs_owner_and_removal_date(self):
        document = complete_credentials()
        document["credentials"][0].update(owner="TBD", removal_date="TBD")
        self.assertEqual(paths(self.check(document), "incomplete"),
                         ["$.credentials[0].owner", "$.credentials[0].removal_date"])

    def test_broad_cannot_be_na(self):
        document = complete_credentials()
        document["credentials"][0]["removal_date"] = "N/A"
        self.assertEqual(self.check(document).exit_code(), 1)

    def test_overdue_removal(self):
        document = complete_credentials()
        document["credentials"][0]["removal_date"] = "2026-11-01"
        self.assertEqual(paths(self.check(document), "overdue"), ["$.credentials[0].removal_date"])

    def test_unreviewed_is_incomplete(self):
        document = complete_credentials()
        document["security_review"] = {"reviewer": "TBD", "date": "TBD"}
        self.assertEqual(self.check(document).exit_code(), 3)

    def test_value_field_rejected(self):
        document = complete_credentials()
        document["credentials"][0]["value"] = "x"
        self.assertEqual(self.check(document).exit_code(), 1)

    def test_token_in_notes_rejected_and_not_echoed(self):
        document = complete_credentials()
        document["credentials"][0]["notes"] = "key is " + FAKE_TOKEN
        report = self.check(document)
        self.assertEqual(report.exit_code(), 1)
        self.assertNotIn(FAKE_TOKEN, json.dumps(report.issues))


class CliTests(unittest.TestCase):
    def run_cli(self, *args):
        out = io.StringIO()
        err = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = validate.main(list(args))
        return code, out.getvalue() + err.getvalue()

    def test_default_register_exit_codes(self):
        self.assertEqual(self.run_cli("register")[0], 3)
        self.assertEqual(self.run_cli("register", "--allow-incomplete")[0], 0)

    def test_today_flag_changes_result(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "r.yaml")
            with open(path, "w") as handle:
                json.dump(complete_register(), handle)
            self.assertEqual(self.run_cli("register", path, "--today", "2026-11-08")[0], 0)
            code, output = self.run_cli("register", path, "--today", "2027-01-15")
            self.assertEqual(code, 1)
            self.assertIn("OVERDUE", output)

    def test_unreadable_and_invalid_files(self):
        self.assertEqual(self.run_cli("register", "/nonexistent/file.yaml")[0], 2)
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "bad.yaml")
            with open(path, "w") as handle:
                handle.write("a: SENSITIVE\n  b: SENSITIVE\n")
            code, output = self.run_cli("register", path)
            self.assertEqual(code, 2)
            self.assertNotIn("SENSITIVE", output)

    def test_json_format(self):
        code, output = self.run_cli("register", "--format", "json")
        self.assertEqual(json.loads(output)["exit_code"], code)

    def test_credentials_needs_a_file(self):
        with self.assertRaises(SystemExit):
            self.run_cli("credentials")


class SchemaliteTests(unittest.TestCase):
    def test_unknown_keyword_is_refused(self):
        with self.assertRaises(schemalite.SchemaError):
            schemalite.validate({}, {"oneOf": []})

    def test_shipped_schemas_use_supported_keywords(self):
        for name in validate.SCHEMAS.values():
            with open(name) as handle:
                schema = json.load(handle)
            schemalite.validate({}, schema)
            self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")

    def test_bool_is_not_integer(self):
        self.assertTrue(schemalite.validate(True, {"type": "integer"}))

    def test_messages_do_not_echo_values(self):
        problems = schemalite.validate("SENSITIVE", {"type": "string", "pattern": "^x$"})
        self.assertNotIn("SENSITIVE", json.dumps(problems))


if __name__ == "__main__":
    unittest.main()
