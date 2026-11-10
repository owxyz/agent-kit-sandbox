"""Secret and personal-data redaction."""
import unittest

from advisory_service import logs
from advisory_service.redact import clean, redact
from advisory_service.untrusted import sanitize_output

from .support import Harness, log_lines

# Assembled at runtime so secret scanners do not flag this test file.
GH = "ghp_" + "a1B2c3D4e5" * 4
FINE = "github_pat_" + "11ABCDE0" * 5
ANT = "sk-ant-api03-" + "xY9_kL2-" * 6
AWS_ID = "AKIA" + "IOSFODNN7EXAMPLE"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCY" + "EXAMPLEKEY"
SLACK = "xoxb-" + "123456789012-abcdefGHIJKL"
GOOGLE = "AIza" + "SyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY"
NPM = "npm_" + "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0"
STRIPE = "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc"
JWT = "eyJhbGciOiJIUzI1NiJ9" + ".eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
PEM_BODY = "MIIEowIBAAKCAQEA7bq1\nZ9Xk2lQ0pAbCdEf\n"
PEM = "-----BEGIN RSA " + "PRIVATE KEY-----\n" + PEM_BODY + "-----END RSA " + "PRIVATE KEY-----"

SECRETS = {
    "github classic": GH,
    "github fine-grained": FINE,
    "anthropic": ANT,
    "aws id": AWS_ID,
    "slack": SLACK,
    "google": GOOGLE,
    "npm": NPM,
    "stripe": STRIPE,
    "jwt": JWT,
}
ASSIGNMENTS = {
    "env": ("export DB_PASSWORD=hunter2hunter", "hunter2hunter"),
    "quoted": ('password: "correct horse battery"', "correct horse"),
    "json": ('{"client_secret": "abc123xyz"}', "abc123xyz"),
    "aws": (f"aws_secret_access_key = {AWS_SECRET}", AWS_SECRET),
    "cli equals": ("mysql --password=s3cretpw", "s3cretpw"),
    "cli space": ("tool --token s3cretvalue run", "s3cretvalue"),
    "header": ("Authorization: token abcdef123456", "abcdef123456"),
    "bearer": ("curl -H 'X: Bearer abc.def-123456789'", "abc.def-123456789"),
    "cookie": ("Set-Cookie: session=deadbeefcafe; Path=/", "deadbeefcafe"),
    "url password": ("git clone https://bot:pa55word@github.com/a/b", "pa55word"),
    "url sas": ("GET https://x.blob.core/c?sv=1&sig=AbCdEf%2B123", "AbCdEf%2B123"),
    "azure": ("DefaultEndpoints;AccountKey=AbCd1234==;Suffix", "AbCd1234"),
}
PERSONAL = {
    "email": ("failure for jane.doe@example.org in run", "jane.doe@example.org"),
    "git author": ("Author: Jane Doe", "Jane Doe"),
    "co-author": ("Co-authored-by: Sam Lee", "Sam Lee"),
    "phone": ("call (415) 555-0132 now", "555-0132"),
    "intl phone": ("call +442079460958 now", "+442079460958"),
    "ssn": ("ssn 123-45-6789", "123-45-6789"),
    "card": ("card 4111 1111 1111 1111 declined", "4111 1111"),
    "ipv4": ("connect to 203.0.113.9 failed", "203.0.113.9"),
    "linux home": ("/home/jdoe/app/main.py", "jdoe"),
    "mac home": ("/Users/jdoe/app/main.py", "jdoe"),
    "windows home": ("C:\\Users\\jdoe\\app", "jdoe"),
}


class Redaction(unittest.TestCase):
    def test_known_token_formats(self):
        for name, value in SECRETS.items():
            with self.subTest(name):
                self.assertNotIn(value, redact(f"prefix {value} suffix").text)

    def test_assignments_headers_and_urls(self):
        for name, (text, secret) in ASSIGNMENTS.items():
            with self.subTest(name):
                self.assertNotIn(secret, redact(text).text)

    def test_personal_data(self):
        for name, (text, value) in PERSONAL.items():
            with self.subTest(name):
                self.assertNotIn(value, redact(text).text)

    def test_private_key_block(self):
        out = redact(f"before\n{PEM}\nafter").text
        self.assertNotIn("MIIEowIBAAK", out)
        self.assertIn("before", out)
        self.assertIn("after", out)

    def test_private_key_cut_off_before_its_end_marker(self):
        out = redact("-----BEGIN PRIVATE " + "KEY-----\n" + PEM_BODY).text
        self.assertNotIn("MIIEowIBAAK", out)

    def test_invisible_characters_cannot_split_a_token(self):
        hidden = GH[:8] + "\u200b" + GH[8:]
        self.assertNotIn(GH, redact(hidden).text)
        self.assertIn("REDACTED", redact(hidden).text)

    def test_ansi_cannot_split_a_token(self):
        hidden = GH[:8] + "\x1b[0m" + GH[8:]
        self.assertIn("REDACTED", redact(hidden).text)

    def test_high_entropy_without_a_label(self):
        value = "Zx8Kq2Lm9Vt4Rb7Np3Wc6Yh1Jd5Fs0Gu"
        self.assertNotIn(value, redact(f"got {value}").text)

    def test_identity_literals(self):
        self.assertNotIn("alice-dev", redact("triggered by alice-dev today", ["alice-dev"]).text)

    def test_idempotent(self):
        once = redact("password=abc123 and " + GH + " jane@example.org").text
        self.assertEqual(redact(once).text, once)

    def test_diagnostic_detail_is_kept(self):
        text = "commit " + "a" * 40 + " in /home/runner/work/app/test.py line 3: basic configuration failed, 1234 tests, v1.2.3"
        self.assertEqual(redact(text).text, text)

    def test_empty_value_does_not_swallow_the_next_line(self):
        out = redact("env:\n  AUDIT_REPO_TOKEN: \n  OVERRIDE_TEAM_TOKEN: \n  PR_NUMBER: 18").text
        self.assertIn("OVERRIDE_TEAM_TOKEN:", out)
        self.assertIn("PR_NUMBER: 18", out)

    def test_masked_secret_lines_from_actions(self):
        self.assertNotIn("abc123", redact("  GITHUB_TOKEN: abc123").text)

    def test_non_luhn_digits_are_kept(self):
        self.assertIn("1234567890123", redact("id 1234567890123 ok").text)

    def test_clean_removes_bidi_and_tag_characters(self):
        self.assertEqual(clean("a\u202eb\U000e0041c\x07"), "abc")


class PreparedLogs(unittest.TestCase):
    def test_secret_is_gone_after_trim(self):
        raw = log_lines("ok", f"token={GH}", "E  error: boom", PEM)
        out = logs.prepare(raw, "2026-11-09T09:50:10Z", "2026-11-09T09:50:20Z")
        self.assertNotIn(GH, out.text)
        self.assertNotIn("MIIEowIBAAK", out.text)
        self.assertIn("boom", out.text)
        self.assertGreater(sum(out.redactions.values()), 0)

    def test_trim_bounds_size_and_reports_omission(self):
        raw = log_lines(*[f"noise line {i}" for i in range(5000)], "E  error: boom", "tail")
        out = logs.prepare(raw, None, None, max_lines=100, max_chars=4000)
        self.assertLessEqual(len(out.text), 4100)
        self.assertIn("boom", out.text)
        self.assertIn("lines omitted", out.text)
        self.assertEqual(out.total_lines, 5003)

    def test_repeated_lines_collapse(self):
        raw = log_lines(*["same"] * 50, "last")
        self.assertEqual(logs.prepare(raw, None, None).text.count("same"), 1)

    def test_window_trims_neighbouring_steps_in_the_same_second(self):
        # Shaped like a real runner log: steps share seconds at both ends.
        raw = (log_lines("checkout tail", stamp="2026-11-09T13:12:51.1Z")
               + log_lines("##[group]Run python3 verify.py", "verify output", "##[error]Process completed with exit code 1.", stamp="2026-11-09T13:12:51.5Z")
               + log_lines("Post job cleanup.", "Cleaning up orphan processes", stamp="2026-11-09T13:13:33.6Z"))
        self.assertEqual(logs.step_lines(raw, "2026-11-09T13:12:51Z", "2026-11-09T13:13:33Z"),
                         ["##[group]Run python3 verify.py", "verify output", "##[error]Process completed with exit code 1."])

    def test_printed_header_or_exit_line_cannot_hide_failing_output(self):
        start = "2026-11-09T09:50:10.1Z"
        raw = (log_lines("##[group]Run real step", "early output", "##[group]Run fake", "##[error]Process completed with exit code 0.", stamp=start)
               + log_lines("later output", "##[group]Run fake again", "real failure", "##[error]Process completed with exit code 1.", "next step"))
        selected = logs.step_lines(raw, "2026-11-09T09:50:10Z", "2026-11-09T09:50:20Z")
        self.assertEqual(selected[0], "##[group]Run real step")
        for line in ("early output", "later output", "real failure"):
            self.assertIn(line, selected)

    def test_header_after_the_first_second_never_moves_the_start(self):
        raw = log_lines("output before", "##[group]Run printed by the step", "after")
        self.assertEqual(logs.step_lines(raw, "2026-11-09T09:50:10Z", "2026-11-09T09:50:20Z")[0], "output before")

    def test_window_keeps_only_the_failing_step(self):
        raw = log_lines("earlier step output", stamp="2026-11-09T09:50:01.0Z") + log_lines("failing step output")
        out = logs.prepare(raw, "2026-11-09T09:50:10Z", "2026-11-09T09:50:20Z")
        self.assertIn("failing step output", out.text)
        self.assertNotIn("earlier step", out.text)


class EndToEnd(Harness):
    def test_nothing_sensitive_reaches_the_model(self):
        raw = log_lines(f"token={GH}", f"key {ANT}", "mail jane.doe@example.org", "E assert failed for alice-dev", PEM)
        self.fail_run(raw)
        prompt = self.prompt()
        for value in (GH, ANT, "jane.doe@example.org", "alice-dev", "MIIEowIBAAK"):
            self.assertNotIn(value, prompt)

    def test_redactor_failure_stops_the_model_call(self):
        from unittest import mock

        with mock.patch("advisory_service.logs.redact", side_effect=RuntimeError("boom")):
            self.fail_run()
        self.assertEqual(self.diagnosis_model.requests, [])


class ModelEcho(unittest.TestCase):
    def test_secret_echoed_by_model_is_removed(self):
        self.assertNotIn(GH, sanitize_output(f"the token {GH} leaked"))
