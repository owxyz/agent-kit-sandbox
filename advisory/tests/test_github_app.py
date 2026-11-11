"""Token scope, write restrictions and credential handling."""
import base64
import json
import unittest

from advisory_service.agents.diagnosis import DiagnosisAgent
from advisory_service.agents.judge import JudgeAgent
from advisory_service.github import ALLOWED_PERMISSIONS, GitHubApp, GitHubError, HttpResponse, InstallationClient, check_permissions

from .support import NOW, REPO, FakeGitHub, Harness, workflow_event

class Scope(Harness):
    def test_ceiling_is_read_plus_checks(self):
        self.assertEqual(ALLOWED_PERMISSIONS, {"actions": "read", "contents": "read", "metadata": "read", "checks": "write"})

    def test_write_permissions_are_refused(self):
        for bad in ({"pull_requests": "write"}, {"contents": "write"}, {"pull_requests": "read"}, {"administration": "read"}, {"actions": "write"}):
            with self.assertRaises(ValueError):
                check_permissions(bad)

    def test_agents_stay_inside_the_ceiling_and_cannot_write_prs(self):
        for agent in (DiagnosisAgent(), JudgeAgent()):
            check_permissions(agent.permissions)
            self.assertNotIn("pull_requests", agent.permissions)

    def test_token_is_narrowed_to_one_repo_and_agent_permissions(self):
        self.github.jobs = []
        self.deliver(workflow_event())
        request = json.loads(next(c for c in self.github.calls if c["url"].endswith("/access_tokens"))["body"])
        self.assertEqual(request, {"repositories": ["widgets"], "permissions": {"actions": "read", "checks": "write"}})

    def test_broader_token_from_github_is_refused(self):
        self.github.jobs = []
        self.github.granted = {"checks": "write", "contents": "write"}
        self.deliver(workflow_event())
        self.assertEqual(self.github.posted, [])

    def test_client_can_only_create_check_runs(self):
        client = InstallationClient("t", REPO, self.github)
        for method, path in (("POST", "/pulls/1/reviews"), ("PUT", "/contents/x"), ("PATCH", "/check-runs"), ("DELETE", "/check-runs")):
            with self.assertRaises(GitHubError):
                client._send(method, path)
        self.assertEqual(self.github.calls, [])


class LogDownload(unittest.TestCase):
    def test_token_is_not_sent_to_the_log_host(self):
        github = FakeGitHub()
        github.logs = {9: "hello"}
        client = InstallationClient("secret-token", REPO, github)
        self.assertEqual(client.job_log(9), "hello")
        blob = github.calls[-1]
        self.assertTrue(blob["url"].startswith("https://blob.example/"))
        self.assertNotIn("Authorization", blob["headers"])

    def test_insecure_redirect_is_refused(self):
        client = InstallationClient("t", REPO, lambda *a: HttpResponse(302, {"Location": "http://evil.example/x"}, b""))
        with self.assertRaises(GitHubError):
            client.job_log(1)


class Jwt(unittest.TestCase):
    def test_claims(self):
        github = FakeGitHub()
        GitHubApp(123, lambda m: b"sig", github, clock=lambda: NOW).installation(42, REPO, {"checks": "write"})
        token = github.calls[0]["headers"]["Authorization"].split()[1]
        claims = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))
        self.assertEqual(claims["iss"], "123")
        self.assertLessEqual(claims["exp"] - NOW, 600)
        self.assertLess(claims["iat"], NOW)

    def test_https_only(self):
        with self.assertRaises(ValueError):
            GitHubApp(1, lambda m: b"", FakeGitHub(), api="http://api.example")
