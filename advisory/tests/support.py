"""Fakes and builders shared by the tests. Nothing here touches a network."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import shutil
import tempfile
import unittest
import uuid
from typing import Any, Callable, Dict, List, Optional, Sequence, Union

from advisory_service.agents.diagnosis import DiagnosisAgent
from advisory_service.agents.judge import JudgeAgent
from advisory_service.github import GitHubApp, HttpResponse
from advisory_service.models import ModelClient, ModelRequest, ModelResponse, validate
from advisory_service.service import AdvisoryService, BoundAgent, Settings
from advisory_service.store import Store

SECRET = "test-webhook-secret"
REPO = "acme/widgets"
NOW = 1_794_218_400.0  # 2026-11-09T10:00:00Z
RECENT = "2026-11-09T09:59:00Z"
SHA = "a" * 40
BASE = "b" * 40
DIAGNOSIS_APP = 111
JUDGE_APP = 222
GOOD_HINT = {"root_cause": "test_x asserts 1 == 2", "failure_type": "unit_test", "confidence": "high", "next_step": "Fix test_x"}


class FakeModel(ModelClient):
    """Returns scripted output after applying the same schema check as real clients."""

    def __init__(self, *outputs: Union[Dict[str, Any], Exception, Callable[[ModelRequest], Dict[str, Any]]]):
        self.outputs = list(outputs)
        self.requests: List[ModelRequest] = []

    def complete_json(self, request: ModelRequest) -> ModelResponse:
        self.requests.append(request)
        output = self.outputs.pop(0) if len(self.outputs) > 1 else self.outputs[0]
        if isinstance(output, Exception):
            raise output
        data = output(request) if callable(output) else output
        validate(data, request.schema)
        return ModelResponse(data, "fake", 10, 5)


class FakeGitHub:
    """A scripted GitHub REST API. Records every request."""

    def __init__(self):
        self.calls: List[Dict[str, Any]] = []
        self.jobs: List[Dict[str, Any]] = []
        self.logs: Dict[int, str] = {}
        self.diff = ""
        self.granted: Optional[Dict[str, str]] = None
        self.check_status = 201

    @property
    def posted(self) -> List[Dict[str, Any]]:
        return [json.loads(c["body"]) for c in self.calls if c["url"].endswith("/check-runs")]

    def __call__(self, method: str, url: str, headers: Dict[str, str], body: Optional[bytes]) -> HttpResponse:
        self.calls.append({"method": method, "url": url, "headers": headers, "body": body})
        if url.endswith("/access_tokens"):
            granted = self.granted if self.granted is not None else json.loads(body)["permissions"]
            return HttpResponse(201, {}, json.dumps({"token": "installation-token", "permissions": granted}).encode())
        if "/attempts/" in url:
            return HttpResponse(200, {}, json.dumps({"jobs": self.jobs}).encode())
        if "/actions/jobs/" in url:
            job_id = int(url.split("/actions/jobs/")[1].split("/")[0])
            if job_id not in self.logs:
                return HttpResponse(404, {}, b"{}")
            return HttpResponse(302, {"Location": f"https://blob.example/{job_id}"}, b"")
        if url.startswith("https://blob.example/"):
            return HttpResponse(200, {}, self.logs[int(url.rsplit("/", 1)[1])].encode())
        if "/compare/" in url:
            return HttpResponse(200, {}, self.diff.encode())
        if url.endswith("/check-runs"):
            return HttpResponse(self.check_status, {}, json.dumps({"id": 900 + len(self.posted)}).encode())
        return HttpResponse(404, {}, b"{}")


def sign(body: bytes, secret: str = SECRET) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def headers(body: bytes, event: str = "workflow_run", secret: str = SECRET, delivery: Optional[str] = None) -> Dict[str, str]:
    return {"X-Hub-Signature-256": sign(body, secret), "X-GitHub-Event": event, "X-GitHub-Delivery": delivery or str(uuid.uuid4())}


def workflow_event(conclusion: str = "failure", run_id: int = 77, attempt: int = 1, login: str = "alice-dev",
                   pulls: Optional[Sequence[int]] = (5,), updated: str = RECENT, **run_extra: Any) -> bytes:
    run = {
        "id": run_id, "run_attempt": attempt, "name": "CI", "path": ".github/workflows/ci.yml", "event": "pull_request",
        "head_sha": SHA, "head_branch": "feature", "conclusion": conclusion, "updated_at": updated,
        "actor": {"login": login}, "triggering_actor": {"login": login},
        "pull_requests": [{"number": n, "head": {"sha": SHA}, "base": {"sha": BASE}} for n in pulls or ()],
    }
    run.update(run_extra)
    return json.dumps({"action": "completed", "workflow_run": run, "repository": {"full_name": REPO}, "installation": {"id": 42}}).encode()


def rating_event(external_id: str, sender: str = "bob", app_id: int = DIAGNOSIS_APP, identifier: str = "not_helpful") -> bytes:
    return json.dumps({
        "action": "requested_action", "requested_action": {"identifier": identifier},
        "check_run": {"id": 901, "external_id": external_id, "app": {"id": app_id}},
        "sender": {"login": sender}, "repository": {"full_name": REPO}, "installation": {"id": 42},
    }).encode()


def job(job_id: int = 1, name: str = "tests", step: str = "Run pytest -q", conclusion: str = "failure",
        started: str = "2026-11-09T09:50:10Z", completed: str = "2026-11-09T09:50:20Z") -> Dict[str, Any]:
    return {"id": job_id, "name": name, "conclusion": conclusion, "steps": [
        {"number": 1, "name": "Checkout", "conclusion": "success", "started_at": "2026-11-09T09:50:00Z", "completed_at": "2026-11-09T09:50:05Z"},
        {"number": 2, "name": step, "conclusion": conclusion, "started_at": started, "completed_at": completed},
    ]}


def log_lines(*lines: str, stamp: str = "2026-11-09T09:50:15.1234567Z") -> str:
    return "\n".join(f"{stamp} {line}" for line in lines) + "\n"


class Harness(unittest.TestCase):
    """Builds a service with fake GitHub and fake models and synchronous jobs."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="advisory-test-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.github = FakeGitHub()
        self.store = Store(os.path.join(self.tmp, "state.db"), clock=lambda: NOW)
        self.diagnosis_model = FakeModel(GOOD_HINT)
        self.judge_model = FakeModel({"alternative_comparison": "n/a", "findings": []})
        self.kill = "off"
        self.service = self.build()

    def app(self, app_id: int) -> GitHubApp:
        return GitHubApp(app_id, lambda message: b"signature", self.github, clock=lambda: NOW)

    def build(self, submit=None, agents=None, secrets=(SECRET,)) -> AdvisoryService:
        settings = Settings(secrets, frozenset({REPO}), agent_logins=frozenset({"agent-bot[bot]"}))
        bound = agents or [
            BoundAgent(DiagnosisAgent(), self.app(DIAGNOSIS_APP), self.diagnosis_model),
            BoundAgent(JudgeAgent(), self.app(JUDGE_APP), self.judge_model),
        ]
        return AdvisoryService(settings, bound, self.store, submit=submit, clock=lambda: NOW, kill_switch=lambda: self.kill)

    def deliver(self, body: bytes, agent: str = "diagnosis", event: str = "workflow_run", delivery: Optional[str] = None):
        return self.service.handle(f"/webhooks/{agent}", headers(body, event, delivery=delivery), body)

    def fail_run(self, log: str = "", **kwargs):
        self.github.jobs = [job()]
        self.github.logs = {1: log or log_lines("E   assert 1 == 2", "##[error]Process completed with exit code 1.")}
        return self.deliver(workflow_event(**kwargs))

    def prompt(self, model: Optional[FakeModel] = None, index: int = -1) -> str:
        return (model or self.diagnosis_model).requests[index].user
