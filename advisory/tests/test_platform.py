"""The shared service with a third agent, the CLI, and the real SDK offline."""
import contextlib
import io
import json
import os
import unittest
from unittest import mock

from advisory_service.agents.base import Agent
from advisory_service import cli
from advisory_service.checks import Annotation, CheckRunSpec
from advisory_service.models import ModelOutputInvalid, ModelRefused, ModelRequest, make_client, register_provider, validate
from advisory_service.service import BoundAgent

from .support import GOOD_HINT, REPO, FakeModel, Harness, workflow_event

try:
    import anthropic
    try:
        import httpx2 as httpx  # the transport used by current SDK releases
    except ImportError:
        import httpx
except ImportError:
    anthropic = None


class StubReview(Agent):
    """Shaped like P4.2: runs when CI finishes and posts line annotations."""

    id = "review"
    check_name = "advisory/ai-review"
    permissions = {"contents": "read", "checks": "write"}

    def accepts(self, event):
        return event.name == "workflow_run" and bool(event.run["pull_requests"])

    def job_key(self, event):
        return f"{event.repo}:{event.run['head_sha']}"

    def run(self, context):
        notes = tuple(Annotation("a.py", i + 1, i + 1, f"finding {i}") for i in range(60))
        return CheckRunSpec(self.check_name, "t", "s", f"{self.id}:{self.job_key(context.event)}", annotations=notes)


class Reuse(Harness):
    def test_a_new_agent_plugs_in_with_no_service_changes(self):
        self.service = self.build(agents=[BoundAgent(StubReview(), self.app(333), FakeModel(GOOD_HINT))])
        self.deliver(workflow_event("success"), agent="review")
        check = self.github.posted[0]
        self.assertEqual((check["conclusion"], check["name"]), ("neutral", "advisory/ai-review"))
        self.assertEqual(len(check["output"]["annotations"]), 50)

    def test_an_agent_asking_for_too_much_is_refused(self):
        class Greedy(StubReview):
            permissions = {"pull_requests": "write"}

        with self.assertRaises(ValueError):
            self.build(agents=[BoundAgent(Greedy(), self.app(333), FakeModel(GOOD_HINT))])

    def test_an_agent_with_a_bad_check_name_is_refused(self):
        class Renamed(StubReview):
            check_name = "provenance"

        with self.assertRaises(ValueError):
            self.build(agents=[BoundAgent(Renamed(), self.app(333), FakeModel(GOOD_HINT))])

    def test_agents_are_isolated_by_path(self):
        self.github.jobs = []
        self.deliver(workflow_event())
        self.assertEqual([p["name"] for p in self.github.posted], ["advisory/diagnosis: CI"])


class Cli(Harness):
    def run_cli(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), mock.patch.dict(os.environ, {"ADVISORY_DB": self.store.path}):
            code = cli.main(list(argv))
        return code, out.getvalue()

    def test_signals_keep_the_hint_under_its_own_key(self):
        self.fail_run()
        code, out = self.run_cli("signals", "--repo", REPO, "--run", "77")
        data = json.loads(out)
        self.assertEqual(code, 0)
        self.assertEqual(data["signals"]["source"], "structured")
        self.assertEqual(data["hint"]["use"], "hint-only")

    def test_confirm_records_by_category(self):
        self.store.save_finding("abc", REPO, "s", 1, "comparison_tampering", "high", "x")
        code, _ = self.run_cli("confirm", "abc", "--verdict", "confirmed_hack", "--by", "pat")
        self.assertEqual(code, 0)
        _, out = self.run_cli("ledger-report")
        self.assertEqual(json.loads(out)["comparison_tampering"]["confirmed_hack"], 1)

    def test_confirm_refuses_unknown_findings_and_categories(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(self.run_cli("confirm", "nope", "--verdict", "confirmed_hack", "--by", "pat")[0], 2)
            with self.assertRaises(SystemExit):
                self.run_cli("confirm", "x", "--verdict", "confirmed_hack", "--by", "p", "--category", "made_up")


class ModelInterface(unittest.TestCase):
    def test_providers_are_pluggable(self):
        fake = FakeModel(GOOD_HINT)
        register_provider("fake-provider", lambda key, model: fake)
        self.assertIs(make_client("fake-provider", "k"), fake)
        with self.assertRaises(ValueError):
            make_client("nope", "k")

    def test_validator(self):
        schema = {"type": "object", "properties": {"a": {"type": "array", "items": {"type": "string", "enum": ["x"]}}}, "required": ["a"], "additionalProperties": False}
        validate({"a": ["x"]}, schema)
        for bad in ({}, {"a": "x"}, {"a": ["y"]}, {"a": [], "b": 1}, []):
            with self.assertRaises(ModelOutputInvalid):
                validate(bad, schema)


@unittest.skipIf(anthropic is None, "anthropic SDK not installed")
class RealSdkOffline(unittest.TestCase):
    """Runs the real SDK against a mock transport. No request leaves this process."""

    SCHEMA = {"type": "object", "properties": {"a": {"type": "string"}}, "required": ["a"], "additionalProperties": False}

    def client(self, response):
        from advisory_service.models import AnthropicModelClient

        self.sent = []

        def handler(request):
            self.sent.append(request)
            return httpx.Response(200, json={
                "id": "msg_1", "type": "message", "role": "assistant", "model": "claude-opus-5-5",
                "usage": {"input_tokens": 3, "output_tokens": 4}, "stop_sequence": None, **response,
            })

        sdk = anthropic.Anthropic(api_key="test", max_retries=0, http_client=httpx.Client(transport=httpx.MockTransport(handler)))
        return AnthropicModelClient("test", client=sdk)

    def call(self, response):
        return self.client(response).complete_json(ModelRequest("sys", "usr", self.SCHEMA))

    def test_request_shape(self):
        result = self.call({"stop_reason": "end_turn", "content": [{"type": "text", "text": '{"a": "b"}'}]})
        self.assertEqual(result.data, {"a": "b"})
        body = json.loads(self.sent[0].content)
        self.assertEqual(body["model"], "claude-opus-5-5")
        self.assertEqual(body["thinking"], {"type": "adaptive"})
        self.assertEqual(body["output_config"]["format"]["schema"], self.SCHEMA)
        self.assertEqual(body["fallbacks"], "default")
        self.assertNotIn("tools", body)
        self.assertNotIn("temperature", body)
        self.assertIn("server-side-fallback-2026-07-01", self.sent[0].headers["anthropic-beta"])

    def test_api_error_keeps_status_and_type_but_not_on_the_check(self):
        from advisory_service.models import AnthropicModelClient, ModelError

        def handler(request):
            return httpx.Response(400, json={"type": "error", "error": {"type": "invalid_request_error", "message": "fallbacks: not allowed here"}})

        sdk = anthropic.Anthropic(api_key="test", max_retries=0, http_client=httpx.Client(transport=httpx.MockTransport(handler)))
        with self.assertRaises(ModelError) as caught:
            AnthropicModelClient("test", client=sdk).complete_json(ModelRequest("s", "u", self.SCHEMA))
        self.assertEqual(caught.exception.summary(), "ModelError: bad request: HTTP 400 invalid_request_error")
        self.assertEqual(caught.exception.detail, "fallbacks: not allowed here")

    def test_refusal(self):
        with self.assertRaises(ModelRefused):
            self.call({"stop_reason": "refusal", "content": []})

    def test_truncated_output(self):
        with self.assertRaises(ModelOutputInvalid):
            self.call({"stop_reason": "max_tokens", "content": [{"type": "text", "text": '{"a"'}]})

    def test_schema_violation(self):
        with self.assertRaises(ModelOutputInvalid):
            self.call({"stop_reason": "end_turn", "content": [{"type": "text", "text": '{"a": "b", "conclusion": "success"}'}]})
