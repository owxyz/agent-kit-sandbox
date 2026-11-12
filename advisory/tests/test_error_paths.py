"""Error paths: limits, failed GitHub calls, bad settings, and every model-client failure.

The model-client tests use a stand-in `anthropic` module, so they run without the SDK.
"""
import http.client
import json
import os
import sys
import threading
import types
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

from advisory_service import cli
from advisory_service.checks import Action, CheckRunSpec, render
from advisory_service.github import GitHubApp, GitHubError, HttpResponse, InstallationClient, http_transport
from advisory_service.models import AnthropicModelClient, ModelError, ModelOutputInvalid, ModelRefused, ModelRequest
from advisory_service.service import Settings

from .support import NOW, REPO, SHA, FakeGitHub, Harness, rating_event, workflow_event

SCHEMA = {"type": "object", "properties": {"a": {"type": "string"}}, "required": ["a"], "additionalProperties": False}


class Limits(unittest.TestCase):
    def test_action_field_limits(self):
        for label, description, identifier in (("x" * 21, "d", "i"), ("l", "x" * 41, "i"), ("l", "d", "x" * 21)):
            with self.assertRaises(ValueError):
                Action(label, description, identifier)

    def test_at_most_three_actions(self):
        actions = tuple(Action("a", "b", f"id{i}") for i in range(4))
        with self.assertRaises(ValueError):
            render(CheckRunSpec("advisory/x", "t", "s", "e", actions=actions), SHA, "now")

    def test_retention_must_outlast_event_age(self):
        with self.assertRaises(ValueError):
            Settings(("s",), frozenset(), max_event_age=100, delivery_retention=100)


class GitHubFailures(unittest.TestCase):
    def failing(self, status=500):
        return InstallationClient("t", REPO, lambda *a: HttpResponse(status, {}, b"{}"))

    def test_token_request_failure(self):
        def transport(method, url, headers, body):
            return HttpResponse(403, {}, b"{}")

        with self.assertRaises(GitHubError):
            GitHubApp(1, lambda m: b"s", transport, clock=lambda: NOW).installation(42, REPO, {"checks": "write"})

    def test_list_jobs_failure(self):
        with self.assertRaises(GitHubError):
            self.failing().list_jobs(1, 1)

    def test_compare_failure(self):
        with self.assertRaises(GitHubError):
            self.failing(404).compare_diff("a", "b")

    def test_log_failure(self):
        with self.assertRaises(GitHubError):
            self.failing(410).job_log(1)

    def test_check_creation_failure(self):
        with self.assertRaises(GitHubError):
            self.failing(422).create_check_run(CheckRunSpec("advisory/x", "t", "s", "e"), SHA)

    def test_http_transport_returns_error_responses(self):
        class NotFound(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(404)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"no")

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), NotFound)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        response = http_transport("GET", f"http://127.0.0.1:{server.server_port}/x", {}, None)
        self.assertEqual((response.status, response.body), (404, b"no"))


class ServiceInputs(Harness):
    def test_unparseable_timestamp_is_treated_as_too_old(self):
        self.assertEqual(self.deliver(workflow_event(updated="not a date")).outcome, "event too old")
        self.assertEqual(self.github.calls, [])

    def test_malformed_rating_is_rejected(self):
        body = json.loads(rating_event("diagnosis:x"))
        del body["check_run"]
        self.assertEqual(self.deliver(json.dumps(body).encode(), event="check_run").status, 400)


class CliPaths(Harness):
    def test_missing_setting_stops_startup(self):
        with mock.patch.dict(os.environ, {}, clear=True), self.assertRaises(SystemExit):
            cli._secret("ADVISORY_WEBHOOK_SECRETS")

    def test_setting_read_from_file(self):
        path = os.path.join(self.tmp, "secret")
        with open(path, "w") as handle:
            handle.write("value\n")
        with mock.patch.dict(os.environ, {"X_FILE": path}, clear=True):
            self.assertEqual(cli._secret("X"), "value")

    def test_bad_content_length_is_refused(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), cli.make_handler(self.service))
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        for length, expected in (("abc", 411), ("-1", 413), (str(26 * 1024 * 1024), 413)):
            connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=10)
            self.addCleanup(connection.close)
            connection.putrequest("POST", "/webhooks/diagnosis")
            connection.putheader("Content-Length", length)
            connection.endheaders()
            self.assertEqual(connection.getresponse().status, expected)

    def test_full_queue_and_crashing_job(self):
        blocked = threading.Event()
        submit = cli.start_workers(workers=0, depth=1)
        self.assertTrue(submit(blocked.set))
        self.assertFalse(submit(blocked.set))  # queue full

        done = threading.Event()
        submit = cli.start_workers(workers=1, depth=5)

        def crash():
            raise RuntimeError("boom")

        submit(crash)
        submit(done.set)
        self.assertTrue(done.wait(5), "the worker died after a crashing job")


def _stub_sdk():
    """A stand-in for the `anthropic` module: just the exception classes the client catches."""

    class APIStatusError(Exception):
        def __init__(self, status_code, body=None):
            super().__init__(status_code)
            self.status_code, self.body = status_code, body

    names = ("BadRequestError", "AuthenticationError", "PermissionDeniedError", "NotFoundError", "RateLimitError")
    module = types.SimpleNamespace(APIStatusError=APIStatusError, APIConnectionError=type("APIConnectionError", (Exception,), {}))
    for name in names:
        setattr(module, name, type(name, (APIStatusError,), {}))
    return module


def _response(stop_reason="end_turn", content=None):
    blocks = content if content is not None else [types.SimpleNamespace(type="text", text='{"a": "b"}')]
    usage = types.SimpleNamespace(input_tokens=3, output_tokens=4)
    return types.SimpleNamespace(stop_reason=stop_reason, content=blocks, model="claude-opus-5-5", usage=usage)


class ModelClientWithoutSdk(unittest.TestCase):
    def setUp(self):
        self.sdk = _stub_sdk()
        patcher = mock.patch.dict(sys.modules, {"anthropic": self.sdk})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.sent = []

    def call(self, outcome):
        def create(**kwargs):
            self.sent.append(kwargs)
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

        fake = types.SimpleNamespace(beta=types.SimpleNamespace(messages=types.SimpleNamespace(create=create)))
        return AnthropicModelClient("k", client=fake).complete_json(ModelRequest("sys", "usr", SCHEMA))

    def test_success_and_request_shape(self):
        result = self.call(_response())
        self.assertEqual((result.data, result.input_tokens, result.output_tokens), ({"a": "b"}, 3, 4))
        sent = self.sent[0]
        self.assertEqual((sent["model"], sent["fallbacks"], sent["thinking"]), ("claude-opus-5-5", "default", {"type": "adaptive"}))
        self.assertEqual(sent["output_config"]["format"]["schema"], SCHEMA)
        self.assertNotIn("tools", sent)

    def test_every_status_error_keeps_status_and_type(self):
        body = {"error": {"type": "some_error", "message": "provider says no"}}
        cases = (("BadRequestError", 400, "bad request"), ("AuthenticationError", 401, "model key rejected"),
                 ("PermissionDeniedError", 403, "model key lacks permission"), ("NotFoundError", 404, "model or endpoint not found"),
                 ("RateLimitError", 429, "rate limited"), ("APIStatusError", 529, "provider error"))
        for name, status, label in cases:
            with self.subTest(name):
                with self.assertRaises(ModelError) as caught:
                    self.call(getattr(self.sdk, name)(status, body))
                self.assertEqual(str(caught.exception), f"{label}: HTTP {status} some_error")
                self.assertEqual(caught.exception.detail, "provider says no")

    def test_status_error_without_a_body(self):
        with self.assertRaises(ModelError) as caught:
            self.call(self.sdk.APIStatusError(500, None))
        self.assertEqual((str(caught.exception), caught.exception.detail), ("provider error: HTTP 500", ""))

    def test_connection_error(self):
        with self.assertRaises(ModelError) as caught:
            self.call(self.sdk.APIConnectionError())
        self.assertEqual(str(caught.exception), "could not reach the provider")

    def test_unusable_responses(self):
        cases = ((_response("refusal", []), ModelRefused), (_response("max_tokens"), ModelOutputInvalid),
                 (_response(content=[types.SimpleNamespace(type="thinking", text="")]), ModelOutputInvalid),
                 (_response(content=[types.SimpleNamespace(type="text", text="not json")]), ModelOutputInvalid),
                 (_response(content=[types.SimpleNamespace(type="text", text='{"a": "b", "conclusion": "success"}')]), ModelOutputInvalid))
        for response, error in cases:
            with self.subTest(error=error.__name__, stop=response.stop_reason):
                with self.assertRaises(error):
                    self.call(response)
