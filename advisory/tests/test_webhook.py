"""Forged, malformed and replayed webhooks."""
import http.client
import json
import threading
from http.server import ThreadingHTTPServer

from advisory_service.cli import make_handler
from advisory_service.service import Settings, verify_signature

from .support import SECRET, Harness, headers, sign, workflow_event


class ForgedWebhooks(Harness):
    def assert_rejected(self, reply):
        self.assertEqual(reply.status, 401)
        self.assertEqual(self.github.calls, [])
        self.assertEqual(self.diagnosis_model.requests, [])

    def test_missing_signature(self):
        body = workflow_event()
        h = headers(body)
        del h["X-Hub-Signature-256"]
        self.assert_rejected(self.service.handle("/webhooks/diagnosis", h, body))

    def test_wrong_secret(self):
        body = workflow_event()
        self.assert_rejected(self.service.handle("/webhooks/diagnosis", headers(body, secret="guess"), body))

    def test_signature_for_a_different_body(self):
        body = workflow_event()
        tampered = workflow_event(run_id=999)
        self.assert_rejected(self.service.handle("/webhooks/diagnosis", headers(body), tampered))

    def test_sha1_style_and_junk_signatures(self):
        body = workflow_event()
        for value in ("sha1=abc", "abc", "sha256=", "sha256=" + "0" * 64, "sha256=é"):
            h = headers(body)
            h["X-Hub-Signature-256"] = value
            self.assert_rejected(self.service.handle("/webhooks/diagnosis", h, body))

    def test_unsigned_garbage_is_not_parsed(self):
        self.assert_rejected(self.service.handle("/webhooks/diagnosis", {"X-GitHub-Event": "workflow_run"}, b"{not json"))

    def test_empty_secret_is_refused_at_startup(self):
        with self.assertRaises(ValueError):
            Settings(("",), frozenset())
        with self.assertRaises(ValueError):
            Settings((), frozenset())

    def test_unknown_path_and_oversize(self):
        body = workflow_event()
        self.assertEqual(self.service.handle("/webhooks/nobody", headers(body), body).status, 404)
        self.assertEqual(self.service.handle("/hooks", headers(body), body).status, 404)
        huge = b"x" * (25 * 1024 * 1024 + 1)
        self.assertEqual(self.service.handle("/webhooks/diagnosis", headers(huge), huge).status, 413)

    def test_signed_but_malformed(self):
        for body in (b"{not json", b"[]", b'{"repository": {}}'):
            self.assertEqual(self.deliver(body).status, 400)

    def test_signed_event_with_a_bad_run_id_is_ignored(self):
        self.assertEqual(self.deliver(workflow_event(run_id="abc")).outcome, "ignored")

    def test_missing_delivery_header(self):
        body = workflow_event()
        h = headers(body)
        del h["X-GitHub-Delivery"]
        self.assertEqual(self.service.handle("/webhooks/diagnosis", h, body).status, 400)

    def test_repository_not_on_the_allowlist(self):
        body = json.loads(workflow_event())
        body["repository"]["full_name"] = "evil/repo"
        reply = self.deliver(json.dumps(body).encode())
        self.assertEqual(reply.outcome, "repository not allowed")
        self.assertEqual(self.github.calls, [])

    def test_unhandled_event_types_are_acknowledged(self):
        body = b'{"action": "removed", "installation": {"id": 42}}'
        self.assertEqual(self.deliver(body, event="installation_repositories").status, 202)

    def test_ping(self):
        self.assertEqual(self.deliver(b"{}", event="ping").outcome, "pong")

    def test_rotation_accepts_old_and_new_secret_only(self):
        body = b"{}"
        self.assertTrue(verify_signature(("new", "old"), body, sign(body, "old")))
        self.assertTrue(verify_signature(("new", "old"), body, sign(body, "new")))
        self.assertFalse(verify_signature(("new", "old"), body, sign(body, "retired")))


class Replay(Harness):
    def test_exact_replay_runs_once(self):
        self.github.jobs = []
        body = workflow_event()
        self.assertEqual(self.deliver(body, delivery="delivery-0001").status, 202)
        reply = self.deliver(body, delivery="delivery-0001")
        self.assertEqual(reply.status, 200)
        self.assertIn("replay refused", reply.outcome)
        self.assertEqual(len(self.github.posted), 1)

    def test_replay_with_a_fresh_delivery_id_is_refused(self):
        # The delivery ID is outside the signature, so an attacker can change it.
        self.github.jobs = []
        body = workflow_event()
        self.deliver(body, delivery="delivery-0001")
        self.assertIn("replay refused", self.deliver(body, delivery="delivery-9999").outcome)
        self.assertEqual(len(self.github.posted), 1)

    def test_old_event_refused_even_if_digest_forgotten(self):
        reply = self.deliver(workflow_event(updated="2026-11-01T00:00:00Z"))
        self.assertEqual(reply.outcome, "event too old")
        self.assertEqual(self.github.calls, [])

    def test_same_run_in_a_different_body_runs_once(self):
        self.github.jobs = []
        self.deliver(workflow_event(updated="2026-11-09T09:59:00Z"))
        self.deliver(workflow_event(updated="2026-11-09T09:59:30Z"))
        self.assertEqual(len(self.github.posted), 1)

    def test_a_new_run_attempt_gets_its_own_check(self):
        self.github.jobs = []
        self.deliver(workflow_event(attempt=1))
        self.deliver(workflow_event(attempt=2))
        self.assertEqual(len(self.github.posted), 2)

    def test_failed_job_can_be_redelivered(self):
        self.github.jobs = []
        self.github.check_status = 500
        body = workflow_event()
        self.deliver(body, delivery="delivery-0001")
        self.github.check_status = 201
        self.assertEqual(self.deliver(body, delivery="delivery-0001").status, 202)
        self.assertEqual(self.store.rating_rate("diagnosis", "not_helpful")["checks"], 1)

    def test_kill_switch_fails_closed_and_leaves_event_redeliverable(self):
        self.github.jobs = []
        body = workflow_event()
        for value in ("on", "", None, "OFF"):
            self.kill = value
            self.assertEqual(self.deliver(body).outcome, "kill switch engaged")
        self.assertEqual(self.github.calls, [])
        self.kill = "off"
        self.assertEqual(self.deliver(body).status, 202)

    def test_full_queue_releases_the_claim(self):
        service, self.service = self.service, self.build(submit=lambda job: False)
        self.github.jobs = []
        body = workflow_event()
        self.assertEqual(self.deliver(body).status, 503)
        self.service = service
        self.assertEqual(self.deliver(body).status, 202)


class OverSocket(Harness):
    def test_http_round_trip_and_forged_request(self):
        self.github.jobs = []
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.service))
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        threading.Thread(target=server.serve_forever, daemon=True).start()

        def post(body, extra):
            connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=10)
            self.addCleanup(connection.close)
            connection.request("POST", "/webhooks/diagnosis", body, extra)
            return connection.getresponse().status

        body = workflow_event()
        self.assertEqual(post(body, headers(body, secret="wrong")), 401)
        self.assertEqual(post(body, headers(body, secret=SECRET)), 202)
        self.assertEqual(len(self.github.posted), 1)
