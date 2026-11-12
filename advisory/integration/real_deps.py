"""Integration checks against the real optional dependencies in requirements.txt.

Not part of the unit suite: CI does not install these packages, and a skipped test
is not a pass. Run by hand after installing requirements.txt, from advisory/:

    python3 -m unittest integration.real_deps

It fails, rather than skips, when a dependency is missing. Nothing leaves this
process: the SDK runs against a mock transport.
"""
import importlib
import importlib.util
import json
import unittest

import anthropic

# Current SDK releases use httpx2; older ones use httpx.
httpx = importlib.import_module("httpx2" if importlib.util.find_spec("httpx2") else "httpx")

from advisory_service.models import ModelOutputInvalid, ModelRefused, ModelRequest


class RealRs256(unittest.TestCase):
    def test_signature_verifies(self):
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
        from advisory_service.github import rs256_signer

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()).decode()
        key.public_key().verify(rs256_signer(pem)(b"message"), b"message", padding.PKCS1v15(), hashes.SHA256())


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
