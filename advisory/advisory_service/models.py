"""Pluggable model client. The default talks to the Anthropic API.

Agents see only `ModelClient.complete_json`. No client offers tools to the model,
so model output is data: nothing the model says can call anything.
"""
from __future__ import annotations

import abc
import json
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

DEFAULT_MODEL = "claude-opus-5-5"
_FALLBACK_BETA = "server-side-fallback-2026-07-01"


class ModelError(Exception):
    """The call failed, or returned something unusable.

    `str(error)` is written by this module from status codes and error types, so
    it is safe to show on a check run. `detail` may hold the provider's own
    message and belongs in the service log only.
    """

    def __init__(self, message: str, detail: str = ""):
        super().__init__(message)
        self.detail = detail

    def summary(self) -> str:
        return f"{type(self).__name__}: {self}"


class ModelRefused(ModelError):
    """The provider declined the request."""


class ModelOutputInvalid(ModelError):
    """The model's output does not match the schema, so it is discarded."""


@dataclass(frozen=True)
class ModelRequest:
    system: str
    user: str
    schema: Dict[str, Any]
    max_tokens: int = 16000
    effort: str = "medium"


@dataclass(frozen=True)
class ModelResponse:
    data: Dict[str, Any]
    model: str = ""
    input_tokens: int = 0
    output_tokens: int = 0


class ModelClient(abc.ABC):
    @abc.abstractmethod
    def complete_json(self, request: ModelRequest) -> ModelResponse:
        """Return JSON matching `request.schema`, or raise a ModelError."""


def validate(value: Any, schema: Dict[str, Any], path: str = "$") -> None:
    """Check the subset of JSON Schema used by agent schemas, on every provider."""
    kind = schema.get("type")
    expected = {"object": dict, "array": list, "string": str, "boolean": bool}.get(kind)
    if expected is not None and not isinstance(value, expected):
        raise ModelOutputInvalid(f"{path}: expected {kind}")
    if "enum" in schema and value not in schema["enum"]:
        raise ModelOutputInvalid(f"{path}: value outside the allowed set")
    if kind == "object":
        properties = schema.get("properties", {})
        missing = set(schema.get("required", ())) - set(value)
        extra = set(value) - set(properties)
        if missing or (extra and schema.get("additionalProperties") is False):
            raise ModelOutputInvalid(f"{path}: missing or unexpected fields")
        for key, item in value.items():
            if key in properties:
                validate(item, properties[key], f"{path}.{key}")
    elif kind == "array":
        for index, item in enumerate(value):
            validate(item, schema.get("items", {}), f"{path}[{index}]")


class AnthropicModelClient(ModelClient):
    """Anthropic Messages API with structured output and refusal fallback."""

    def __init__(self, api_key: str, model: str = DEFAULT_MODEL, client: Any = None, timeout: float = 120.0):
        import anthropic  # imported here so tests and other providers do not need it

        self._anthropic = anthropic
        self.model = model
        self._client = client or anthropic.Anthropic(api_key=api_key, timeout=timeout, max_retries=2)

    def complete_json(self, request: ModelRequest) -> ModelResponse:
        sdk = self._anthropic

        def status_error(label, exc):
            body = exc.body if isinstance(getattr(exc, "body", None), dict) else {}
            error = body.get("error") if isinstance(body.get("error"), dict) else {}
            kind = str(error.get("type", ""))[:60]
            return ModelError(f"{label}: HTTP {exc.status_code} {kind}".strip(), str(error.get("message", ""))[:500])

        try:
            response = self._client.beta.messages.create(
                model=self.model,
                max_tokens=request.max_tokens,
                betas=[_FALLBACK_BETA],
                fallbacks="default",
                thinking={"type": "adaptive"},
                output_config={
                    "effort": request.effort,
                    "format": {"type": "json_schema", "schema": request.schema},
                },
                system=request.system,
                messages=[{"role": "user", "content": request.user}],
            )
        except sdk.BadRequestError as exc:
            raise status_error("bad request", exc) from None
        except sdk.AuthenticationError as exc:
            raise status_error("model key rejected", exc) from None
        except sdk.PermissionDeniedError as exc:
            raise status_error("model key lacks permission", exc) from None
        except sdk.NotFoundError as exc:
            raise status_error("model or endpoint not found", exc) from None
        except sdk.RateLimitError as exc:
            raise status_error("rate limited", exc) from None
        except sdk.APIStatusError as exc:
            raise status_error("provider error", exc) from None
        except sdk.APIConnectionError:
            raise ModelError("could not reach the provider") from None

        if response.stop_reason == "refusal":
            raise ModelRefused("provider declined the request")
        if response.stop_reason != "end_turn":
            raise ModelOutputInvalid(f"unexpected stop reason: {response.stop_reason}")
        text = next((b.text for b in response.content if b.type == "text"), None)
        if text is None:
            raise ModelOutputInvalid("no text block in the response")
        try:
            data = json.loads(text)
        except ValueError:
            raise ModelOutputInvalid("response is not JSON") from None
        validate(data, request.schema)
        return ModelResponse(data, response.model, response.usage.input_tokens, response.usage.output_tokens)


Factory = Callable[[str, str], ModelClient]
_PROVIDERS: Dict[str, Factory] = {"anthropic": lambda key, model: AnthropicModelClient(key, model)}


def register_provider(name: str, factory: Factory) -> None:
    _PROVIDERS[name] = factory


def make_client(provider: str, api_key: str, model: Optional[str] = None) -> ModelClient:
    if provider not in _PROVIDERS:
        raise ValueError(f"unknown model provider: {provider}")
    return _PROVIDERS[provider](api_key, model or DEFAULT_MODEL)
