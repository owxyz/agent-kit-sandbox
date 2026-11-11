"""The webhook receiver and job runner shared by all advisory agents.

Nothing in a delivery is parsed until its signature is verified. GitHub signs the
body but not the X-GitHub-Delivery header, so replay protection keys on the digest
of the signed body: resending a captured body under a new delivery ID is caught.
The body has no signed timestamp either, so `workflow_run.updated_at` limits event
age, and body digests are kept for longer than that limit.
"""
from __future__ import annotations

import calendar
import hashlib
import hmac
import json
import logging
import os
import re
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, FrozenSet, Mapping, Optional, Sequence, Tuple

from . import checks, store as store_module
from .agents.base import Agent, Event, RunContext
from .github import GitHubApp, check_permissions
from .models import ModelClient
from .store import Store

log = logging.getLogger("advisory")
MAX_BODY = 25 * 1024 * 1024  # GitHub caps webhook payloads at 25 MB
HANDLED_EVENTS = frozenset({"workflow_run", "check_run"})
_DELIVERY = re.compile(r"^[0-9A-Za-z-]{8,64}$")
_REPO = re.compile(r"^[\w.-]+/[\w.-]+$")


@dataclass(frozen=True)
class Reply:
    status: int
    outcome: str


@dataclass(frozen=True)
class Settings:
    webhook_secrets: Tuple[str, ...]
    allowed_repos: FrozenSet[str]
    agent_logins: FrozenSet[str] = frozenset()
    max_event_age: float = 24 * 3600
    delivery_retention: float = 8 * 24 * 3600
    job_lease: float = 900

    def __post_init__(self):
        if not self.webhook_secrets or not all(self.webhook_secrets):
            raise ValueError("at least one non-empty webhook secret is required")
        if self.delivery_retention <= self.max_event_age:
            raise ValueError("delivery retention must exceed the maximum event age")


@dataclass(frozen=True)
class BoundAgent:
    """An agent with its own App identity and its own model key."""

    agent: Agent
    app: GitHubApp
    model: ModelClient


def verify_signature(secrets: Sequence[str], body: bytes, header: Optional[str]) -> bool:
    """Check X-Hub-Signature-256. Several secrets are accepted during rotation."""
    if not header or not header.startswith("sha256="):
        return False
    supplied = header.encode("utf-8", "replace")
    matched = False
    for secret in secrets:
        expected = b"sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest().encode()
        matched |= hmac.compare_digest(expected, supplied)
    return matched


def _epoch(stamp: Any) -> Optional[float]:
    try:
        return float(calendar.timegm(time.strptime(str(stamp)[:19], "%Y-%m-%dT%H:%M:%S")))
    except ValueError:
        return None


class AdvisoryService:
    def __init__(self, settings: Settings, agents: Sequence[BoundAgent], store: Store,
                 submit: Optional[Callable[[Callable[[], None]], bool]] = None,
                 clock: Callable[[], float] = time.time,
                 kill_switch: Optional[Callable[[], Optional[str]]] = None):
        self.settings = settings
        self.store = store
        self._agents: Dict[str, BoundAgent] = {}
        for bound in agents:
            checks.validate_name(bound.agent.check_name)
            check_permissions(bound.agent.permissions)
            self._agents[bound.agent.id] = bound
        self._submit = submit or self._run_now
        self._clock = clock
        self._kill_switch = kill_switch or (lambda: os.environ.get("ADVISORY_KILL_SWITCH"))

    @staticmethod
    def _run_now(job: Callable[[], None]) -> bool:
        job()
        return True

    def _running(self) -> bool:
        # Same convention as the kit: anything but exactly "off" stops agents.
        return self._kill_switch() == "off"

    def handle(self, path: str, headers: Mapping[str, str], body: bytes) -> Reply:
        """Authenticate one delivery and route it. Returns quickly; work is queued."""
        match = re.fullmatch(r"/webhooks/([\w-]+)", path)
        bound = self._agents.get(match.group(1)) if match else None
        if bound is None:
            return Reply(404, "unknown path")
        if len(body) > MAX_BODY:
            return Reply(413, "body too large")
        lowered = {k.lower(): v for k, v in headers.items()}
        if not verify_signature(self.settings.webhook_secrets, body, lowered.get("x-hub-signature-256")):
            log.warning("rejected delivery with a bad signature for %s", bound.agent.id)
            return Reply(401, "bad signature")

        # From here the body is authentic. Headers are still not signed.
        delivery = lowered.get("x-github-delivery", "")
        name = lowered.get("x-github-event", "")
        if not _DELIVERY.match(delivery) or not name:
            return Reply(400, "missing delivery headers")
        if name == "ping":
            return Reply(200, "pong")
        if name not in HANDLED_EVENTS:  # e.g. installation events: authentic, not ours
            return Reply(202, "event type not handled")
        try:
            payload = json.loads(body)
            repo = payload["repository"]["full_name"]
            event = Event(name, str(payload.get("action", "")), delivery, payload)
            event.installation_id
        except (ValueError, KeyError, TypeError):
            return Reply(400, "malformed event")
        if not _REPO.match(str(repo)) or repo not in self.settings.allowed_repos:
            return Reply(202, "repository not allowed")

        if name == "check_run" and event.action == "requested_action":
            return self._rating(bound, event)
        if not self._accepted(bound.agent, event):
            return Reply(202, "ignored")
        if name == "workflow_run":
            updated = _epoch(event.run.get("updated_at"))
            if updated is None or self._clock() - updated > self.settings.max_event_age:
                return Reply(202, "event too old")
        if not self._running():
            return Reply(202, "kill switch engaged")

        digest = hashlib.sha256(body).hexdigest()
        claim = self.store.claim("delivery", bound.agent.id, digest, self.settings.job_lease)
        if claim != store_module.CLAIMED:
            return Reply(200, f"replay refused: {claim}")
        self.store.expire_deliveries(self.settings.delivery_retention)
        if not self._submit(lambda: self.execute(bound, event, digest)):
            self.store.release("delivery", bound.agent.id, digest)
            return Reply(503, "queue full")
        return Reply(202, "accepted")

    @staticmethod
    def _accepted(agent: Agent, event: Event) -> bool:
        try:
            return agent.accepts(event) and bool(agent.job_key(event))
        except (KeyError, TypeError, ValueError, AttributeError):
            return False

    def _rating(self, bound: BoundAgent, event: Event) -> Reply:
        payload = event.payload
        try:
            check = payload["check_run"]
            app_id = int(check["app"]["id"])
            identifier = payload["requested_action"]["identifier"]
            external_id = str(check["external_id"])
            sender = str(payload["sender"]["login"])
        except (KeyError, TypeError, ValueError):
            return Reply(400, "malformed rating")
        agent = bound.agent
        rating = agent.ratings.get(identifier)
        if app_id != bound.app.app_id or rating is None or not external_id.startswith(agent.id + ":"):
            return Reply(202, "not this agent's check")
        if not self.store.record_rating(agent.id, external_id, event.repo, rating, sender):
            return Reply(202, "unknown check")
        return Reply(200, "rating recorded")

    def execute(self, bound: BoundAgent, event: Event, digest: str) -> None:
        agent = bound.agent
        if not self._running():
            self.store.release("delivery", agent.id, digest)
            return
        key = agent.job_key(event)
        claim = self.store.claim("job", agent.id, key, self.settings.job_lease)
        if claim != store_module.CLAIMED:
            self.store.finish("delivery", agent.id, digest, True)
            return
        ok = False
        try:
            github = bound.app.installation(event.installation_id, event.repo, agent.permissions)
            context = RunContext(event, github, bound.model, self.store, self.settings.agent_logins)
            spec = agent.run(context)
            if spec is not None:
                check_id = github.create_check_run(spec, agent.head_sha(event))
                self.store.record_check(agent.id, spec.external_id, event.repo, check_id)
            ok = True
        except Exception as exc:  # one bad job must not take the worker down
            # Type only: exception text could quote untrusted input.
            log.error("agent %s failed job %s: %s", agent.id, key, type(exc).__name__)
        finally:
            self.store.finish("job", agent.id, key, ok)
            self.store.finish("delivery", agent.id, digest, ok)
