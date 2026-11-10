"""The contract every advisory agent implements. P4.2 AI review plugs in here."""
from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, Mapping, Optional, Tuple

from ..checks import Action, CheckRunSpec
from ..github import InstallationClient
from ..models import ModelClient
from ..store import Store


@dataclass(frozen=True)
class Event:
    """A verified webhook. Every field came from the signed body."""

    name: str
    action: str
    delivery: str
    payload: Dict[str, Any]

    @property
    def repo(self) -> str:
        return self.payload["repository"]["full_name"]

    @property
    def installation_id(self) -> int:
        return int(self.payload["installation"]["id"])

    @property
    def run(self) -> Dict[str, Any]:
        return self.payload.get("workflow_run") or {}


@dataclass(frozen=True)
class RunContext:
    event: Event
    github: InstallationClient
    model: ModelClient
    store: Store
    agent_logins: FrozenSet[str] = frozenset()


class Agent(abc.ABC):
    id: str
    check_name: str
    permissions: Mapping[str, str]
    # Rating actions offered on the check: {action identifier: rating stored}.
    ratings: Mapping[str, str] = {}

    @abc.abstractmethod
    def accepts(self, event: Event) -> bool:
        """Should this agent run for a verified event?"""

    @abc.abstractmethod
    def job_key(self, event: Event) -> str:
        """Identity of the work, so one piece of work runs once."""

    @abc.abstractmethod
    def run(self, context: RunContext) -> Optional[CheckRunSpec]:
        """Do the work and describe the neutral check to post."""

    def head_sha(self, event: Event) -> str:
        return event.run["head_sha"]

    def actions(self) -> Tuple[Action, ...]:
        return ()
