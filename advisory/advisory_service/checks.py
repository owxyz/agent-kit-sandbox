"""Check-run construction. Every advisory check is completed and neutral.

`CheckRunSpec` has no conclusion or status field, so no agent, and nothing a
model returns, can choose one. The only place those values are set is `render`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Sequence, Tuple

CONCLUSION = "neutral"
NAME_PREFIX = "advisory/"
MAX_BODY = 60000
MAX_ANNOTATIONS = 50  # GitHub's per-request limit


@dataclass(frozen=True)
class Action:
    label: str
    description: str
    identifier: str

    def __post_init__(self):
        if len(self.label) > 20 or len(self.description) > 40 or len(self.identifier) > 20:
            raise ValueError("check-run action exceeds GitHub's field limits")


@dataclass(frozen=True)
class Annotation:
    path: str
    start_line: int
    end_line: int
    message: str
    title: str = ""
    annotation_level: str = "notice"


@dataclass(frozen=True)
class CheckRunSpec:
    name: str
    title: str
    summary: str
    external_id: str
    text: str = ""
    actions: Tuple[Action, ...] = ()
    annotations: Tuple[Annotation, ...] = field(default_factory=tuple)


def validate_name(name: str, required_checks: Iterable[str] = ()) -> None:
    if not name.startswith(NAME_PREFIX) or name in set(required_checks):
        raise ValueError(f"advisory checks must use the {NAME_PREFIX} prefix and not be required: {name}")


def render(spec: CheckRunSpec, head_sha: str, completed_at: str) -> Dict[str, Any]:
    validate_name(spec.name)
    if len(spec.actions) > 3:
        raise ValueError("GitHub allows at most 3 check-run actions")
    output: Dict[str, Any] = {
        "title": spec.title[:200],
        "summary": spec.summary[:MAX_BODY],
    }
    if spec.text:
        output["text"] = spec.text[:MAX_BODY]
    annotations: Sequence[Annotation] = spec.annotations[:MAX_ANNOTATIONS]
    if annotations:
        output["annotations"] = [_annotation(a) for a in annotations]
    payload: Dict[str, Any] = {
        "name": spec.name,
        "head_sha": head_sha,
        "external_id": spec.external_id,
        "status": "completed",
        "conclusion": CONCLUSION,
        "completed_at": completed_at,
        "output": output,
    }
    if spec.actions:
        payload["actions"] = [
            {"label": a.label, "description": a.description, "identifier": a.identifier} for a in spec.actions
        ]
    return payload


def _annotation(item: Annotation) -> Dict[str, Any]:
    body: Dict[str, Any] = {
        "path": item.path,
        "start_line": item.start_line,
        "end_line": item.end_line,
        "annotation_level": item.annotation_level,
        "message": item.message[:60000],
    }
    if item.title:
        body["title"] = item.title[:255]
    return body


def required_names(config: Dict[str, Any]) -> List[str]:
    return [c["context"] for c in config.get("checks", [])]
