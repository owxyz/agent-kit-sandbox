"""Decide from PR metadata whether a PR is a bug fix and whether an owner approved it."""
from __future__ import annotations

import re

BUG_LABELS = {"bug", "bugfix", "bug-fix", "fix", "hotfix", "regression", "type:bug", "type/bug",
              "kind/bug", "kind:bug"}
BUG_TITLE = re.compile(r"^\s*(fix|bugfix|hotfix)(\([^)]*\))?!?:", re.I)
BUG_BRANCH = re.compile(r"^(fix|bugfix|hotfix)[/-]", re.I)
BUG_BODY = re.compile(r"\b(fix|fixes|fixed)\s+(#\d+|[\w.-]+/[\w.-]+#\d+)", re.I)


def label_names(pull):
    return [item.get("name", "") for item in pull.get("labels") or []]


def bug_fix_signals(pull):
    """Any one signal marks a bug fix. Each is PR-author-controlled, so more signals only make it stricter."""
    signals = []
    labels = {name.lower() for name in label_names(pull)}
    matched = sorted(labels & BUG_LABELS)
    if matched:
        signals.append("label:%s" % matched[0])
    if BUG_TITLE.search(pull.get("title") or ""):
        signals.append("title")
    if BUG_BRANCH.search((pull.get("head") or {}).get("ref") or ""):
        signals.append("branch")
    if BUG_BODY.search(pull.get("body") or ""):
        signals.append("body-fixes-issue")
    return signals


def owner_approved(reviews, owners, head_sha):
    """True when a listed owner's latest decisive review approves this exact head commit."""
    owners, latest = {x.lower() for x in owners}, {}
    for review in reviews:
        login = (review.get("user") or {}).get("login", "").lower()
        if login in owners and review.get("state") in ("APPROVED", "CHANGES_REQUESTED", "DISMISSED"):
            latest[login] = review
    decided = list(latest.values())
    return bool(decided) and all(r.get("state") == "APPROVED" for r in decided) and any(
        r.get("commit_id") == head_sha for r in decided)
