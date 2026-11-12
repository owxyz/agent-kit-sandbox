#!/usr/bin/env python3
"""Decide a gate's result, honoring a code owner's written override (P2.7).

Usage: apply_override.py --gate NAME --findings FILE --gate-exit N
           --codeowners BASE_CODEOWNERS --repo OWNER/NAME --pr N --sha SHA
           (--audit-file PATH | --audit-repo OWNER/NAME) [--path-prefix P ...]
           [--output FILE]

An owner overrides by commenting on the PR. The first line binds it to one gate
and one commit, so any new push voids it:

    /gate-override gate=tamper sha=abc1234 reason: why this block is wrong

The decision is logged before it takes effect; if logging fails, nothing passes.
A gate tool error (exit 2) can never be overridden.
"""
import argparse
import os
import re

from audit_log import add_store_arguments, append_events, store_from
from codeowners import CodeOwners
from common import FINDING_FIELDS, GitHub, ToolError, emit, load_json, quote, run

COMMAND = "/gate-override"
MIN_REASON_CHARS = 20
MIN_REASON_WORDS = 3
MAX_REASON_CHARS = 2000
WRITE_PERMISSIONS = {"admin", "write"}


def load_findings(path, gate):
    data = load_json(path)
    if not isinstance(data, list):
        raise ToolError("findings must be a list")
    for item in data:
        if not isinstance(item, dict) or any(f not in item for f in FINDING_FIELDS):
            raise ToolError("malformed finding: %r" % (item,))
        if item["mode"] not in ("warn", "block"):
            raise ToolError("invalid mode %r" % item["mode"])
        if item["gate"] != gate:
            raise ToolError("finding belongs to gate %r, not %r" % (item["gate"], gate))
    return data


def parse_command(body):
    """Return {gate, sha, reason} for a command comment, else None."""
    text = (body or "").replace("\r\n", "\n").strip()
    first_line = text.split("\n", 1)[0]
    if first_line.split(" ", 1)[0] != COMMAND:
        return None
    position = text.find("reason:")
    head = text if position < 0 else text[:position]
    reason = "" if position < 0 else text[position + len("reason:"):].strip()
    fields = dict(t.split("=", 1) for t in head.split()[1:] if "=" in t)
    return {"gate": fields.get("gate"), "sha": fields.get("sha"), "reason": reason[:MAX_REASON_CHARS]}


def reason_problem(reason):
    if not reason:
        return "no written reason"
    if len(reason) < MIN_REASON_CHARS or len(reason.split()) < MIN_REASON_WORDS:
        return "reason is too short (need %d characters and %d words)" % (MIN_REASON_CHARS, MIN_REASON_WORDS)
    return None


def is_bot(user, bot_logins):
    login = str(user.get("login", ""))
    return user.get("type") != "User" or login.lower().endswith("[bot]") or login.lower() in bot_logins


class OwnerCheck:
    def __init__(self, github, team_github, repo, codeowners):
        self.github, self.team_github, self.repo, self.codeowners = github, team_github, repo, codeowners
        self.memo = {}

    def has_write(self, login):
        body = self.github.get_json(
            "/repos/%s/collaborators/%s/permission" % (self.repo, quote(login)), allow_404=True)
        return isinstance(body, dict) and body.get("permission") in WRITE_PERMISSIONS

    def in_owner(self, login, owner):
        key = (login.lower(), owner.lower())
        if key not in self.memo:
            self.memo[key] = self.lookup(login, owner)
        return self.memo[key]

    def lookup(self, login, owner):
        if not owner.startswith("@"):
            return False  # e-mail owners cannot be matched to a login
        name = owner[1:]
        if "/" not in name:
            return name.lower() == login.lower()
        org, team = name.split("/", 1)
        body = self.team_github.get_json(
            "/orgs/%s/teams/%s/memberships/%s" % (quote(org), quote(team), quote(login)), allow_404=True)
        return isinstance(body, dict) and body.get("state") == "active"

    def owns_all(self, login, paths):
        for path in paths:
            if not any(self.in_owner(login, owner) for owner in self.codeowners.owners_for(path)):
                return False
        return self.has_write(login)


def strip_prefix(path, prefixes):
    for prefix in prefixes:
        if path.startswith(prefix):
            return path[len(prefix):]
    return path


def review_comments(comments, args, pr_author, bot_logins, owners, paths):
    """Return (accepted (comment, command) or None, rejected [(comment, command, why)])."""
    accepted, rejected = None, []
    for comment in comments:
        command = parse_command(comment.get("body"))
        if command is None or command["gate"] != args.gate:
            continue
        sha = command["sha"]
        if sha is None:
            rejected.append((comment, command, "no sha= given"))
            continue
        if len(sha) < 7 or not args.sha.startswith(sha):
            continue  # meant for another commit
        user = comment.get("user") or {}
        login = str(user.get("login", ""))
        why = None
        if comment.get("updated_at") != comment.get("created_at"):
            why = "comment was edited after posting"
        elif is_bot(user, bot_logins):
            why = "bots and agents cannot override"
        elif login.lower() == pr_author.lower():
            why = "the PR author cannot override their own PR"
        elif reason_problem(command["reason"]):
            why = reason_problem(command["reason"])
        elif not owners.owns_all(login, paths):
            why = "not a code owner of every blocked file"
        if why:
            rejected.append((comment, command, why))
        else:
            accepted = (comment, command)
    return accepted, rejected


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--gate", required=True)
    parser.add_argument("--findings", required=True)
    parser.add_argument("--gate-exit", type=int, required=True)
    parser.add_argument("--codeowners", required=True)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--pr", type=int, required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--path-prefix", action="append", default=[])
    parser.add_argument("--run-url", default="")
    parser.add_argument("--output")
    add_store_arguments(parser)
    args = parser.parse_args()

    if args.gate_exit not in (0, 1):
        raise ToolError("gate exited %d; a tool error cannot be overridden" % args.gate_exit)
    if not re.fullmatch(r"[0-9a-f]{40}", args.sha):
        raise ToolError("--sha must be a full commit SHA")
    findings = load_findings(args.findings, args.gate)
    blocks = [f for f in findings if f["mode"] == "block"]
    if bool(blocks) != (args.gate_exit == 1):
        raise ToolError("gate exit %d disagrees with its findings" % args.gate_exit)
    if not blocks:
        return emit(findings, args.output)

    try:
        with open(args.codeowners, encoding="utf-8") as handle:
            codeowners = CodeOwners(handle.read())
    except OSError as error:
        raise ToolError("cannot read CODEOWNERS: %s" % error)

    github = GitHub()
    team_token = os.environ.get("OVERRIDE_TEAM_TOKEN")
    team_github = GitHub(token=team_token) if team_token else github
    pull = github.get_json("/repos/%s/pulls/%d" % (args.repo, args.pr))
    if (pull.get("head") or {}).get("sha") != args.sha:
        raise ToolError("--sha is not the PR's current head; re-run on the latest commit")
    pr_author = str((pull.get("user") or {}).get("login", ""))
    if not pr_author:
        raise ToolError("PR has no author")
    labels = [str(item.get("name", "")) for item in pull.get("labels", [])]
    bot_logins = {x.strip().lower() for x in os.environ.get("AGENT_BOT_LOGINS", "").split(",") if x.strip()}
    paths = sorted({strip_prefix(str(f["file"]), args.path_prefix) for f in blocks})
    comments = github.list_all("/repos/%s/issues/%d/comments" % (args.repo, args.pr))
    owners = OwnerCheck(github, team_github, args.repo, codeowners)
    accepted, rejected = review_comments(comments, args, pr_author, bot_logins, owners, paths)

    base = {
        "repo": args.repo, "pr": args.pr, "sha": args.sha, "gate": args.gate,
        "rules": sorted({str(f["rule"]) for f in blocks}), "files": paths,
        "blocking_count": len(blocks), "agent_pr": any(x.startswith("agent:") for x in labels),
        "run_url": args.run_url,
    }
    def from_comment(comment, command):
        return {
            "actor": (comment.get("user") or {}).get("login"), "reason": command["reason"],
            "comment_id": comment.get("id"), "comment_url": comment.get("html_url"),
        }
    events = [
        dict(base, event="override_rejected", rejection=why, **from_comment(comment, command))
        for comment, command, why in rejected
    ]
    if accepted:
        events.append(dict(base, event="override", **from_comment(*accepted)))
    else:
        events.append(dict(base, event="block"))
    append_events(store_from(args), events)

    if not accepted:
        return emit(findings, args.output)
    actor = accepted[0]["user"]["login"]
    return emit([
        dict(f, mode="warn", message="[overridden by @%s] %s" % (actor, f["message"])) if f["mode"] == "block" else f
        for f in findings
    ], args.output)


if __name__ == "__main__":
    run(main)
