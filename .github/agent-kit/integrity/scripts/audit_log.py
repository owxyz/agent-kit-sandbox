#!/usr/bin/env python3
"""Append-only, hash-chained audit log for gate decisions (P2.7).

Usage: audit_log.py init   (--audit-file PATH | --audit-repo OWNER/NAME [--audit-path P] [--audit-branch B])
       audit_log.py verify (same store options) [--expect-head SEQ:HASH]

Run init once at install. Appends never create the log, so a deleted log stops
decisions instead of silently starting a new chain.

The log is JSON Lines. Each entry records the previous entry's hash, so changing
or removing an entry breaks the chain. Cutting entries off the end cannot be seen
from the chain alone: pass a head recorded earlier with --expect-head.
"""
import argparse
import base64
import contextlib
import datetime
import fcntl
import hashlib
import json
import os
import sys
import time

from common import GitHub, ToolError, quote, run

SCHEMA = 1
GENESIS = "0" * 64
EVENTS = {"block", "override", "override_rejected"}
REQUIRED_FIELDS = ("event", "repo", "pr", "sha", "gate", "rules", "files", "blocking_count", "agent_pr")
DEFAULT_PATH = "gate-overrides.jsonl"
MAX_ATTEMPTS = 8


class Conflict(Exception):
    """Someone else appended first; read again and retry."""


class FileStore:
    def __init__(self, path):
        self.path = path

    @contextlib.contextmanager
    def locked(self):
        with open(self.path + ".lock", "w", encoding="utf-8") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            yield

    def read(self, allow_missing=False):
        if not os.path.exists(self.path):
            if not allow_missing:
                raise ToolError("audit log %s does not exist" % self.path)
            return "", None
        with open(self.path, encoding="utf-8") as handle:
            return handle.read(), None

    def write(self, _previous_text, addition, _token):
        with open(self.path, "a", encoding="utf-8") as handle:
            handle.write(addition)

    def create(self):
        try:
            with open(self.path, "x", encoding="utf-8"):
                pass
        except FileExistsError:
            raise ToolError("audit log %s already exists" % self.path)


class GitHubStore:
    """One file in a dedicated audit repo, updated with optimistic concurrency."""

    def __init__(self, repo, path=DEFAULT_PATH, branch="main", github=None):
        self.repo, self.path, self.branch = repo, path, branch
        self.github = github or GitHub(token=os.environ.get("AUDIT_REPO_TOKEN"))

    @contextlib.contextmanager
    def locked(self):
        yield

    def contents_url(self):
        return "/repos/%s/contents/%s" % (self.repo, quote(self.path, safe="/"))

    def read(self, allow_missing=False):
        url = "%s?ref=%s" % (self.contents_url(), quote(self.branch))
        body = self.github.get_json(url, allow_404=True)
        if body is None:
            # GitHub also answers 404 for a repo the token can't see.
            if self.github.get_json("/repos/%s" % self.repo, allow_404=True) is None:
                raise ToolError("audit repo %s is missing or not readable with this token" % self.repo)
            if not allow_missing:
                raise ToolError("audit log %s does not exist in %s" % (self.path, self.repo))
            return "", None
        if not isinstance(body, dict) or "sha" not in body:
            raise ToolError("%s is not a file in %s" % (self.path, self.repo))
        if body.get("size") == 0:
            return "", body["sha"]
        if body.get("encoding") == "base64" and body.get("content"):
            return base64.b64decode(body["content"]).decode("utf-8"), body["sha"]
        return self.github.get_raw(url).decode("utf-8"), body["sha"]  # over 1 MB

    def write(self, previous_text, addition, token):
        payload = {
            "message": "audit: append gate decision",
            "branch": self.branch,
            "content": base64.b64encode((previous_text + addition).encode("utf-8")).decode("ascii"),
        }
        if token:
            payload["sha"] = token
        status, raw = self.github.request("PUT", self.contents_url(), body=payload)
        if status in (409, 422):
            raise Conflict(raw.decode("utf-8", "replace"))
        if status not in (200, 201):
            raise ToolError("audit write returned %d" % status)


    def create(self):
        if self.read(allow_missing=True)[1] is not None:
            raise ToolError("audit log %s already exists in %s" % (self.path, self.repo))
        try:
            self.write("", "", None)
        except Conflict as error:
            raise ToolError("could not create the audit log: %s" % error)


def entry_hash(entry):
    unhashed = {k: v for k, v in entry.items() if k != "entry_hash"}
    canonical = json.dumps(unhashed, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def parse_chain(text):
    """Return entries, raising ToolError if the chain is broken in any way."""
    entries, previous = [], GENESIS
    for number, line in enumerate(text.splitlines(), 1):
        try:
            entry = json.loads(line)
        except ValueError as error:
            raise ToolError("audit line %d is not JSON: %s" % (number, error))
        if not isinstance(entry, dict):
            raise ToolError("audit line %d is not an object" % number)
        if entry.get("seq") != number or entry.get("prev_hash") != previous:
            raise ToolError("audit chain broken at line %d" % number)
        if entry.get("entry_hash") != entry_hash(entry):
            raise ToolError("audit entry %d was altered" % number)
        previous = entry["entry_hash"]
        entries.append(entry)
    if text and not text.endswith("\n"):
        raise ToolError("audit log has a partial last line")
    return entries


def now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def dedupe_key(event):
    if event["event"] == "override_rejected":
        return ("override_rejected", event.get("comment_id"))
    return (event["event"], event["repo"], event["pr"], event["sha"], event["gate"])


def validate(event):
    if event.get("event") not in EVENTS:
        raise ToolError("unknown audit event %r" % event.get("event"))
    missing = [f for f in REQUIRED_FIELDS if f not in event]
    if missing:
        raise ToolError("audit event lacks %s" % ", ".join(missing))
    if event["event"] == "override" and not (event.get("actor") and event.get("reason")):
        raise ToolError("an override must record its actor and reason")


def append_events(store, events):
    """Append events, skipping any already logged. Failure raises, never passes."""
    for event in events:
        validate(event)
    for attempt in range(MAX_ATTEMPTS):
        with store.locked():
            text, token = store.read()
            entries = parse_chain(text)
            seen = {dedupe_key(e) for e in entries}
            previous = entries[-1]["entry_hash"] if entries else GENESIS
            addition, seq = "", len(entries)
            for event in events:
                if dedupe_key(event) in seen:
                    continue
                seen.add(dedupe_key(event))
                seq += 1
                entry = {"schema": SCHEMA, "ts": event.get("ts") or now(), **event, "seq": seq, "prev_hash": previous}
                entry["entry_hash"] = entry_hash(entry)
                previous = entry["entry_hash"]
                addition += json.dumps(entry, sort_keys=True, ensure_ascii=False) + "\n"
            if not addition:
                return
            try:
                store.write(text, addition, token)
                return
            except Conflict:
                pass
        time.sleep(0.2 * (attempt + 1))
    raise ToolError("could not append to the audit log after %d attempts" % MAX_ATTEMPTS)


def add_store_arguments(parser):
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--audit-file")
    group.add_argument("--audit-repo")
    parser.add_argument("--audit-path", default=DEFAULT_PATH)
    parser.add_argument("--audit-branch", default="main")


def store_from(args):
    if args.audit_file:
        return FileStore(args.audit_file)
    return GitHubStore(args.audit_repo, args.audit_path, args.audit_branch)


def check_head(entries, expected):
    try:
        seq_text, digest = expected.split(":", 1)
        seq = int(seq_text)
    except ValueError:
        raise ToolError("--expect-head must be SEQ:HASH")
    if seq > len(entries) or (seq > 0 and entries[seq - 1]["entry_hash"] != digest):
        raise ToolError("the log does not contain the expected head %s; it was cut or rewritten" % expected)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=["init", "verify"])
    add_store_arguments(parser)
    parser.add_argument("--expect-head")
    args = parser.parse_args()
    if args.command == "init":
        store_from(args).create()
        print("created an empty audit log")
        return 0
    entries = parse_chain(store_from(args).read()[0])
    if args.expect_head:
        check_head(entries, args.expect_head)
    head = entries[-1]["entry_hash"] if entries else GENESIS
    print("ok: %d entries, head %d:%s" % (len(entries), len(entries), head), file=sys.stdout)
    return 0


if __name__ == "__main__":
    run(main)
