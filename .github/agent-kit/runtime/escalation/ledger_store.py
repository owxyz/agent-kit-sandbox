#!/usr/bin/env python3
"""Durable, hash-chained copy of the flag ledger in the gate audit repo (R1.10, P2.8).

The runner writes each task's record to a local ledger in its temp folder, which
doesn't survive the job. After the task, the trusted workflow step appends those
records here, to one file in the audit repo (D6: `owxyz/gate-audit`). The agent's
token can't reach that repo, and its ruleset blocks deletion and force pushes.

  ledger_store.py init   STORE
  ledger_store.py append STORE --ledger LOCAL.jsonl [--allow-missing]
  ledger_store.py verify STORE [--expect-head SEQ:HASH]
  ledger_store.py fetch  STORE --output LOCAL.jsonl   # then flag_ledger.py report --ledger LOCAL.jsonl

STORE is --audit-file PATH, or --audit-repo OWNER/NAME [--audit-path P] [--audit-branch B]
with the token in AUDIT_REPO_TOKEN. Run init once; append never creates the file, so a
deleted ledger stops appends instead of silently starting a new chain.

The chain format is the gate audit log's (gates/integrity/scripts/audit_log.py): each
line carries seq, prev_hash and entry_hash, so a changed or removed line breaks the
chain. Cutting lines off the end needs --expect-head to see. Standard library only.

Exit 0 ok, 2 tool error.
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
import urllib.error
import urllib.parse
import urllib.request

SCHEMA = 1
KIND = "flag-task"
GENESIS = "0" * 64
DEFAULT_PATH = "flag-ledger.jsonl"
CHAIN_FIELDS = ("schema", "kind", "seq", "prev_hash", "entry_hash")
REQUIRED_FIELDS = ("time", "task_id", "agent")
MAX_ATTEMPTS = 8


class ToolError(Exception):
    pass


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
                raise ToolError("ledger %s does not exist; run init once" % self.path)
            return "", None
        with open(self.path, encoding="utf-8") as handle:
            return handle.read(), None

    def write(self, _previous, addition, _sha):
        with open(self.path, "a", encoding="utf-8") as handle:
            handle.write(addition)

    def create(self):
        try:
            with open(self.path, "x", encoding="utf-8"):
                pass
        except FileExistsError:
            raise ToolError("ledger %s already exists" % self.path)


class GitHubStore:
    """One file in the audit repo, updated through the contents API with the file's sha as a lock."""

    def __init__(self, repo, path=DEFAULT_PATH, branch="main", token=None, api_url=None):
        self.repo, self.path, self.branch = repo, path, branch
        self.token = token if token is not None else os.environ.get("AUDIT_REPO_TOKEN", "")
        self.api_url = (api_url or os.environ.get("GITHUB_API_URL") or "https://api.github.com").rstrip("/")
        if not self.token:
            raise ToolError("AUDIT_REPO_TOKEN is not set")

    @contextlib.contextmanager
    def locked(self):
        yield

    def _request(self, method, path, body=None, accept="application/vnd.github+json"):
        data = json.dumps(body).encode("utf-8") if body is not None else None
        request = urllib.request.Request(self.api_url + path, data=data, method=method)
        request.add_header("Authorization", "Bearer " + self.token)
        request.add_header("Accept", accept)
        request.add_header("X-GitHub-Api-Version", "2022-11-28")
        request.add_header("User-Agent", "agent-kit-ledger-store")
        if data is not None:
            request.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            if error.code >= 500:
                raise ToolError("GitHub returned %d for %s" % (error.code, path))
            return error.code, error.read()
        except OSError as error:
            raise ToolError("GitHub request failed: %s" % error)

    def _contents(self):
        return "/repos/%s/contents/%s" % (self.repo, urllib.parse.quote(self.path, safe="/"))

    def read(self, allow_missing=False):
        url = "%s?ref=%s" % (self._contents(), urllib.parse.quote(self.branch))
        status, raw = self._request("GET", url)
        if status == 404:
            # GitHub also answers 404 for a repo the token can't see.
            if self._request("GET", "/repos/%s" % self.repo)[0] != 200:
                raise ToolError("audit repo %s is missing or not readable with this token" % self.repo)
            if not allow_missing:
                raise ToolError("ledger %s does not exist in %s; run init once" % (self.path, self.repo))
            return "", None
        if status != 200:
            raise ToolError("reading the ledger returned %d" % status)
        body = json.loads(raw.decode("utf-8"))
        if not isinstance(body, dict) or "sha" not in body:
            raise ToolError("%s is not a file in %s" % (self.path, self.repo))
        if body.get("size") == 0:
            return "", body["sha"]
        if body.get("encoding") == "base64" and body.get("content"):
            return base64.b64decode(body["content"]).decode("utf-8"), body["sha"]
        status, raw = self._request("GET", url, accept="application/vnd.github.raw")  # over 1 MB
        if status != 200:
            raise ToolError("reading the ledger returned %d" % status)
        return raw.decode("utf-8"), body["sha"]

    def write(self, previous, addition, sha):
        payload = {
            "message": "ledger: append flag records",
            "branch": self.branch,
            "content": base64.b64encode((previous + addition).encode("utf-8")).decode("ascii"),
        }
        if sha:
            payload["sha"] = sha
        status, raw = self._request("PUT", self._contents(), body=payload)
        if status in (409, 422):
            raise Conflict(raw.decode("utf-8", "replace"))
        if status not in (200, 201):
            raise ToolError("ledger write returned %d" % status)

    def create(self):
        if self.read(allow_missing=True)[1] is not None:
            raise ToolError("ledger %s already exists in %s" % (self.path, self.repo))
        try:
            self.write("", "", None)
        except Conflict as error:
            raise ToolError("could not create the ledger: %s" % error)


def entry_hash(entry):
    unhashed = {k: v for k, v in entry.items() if k != "entry_hash"}
    canonical = json.dumps(unhashed, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def parse_chain(text):
    """Entries in order, or ToolError if any line was changed, removed or reordered."""
    entries, previous = [], GENESIS
    for number, line in enumerate(text.splitlines(), 1):
        try:
            entry = json.loads(line)
        except ValueError as error:
            raise ToolError("ledger line %d is not JSON: %s" % (number, error))
        if not isinstance(entry, dict):
            raise ToolError("ledger line %d is not an object" % number)
        if entry.get("seq") != number or entry.get("prev_hash") != previous:
            raise ToolError("ledger chain broken at line %d" % number)
        if entry.get("entry_hash") != entry_hash(entry):
            raise ToolError("ledger entry %d was altered" % number)
        previous = entry["entry_hash"]
        entries.append(entry)
    if text and not text.endswith("\n"):
        raise ToolError("ledger has a partial last line")
    return entries


def record_key(record):
    return (record.get("task_id"), record.get("agent"), record.get("time"))


def strip_chain(entry):
    return {k: v for k, v in entry.items() if k not in CHAIN_FIELDS}


def read_local(path, allow_missing):
    if not os.path.exists(path):
        if allow_missing:
            return []
        raise ToolError("local ledger %s does not exist" % path)
    records = []
    with open(path, encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except ValueError:
                raise ToolError("%s:%d: not valid JSON" % (path, number))
            if not isinstance(record, dict) or any(not record.get(f) for f in REQUIRED_FIELDS):
                raise ToolError("%s:%d: a record needs %s" % (path, number, ", ".join(REQUIRED_FIELDS)))
            if any(f in record for f in CHAIN_FIELDS):
                raise ToolError("%s:%d: a record can't set %s" % (path, number, ", ".join(CHAIN_FIELDS)))
            records.append(record)
    return records


def append_records(store, records):
    """Append records not already stored. Returns how many were added. Failure raises."""
    for attempt in range(MAX_ATTEMPTS):
        with store.locked():
            text, sha = store.read()
            entries = parse_chain(text)
            seen = {record_key(e) for e in entries}
            previous = entries[-1]["entry_hash"] if entries else GENESIS
            addition, seq, added = "", len(entries), 0
            for record in records:
                if record_key(record) in seen:
                    continue
                seen.add(record_key(record))
                seq += 1
                entry = {"schema": SCHEMA, "kind": KIND, **record, "seq": seq, "prev_hash": previous}
                entry["entry_hash"] = entry_hash(entry)
                previous = entry["entry_hash"]
                addition += json.dumps(entry, sort_keys=True, ensure_ascii=False) + "\n"
                added += 1
            if not addition:
                return 0
            try:
                store.write(text, addition, sha)
                return added
            except Conflict:
                pass
        time.sleep(0.2 * (attempt + 1))
    raise ToolError("could not append to the ledger after %d attempts" % MAX_ATTEMPTS)


def check_head(entries, expected):
    try:
        seq_text, digest = expected.split(":", 1)
        seq = int(seq_text)
    except ValueError:
        raise ToolError("--expect-head must be SEQ:HASH")
    if seq > len(entries) or (seq > 0 and entries[seq - 1]["entry_hash"] != digest):
        raise ToolError("the ledger does not contain the expected head %s; it was cut or rewritten" % expected)


def head_of(entries):
    return "%d:%s" % (len(entries), entries[-1]["entry_hash"] if entries else GENESIS)


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=["init", "append", "verify", "fetch"])
    store = parser.add_mutually_exclusive_group(required=True)
    store.add_argument("--audit-file")
    store.add_argument("--audit-repo")
    parser.add_argument("--audit-path", default=DEFAULT_PATH)
    parser.add_argument("--audit-branch", default="main")
    parser.add_argument("--ledger", help="append: the runner's local ledger")
    parser.add_argument("--allow-missing", action="store_true",
                        help="append: pass when the local ledger doesn't exist (the task never started)")
    parser.add_argument("--expect-head", help="verify: a SEQ:HASH recorded earlier")
    parser.add_argument("--output", help="fetch: write the records, without chain fields, here")
    args = parser.parse_args(argv)
    try:
        target = FileStore(args.audit_file) if args.audit_file else GitHubStore(
            args.audit_repo, args.audit_path, args.audit_branch)
        if args.command == "init":
            target.create()
            print("created an empty ledger")
        elif args.command == "append":
            if not args.ledger:
                raise ToolError("append needs --ledger")
            records = read_local(args.ledger, args.allow_missing)
            added = append_records(target, records)
            entries = parse_chain(target.read()[0])
            print("appended %d of %d record(s); head %s" % (added, len(records), head_of(entries)))
        elif args.command == "verify":
            entries = parse_chain(target.read()[0])
            if args.expect_head:
                check_head(entries, args.expect_head)
            print("ok: %d entries, head %s" % (len(entries), head_of(entries)))
        else:
            if not args.output:
                raise ToolError("fetch needs --output")
            entries = parse_chain(target.read()[0])
            descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                for entry in entries:
                    handle.write(json.dumps(strip_chain(entry), sort_keys=True) + "\n")
            print("fetched %d record(s), head %s, at %s" % (len(entries), head_of(entries), _now()))
    except (ToolError, OSError, ValueError) as error:
        print("ledger store error: %s" % error, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
