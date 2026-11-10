"""Durable state: replay claims, signals, hints, ratings, findings and the hack ledger.

Structured signals and model hints live in separate tables so a consumer such as
P3.1 reads signals without touching model text. Raw logs and diffs are never stored.
"""
from __future__ import annotations

import collections
import contextlib
import json
import os
import sqlite3
import time
from typing import Any, Callable, Dict, Iterator, List, Optional

CLAIMED, DUPLICATE, IN_PROGRESS = "claimed", "duplicate", "in_progress"
CONFIRMED_HACK, FALSE_POSITIVE = "confirmed_hack", "false_positive"

SCHEMA = """
CREATE TABLE IF NOT EXISTS claims (scope TEXT, agent TEXT, key TEXT, status TEXT, claimed_at REAL, PRIMARY KEY (scope, agent, key));
CREATE TABLE IF NOT EXISTS signals (repo TEXT, run_id INTEGER, attempt INTEGER, body TEXT, created REAL, PRIMARY KEY (repo, run_id, attempt));
CREATE TABLE IF NOT EXISTS hints (repo TEXT, run_id INTEGER, attempt INTEGER, body TEXT, created REAL, PRIMARY KEY (repo, run_id, attempt));
CREATE TABLE IF NOT EXISTS checks (agent TEXT, external_id TEXT PRIMARY KEY, repo TEXT, check_run_id INTEGER, created REAL);
CREATE TABLE IF NOT EXISTS ratings (agent TEXT, external_id TEXT, rating TEXT, sender TEXT, created REAL, PRIMARY KEY (external_id, rating, sender));
CREATE TABLE IF NOT EXISTS findings (finding_id TEXT PRIMARY KEY, repo TEXT, head_sha TEXT, pr INTEGER, category TEXT, confidence TEXT, explanation TEXT, created REAL);
CREATE TABLE IF NOT EXISTS hack_ledger (finding_id TEXT PRIMARY KEY, category TEXT, verdict TEXT, reviewer TEXT, note TEXT, created REAL);
CREATE TABLE IF NOT EXISTS model_calls (agent TEXT, key TEXT, model TEXT, input_tokens INTEGER, output_tokens INTEGER, created REAL);
"""


class Store:
    def __init__(self, path: str, clock: Callable[[], float] = time.time):
        self.path = path
        self._clock = clock
        descriptor = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(descriptor)
        with self._db() as db:
            db.executescript(SCHEMA)

    @contextlib.contextmanager
    def _db(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
        finally:
            connection.close()

    # Claims: a key is processed once; a failed or abandoned claim may be retried.
    def claim(self, scope: str, agent: str, key: str, lease_seconds: float = 900) -> str:
        now = self._clock()
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT status, claimed_at FROM claims WHERE scope=? AND agent=? AND key=?", (scope, agent, key)).fetchone()
            if row and row["status"] == "done":
                db.execute("COMMIT")
                return DUPLICATE
            if row and row["status"] == "processing" and now - row["claimed_at"] < lease_seconds:
                db.execute("COMMIT")
                return IN_PROGRESS
            db.execute("INSERT OR REPLACE INTO claims VALUES (?,?,?,'processing',?)", (scope, agent, key, now))
            db.execute("COMMIT")
            return CLAIMED

    def finish(self, scope: str, agent: str, key: str, ok: bool) -> None:
        with self._db() as db:
            db.execute("UPDATE claims SET status=? WHERE scope=? AND agent=? AND key=?", ("done" if ok else "failed", scope, agent, key))

    def release(self, scope: str, agent: str, key: str) -> None:
        with self._db() as db:
            db.execute("DELETE FROM claims WHERE scope=? AND agent=? AND key=?", (scope, agent, key))

    def expire_deliveries(self, older_than_seconds: float) -> None:
        """Forget old body digests. Keep this longer than the event age limit."""
        with self._db() as db:
            db.execute("DELETE FROM claims WHERE scope='delivery' AND claimed_at < ?", (self._clock() - older_than_seconds,))

    # Signals and hints are deliberately separate.
    def save_signals(self, repo: str, run_id: int, attempt: int, body: Dict[str, Any]) -> None:
        self._put("signals", repo, run_id, attempt, body)

    def save_hint(self, repo: str, run_id: int, attempt: int, body: Dict[str, Any]) -> None:
        self._put("hints", repo, run_id, attempt, body)

    def _put(self, table: str, repo: str, run_id: int, attempt: int, body: Dict[str, Any]) -> None:
        with self._db() as db:
            db.execute(f"INSERT OR REPLACE INTO {table} VALUES (?,?,?,?,?)", (repo, run_id, attempt, json.dumps(body, sort_keys=True), self._clock()))

    def get_signals(self, repo: str, run_id: int, attempt: int) -> Optional[Dict[str, Any]]:
        return self._get("signals", repo, run_id, attempt)

    def get_hint(self, repo: str, run_id: int, attempt: int) -> Optional[Dict[str, Any]]:
        return self._get("hints", repo, run_id, attempt)

    def _get(self, table: str, repo: str, run_id: int, attempt: int) -> Optional[Dict[str, Any]]:
        with self._db() as db:
            row = db.execute(f"SELECT body FROM {table} WHERE repo=? AND run_id=? AND attempt=?", (repo, run_id, attempt)).fetchone()
        return json.loads(row["body"]) if row else None

    # Posted checks and ratings.
    def record_check(self, agent: str, external_id: str, repo: str, check_run_id: int) -> None:
        with self._db() as db:
            db.execute("INSERT OR REPLACE INTO checks VALUES (?,?,?,?,?)", (agent, external_id, repo, check_run_id, self._clock()))

    def record_rating(self, agent: str, external_id: str, repo: str, rating: str, sender: str) -> bool:
        """Record one rating per person per check. Unknown checks are refused."""
        with self._db() as db:
            known = db.execute("SELECT 1 FROM checks WHERE agent=? AND external_id=? AND repo=?", (agent, external_id, repo)).fetchone()
            if not known:
                return False
            db.execute("INSERT OR IGNORE INTO ratings VALUES (?,?,?,?,?)", (agent, external_id, rating, sender, self._clock()))
        return True

    def rating_rate(self, agent: str, rating: str) -> Dict[str, Any]:
        with self._db() as db:
            total = db.execute("SELECT COUNT(*) FROM checks WHERE agent=?", (agent,)).fetchone()[0]
            rated = db.execute("SELECT COUNT(DISTINCT external_id) FROM ratings WHERE agent=? AND rating=?", (agent, rating)).fetchone()[0]
        return {"agent": agent, "rating": rating, "checks": total, "rated": rated, "rate": rated / total if total else None}

    # Judge findings and the human-confirmed ledger.
    def save_finding(self, finding_id: str, repo: str, head_sha: str, pr: int, category: str, confidence: str, explanation: str) -> None:
        with self._db() as db:
            db.execute("INSERT OR REPLACE INTO findings VALUES (?,?,?,?,?,?,?,?)", (finding_id, repo, head_sha, pr, category, confidence, explanation, self._clock()))

    def get_finding(self, finding_id: str) -> Optional[Dict[str, Any]]:
        with self._db() as db:
            row = db.execute("SELECT * FROM findings WHERE finding_id=?", (finding_id,)).fetchone()
        return dict(row) if row else None

    def record_verdict(self, finding_id: str, category: str, verdict: str, reviewer: str, note: str = "") -> None:
        with self._db() as db:
            db.execute("INSERT OR REPLACE INTO hack_ledger VALUES (?,?,?,?,?,?)", (finding_id, category, verdict, reviewer, note, self._clock()))

    def ledger_report(self) -> Dict[str, Dict[str, int]]:
        report: Dict[str, Dict[str, int]] = collections.defaultdict(lambda: {CONFIRMED_HACK: 0, FALSE_POSITIVE: 0})
        with self._db() as db:
            for row in db.execute("SELECT category, verdict, COUNT(*) AS n FROM hack_ledger GROUP BY category, verdict"):
                report[row["category"]][row["verdict"]] = row["n"]
        return dict(report)

    def ledger_rows(self) -> List[Dict[str, Any]]:
        with self._db() as db:
            return [dict(row) for row in db.execute("SELECT * FROM hack_ledger ORDER BY created")]

    def record_model_call(self, agent: str, key: str, model: str, input_tokens: int, output_tokens: int) -> None:
        with self._db() as db:
            db.execute("INSERT INTO model_calls VALUES (?,?,?,?,?,?)", (agent, key, model, input_tokens, output_tokens, self._clock()))
