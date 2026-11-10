"""Read-only access to the P0.11 metrics store.

metrics' store.connect() creates a missing database and runs CREATE statements,
so a lost store would read as zero spend. This opens the existing file read-only
and uses metrics' own constants and conflict calculation on that connection.
"""
import importlib
import os
import sqlite3
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from limits_config import ToolError

COUNTED_RELATIONS = ("different_agent", "same_agent", "no_overlap_found")


def _fail(message):
    raise ToolError("store_unreadable", message)


def load_metrics(metrics_path=None):
    root = metrics_path or str(Path(__file__).resolve().parents[2] / "metrics")
    if root not in sys.path:
        sys.path.insert(0, root)
    try:
        importlib.invalidate_caches()
        return importlib.import_module("agentmetrics.store"), importlib.import_module("agentmetrics.report")
    except Exception as error:
        _fail("cannot load agentmetrics from %s: %s" % (root, type(error).__name__))


def open_store(path, store_module):
    if not path or not os.path.isfile(path):
        _fail("metrics store not found")
    try:
        conn = sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True, timeout=5)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only = ON")
        version = store_module.get_meta(conn, "schema_version")
        source = store_module.get_meta(conn, "data_source")
    except sqlite3.Error as error:
        _fail("metrics store is unreadable: %s" % type(error).__name__)
    if version != store_module.SCHEMA_VERSION:
        _fail("metrics store schema is %r, expected %r" % (version, store_module.SCHEMA_VERSION))
    if source != "live":
        _fail("metrics store data source is %r, not live" % source)
    return conn


def month_usage(conn, today):
    """Tokens used in today's UTC month, for all agents and repos."""
    used = rows_seen = unmetered = 0
    newest = None
    try:
        rows = conn.execute("SELECT date, input_tokens, output_tokens, cost_usd FROM costs").fetchall()
    except sqlite3.Error as error:
        _fail("cannot read costs: %s" % type(error).__name__)
    for row in rows:
        rows_seen += 1
        try:
            day = date.fromisoformat(row["date"])
        except (TypeError, ValueError):
            _fail("costs row has a bad date")
        tokens = (row["input_tokens"], row["output_tokens"])
        if any(isinstance(t, bool) or not isinstance(t, int) or t < 0 for t in tokens):
            _fail("costs row has bad token counts")
        if day <= today and (newest is None or day > newest):
            newest = day
        if (day.year, day.month) == (today.year, today.month):
            used += sum(tokens)
            if not sum(tokens) and row["cost_usd"]:
                unmetered += 1
    return {"used": used, "rows": rows_seen, "newest": newest, "unmetered_rows": unmetered}


def conflict_status(conn, report_module, repo, now, cfg):
    """Agent conflict rate for one repo, computed by metrics' own report code.

    A conflicted PR counts unless it collided only with human or other-bot PRs.
    no_overlap_found is counted because another agent cannot be ruled out. The
    three relations can overlap only between same_agent and different_agent, and
    the count is capped at conflicted PRs, so it can only err high.
    """
    try:
        sync = [r for r in conn.execute("SELECT repo, last_success_at FROM sync_state").fetchall()
                if r["repo"].lower() == repo.lower()]
        collected = max((_parse(r["last_success_at"]) for r in sync), default=None)
        fresh = collected is not None and now - collected <= timedelta(hours=cfg["conflict_data_max_age_hours"])
        since = now - timedelta(days=cfg["conflict_window_days"])
        prs = {(p["repo"], p["number"]): p for p in conn.execute("SELECT * FROM prs").fetchall()
               if p["repo"].lower() == repo.lower()}
        groups, _ = report_module._conflicts(conn, prs, since, now)
    except (sqlite3.Error, AttributeError, KeyError, TypeError, ValueError) as error:
        _fail("cannot compute the conflict rate: %s" % type(error).__name__)
    bucket = groups.get(report_module.ALL_AGENTS) or {"n": 0, "conflicted": 0, "by_relation": {}}
    relations = bucket["by_relation"]
    counted = min(bucket["conflicted"], sum(relations.get(k, 0) for k in COUNTED_RELATIONS))
    n = bucket["n"]
    return {"n": n, "counted": counted, "rate": counted / n if n else None, "fresh": fresh,
            "by_relation": dict(relations)}


def _parse(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp has no zone")
    return parsed.astimezone(timezone.utc)
