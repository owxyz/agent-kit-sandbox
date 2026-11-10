"""Local fake GitHub API and metrics-store builder for the limits tests."""
import json
import os
import sys
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

LIMITS = Path(__file__).resolve().parents[1]
ROOT = LIMITS.parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(LIMITS / "scripts"))
sys.path.insert(0, str(ROOT / "metrics"))

from agentmetrics import report as report_module, store as store_module  # noqa: E402

METRICS = (store_module, report_module)
REPO = "acme/pilot"
AGENT_WF = ".github/workflows/agent-claude.yml"
NOW = datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc)


class FakeState:
    def __init__(self):
        self.lock = threading.Lock()
        self.runs = {}  # id -> {"path", "status"}
        self.pulls = []
        self.reviews = {}
        self.fail_prefixes = []
        self.requests = []
        self.alerts = []
        self.hide_once = set()
        self.total_count_override = None
        self.page_size = None

    def add_run(self, run_id, path=AGENT_WF, status="in_progress"):
        with self.lock:
            self.runs[run_id] = {"id": run_id, "path": path, "status": status}

    def end_run(self, run_id):
        with self.lock:
            self.runs.pop(run_id, None)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def send(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.server.state.alerts.append(json.loads(self.rfile.read(length)))
        self.send(200, {})

    def do_GET(self):
        state = self.server.state
        url = urlsplit(self.path)
        query = parse_qs(url.query)
        state.requests.append(self.path)
        if any(url.path.startswith(p) or p in url.path for p in state.fail_prefixes):
            return self.send(500, {})
        page, per = int(query.get("page", ["1"])[0]), int(query.get("per_page", ["100"])[0])
        slice_ = lambda items: items[(page - 1) * per:page * per]
        if url.path.endswith("/actions/runs"):
            status = query["status"][0]
            with state.lock:
                runs = [r for r in state.runs.values() if r["status"] == status]
                visible = [r for r in runs if r["id"] not in state.hide_once]
                state.hide_once -= {r["id"] for r in runs if r["status"] == "in_progress"}
            total = state.total_count_override if state.total_count_override is not None else len(visible)
            return self.send(200, {"total_count": total, "workflow_runs": slice_(visible)})
        if url.path.endswith("/reviews"):
            number = int(url.path.split("/")[-2])
            return self.send(200, slice_(state.reviews.get(number, [])))
        if url.path.endswith("/pulls"):
            return self.send(200, slice_(state.pulls))
        return self.send(404, {})


class Server(ThreadingHTTPServer):
    request_queue_size = 256  # The race tests open many connections at once.
    daemon_threads = True


class FakeGitHub:
    def __enter__(self):
        self.server = Server(("127.0.0.1", 0), Handler)
        self.server.state = self.state = FakeState()
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = "http://127.0.0.1:%d" % self.server.server_address[1]
        return self

    def __exit__(self, *_):
        self.server.shutdown()
        self.server.server_close()


def pr(number, author="claude[bot]", labels=(), draft=False, head="h%d"):
    return {"number": number, "draft": draft, "user": {"login": author, "type": "Bot" if "[bot]" in author else "User"},
            "labels": [{"name": n} for n in labels], "head": {"sha": head % number if "%d" in head else head}}


def review(login, state, commit, user_type="User"):
    return {"user": {"login": login, "type": user_type}, "state": state, "commit_id": commit}


def config(**over):
    data = json.loads((LIMITS / "config" / "limits.json").read_text())
    data["budget"]["monthly_tokens"] = 1000
    data["agents"] = {"claude": {"labels": ["agent:claude"], "bots": ["claude[bot]"]}}
    data["concurrency"].update(settle_seconds=0, wait_seconds=0, poll_seconds=0.01)
    for path, value in over.items():
        section, key = path.split("__")
        data[section][key] = value
    return data


class Workspace:
    """A temp folder with a config and a live store holding one cost row."""

    def __init__(self, used=100, source="live", cost_date=None, sync_age_hours=1, **cfg_over):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.config = os.path.join(self.dir, "limits.json")
        self.db = os.path.join(self.dir, "metrics.db")
        self.write_config(config(**cfg_over))
        conn = store_module.connect(self.db)
        if source:
            store_module.claim_data_source(conn, source)
        conn.execute("INSERT INTO sync_state VALUES (?, ?)", (REPO, (NOW - timedelta(hours=sync_age_hours)).strftime("%Y-%m-%dT%H:%M:%SZ")))
        if used is not None:
            add_cost(conn, "r1", cost_date or NOW.date().isoformat(), used)
        conn.commit()
        self.conn = conn

    def write_config(self, data):
        with open(self.config, "w") as handle:
            json.dump(data, handle)

    def close(self):
        self.conn.close()
        self.tmp.cleanup()


def add_cost(conn, record, day, tokens, cost_usd=None):
    conn.execute("INSERT INTO costs (record_id, date, agent, input_tokens, output_tokens, cost_usd, source) VALUES (?,?,?,?,?,?,?)",
                 (record, day, "claude", tokens, 0, cost_usd, "provider-export"))
    conn.commit()


def add_prs(conn, total, conflicted, relation="agent", repo=REPO):
    """`total` agent PRs sampled clean; `conflicted` of them collide with a merged PR."""
    stamp = lambda hours: (NOW - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    insert = """INSERT INTO prs (repo, number, state, created_at, updated_at, merged_at, base_ref, cohort, agent)
                VALUES (?,?,?,?,?,?,?,?,?)"""
    for number in range(1, total + 1):
        conn.execute(insert, (repo, number, "open", stamp(72), stamp(1), None, "main", "agent", "claude"))
        conn.execute("INSERT INTO pr_files VALUES (?,?,?)", (repo, number, "f%d.py" % number))
        if number <= conflicted:
            conn.execute("INSERT INTO mergeability_samples VALUES (?,?,?,?,?,?,?)", (repo, number, "2026-11-18", 1, "clean", 0, stamp(50)))
            conn.execute("INSERT INTO mergeability_samples VALUES (?,?,?,?,?,?,?)", (repo, number, "2026-11-19", 0, "dirty", 1, stamp(26)))
            other = 1000 + number
            cohort, agent = ("human", None) if relation == "human" else ("agent", "other-agent")
            conn.execute(insert, (repo, other, "closed", stamp(90), stamp(30), stamp(30), "main", cohort, agent))
            conn.execute("INSERT INTO pr_files VALUES (?,?,?)", (repo, other, "f%d.py" % number))
        else:
            conn.execute("INSERT INTO mergeability_samples VALUES (?,?,?,?,?,?,?)", (repo, number, "2026-11-19", 1, "clean", 0, stamp(26)))
    conn.commit()
