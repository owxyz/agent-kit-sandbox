"""Run the service, and read or update its records.

    python3 -m advisory_service.cli serve
    python3 -m advisory_service.cli signals --repo OWNER/NAME --run 123 --attempt 1
    python3 -m advisory_service.cli not-helpful-rate
    python3 -m advisory_service.cli confirm FINDING_ID --verdict confirmed_hack --by LOGIN
    python3 -m advisory_service.cli ledger-report
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import queue
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, List, Optional

from .agents.base import Agent
from .agents.diagnosis import DiagnosisAgent, hint_only_view
from .agents.judge import CATALOGUE, JudgeAgent
from .github import GitHubApp, rs256_signer
from .models import make_client
from .service import MAX_BODY, AdvisoryService, BoundAgent, Settings
from .store import CONFIRMED_HACK, FALSE_POSITIVE, Store

AGENTS = (DiagnosisAgent, JudgeAgent)


def _secret(name: str) -> str:
    """Read NAME, or the file named by NAME_FILE (how a secrets manager mounts it)."""
    path = os.environ.get(name + "_FILE")
    if path:
        with open(path, encoding="utf-8") as handle:
            return handle.read().strip()
    value = os.environ.get(name, "")
    if not value:
        raise SystemExit(f"missing required setting: {name} or {name}_FILE")
    return value


def _split(value: str) -> List[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def build_service(submit: Optional[Callable] = None) -> AdvisoryService:
    settings = Settings(
        webhook_secrets=tuple(_split(_secret("ADVISORY_WEBHOOK_SECRETS"))),
        allowed_repos=frozenset(_split(os.environ.get("ADVISORY_ALLOWED_REPOS", ""))),
        agent_logins=frozenset(_split(os.environ.get("ADVISORY_AGENT_LOGINS", ""))),
    )
    provider = os.environ.get("ADVISORY_MODEL_PROVIDER", "anthropic")
    model = os.environ.get("ADVISORY_MODEL") or None
    bound = []
    for agent_type in AGENTS:
        agent: Agent = agent_type()
        env = "ADVISORY_" + agent.id.upper().replace("-", "_")
        app = GitHubApp(int(_secret(env + "_APP_ID")), rs256_signer(_secret(env + "_PRIVATE_KEY")))
        bound.append(BoundAgent(agent, app, make_client(provider, _secret(env + "_MODEL_KEY"), model)))
    return AdvisoryService(settings, bound, _store(), submit=submit)


def _store() -> Store:
    return Store(_secret("ADVISORY_DB"))


def make_handler(service: AdvisoryService):
    class Handler(BaseHTTPRequestHandler):
        server_version = "advisory"
        sys_version = ""

        def _reply(self, status: int, outcome: str) -> None:
            body = json.dumps({"outcome": outcome}).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            self._reply(200, "ok") if self.path == "/healthz" else self._reply(404, "not found")

        def do_POST(self):
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                return self._reply(411, "length required")
            if length < 0 or length > MAX_BODY:
                return self._reply(413, "body too large")
            reply = service.handle(self.path, dict(self.headers), self.rfile.read(length))
            self._reply(reply.status, reply.outcome)

        def log_message(self, *args):  # request lines are logged by the proxy in front
            pass

    return Handler


def serve(host: str, port: int, workers: int = 4, depth: int = 200) -> None:
    jobs: "queue.Queue[Callable[[], None]]" = queue.Queue(maxsize=depth)

    def submit(job: Callable[[], None]) -> bool:
        try:
            jobs.put_nowait(job)
            return True
        except queue.Full:
            return False

    def work() -> None:
        while True:
            try:
                jobs.get()()
            except Exception as exc:  # a bad job must not end the worker
                logging.getLogger("advisory").error("job crashed: %s", type(exc).__name__)

    for _ in range(workers):
        threading.Thread(target=work, daemon=True).start()
    ThreadingHTTPServer((host, port), make_handler(build_service(submit))).serve_forever()


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    start = commands.add_parser("serve")
    start.add_argument("--host", default="127.0.0.1")
    start.add_argument("--port", type=int, default=8080)
    signals = commands.add_parser("signals", help="Structured signals, with the model hint under its own key")
    signals.add_argument("--repo", required=True)
    signals.add_argument("--run", type=int, required=True)
    signals.add_argument("--attempt", type=int, default=1)
    commands.add_parser("not-helpful-rate")
    confirm = commands.add_parser("confirm", help="Record a person's verdict on a judge finding")
    confirm.add_argument("finding")
    confirm.add_argument("--verdict", required=True, choices=(CONFIRMED_HACK, FALSE_POSITIVE))
    confirm.add_argument("--by", required=True, help="Reviewer")
    confirm.add_argument("--category", choices=sorted(CATALOGUE), help="Override the judge's suggested category")
    confirm.add_argument("--note", default="")
    commands.add_parser("ledger-report")
    args = parser.parse_args(argv)

    if args.command == "serve":
        logging.basicConfig(level=logging.INFO)
        serve(args.host, args.port)
        return 0
    store = _store()
    if args.command == "signals":
        result = hint_only_view(store, args.repo, args.run, args.attempt)
    elif args.command == "not-helpful-rate":
        result = store.rating_rate("diagnosis", "not_helpful")
    elif args.command == "ledger-report":
        result = store.ledger_report()
    else:
        finding = store.get_finding(args.finding)
        if finding is None:
            print(f"unknown finding: {args.finding}", file=sys.stderr)
            return 2
        category = args.category or finding["category"]
        store.record_verdict(args.finding, category, args.verdict, args.by, args.note)
        result = {"finding": args.finding, "category": category, "verdict": args.verdict}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
