#!/usr/bin/env python3
"""Concurrency, budget and review-queue limits for agent runs (ticket P1.5).

Runs from the agent pre-flight, after its other rules pass; see INTEGRATION.md.
Exit 0 allows the run, 1 is a limit reached, 2 means the check could not decide.
The agent does not run on 1 or 2.

Checks run in this order, and the first refusal ends the run:
  1. config   valid, and the budget is no longer a placeholder
  2. store    the metrics store opens read-only and holds live data
  3. budget   alert at 80% of the monthly tokens, stop when spent
  4. slot     this run ranks inside the repo's cap, among active agent runs
  5. queue    the agent has room under its waiting-for-review limit
"""
import argparse
import fnmatch
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

import limits_config
import limits_store
from limits_config import AGENT_RE, REPO_RE, Refused, ToolError
from limits_github import GitHub

ACTIVE_STATUSES = ("in_progress", "queued", "requested", "waiting", "pending")


def safe(value, limit=300):
    """Keep a value from forging a workflow command or log line."""
    return re.sub(r"[^A-Za-z0-9_.\-\[\]/@%,;=()' ]", "?", str(value))[:limit]


def concurrency_group(repo, slot):
    """Slot 0 is kit's existing one-agent-per-repo group."""
    base = "agent-" + repo.lower()
    return base if slot == 0 else "%s-slot-%d" % (base, slot)


# Budget ---------------------------------------------------------------------

def send_alert(url, payload):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" and parsed.hostname not in ("127.0.0.1", "localhost"):
        return "webhook must use https"
    request = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"),
                                     headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=10):
            return None
    except Exception as error:
        return type(error).__name__


def check_budget(conn, cfg, now, env, log):
    budget = cfg["budget"]
    limit, usage = budget["monthly_tokens"], limits_store.month_usage(conn, now.date())
    if usage["unmetered_rows"]:
        raise ToolError("budget_unmetered", "%d cost rows this month have dollars but no tokens, so spend is unknown"
                        % usage["unmetered_rows"])
    if usage["rows"] == 0:
        if not budget["allow_empty_cost_history"]:
            raise ToolError("budget_no_data", "the store has no cost rows; import usage, or set "
                            "allow_empty_cost_history for the first run only")
    else:
        newest = usage["newest"]
        age = None if newest is None else (now.date() - newest).days
        if age is None or age > budget["cost_data_max_age_days"]:
            raise ToolError("budget_stale", "newest cost row is %s days old; the limit is %d"
                            % (age, budget["cost_data_max_age_days"]))
    used = usage["used"]
    percent = used * 100 // limit
    result = {"used": used, "limit": limit, "percent": percent, "month": now.strftime("%Y-%m"), "alert": False}
    if used * 100 >= limit * budget["alert_percent"]:
        result["alert"] = True
        payload = {"kind": "token_budget", "month": result["month"], "used": used, "limit": limit, "percent": percent}
        log("LIMITS_ALERT " + json.dumps(payload, sort_keys=True))
        log("::warning title=Agent token budget::%d%% of the monthly tokens used (%d of %d)" % (percent, used, limit))
        webhook = env.get(budget["alert_webhook_env"], "").strip()
        result["alert_delivery"] = "log only"
        if webhook:
            problem = send_alert(webhook, payload)
            result["alert_delivery"] = "failed: " + safe(problem) if problem else "webhook"
            if problem:
                log("::warning title=Budget alert not delivered::%s" % safe(problem))
    if used >= limit:
        raise Refused("budget_spent", "monthly token budget is spent (%d of %d)" % (used, limit))
    return result


# Concurrency ----------------------------------------------------------------

def effective_cap(conn, report_module, repo, now, cfg):
    conc, raised = cfg["concurrency"], cfg["concurrency"]["raised_max_jobs"]
    for name, cap in conc["per_repo_raised_max_jobs"].items():
        if name.lower() == repo.lower():
            raised = cap
    if raised == 1:
        return 1, "cap is configured at 1", None
    if not conc["work_claims_enabled"]:
        return 1, "work claims do not exist yet", None
    status = limits_store.conflict_status(conn, report_module, repo, now, conc)
    if not status["fresh"]:
        return 1, "conflict data is stale", status
    if status["n"] < conc["conflict_min_prs"]:
        return 1, "only %d agent PRs sampled; %d needed" % (status["n"], conc["conflict_min_prs"]), status
    if status["rate"] >= conc["conflict_rate_target"]:
        return 1, "conflict rate is not under target", status
    return raised, "conflict rate is under target", status


def active_agent_runs(client, repo, conc):
    runs = {}
    for status in ACTIVE_STATUSES:
        for run in client.pages("/repos/%s/actions/runs" % repo, {"status": status}, key="workflow_runs"):
            if not isinstance(run, dict) or not isinstance(run.get("id"), int):
                raise ToolError("github_api", "workflow run list has a malformed entry")
            runs[run["id"]] = str(run.get("path") or "").split("@", 1)[0]
    counted = {}
    for run_id, path in runs.items():
        if path in conc["excluded_workflows"]:
            continue
        if any(fnmatch.fnmatchcase(path, pattern) for pattern in conc["agent_workflow_globs"]):
            counted[run_id] = path
    return counted


def rank_of(runs, run_id):
    if run_id not in runs:
        return None, 0
    older = [r for r in runs if r < run_id]
    return len(older), sum(1 for r in older if runs[r] == runs[run_id])


def admit(client, repo, run_id, cap, conc, sleep=time.sleep, clock=time.monotonic):
    """Wait for a slot among active agent runs, ordered by run id.

    Older runs stay in the list until they finish, so each run's rank only falls
    and at most `cap` runs can rank under `cap`. Runs need no lock and leave
    nothing to clean up after a crash. Two reads, `settle_seconds` apart, narrow
    the gap where an older run has not reached the list yet. The slot's GitHub
    concurrency group is the backstop if the list is ever wrong.
    """
    deadline = clock() + conc["wait_seconds"]
    rank = None
    while True:
        rank, _ = rank_of(active_agent_runs(client, repo, conc), run_id)
        if rank is not None and rank < cap:
            sleep(conc["settle_seconds"])
            confirmed = active_agent_runs(client, repo, conc)
            rank, older_same = rank_of(confirmed, run_id)
            if rank is not None and rank < cap:
                return {"slot": rank, "older_same_agent": older_same, "active": len(confirmed)}
        if clock() >= deadline:
            break
        sleep(min(conc["poll_seconds"], max(0.0, deadline - clock())))
    if rank is None:
        raise ToolError("run_not_listed", "run %d is not among active agent runs; check agent_workflow_globs" % run_id)
    raise Refused("concurrency", "repo cap of %d agent job(s) is full; run is number %d in line" % (cap, rank + 1))


# Review queue ---------------------------------------------------------------

def is_bot(user, bot_logins):
    login = str(user.get("login", "")).lower()
    return user.get("type") != "User" or login.endswith("[bot]") or login in bot_logins


def pr_waiting(client, repo, pr, bot_logins):
    """A PR waits until a human approves or requests changes on its current head."""
    author = str((pr.get("user") or {}).get("login", "")).lower()
    head = (pr.get("head") or {}).get("sha")
    if not head:
        raise ToolError("github_api", "pull request has no head SHA")
    for review in client.pages("/repos/%s/pulls/%s/reviews" % (repo, pr["number"])):
        user = review.get("user") or {}
        if (review.get("state") in ("APPROVED", "CHANGES_REQUESTED") and review.get("commit_id") == head
                and not is_bot(user, bot_logins) and str(user.get("login", "")).lower() != author):
            return False
    return True


def waiting_prs(client, repo, agent, cfg, env):
    queue, spec = cfg["review_queue"], cfg["agents"][agent]
    bots = {b.lower() for b in spec["bots"]}
    labels = {l.lower() for l in spec["labels"]}
    reviewer_bots = {b.strip().lower() for b in env.get("AGENT_BOT_LOGINS", "").split(",") if b.strip()}
    for other in cfg["agents"].values():
        reviewer_bots.update(b.lower() for b in other["bots"])
    count = 0
    for pr in client.pages("/repos/%s/pulls" % repo, {"state": "open"}):
        if pr.get("draft") and not queue["count_drafts"]:
            continue
        author = str((pr.get("user") or {}).get("login", "")).lower()
        names = {str(l.get("name", "")).lower() for l in pr.get("labels") or []}
        if (author in bots or names & labels) and pr_waiting(client, repo, pr, reviewer_bots):
            count += 1
    return count


def check_review_queue(client, repo, agent, cfg, env, older_same_agent):
    limit = cfg["review_queue"]["max_waiting_prs"]
    waiting = waiting_prs(client, repo, agent, cfg, env)
    # An older run of this agent may be about to open a PR that this count can't see.
    if waiting + older_same_agent >= limit:
        raise Refused("review_queue", "agent %s has %d PRs waiting and %d older runs active; the limit is %d"
                      % (agent, waiting, older_same_agent, limit))
    return {"waiting": waiting, "older_same_agent": older_same_agent, "limit": limit}


# Decision -------------------------------------------------------------------

def evaluate(args, env, log, metrics=None, sleep=time.sleep, clock=time.monotonic, now=None):
    if not REPO_RE.match(args.repo or ""):
        raise ToolError("arguments", "repository must be owner/name")
    if not re.fullmatch(r"[0-9]+", args.run_id or ""):
        raise ToolError("arguments", "run id must be a number")
    if args.target_pr and not re.fullmatch(r"[0-9]+", args.target_pr):
        raise ToolError("arguments", "target PR must be a number")
    if not AGENT_RE.match(args.agent or ""):
        raise ToolError("arguments", "agent name is missing or invalid")
    cfg = limits_config.load(args.config)
    if args.agent not in cfg["agents"]:
        raise ToolError("unknown_agent", "agent is not listed in the limits config")

    store_module, report_module = metrics or limits_store.load_metrics(args.metrics_path)
    conn = limits_store.open_store(args.db, store_module)
    try:
        now = now or datetime.now(timezone.utc)
        result = {"budget": check_budget(conn, cfg, now, env, log)}
        client = GitHub(env.get("GITHUB_API_URL", "https://api.github.com"), env.get("GITHUB_TOKEN", ""))
        cap, why, status = effective_cap(conn, report_module, args.repo, now, cfg)
    finally:
        conn.close()
    result["cap"] = {"value": cap, "why": why, "conflict": status}
    slot = admit(client, args.repo, int(args.run_id), cap, cfg["concurrency"], sleep, clock)
    result["slot"] = slot
    if args.target_pr:
        result["queue"] = "not checked: this run works on existing PR %s" % args.target_pr
    else:
        result["queue"] = check_review_queue(client, args.repo, args.agent, cfg, env, slot["older_same_agent"])
    result["concurrency_group"] = concurrency_group(args.repo, slot["slot"])
    return result


def finding(rule, severity, mode, message):
    return {"gate": "limits", "rule": rule, "severity": severity, "mode": mode, "file": "", "line": 0, "message": message}


def main(argv=None, env=None, log=print, **seams):
    env = os.environ if env is None else env
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", required=True)
    parser.add_argument("--db", required=True)
    parser.add_argument("--agent", required=True)
    parser.add_argument("--repo", default=env.get("GITHUB_REPOSITORY", ""))
    parser.add_argument("--run-id", default=env.get("GITHUB_RUN_ID", ""))
    parser.add_argument("--target-pr", default="")
    parser.add_argument("--metrics-path", help="Folder holding agentmetrics; defaults to the sibling metrics folder")
    parser.add_argument("--findings", help="Write findings JSON here")
    args = parser.parse_args(argv)

    result, findings, group = {}, [], ""
    try:
        result = evaluate(args, env, log, **seams)
        decision, rule, reason, code = "allowed", "all", "all limits passed", 0
        group = result["concurrency_group"]
        if result["budget"]["alert"]:
            findings.append(finding("budget_alert", "medium", "warn", "%d%% of the monthly tokens used" % result["budget"]["percent"]))
    except Refused as refusal:
        decision, rule, reason, code = "refused", refusal.rule, refusal.message, 1
        findings.append(finding(rule, "high", "block", reason))
    except ToolError as error:
        decision, rule, reason, code = "refused", error.rule, error.message, 2
        findings.append(finding("tool-error", "high", "block", "%s: %s" % (rule, reason)))
    except Exception as error:  # Any surprise must still refuse, not crash into a pass.
        decision, rule, reason, code = "refused", "internal_error", type(error).__name__, 2
        findings.append(finding("tool-error", "high", "block", "internal_error: %s" % reason))

    record = {"decision": decision, "rule": rule, "reason": safe(reason), "agent": safe(args.agent),
              "repository": safe(args.repo), "run_id": safe(args.run_id), "details": result,
              "time": datetime.now(timezone.utc).isoformat()}
    log("LIMITS_DECISION " + json.dumps(record, sort_keys=True))
    if code:
        log("::error title=Agent limits refused::%s: %s" % (safe(rule), safe(reason)))
    if args.findings:
        with open(args.findings, "w", encoding="utf-8") as handle:
            json.dump(findings, handle, indent=2)
    if env.get("GITHUB_OUTPUT"):
        with open(env["GITHUB_OUTPUT"], "a", encoding="utf-8") as handle:
            handle.write("allowed=%s\nconcurrency_group=%s\n" % ("true" if code == 0 else "false", group))
    if env.get("GITHUB_STEP_SUMMARY"):
        with open(env["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as handle:
            handle.write("### Agent limits: %s\n\nRule `%s`: %s\n" % (decision, safe(rule), safe(reason)))
    return code


if __name__ == "__main__":
    sys.exit(main())
