"""Budget, cap-raising, review-queue and decision behaviour."""
import json
import os
import unittest
from datetime import datetime, timezone
from pathlib import Path

from helpers import LIMITS, METRICS, NOW, REPO, FakeGitHub, Workspace, add_cost, add_prs, pr, report_module, review

import check_limits
import limits_store


def run(ws, gh, run_id=500, agent="claude", target="", findings=None, extra_env=None, now=NOW):
    logs, env = [], {"GITHUB_API_URL": gh.url, "GITHUB_TOKEN": "t", "GITHUB_REPOSITORY": REPO, "GITHUB_RUN_ID": str(run_id)}
    env.update(extra_env or {})
    argv = ["--config", ws.config, "--db", ws.db, "--agent", agent, "--target-pr", target]
    if findings:
        argv += ["--findings", findings]
    code = check_limits.main(argv, env=env, log=logs.append, metrics=METRICS, now=now, sleep=lambda _: None)
    decision = json.loads(next(l for l in logs if l.startswith("LIMITS_DECISION ")).split(" ", 1)[1])
    return code, decision, logs


class Base(unittest.TestCase):
    def setUp(self):
        self.gh = FakeGitHub().__enter__()
        self.addCleanup(self.gh.__exit__)
        self.gh.state.add_run(500)

    def ws(self, **kwargs):
        ws = Workspace(**kwargs)
        self.addCleanup(ws.close)
        return ws


class Budget(Base):
    def test_below_alert_passes_quietly(self):
        code, d, logs = run(self.ws(used=799), self.gh)
        self.assertEqual((code, d["details"]["budget"]["alert"]), (0, False))
        self.assertFalse([l for l in logs if l.startswith("LIMITS_ALERT")])

    def test_alert_at_exactly_80_percent_but_still_runs(self):
        code, d, logs = run(self.ws(used=800), self.gh)
        self.assertEqual((code, d["details"]["budget"]["alert"]), (0, True))
        self.assertTrue([l for l in logs if l.startswith("LIMITS_ALERT")])
        self.assertTrue([l for l in logs if l.startswith("::warning")])
        self.assertEqual(d["details"]["budget"]["alert_delivery"], "log only")

    def test_alert_reaches_webhook(self):
        code, d, _ = run(self.ws(used=900), self.gh, extra_env={"LIMITS_ALERT_WEBHOOK": self.gh.url + "/hook"})
        self.assertEqual((code, d["details"]["budget"]["alert_delivery"]), (0, "webhook"))
        self.assertEqual(self.gh.state.alerts[0]["percent"], 90)

    def test_failed_alert_delivery_is_reported_and_does_not_stop_the_run(self):
        code, d, logs = run(self.ws(used=900), self.gh, extra_env={"LIMITS_ALERT_WEBHOOK": "http://example.invalid/x"})
        self.assertEqual(code, 0)
        self.assertIn("failed", d["details"]["budget"]["alert_delivery"])
        self.assertTrue([l for l in logs if "not delivered" in l])

    def test_hard_stop_when_exactly_spent(self):
        code, d, _ = run(self.ws(used=1000), self.gh)
        self.assertEqual((code, d["rule"]), (1, "budget_spent"))

    def test_one_below_spent_still_runs(self):
        self.assertEqual(run(self.ws(used=999), self.gh)[0], 0)

    def test_hard_stop_makes_no_github_calls(self):
        run(self.ws(used=1000), self.gh)
        self.assertEqual(self.gh.state.requests, [])

    def test_only_this_utc_month_counts(self):
        ws = self.ws(used=1)
        add_cost(ws.conn, "old", "2026-10-31", 5000)
        add_cost(ws.conn, "next", "2026-12-01", 5000)
        self.assertEqual(run(ws, self.gh)[1]["details"]["budget"]["used"], 1)

    def test_month_rolls_over_at_utc_midnight(self):
        ws = self.ws(used=None)
        add_cost(ws.conn, "oct", "2026-10-31", 1000)
        end = datetime(2026, 10, 31, 23, 59, tzinfo=timezone.utc)
        start = datetime(2026, 11, 1, 0, 0, tzinfo=timezone.utc)
        self.assertEqual(run(ws, self.gh, now=end)[1]["rule"], "budget_spent")
        self.assertEqual(run(ws, self.gh, now=start)[0], 0)

    def test_input_and_output_tokens_both_count(self):
        ws = self.ws(used=None)
        ws.conn.execute("INSERT INTO costs (record_id,date,agent,input_tokens,output_tokens,source) VALUES ('x',?,?,600,400,'p')",
                        (NOW.date().isoformat(), "claude"))
        ws.conn.commit()
        self.assertEqual(run(ws, self.gh)[1]["rule"], "budget_spent")


class CapRaising(Base):
    RAISED = dict(concurrency__work_claims_enabled=True, concurrency__raised_max_jobs=3)

    def cap(self, ws):
        conn = limits_store.open_store(ws.db, METRICS[0])
        self.addCleanup(conn.close)
        data = json.loads(Path(ws.config).read_text())
        return check_limits.effective_cap(conn, report_module, REPO, NOW, data)

    def test_shipped_config_is_one(self):
        self.assertEqual(self.cap(self.ws())[0], 1)

    def test_without_work_claims_stays_one_even_with_a_good_rate(self):
        ws = self.ws(concurrency__raised_max_jobs=3)
        add_prs(ws.conn, 30, 0)
        cap, why, _ = self.cap(ws)
        self.assertEqual(cap, 1)
        self.assertIn("work claims", why)

    def test_raised_while_rate_under_target(self):
        ws = self.ws(**self.RAISED)
        add_prs(ws.conn, 30, 3)  # 10%
        self.assertEqual(self.cap(ws)[0], 3)

    def test_falls_back_when_rate_reaches_target(self):
        ws = self.ws(**self.RAISED)
        add_prs(ws.conn, 20, 3)  # exactly 15%: "under" is strict
        self.assertEqual(self.cap(ws)[0], 1)

    def test_too_few_prs_stays_one(self):
        ws = self.ws(**self.RAISED)
        add_prs(ws.conn, 19, 0)
        self.assertEqual(self.cap(ws)[0], 1)

    def test_stale_collection_stays_one(self):
        ws = self.ws(sync_age_hours=49, **self.RAISED)
        add_prs(ws.conn, 30, 0)
        self.assertIn("stale", self.cap(ws)[1])

    def test_human_collisions_do_not_count_as_cross_agent(self):
        ws = self.ws(**self.RAISED)
        add_prs(ws.conn, 30, 15, relation="human")
        status = self.cap(ws)
        self.assertEqual((status[0], status[2]["counted"]), (3, 0))

    def test_other_repos_do_not_affect_this_repo(self):
        ws = self.ws(**self.RAISED)
        add_prs(ws.conn, 30, 0)
        add_prs(ws.conn, 30, 30, repo="acme/other")
        self.assertEqual(self.cap(ws)[0], 3)

    def test_per_repo_value_overrides(self):
        ws = self.ws(concurrency__per_repo_raised_max_jobs={"ACME/pilot": 2}, **self.RAISED)
        add_prs(ws.conn, 30, 0)
        self.assertEqual(self.cap(ws)[0], 2)

    def test_target_matches_the_metrics_report(self):
        self.assertIn("15%", report_module.TARGETS["conflict"])
        shipped = json.loads((LIMITS / "config" / "limits.json").read_text())
        self.assertEqual(shipped["concurrency"]["conflict_rate_target"], 0.15)


class ReviewQueue(Base):
    def waiting(self, count):
        self.gh.state.pulls = [pr(n) for n in range(1, count + 1)]

    def test_refused_at_three(self):
        self.waiting(3)
        code, d, _ = run(self.ws(), self.gh)
        self.assertEqual((code, d["rule"]), (1, "review_queue"))

    def test_allowed_at_two(self):
        self.waiting(2)
        self.assertEqual(run(self.ws(), self.gh)[0], 0)

    def test_limit_is_configurable(self):
        self.waiting(3)
        self.assertEqual(run(self.ws(review_queue__max_waiting_prs=4), self.gh)[0], 0)

    def test_label_identifies_agent_pr_under_a_human_author(self):
        self.gh.state.pulls = [pr(n, author="alice", labels=["agent:claude"]) for n in (1, 2, 3)]
        self.assertEqual(run(self.ws(), self.gh)[1]["rule"], "review_queue")

    def test_other_agents_and_humans_do_not_count(self):
        self.gh.state.pulls = [pr(1, author="alice"), pr(2, author="other[bot]"), pr(3, labels=[], author="bob")]
        self.assertEqual(run(self.ws(), self.gh)[0], 0)

    def test_human_verdict_on_head_stops_waiting(self):
        self.waiting(3)
        self.gh.state.reviews[1] = [review("alice", "APPROVED", "h1")]
        self.gh.state.reviews[2] = [review("bob", "CHANGES_REQUESTED", "h2")]
        self.assertEqual(run(self.ws(), self.gh)[0], 0)

    def test_stale_or_weak_reviews_do_not_stop_waiting(self):
        self.waiting(3)
        self.gh.state.reviews[1] = [review("alice", "APPROVED", "old-sha")]
        self.gh.state.reviews[2] = [review("alice", "COMMENTED", "h2")]
        self.gh.state.reviews[3] = [review("alice", "DISMISSED", "h3")]
        self.assertEqual(run(self.ws(), self.gh)[1]["rule"], "review_queue")

    def test_bot_and_agent_reviews_do_not_count(self):
        self.waiting(3)
        self.gh.state.reviews[1] = [review("ci[bot]", "APPROVED", "h1", "Bot")]
        self.gh.state.reviews[2] = [review("claude[bot]", "APPROVED", "h2", "Bot")]
        self.gh.state.reviews[3] = [review("machine-user", "APPROVED", "h3")]
        ws = self.ws()
        self.assertEqual(run(ws, self.gh, extra_env={"AGENT_BOT_LOGINS": "machine-user"})[1]["rule"], "review_queue")

    def test_drafts_count_by_default_and_can_be_excluded(self):
        self.gh.state.pulls = [pr(n, draft=True) for n in (1, 2, 3)]
        self.assertEqual(run(self.ws(), self.gh)[1]["rule"], "review_queue")
        self.assertEqual(run(self.ws(review_queue__count_drafts=False), self.gh)[0], 0)

    def test_work_on_an_existing_pr_is_not_blocked(self):
        self.waiting(3)
        code, d, _ = run(self.ws(), self.gh, target="2")
        self.assertEqual(code, 0)
        self.assertIn("existing PR", d["details"]["queue"])

    def test_paginates_past_one_page(self):
        self.gh.state.pulls = [pr(n, author="alice") for n in range(1, 151)] + [pr(n) for n in (201, 202, 203)]
        self.assertEqual(run(self.ws(), self.gh)[1]["rule"], "review_queue")


class Outputs(Base):
    def test_outputs_and_group_on_success(self):
        ws = self.ws()
        out, summary = os.path.join(ws.dir, "o"), os.path.join(ws.dir, "s")
        code, _, _ = run(ws, self.gh, extra_env={"GITHUB_OUTPUT": out, "GITHUB_STEP_SUMMARY": summary})
        self.assertEqual(code, 0)
        self.assertEqual(Path(out).read_text(), "allowed=true\nconcurrency_group=agent-acme/pilot\n")
        self.assertIn("allowed", Path(summary).read_text())

    def test_outputs_on_refusal_never_allow(self):
        ws = self.ws(used=1000)
        out = os.path.join(ws.dir, "o")
        run(ws, self.gh, extra_env={"GITHUB_OUTPUT": out})
        self.assertEqual(Path(out).read_text(), "allowed=false\nconcurrency_group=\n")

    def test_findings_follow_the_shared_contract(self):
        ws = self.ws(used=1000)
        path = os.path.join(ws.dir, "f.json")
        run(ws, self.gh, findings=path)
        item = json.loads(Path(path).read_text())[0]
        self.assertEqual(set(item), {"gate", "rule", "severity", "mode", "file", "line", "message"})
        self.assertEqual((item["gate"], item["mode"]), ("limits", "block"))

    def test_slot_zero_group_equals_kits_group(self):
        from helpers import ROOT
        text = (ROOT / "kit" / "workflows" / "agent-preflight.yml").read_text()
        self.assertIn('group = "agent-" + repo.lower()', text)
        self.assertEqual(check_limits.concurrency_group("Acme/Pilot", 0), "agent-acme/pilot")
        self.assertEqual(check_limits.concurrency_group("Acme/Pilot", 2), "agent-acme/pilot-slot-2")

    def test_log_cannot_be_forged_by_reason_text(self):
        self.assertNotIn("\n", check_limits.safe("x\n::error::y"))
        self.assertNotIn("::", check_limits.safe("x\n::error::y"))


if __name__ == "__main__":
    unittest.main()
