"""Every way the check can lack an answer must refuse, as exit 2 with no allowed output."""
import json
import os
import sqlite3
import subprocess
import sys
import unittest
from pathlib import Path

from helpers import LIMITS, METRICS, NOW, REPO, FakeGitHub, Workspace, add_cost, config, pr, store_module

import check_limits
import limits_config
import limits_store
from limits_config import ToolError
from test_limits import run


class Closed(unittest.TestCase):
    def setUp(self):
        self.gh = FakeGitHub().__enter__()
        self.addCleanup(self.gh.__exit__)
        self.gh.state.add_run(500)
        self.ws = Workspace()
        self.addCleanup(self.ws.close)

    def assertClosed(self, ws=None, rule=None, **kwargs):
        ws = ws or self.ws
        out = os.path.join(ws.dir, "out")
        if os.path.exists(out):
            os.unlink(out)
        code, decision, _ = run(ws, self.gh, extra_env=dict(kwargs.pop("extra_env", {}), GITHUB_OUTPUT=out), **kwargs)
        self.assertEqual(code, 2, decision)
        with open(out) as handle:
            self.assertEqual(handle.read(), "allowed=false\nconcurrency_group=\n")
        if rule:
            self.assertEqual(decision["rule"], rule)
        return decision

    def fresh(self, **kwargs):
        ws = Workspace(**kwargs)
        self.addCleanup(ws.close)
        return ws

    # Store ------------------------------------------------------------------
    def test_missing_store_refuses_and_is_not_created(self):
        os.unlink(self.ws.db)
        self.assertClosed(rule="store_unreadable")
        self.assertFalse(os.path.exists(self.ws.db))

    def test_corrupt_store(self):
        with open(self.ws.db, "wb") as handle:
            handle.write(b"this is not a database" * 100)
        self.assertClosed(rule="store_unreadable")

    def test_store_path_is_a_directory(self):
        os.unlink(self.ws.db)
        os.mkdir(self.ws.db)
        self.addCleanup(os.rmdir, self.ws.db)
        self.assertClosed(rule="store_unreadable")

    def test_empty_file_store(self):
        open(self.ws.db, "w").close()
        self.assertClosed(rule="store_unreadable")

    def test_unknown_schema_version(self):
        self.ws.conn.execute("UPDATE meta SET value='999' WHERE key='schema_version'")
        self.ws.conn.commit()
        self.assertClosed(rule="store_unreadable")

    def test_costs_table_missing(self):
        self.ws.conn.execute("DROP TABLE costs")
        self.ws.conn.commit()
        self.assertClosed(rule="store_unreadable")

    def test_fixture_store_refused(self):
        self.assertIn("fixture", self.assertClosed(self.fresh(source="fixture"), rule="store_unreadable")["reason"])

    def test_store_never_written_to(self):
        before = Path(self.ws.db).read_bytes()
        run(self.ws, self.gh)
        self.assertEqual(Path(self.ws.db).read_bytes(), before)

    def test_read_only_connection_rejects_writes(self):
        conn = limits_store.open_store(self.ws.db, store_module)
        self.addCleanup(conn.close)
        with self.assertRaises(sqlite3.OperationalError):
            conn.execute("DELETE FROM costs")

    def test_path_with_spaces_and_uri_characters(self):
        path = os.path.join(self.ws.dir, "a b?c#d.db")
        with open(self.ws.db, "rb") as src, open(path, "wb") as dst:
            dst.write(src.read())
        conn = limits_store.open_store(path, store_module)
        conn.close()

    def test_metrics_package_missing(self):
        with self.assertRaises(ToolError):
            sys_path = list(sys.path)
            saved = {k: sys.modules.pop(k) for k in list(sys.modules) if k.startswith("agentmetrics")}
            try:
                sys.path[:] = [p for p in sys.path if not p.endswith("/metrics")]
                limits_store.load_metrics(os.path.join(self.ws.dir, "nothing"))
            finally:
                sys.path[:] = sys_path
                sys.modules.update(saved)

    def test_malformed_date_in_costs(self):
        self.ws.conn.execute("INSERT INTO costs (record_id,date,agent,source) VALUES ('b','not-a-date','x','p')")
        self.ws.conn.commit()
        self.assertClosed(rule="store_unreadable")

    def test_text_in_token_column(self):
        self.ws.conn.execute("INSERT INTO costs (record_id,date,agent,input_tokens,source) VALUES ('b','2026-11-02','x','lots','p')")
        self.ws.conn.commit()
        self.assertClosed(rule="store_unreadable")

    # Budget data ------------------------------------------------------------
    def test_no_cost_history_refuses_by_default(self):
        self.assertClosed(self.fresh(used=None), rule="budget_no_data")

    def test_no_cost_history_allowed_only_when_set(self):
        ws = self.fresh(used=None, budget__allow_empty_cost_history=True)
        self.assertEqual(run(ws, self.gh)[0], 0)

    def test_allow_empty_does_not_excuse_stale_rows(self):
        self.assertClosed(self.fresh(cost_date="2026-11-10", budget__allow_empty_cost_history=True), rule="budget_stale")

    def test_stale_cost_import_refuses(self):
        self.assertClosed(self.fresh(cost_date="2026-11-16"), rule="budget_stale")

    def test_cost_import_at_age_limit_passes(self):
        self.assertEqual(run(self.fresh(cost_date="2026-11-17"), self.gh)[0], 0)

    def test_dollar_only_row_refuses_because_tokens_unknown(self):
        add_cost(self.ws.conn, "usd", NOW.date().isoformat(), 0, cost_usd=3.1)
        self.assertClosed(rule="budget_unmetered")

    def test_future_rows_do_not_hide_a_stale_import(self):
        ws = self.fresh(cost_date="2026-11-01")
        add_cost(ws.conn, "future", "2026-12-25", 1)
        self.assertClosed(ws, rule="budget_stale")

    # Config -----------------------------------------------------------------
    def test_shipped_config_refuses_until_budget_set(self):
        self.ws.write_config(json.loads((LIMITS / "config" / "limits.json").read_text()))
        self.assertClosed(rule="budget_placeholder")

    def test_shipped_placeholder_is_exact(self):
        data = json.loads((LIMITS / "config" / "limits.json").read_text())
        self.assertEqual(data["budget"]["monthly_tokens"], limits_config.PLACEHOLDER)

    def test_bad_budget_values(self):
        for bad in (0, -5, 1.5, True, "1000", None):
            data = config()
            data["budget"]["monthly_tokens"] = bad
            self.ws.write_config(data)
            self.assertClosed(rule="config")

    def test_unknown_or_missing_keys(self):
        data = config()
        data["budget"]["typo"] = 1
        self.ws.write_config(data)
        self.assertClosed(rule="config")
        data = config()
        del data["review_queue"]["max_waiting_prs"]
        self.ws.write_config(data)
        self.assertClosed(rule="config")

    def test_invalid_json_config(self):
        with open(self.ws.config, "w") as handle:
            handle.write("{")
        self.assertClosed(rule="config")

    def test_missing_config(self):
        os.unlink(self.ws.config)
        self.assertClosed(rule="config")

    def test_unlisted_agent(self):
        self.assertClosed(agent="unknown-agent", rule="unknown_agent")

    def test_blank_agent_name(self):
        self.assertClosed(agent="", rule="arguments")

    def test_bad_target_pr(self):
        self.assertClosed(target="1;rm", rule="arguments")

    # GitHub -----------------------------------------------------------------
    def test_no_token(self):
        self.assertClosed(extra_env={"GITHUB_TOKEN": ""}, rule="github_api")

    def test_run_list_failure(self):
        self.gh.state.fail_prefixes = ["/actions/runs"]
        self.assertClosed(rule="github_api")

    def test_pull_list_failure(self):
        self.gh.state.fail_prefixes = ["/pulls"]
        self.assertClosed(rule="github_api")

    def test_review_lookup_failure(self):
        self.gh.state.pulls = [pr(1)]
        self.gh.state.fail_prefixes = ["/reviews"]
        self.assertClosed(rule="github_api")

    def test_github_unreachable(self):
        self.assertClosed(extra_env={"GITHUB_API_URL": "http://127.0.0.1:1"}, rule="github_api")

    def test_run_list_over_github_result_cap(self):
        self.gh.state.total_count_override = 1001
        self.assertClosed(rule="github_api")

    def test_own_run_missing_from_list(self):
        self.assertClosed(run_id=999, rule="run_not_listed")

    def test_unexpected_exception_still_refuses(self):
        def boom(*_a, **_k):
            raise RuntimeError("surprise")
        original = check_limits.check_budget
        check_limits.check_budget = boom
        self.addCleanup(setattr, check_limits, "check_budget", original)
        self.assertClosed(rule="internal_error")

    def test_real_command_line_exits_2_on_missing_store(self):
        os.unlink(self.ws.db)
        env = {k: v for k, v in os.environ.items() if not k.startswith("GITHUB_")}
        env.update(GITHUB_REPOSITORY=REPO, GITHUB_RUN_ID="500", GITHUB_TOKEN="t", PYTHONDONTWRITEBYTECODE="1")
        done = subprocess.run([sys.executable, str(LIMITS / "scripts" / "check_limits.py"), "--config", self.ws.config,
                               "--db", self.ws.db, "--agent", "claude"], env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(done.returncode, 2, done.stdout + done.stderr)
        self.assertIn("LIMITS_DECISION", done.stdout)
        self.assertIn("::error", done.stdout)


if __name__ == "__main__":
    unittest.main()
