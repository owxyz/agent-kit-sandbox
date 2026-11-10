"""Concurrent runs racing for slots, against a live local fake API over real HTTP."""
import random
import threading
import time
import unittest

from helpers import AGENT_WF, REPO, FakeGitHub, config, pr

import check_limits
from limits_config import Refused, ToolError
from limits_github import GitHub


def conc(**over):
    data = config()["concurrency"]
    data.update(over)
    return data


class Tracker:
    def __init__(self):
        self.lock = threading.Lock()
        self.now = self.peak = self.admitted = self.refused = 0

    def enter(self):
        with self.lock:
            self.admitted += 1
            self.now += 1
            self.peak = max(self.peak, self.now)

    def leave(self):
        with self.lock:
            self.now -= 1


class Race(unittest.TestCase):
    def setUp(self):
        self.gh = FakeGitHub().__enter__()
        self.addCleanup(self.gh.__exit__)
        self.client = GitHub(self.gh.url, "t", attempts=1)

    def racers(self, ids, cap, settings, hold=0.02, jitter=0.0):
        tracker, errors, start = Tracker(), [], threading.Barrier(len(ids))

        def worker(run_id):
            try:
                start.wait()
                if jitter:
                    time.sleep(random.uniform(0, jitter))
                    self.gh.state.add_run(run_id)
                try:
                    check_limits.admit(GitHub(self.gh.url, "t", attempts=1), REPO, run_id, cap, settings)
                except Refused:
                    with tracker.lock:
                        tracker.refused += 1
                    return
                tracker.enter()
                time.sleep(hold)
                tracker.leave()
            except Exception as error:  # noqa: BLE001 - reported by the assertion below
                errors.append(error)
            finally:
                self.gh.state.end_run(run_id)

        threads = [threading.Thread(target=worker, args=(i,)) for i in ids]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(60)
        self.assertEqual(errors, [])
        return tracker

    def test_twenty_racers_cap_one_exactly_one_admitted_without_waiting(self):
        ids = list(range(100, 120))
        for i in ids:
            self.gh.state.add_run(i)
        result = self.racers(ids, 1, conc(), hold=0.2)
        self.assertEqual((result.admitted, result.refused, result.peak), (1, 19, 1))

    def test_twenty_racers_cap_three_exactly_three_admitted(self):
        ids = list(range(100, 120))
        for i in ids:
            self.gh.state.add_run(i)
        result = self.racers(ids, 3, conc(), hold=0.2)
        self.assertEqual(result.admitted, 3)
        self.assertLessEqual(result.peak, 3)

    def test_waiters_all_run_in_turn_and_never_exceed_the_cap(self):
        ids = list(range(100, 112))
        for i in ids:
            self.gh.state.add_run(i)
        result = self.racers(ids, 2, conc(wait_seconds=30, poll_seconds=0.01))
        self.assertEqual((result.admitted, result.refused), (12, 0))
        self.assertLessEqual(result.peak, 2)

    def test_staggered_arrivals_never_exceed_the_cap(self):
        for attempt in range(5):
            ids = list(range(100, 112))
            result = self.racers(ids, 2, conc(wait_seconds=30, poll_seconds=0.01, settle_seconds=0.03), jitter=0.02)
            self.assertLessEqual(result.peak, 2, "attempt %d" % attempt)

    def test_older_run_appearing_late_is_caught_by_the_second_read(self):
        self.gh.state.add_run(100)
        self.gh.state.add_run(101)
        self.gh.state.hide_once = {100}
        with self.assertRaises(Refused):
            check_limits.admit(self.client, REPO, 101, 1, conc())

    def test_rank_falls_when_an_older_run_ends(self):
        self.gh.state.add_run(100)
        self.gh.state.add_run(101)
        timer = threading.Timer(0.05, self.gh.state.end_run, args=(100,))
        timer.start()
        self.addCleanup(timer.join)
        slot = check_limits.admit(self.client, REPO, 101, 1, conc(wait_seconds=5, poll_seconds=0.01))
        self.assertEqual(slot["slot"], 0)

    def test_all_active_statuses_hold_a_place(self):
        for offset, status in enumerate(check_limits.ACTIVE_STATUSES):
            self.gh.state.add_run(100 + offset, status=status)
        self.gh.state.add_run(200)
        with self.assertRaises(Refused):
            check_limits.admit(self.client, REPO, 200, 5, conc())

    def test_only_agent_workflows_count(self):
        self.gh.state.add_run(100, path=".github/workflows/agent-provenance.yml")
        self.gh.state.add_run(101, path=".github/workflows/ci.yml")
        self.gh.state.add_run(102)
        self.assertEqual(check_limits.admit(self.client, REPO, 102, 1, conc())["slot"], 0)

    def test_ref_suffix_on_workflow_path_is_ignored(self):
        self.gh.state.add_run(100, path=AGENT_WF + "@main")
        self.gh.state.add_run(101)
        with self.assertRaises(Refused):
            check_limits.admit(self.client, REPO, 101, 1, conc())

    def test_racing_runs_of_one_agent_cannot_overfill_the_review_queue(self):
        self.gh.state.pulls = [pr(1), pr(2)]
        cfg = config()
        self.gh.state.add_run(100)
        self.gh.state.add_run(101)
        first = check_limits.admit(self.client, REPO, 100, 2, conc())
        second = check_limits.admit(self.client, REPO, 101, 2, conc())
        check_limits.check_review_queue(self.client, REPO, "claude", cfg, {}, first["older_same_agent"])
        with self.assertRaises(Refused):
            check_limits.check_review_queue(self.client, REPO, "claude", cfg, {}, second["older_same_agent"])

    def test_different_agents_do_not_share_a_queue_count(self):
        self.gh.state.add_run(100, path=".github/workflows/agent-other.yml")
        self.gh.state.add_run(101)
        self.assertEqual(check_limits.admit(self.client, REPO, 101, 2, conc())["older_same_agent"], 0)


if __name__ == "__main__":
    unittest.main()
