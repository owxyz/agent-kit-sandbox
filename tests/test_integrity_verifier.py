"""Tests for the installed required-checks verifier and its helpers (P2.9).

They run in process, with a fake GitHub client, and make no network calls.
"""
import io
import json
import os
import sys
import urllib.error

import pytest

SCRIPTS = os.path.join(os.path.dirname(__file__), "..", ".github", "agent-kit", "integrity", "scripts")
sys.path.insert(0, os.path.abspath(SCRIPTS))

import common  # noqa: E402
import verify_required_checks as vrc  # noqa: E402

SHA = "a" * 40
OTHER = "b" * 40
APP = 15368


def run_(name, conclusion="success", status="completed", app=APP, suite=1, rid=1, sha=SHA):
    return {"name": name, "status": status, "conclusion": conclusion, "app": {"id": app},
            "check_suite": {"id": suite}, "id": rid, "head_sha": sha}


def spec(**kw):
    base = {"kind": "check_run", "integration_id": APP, "queue": "merge"}
    base.update(kw)
    return base


def write(tmp_path, name, data):
    path = tmp_path / name
    path.write_text(data if isinstance(data, str) else json.dumps(data))
    return str(path)


def ruleset(checks):
    return {"rules": [{"type": "required_status_checks", "parameters": {"required_status_checks": checks}}]}


class FakeGitHub:
    def __init__(self, pages=None, json_by_path=None, lists=None):
        self.pages = pages or []
        self.json_by_path = json_by_path or {}
        self.lists = lists or {}
        self.calls = []

    def get_json(self, path, allow_404=False):
        self.calls.append(path)
        if "/check-runs" in path:
            return self.pages.pop(0)
        return self.json_by_path[path]

    def list_all(self, path):
        return self.lists.get(path, [])


# --- common: findings, exit codes, run ---------------------------------------

def test_finding_severity_follows_mode():
    assert common.finding("R", "block", "f", 1, "m")["severity"] == "high"
    assert common.finding("R", "warn", "f", 1, "m")["severity"] == "medium"
    assert common.finding("R", "warn", "f", 1, "m", severity="low")["severity"] == "low"


def test_emit_writes_stdout_or_file_and_returns_exit_code(tmp_path, capsys):
    assert common.emit([]) == 0
    assert json.loads(capsys.readouterr().out) == []
    out = tmp_path / "f.json"
    blocking = [common.finding("R", "block", "f", 0, "m")]
    assert common.emit(blocking, str(out)) == 1
    assert json.loads(out.read_text())[0]["rule"] == "R"


def test_run_maps_results_and_errors_to_exit_codes():
    with pytest.raises(SystemExit) as ok:
        common.run(lambda: 0)
    assert ok.value.code == 0

    def boom():
        raise RuntimeError("x")
    with pytest.raises(SystemExit) as err:
        common.run(boom)
    assert err.value.code == 2

    def exits():
        raise SystemExit(5)
    with pytest.raises(SystemExit) as passthrough:
        common.run(exits)
    assert passthrough.value.code == 5


def test_load_json_errors(tmp_path):
    with pytest.raises(common.ToolError):
        common.load_json(str(tmp_path / "missing.json"))
    with pytest.raises(common.ToolError):
        common.load_json(write(tmp_path, "bad.json", "{not json"))


# --- common: ruleset and config loading --------------------------------------

def test_load_required_checks_reads_pins(tmp_path):
    path = write(tmp_path, "r.json", ruleset([{"context": "a", "integration_id": 1}, {"context": "b", "integration_id": 2}]))
    assert common.load_required_checks([path, path]) == {"a": 1, "b": 2}


@pytest.mark.parametrize("data", [
    [],
    {"rules": []},
    {"rules": [{"type": "required_status_checks", "parameters": {}}]},
    ruleset([{"integration_id": 1}]),
    ruleset(["not a dict"]),
    ruleset([{"context": "a"}]),
    ruleset([{"context": "a", "integration_id": True}]),
    ruleset([{"context": "a", "integration_id": 0}]),
    ruleset([{"context": "a", "integration_id": 1}, {"context": "a", "integration_id": 2}]),
])
def test_load_required_checks_refuses_bad_rulesets(tmp_path, data):
    with pytest.raises(common.ToolError):
        common.load_required_checks([write(tmp_path, "r.json", data)])


def good_entry(**kw):
    entry = {"context": "c", "integration_id": 7, "kind": "check_run", "queue": "merge"}
    entry.update(kw)
    return entry


def test_load_check_config_reads_entries(tmp_path):
    data = {"checks": [good_entry(), good_entry(context="s", kind="status", creator_id=9, workflow="w")],
            "status_writers": [{"workflow": "w", "job": "j"}],
            "reviewed_exceptions": [{"rule": "R", "workflow": "w", "job": "j"}]}
    config = common.load_check_config(write(tmp_path, "c.json", data))
    assert set(config["required"]) == {"c", "s"}
    assert config["status_writers"] == {("w", "j")}
    assert config["exceptions"] == {("R", "w", "j")}


@pytest.mark.parametrize("checks", [
    None,
    [],
    ["x"],
    [good_entry(context="")],
    [good_entry(), good_entry()],
    [good_entry(integration_id=False)],
    [good_entry(integration_id=-1)],
    [good_entry(dedicated_app=True, integration_id=common.ACTIONS_APP_ID)],
    [good_entry(kind="other")],
    [good_entry(queue="later")],
    [good_entry(kind="status")],
    [good_entry(kind="status", creator_id=1)],
])
def test_load_check_config_refuses_bad_entries(tmp_path, checks):
    data = {"checks": checks} if checks is not None else []
    with pytest.raises(common.ToolError):
        common.load_check_config(write(tmp_path, "c.json", data))


# --- common: merge queue refs and PR heads -----------------------------------

def test_queue_pr_number():
    assert common.queue_pr_number("refs/heads/gh-readonly-queue/main/pr-36-" + "c" * 40) == 36
    assert common.queue_pr_number("gh-readonly-queue/main/pr-7-abc123") == 7
    for bad in (None, "", "refs/heads/main", "gh-readonly-queue/main/pr-x-abc"):
        with pytest.raises(common.ToolError):
            common.queue_pr_number(bad)


def test_pr_head_sha():
    gh = FakeGitHub(json_by_path={"/repos/o/r/pulls/1": {"head": {"sha": SHA}},
                                  "/repos/o/r/pulls/2": {"head": {"sha": "short"}},
                                  "/repos/o/r/pulls/3": []})
    assert common.pr_head_sha(gh, "o/r", 1) == SHA
    for number in (2, 3):
        with pytest.raises(common.ToolError):
            common.pr_head_sha(gh, "o/r", number)


def test_quote():
    assert common.quote("a/b c") == "a%2Fb%20c"
    assert common.quote("a/b", safe="/") == "a/b"


# --- common: the REST client, with urlopen replaced --------------------------

class FakeResponse(io.BytesIO):
    def __init__(self, status, body):
        super().__init__(body)
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def fake_urlopen(responses, seen):
    def opener(request, timeout=None):
        seen.append(request)
        result = responses.pop(0)
        if isinstance(result, Exception):
            raise result
        return FakeResponse(*result)
    return opener


def http_error(code, body=b"{}"):
    return urllib.error.HTTPError("https://x", code, "err", {}, io.BytesIO(body))


def test_github_needs_a_token(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    with pytest.raises(common.ToolError):
        common.GitHub()


def test_github_request_and_get_json(monkeypatch):
    seen = []
    monkeypatch.setattr(common.urllib.request, "urlopen", fake_urlopen([
        (200, b'{"ok": true}'), http_error(404), http_error(403), (200, b"not json"),
    ], seen))
    gh = common.GitHub(token="t", api_url="https://api.example/")
    assert gh.get_json("/a") == {"ok": True}
    assert seen[0].get_header("Authorization") == "Bearer t"
    assert seen[0].full_url == "https://api.example/a"
    assert gh.get_json("/b", allow_404=True) is None
    with pytest.raises(common.ToolError):
        gh.get_json("/c")
    with pytest.raises(common.ToolError):
        gh.get_json("/d")


def test_github_request_with_body_and_failures(monkeypatch):
    seen = []
    monkeypatch.setattr(common.urllib.request, "urlopen", fake_urlopen([
        (201, b"{}"), http_error(502), urllib.error.URLError("down"), OSError("reset"),
    ], seen))
    gh = common.GitHub(token="t")
    assert gh.request("POST", "/p", body={"a": 1}) == (201, b"{}")
    assert seen[0].get_header("Content-type") == "application/json"
    for _ in range(3):
        with pytest.raises(common.ToolError):
            gh.request("GET", "/q")


def test_github_get_raw(monkeypatch):
    monkeypatch.setattr(common.urllib.request, "urlopen", fake_urlopen([(200, b"raw"), http_error(404)], []))
    gh = common.GitHub(token="t")
    assert gh.get_raw("/f") == b"raw"
    with pytest.raises(common.ToolError):
        gh.get_raw("/g")


def test_github_list_all_follows_pages(monkeypatch):
    full = json.dumps([{"i": n} for n in range(100)]).encode()
    seen = []
    monkeypatch.setattr(common.urllib.request, "urlopen", fake_urlopen([(200, full), (200, b"[1]"), (200, b"{}")], seen))
    gh = common.GitHub(token="t")
    assert len(gh.list_all("/s?x=1")) == 101
    assert "x=1&per_page=100&page=2" in seen[1].full_url
    with pytest.raises(common.ToolError):
        gh.list_all("/t")


# --- verifier: reading check runs --------------------------------------------

def test_extract_runs_accepts_each_shape():
    one = run_("a")
    assert vrc.extract_runs({"check_runs": [one]}) == [one]
    assert vrc.extract_runs([one]) == [one]
    assert vrc.extract_runs([{"check_runs": [one]}, {"check_runs": [one]}]) == [one, one]
    for bad in ({"check_runs": None}, ["x"], [{"other": 1}]):
        with pytest.raises(common.ToolError):
            vrc.extract_runs(bad)


def test_fetch_runs_pages_until_total():
    gh = FakeGitHub(pages=[{"check_runs": [run_("a")], "total_count": 2}, {"check_runs": [run_("b")], "total_count": 2}])
    assert [r["name"] for r in vrc.fetch_runs(gh, "o/r", SHA)] == ["a", "b"]
    assert "filter=latest" in gh.calls[0] and "page=2" in gh.calls[1]


@pytest.mark.parametrize("pages", [
    [[]],
    [{"check_runs": "x"}],
    [{"check_runs": []}],
    [{"check_runs": [], "total_count": 1}],
])
def test_fetch_runs_refuses_bad_responses(pages):
    with pytest.raises(common.ToolError):
        vrc.fetch_runs(FakeGitHub(pages=pages), "o/r", SHA)


def test_small_helpers():
    assert vrc.app_id({"app": {"id": 3}}) == 3
    assert vrc.app_id({"app": None}) is None
    assert vrc.passed(run_("a"))
    assert not vrc.passed(run_("a", conclusion="neutral"))
    assert not vrc.passed(run_("a", status="in_progress", conclusion=None))
    assert vrc.creator_id({"creator": {"id": 4}}) == 4
    assert vrc.creator_id({}) is None
    assert vrc.target_sha(spec(queue="pr-head"), SHA, OTHER) == OTHER
    assert vrc.target_sha(spec(queue="merge"), SHA, OTHER) == SHA
    assert vrc.target_sha(spec(queue="pr-head"), SHA, None) == SHA


# --- verifier: the newest suite decides (the bug seen on PR 35) --------------

def test_latest_suite_ignores_a_stale_failed_suite():
    stale = run_("provenance", conclusion="failure", suite=10, rid=100)
    fresh = run_("provenance", conclusion="success", suite=11, rid=101)
    assert vrc.latest_suite([stale, fresh]) == [fresh]
    no_suite = dict(run_("x", rid=5), check_suite=None)
    assert vrc.latest_suite([no_suite]) == [no_suite]


def test_current_runs_for_a_dedicated_app_takes_its_newest_post():
    older = run_("heldout-tests", conclusion="failure", suite=1, rid=1)
    newer = run_("heldout-tests", conclusion="success", suite=1, rid=2)
    assert vrc.current_runs(spec(dedicated_app=True), [older, newer]) == [newer]
    assert vrc.current_runs(spec(), [older, newer]) == [older, newer]


def test_evaluate_check_run_rules():
    assert vrc.evaluate_check_run("p", spec(), [run_("p")], SHA, "src") == []
    stale_then_pass = [run_("p", "failure", suite=1, rid=1), run_("p", suite=2, rid=2)]
    assert vrc.evaluate_check_run("p", spec(), stale_then_pass, SHA, "src") == []
    rules = lambda found: sorted(f["rule"] for f in found)  # noqa: E731
    assert rules(vrc.evaluate_check_run("p", spec(), [run_("p", "neutral")], SHA, "src")) == ["CHK001"]
    assert rules(vrc.evaluate_check_run("p", spec(), [run_("p", None, "in_progress")], SHA, "src")) == ["CHK001"]
    assert rules(vrc.evaluate_check_run("p", spec(), [dict(run_("p", None, None), status=None)], SHA, "src")) == ["CHK001"]
    assert rules(vrc.evaluate_check_run("p", spec(), [run_("p", app=99)], SHA, "src")) == ["CHK002", "CHK003"]
    assert rules(vrc.evaluate_check_run("p", spec(), [run_("p", sha=OTHER)], SHA, "src")) == ["CHK002"]


# --- verifier: commit statuses -----------------------------------------------

def status(context, state, creator=9, sid=1):
    return {"context": context, "state": state, "creator": {"id": creator}, "id": sid}


def test_evaluate_status_rules():
    sspec = spec(kind="status", creator_id=9)
    ok = {SHA: [status("s", "failure", sid=1), status("s", "success", sid=2), "junk"]}
    assert vrc.evaluate_status("s", sspec, ok, SHA, "src") == []
    rules = lambda found: sorted(f["rule"] for f in found)  # noqa: E731
    assert rules(vrc.evaluate_status("s", sspec, {SHA: [status("s", "pending")]}, SHA, "src")) == ["CHK001"]
    assert rules(vrc.evaluate_status("s", sspec, {SHA: [status("s", "success", creator=1)]}, SHA, "src")) == ["CHK002", "CHK003"]
    assert rules(vrc.evaluate_status("s", sspec, {}, SHA, "src")) == ["CHK002"]


def test_evaluate_routes_by_kind_and_queue_policy():
    required = {"c": spec(), "s": spec(kind="status", creator_id=9, queue="pr-head")}
    found = vrc.evaluate(required, [run_("c")], {OTHER: [status("s", "success")]}, SHA, OTHER, "src")
    assert found == []


def test_still_pending():
    sspec = spec(kind="status", creator_id=9)
    assert vrc.still_pending({"c": spec()}, [], {}, SHA, None)
    assert vrc.still_pending({"c": spec()}, [run_("c", None, "queued")], {}, SHA, None)
    assert not vrc.still_pending({"c": spec()}, [run_("c")], {}, SHA, None)
    assert vrc.still_pending({"s": sspec}, [], {SHA: [status("s", "pending")]}, SHA, None)
    assert vrc.still_pending({"s": sspec}, [], {}, SHA, None)
    assert not vrc.still_pending({"s": sspec}, [], {SHA: [status("s", "success")]}, SHA, None)
    assert not vrc.still_pending({"s": sspec, "c": spec()}, [run_("c")], {SHA: [status("s", "failure")]}, SHA, None)


def test_load_saved_statuses(tmp_path):
    assert vrc.load_saved_statuses(None) == {}
    assert vrc.load_saved_statuses(write(tmp_path, "s.json", {SHA: []})) == {SHA: []}
    for bad in ([], {SHA: "x"}):
        with pytest.raises(common.ToolError):
            vrc.load_saved_statuses(write(tmp_path, "s.json", bad))


class Args:
    def __init__(self, config=None, ruleset=None, exclude=()):
        self.config, self.ruleset, self.exclude = config, ruleset, list(exclude)


def test_required_from(tmp_path):
    rs = write(tmp_path, "r.json", ruleset([{"context": "a", "integration_id": 1}, {"context": "v", "integration_id": 1}]))
    assert vrc.required_from(Args(ruleset=[rs], exclude=["v"])) == {"a": {"kind": "check_run", "integration_id": 1, "queue": "merge"}}
    cfg = write(tmp_path, "c.json", {"checks": [good_entry()]})
    assert list(vrc.required_from(Args(config=cfg))) == ["c"]
    with pytest.raises(common.ToolError):
        vrc.required_from(Args(ruleset=[rs], exclude=["a", "v"]))


# --- verifier: the command line ----------------------------------------------

def call_main(monkeypatch, argv):
    monkeypatch.setattr(sys, "argv", ["verify_required_checks.py"] + argv)
    return vrc.main()


def test_main_saved_mode(tmp_path, monkeypatch, capsys):
    rs = write(tmp_path, "r.json", ruleset([{"context": "provenance", "integration_id": APP}]))
    stale_then_pass = write(tmp_path, "runs.json", [run_("provenance", "failure", suite=1, rid=1), run_("provenance", suite=2, rid=2)])
    assert call_main(monkeypatch, ["--ruleset", rs, "--sha", SHA, "--saved", stale_then_pass]) == 0
    only_stale = write(tmp_path, "stale.json", {"check_runs": [run_("provenance", "failure")]})
    out = tmp_path / "out.json"
    assert call_main(monkeypatch, ["--ruleset", rs, "--sha", SHA, "--saved", only_stale, "--output", str(out)]) == 1
    assert json.loads(out.read_text())[0]["rule"] == "CHK001"
    capsys.readouterr()


def test_main_refuses_short_shas_and_bad_repos(tmp_path, monkeypatch):
    rs = write(tmp_path, "r.json", ruleset([{"context": "p", "integration_id": APP}]))
    with pytest.raises(common.ToolError):
        call_main(monkeypatch, ["--ruleset", rs, "--sha", "abc", "--saved", "x"])
    with pytest.raises(common.ToolError):
        call_main(monkeypatch, ["--ruleset", rs, "--sha", SHA, "--pr-head-sha", "abc", "--saved", "x"])
    with pytest.raises(common.ToolError):
        call_main(monkeypatch, ["--ruleset", rs, "--sha", SHA, "--repo", "not a repo"])


def live_setup(monkeypatch, pages, lists=None, pulls=None):
    fake = FakeGitHub(pages=pages, lists=lists, json_by_path=pulls)
    monkeypatch.setattr(vrc, "GitHub", lambda: fake)
    monkeypatch.setattr(vrc.time, "sleep", lambda seconds: None)
    return fake


def test_main_live_waits_for_pending_then_passes(tmp_path, monkeypatch, capsys):
    rs = write(tmp_path, "r.json", ruleset([{"context": "p", "integration_id": APP}]))
    live_setup(monkeypatch, [
        {"check_runs": [run_("p", None, "in_progress")], "total_count": 1},
        {"check_runs": [run_("p")], "total_count": 1},
    ])
    assert call_main(monkeypatch, ["--ruleset", rs, "--sha", SHA, "--repo", "o/r", "--wait", "60", "--poll-interval", "0"]) == 0
    assert "waiting for required checks" in capsys.readouterr().err


def test_main_live_stops_at_the_deadline(tmp_path, monkeypatch, capsys):
    rs = write(tmp_path, "r.json", ruleset([{"context": "p", "integration_id": APP}]))
    live_setup(monkeypatch, [{"check_runs": [run_("p", None, "queued")], "total_count": 1}])
    assert call_main(monkeypatch, ["--ruleset", rs, "--sha", SHA, "--repo", "o/r", "--wait", "0"]) == 1
    capsys.readouterr()


def test_main_live_merge_queue_reads_statuses_on_the_pr_head(tmp_path, monkeypatch, capsys):
    cfg = write(tmp_path, "c.json", {"checks": [
        good_entry(context="c", integration_id=APP),
        good_entry(context="s", kind="status", creator_id=9, workflow="w", queue="pr-head"),
    ]})
    queue_ref = "refs/heads/gh-readonly-queue/main/pr-36-" + "c" * 40
    fake = live_setup(
        monkeypatch,
        pages=[{"check_runs": [run_("c")], "total_count": 1}, {"check_runs": [], "total_count": 0}],
        lists={"/repos/o/r/commits/%s/statuses" % SHA: [], "/repos/o/r/commits/%s/statuses" % OTHER: [status("s", "success")]},
        pulls={"/repos/o/r/pulls/36": {"head": {"sha": OTHER}}},
    )
    assert call_main(monkeypatch, ["--config", cfg, "--sha", SHA, "--repo", "o/r", "--queue-ref", queue_ref]) == 0
    assert "/repos/o/r/pulls/36" in fake.calls
    capsys.readouterr()
