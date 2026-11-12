"""Pytest plugin loaded by the harness: records each test's result and same-line condition probes."""
import builtins
import json
import os

_results, _load_errors, _conds = {}, {}, {}


def _cond(index, value):
    seen = _conds.setdefault(index, [False, False])
    seen[0 if value else 1] = True
    return value


builtins.__tq_cond__ = _cond


def pytest_collectreport(report):
    if report.failed:
        _load_errors[report.nodeid] = str(report.longrepr)[:2000]


def pytest_runtest_logreport(report):
    entry = _results.setdefault(report.nodeid, {"status": "passed", "invocations": 1})
    if report.outcome == "rerun":
        entry["invocations"] += 1
    elif report.failed:
        entry["status"] = "failed"
    elif report.skipped and entry["status"] != "failed":
        entry["status"] = "skipped"


def pytest_sessionfinish(session, exitstatus):
    path = os.environ.get("TQ_RESULTS_OUT")
    if path:
        with open(path, "w") as handle:
            json.dump({"results": _results, "load_errors": _load_errors,
                       "conds": {str(k): v for k, v in _conds.items()}}, handle)
