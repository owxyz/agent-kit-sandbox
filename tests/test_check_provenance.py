"""Tests for the installed provenance check's draft handling (P1.4, red-team finding #14).

They run check_provenance.main() in process, with a saved event and commits file,
so no network is used.
"""
import json
import os
import sys

import pytest

SCRIPTS = os.path.join(os.path.dirname(__file__), "..", ".github", "agent-kit", "scripts")
sys.path.insert(0, os.path.abspath(SCRIPTS))

import check_provenance  # noqa: E402

UNDISCLOSED = {"body": "Just a change", "user": {"login": "alice"}, "labels": [], "number": 1}


def run_main(tmp_path, monkeypatch, pull):
    event = tmp_path / "event.json"
    event.write_text(json.dumps({"pull_request": pull, "repository": {"full_name": "o/r"}}))
    commits = tmp_path / "commits.json"
    commits.write_text("[]")
    out = tmp_path / "out"
    monkeypatch.setattr(sys, "argv", ["check_provenance.py", "--event", str(event),
                                      "--commits-file", str(commits), "--github-output", str(out)])
    return check_provenance.main(), out.read_text()


def test_draft_pr_is_deferred_until_ready(tmp_path, monkeypatch, capsys):
    code, output = run_main(tmp_path, monkeypatch, dict(UNDISCLOSED, draft=True))
    printed = capsys.readouterr().out
    assert code == 0
    assert "::error" not in printed
    assert "marked ready for review" in printed
    assert output == "agent_pr=false\n"


@pytest.mark.parametrize("draft", [False, "yes"])
def test_ready_or_non_boolean_draft_is_still_checked(tmp_path, monkeypatch, capsys, draft):
    code, _ = run_main(tmp_path, monkeypatch, dict(UNDISCLOSED, draft=draft))
    assert code == 1
    assert "::error" in capsys.readouterr().out
