#!/usr/bin/env python3
"""P2.6: nightly mutation testing of critical modules, with per-module floors.

  measure   run the tools and write a report; needs no secrets
  evaluate  compare a report to the floors and alert owners; runs no repo code
  run       both, for local use

Rules: MUT001 below floor, MUT002 no floor set yet, MUT003 mutants disabled by
source comments, MUT900 could not measure. Exit 0, 1 or 2 per the gate contract.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import alert_channels  # noqa: E402
from common import EXIT_TOOL_ERROR, ToolError, exit_code, finding, load_config, write_json  # noqa: E402

GATE = "mutation"
COPY_IGNORE = shutil.ignore_patterns(".git", "node_modules", ".venv", "__pycache__", ".stryker-tmp")
# A run where the tool itself failed on this share of mutants measures nothing useful.
MAX_ERROR_SHARE = 0.10
DEFAULT_RUNTIME_SECONDS = 3600


def _env():
    env = dict(os.environ)
    env["PATH"] = os.path.dirname(sys.executable) + os.pathsep + env.get("PATH", "")
    return env


def _run(argv, cwd, timeout, label, shell=False):
    """Run a command; anything but exit 0 is a tool error, with a bounded output tail."""
    try:
        done = subprocess.run(
            argv,
            cwd=cwd,
            env=_env(),
            shell=shell,
            timeout=timeout,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            errors="replace",
        )
    except subprocess.TimeoutExpired:
        raise ToolError("%s timed out after %ss" % (label, timeout))
    except OSError as error:
        raise ToolError("%s could not start: %s" % (label, type(error).__name__))
    if done.returncode != 0:
        raise ToolError("%s exited %d: %s" % (label, done.returncode, done.stdout[-800:]))
    return done.stdout


def _toml_string(value):
    return json.dumps(value)


def _score(killed, survived):
    return round(100.0 * killed / (killed + survived), 2)


def _result(tool, killed, survived, timeouts, no_coverage, ignored, errors):
    """Build a result, refusing numbers that would produce a meaningless score."""
    detected = killed + timeouts
    undetected = survived + no_coverage
    assessed = detected + undetected
    if assessed == 0:
        raise ToolError("%s produced no assessable mutants; check the module paths" % tool)
    if errors / float(assessed + errors) > MAX_ERROR_SHARE:
        raise ToolError("%s failed on %d of %d mutants" % (tool, errors, assessed + errors))
    return {
        "tool": tool,
        "killed": killed,
        "timeouts": timeouts,
        "survived": survived,
        "no_coverage": no_coverage,
        "ignored": ignored,
        "errors": errors,
        "score": _score(detected, undetected),
    }


def run_python(module, repo, work):
    """Cosmic Ray edits files in place, so it only ever touches a private copy."""
    copy = os.path.join(work, "repo")
    shutil.copytree(repo, copy, symlinks=True, ignore=COPY_IGNORE)
    runtime = module.get("max_runtime_seconds", DEFAULT_RUNTIME_SECONDS)
    # Every mutant counts as killed if the unmutated tests already fail.
    started = time.time()
    _run(module["test_command"], copy, runtime, "baseline tests", shell=True)
    timeout = module.get("timeout_seconds", max(30, round((time.time() - started) * 10)))
    paths = ", ".join(_toml_string(path) for path in module["paths"])
    settings = os.path.join(work, "cosmic-ray.toml")
    with open(settings, "w") as output:
        output.write(
            "[cosmic-ray]\nmodule-path = [%s]\ntimeout = %s\nexcluded-modules = []\n"
            'test-command = %s\n[cosmic-ray.distributor]\nname = "local"\n'
            % (paths, float(timeout), _toml_string(module["test_command"]))
        )
    session = os.path.join(work, "session.sqlite")
    base = [sys.executable, "-m", "cosmic_ray.cli"]
    _run(base + ["init", settings, session], copy, 300, "cosmic-ray init")
    _run(base + ["exec", settings, session], copy, runtime, "cosmic-ray exec")
    dumped = _run(base + ["dump", session], copy, 300, "cosmic-ray dump")
    return parse_cosmic_ray(dumped)


def parse_cosmic_ray(dump):
    killed = survived = timeouts = errors = ignored = pending = 0
    for line in dump.splitlines():
        if not line.startswith("["):
            continue
        result = json.loads(line)[1]
        if result is None:
            pending += 1
        elif result.get("worker_outcome") != "normal":
            errors += 1
        elif result.get("test_outcome") == "survived":
            survived += 1
        elif result.get("test_outcome") == "killed":
            if result.get("output") == "timeout":
                timeouts += 1
            else:
                killed += 1
        else:  # Mutated code that can't run says nothing about the tests.
            ignored += 1
    if pending:
        raise ToolError("cosmic-ray left %d mutants unexecuted" % pending)
    return _result("cosmic-ray", killed, survived, timeouts, 0, ignored, errors)


def run_stryker(module, repo, work):
    report = os.path.join(work, "mutation.json")
    options = {
        "mutate": module["paths"],
        "reporters": ["json"],
        "jsonReporter": {"fileName": report},
        "tempDirName": ".stryker-tmp",
        "timeoutMS": 1000 * module.get("timeout_seconds", 30),
    }
    if module.get("test_command"):
        options.update(
            testRunner="command",
            coverageAnalysis="off",
            commandRunner={"command": module["test_command"]},
        )
    options.update(module.get("stryker") or {})
    settings = os.path.join(work, "stryker.conf.json")
    write_json(settings, options)
    # --no-install: the tool must be the pinned one in the repo, never a fresh download.
    argv = ["npx", "--no-install", "stryker", "run", settings]
    _run(argv, repo, module.get("max_runtime_seconds", DEFAULT_RUNTIME_SECONDS), "stryker")
    try:
        with open(report) as source:
            return parse_stryker(json.load(source))
    except (OSError, ValueError):
        raise ToolError("stryker wrote no readable report")


def parse_stryker(report):
    counts = {}
    for entry in report.get("files", {}).values():
        for mutant in entry.get("mutants", []):
            counts[mutant["status"]] = counts.get(mutant["status"], 0) + 1
    known = {"Killed", "Timeout", "Survived", "NoCoverage", "Ignored", "CompileError", "RuntimeError"}
    unknown = set(counts) - known
    if unknown:
        raise ToolError("stryker left mutants in state: %s" % ", ".join(sorted(unknown)))
    return _result(
        "stryker",
        counts.get("Killed", 0),
        counts.get("Survived", 0),
        counts.get("Timeout", 0),
        counts.get("NoCoverage", 0),
        counts.get("Ignored", 0),
        counts.get("CompileError", 0) + counts.get("RuntimeError", 0),
    )


ADAPTERS = {"python": run_python, "javascript": run_stryker, "typescript": run_stryker}


def measure(config, repo):
    """Measure every module. One module failing must not cost the others their result."""
    results = []
    for module in config["modules"]:
        entry = {"name": module["name"]}
        work = tempfile.mkdtemp(prefix="mutation-")
        try:
            entry.update(ADAPTERS[module["language"]](module, repo, work))
            entry["status"] = "ok"
        except ToolError as error:
            entry.update(status="error", error=str(error))
        except (OSError, ValueError, KeyError, shutil.Error) as error:
            entry.update(status="error", error="%s: %s" % (type(error).__name__, error))
        finally:
            shutil.rmtree(work, ignore_errors=True)
        results.append(entry)
    return {"version": 1, "commit": os.environ.get("GITHUB_SHA", ""), "modules": results}


def _alert(kind, module, message, commit, score=None):
    server, repository, run = (
        os.environ.get("GITHUB_SERVER_URL"),
        os.environ.get("GITHUB_REPOSITORY"),
        os.environ.get("GITHUB_RUN_ID"),
    )
    run_url = "%s/%s/actions/runs/%s" % (server, repository, run) if server and repository and run else ""
    return {
        "kind": kind,
        "module": module["name"],
        "owner": module["owner"],
        "score": score,
        "floor": module["floor"],
        "message": message,
        "commit": commit,
        "run_url": run_url,
    }


def evaluate(config, report):
    """Return (findings, alerts, tool_error). A missing report alerts every owner."""
    mode = (config.get("mutation") or {}).get("mode", "warn")
    findings, alerts, tool_error = [], [], False
    measured = {}
    commit = ""
    if isinstance(report, dict):
        commit = str(report.get("commit", ""))
        measured = {item.get("name"): item for item in report.get("modules", []) if isinstance(item, dict)}
    for module in config["modules"]:
        name, floor = module["name"], module["floor"]
        target = module["paths"][0]
        result = measured.get(name)
        if result is None or result.get("status") != "ok":
            detail = result.get("error", "unknown") if result else "module missing from report"
            message = "mutation score for %s could not be measured: %s" % (name, detail)
            tool_error = True
            findings.append(finding(GATE, "MUT900", "high", mode, target, 0, message))
            alerts.append(_alert("measurement_failed", module, message, commit))
            continue
        score = result["score"]
        if result.get("ignored"):
            message = "%s: %d mutants were excluded or could not run; check for disable comments" % (
                name,
                result["ignored"],
            )
            findings.append(finding(GATE, "MUT003", "medium", "warn", target, 0, message))
        if floor is None:
            message = "%s scored %.2f with no floor set; set one from measured scores" % (name, score)
            findings.append(finding(GATE, "MUT002", "info", "warn", target, 0, message))
        elif score < floor:
            message = "%s mutation score %.2f is below its floor of %s" % (name, score, floor)
            findings.append(finding(GATE, "MUT001", "high", mode, target, 0, message))
            alerts.append(_alert("below_floor", module, message, commit, score))
    return findings, alerts, tool_error


def _evaluate_and_alert(config, report, path):
    findings, alerts, tool_error = evaluate(config, report)
    if alerts:
        try:
            alert_channels.deliver((config.get("mutation") or {}).get("alert"), alerts)
        except ToolError as error:
            tool_error = True
            findings.append(finding(GATE, "MUT900", "high", "block", "", 0, str(error)))
    write_json(path, findings)
    return exit_code(findings, tool_error)


def _read_report(path):
    try:
        with open(path) as source:
            return json.load(source)
    except (OSError, ValueError):
        return None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("command", choices=("measure", "evaluate", "run"))
    parser.add_argument("--config", required=True)
    parser.add_argument("--repo", default=".")
    parser.add_argument("--report", required=True)
    parser.add_argument("--findings", required=True)
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config)
        if args.command == "evaluate":
            return _evaluate_and_alert(config, _read_report(args.report), args.findings)
        report = measure(config, os.path.abspath(args.repo))
        write_json(args.report, report)
        if args.command == "run":
            return _evaluate_and_alert(config, report, args.findings)
        failed = [item for item in report["modules"] if item["status"] != "ok"]
        write_json(args.findings, [])
        return EXIT_TOOL_ERROR if failed else 0
    except ToolError as error:
        write_json(args.findings, [finding(GATE, "MUT900", "high", "block", "", 0, str(error))])
        print("tool error: %s" % error, file=sys.stderr)
        return EXIT_TOOL_ERROR


if __name__ == "__main__":
    sys.exit(main())
