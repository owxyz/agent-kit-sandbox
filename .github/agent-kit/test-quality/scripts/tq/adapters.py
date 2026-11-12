"""Language adapters. Add a language by subclassing Adapter and listing it in make_adapters."""
from __future__ import annotations

import ast
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from . import errorsites
from .core import HARNESS_ROOT, ToolError, isolated_env, run, text

KNOWN_CODE_EXTENSIONS = {".go", ".java", ".kt", ".rb", ".rs", ".cs", ".php", ".c", ".cc", ".cpp", ".h",
                         ".hpp", ".swift", ".scala"}


@dataclass
class Branch:
    line: int
    total: int
    covered: int
    lines: set


@dataclass
class FileCoverage:
    branches: list = field(default_factory=list)
    points: dict = field(default_factory=dict)  # (line, col) -> executed?
    excluded: set = field(default_factory=set)
    parse_error: str = ""


@dataclass
class ChangedTests:
    files: list = field(default_factory=list)
    new: set = field(default_factory=set)
    modified: set = field(default_factory=set)
    load_errors: dict = field(default_factory=dict)  # test file -> why it could not be read
    lines: dict = field(default_factory=dict)

    @property
    def wanted(self):
        return self.new | self.modified


@dataclass
class RunResult:
    outcomes: dict = field(default_factory=dict)  # id -> {"status", "invocations"}
    load_errors: dict = field(default_factory=dict)
    exit_code: int = 0

    def matching(self, test_id):
        return [o for key, o in self.outcomes.items() if key == test_id or key.startswith(test_id + "[")]

    def status(self, test_id):
        """passed, failed, skipped, load_error or not_run. Parametrized cases roll up to their test."""
        found = self.matching(test_id)
        if found:
            statuses = {o["status"] for o in found}
            if "failed" in statuses:
                return "failed"
            return "passed" if "passed" in statuses else "skipped"
        test_file = test_id.split("::", 1)[0]
        return "load_error" if any(k.split("::", 1)[0] == test_file for k in self.load_errors) else "not_run"


def _json_file(path, what):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError) as exc:
        raise ToolError("%s was not produced or is not valid JSON (%s)" % (what, exc))


class Adapter:
    name = ""
    granularity = "test"
    extensions = ()
    exclusion_re = None
    retry_re = None

    def __init__(self, cfg, python, jest_bin, base_tree, timeout=None):
        self.cfg, self.python, self.jest_bin = cfg, python, jest_bin
        self.base_tree = Path(base_tree)
        self.timeout = timeout or cfg.get("round_timeout_seconds", 900)

    def owns(self, path):
        return PurePosixPath(path).suffix in self.extensions

    def is_test_path(self, path):
        raise NotImplementedError

    def is_source_path(self, path):
        return self.owns(path) and not self.is_test_path(path)

    def detect(self, tree):
        raise NotImplementedError

    def error_sites(self, source):
        raise NotImplementedError

    def coverage(self, tree, sources, scratch):
        """Return ({path: FileCoverage}, tests_failed)."""
        raise NotImplementedError

    def changed_tests(self, ws, scratch):
        raise NotImplementedError

    def run(self, tree, scratch, seed, changed=None, deselect=(), only=()):
        raise NotImplementedError


# ---------------------------------------------------------------- Python / pytest
PY_COND_OPEN = '__import__("builtins").__dict__.get("__tq_cond__",lambda i,v:v)(%d,'


def _instrument_conditions(source, changed, first_index):
    """Wrap same-line conditions, which coverage.py cannot see, without moving any line.

    Returns (new source, [(index, line, kind)]). Runs only on the throwaway test tree.
    """
    tree = ast.parse(source)
    in_fstring = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            in_fstring.update(id(sub) for sub in ast.walk(node))
    edits, probes, index = [], [], first_index
    for node in ast.walk(tree):
        if id(node) in in_fstring:
            continue
        if isinstance(node, ast.IfExp):
            kind = "ifexp"
        elif isinstance(node, (ast.If, ast.While)) and node.test.end_lineno == node.body[0].lineno:
            kind = "if"
        else:
            continue
        test = node.test
        if not changed & set(range(test.lineno, test.end_lineno + 1)):
            continue
        edits.append((test.end_lineno, test.end_col_offset, 0, b")"))
        edits.append((test.lineno, test.col_offset, 1, (PY_COND_OPEN % index).encode()))
        probes.append((index, test.lineno, kind))
        index += 1
    lines = source.encode("utf-8").split(b"\n")
    for line, col, _order, insert in sorted(edits, reverse=True):
        raw = lines[line - 1]
        lines[line - 1] = raw[:col] + insert + raw[col:]
    return b"\n".join(lines).decode("utf-8"), probes


def _header_lines(source):
    """Map a branching statement's first line to every line of its condition."""
    header = {}
    for node in ast.walk(ast.parse(source)):
        expr = getattr(node, "test", None) if isinstance(node, (ast.If, ast.While)) else None
        if isinstance(node, (ast.For, ast.AsyncFor)):
            expr = node.iter
        if type(node).__name__ == "Match":
            expr = node.subject
        if expr is not None:
            header[node.lineno] = set(range(node.lineno, expr.end_lineno + 1))
    return header


def _python_test_nodes(source):
    """Return {pytest-id suffix: (first line, last line)} for test functions and methods."""
    found = {}

    def span(node):
        start = min([node.lineno] + [d.lineno for d in node.decorator_list])
        return (start, node.end_lineno)

    def is_test_class(node):
        bases = [getattr(b, "attr", getattr(b, "id", "")) for b in node.bases]
        return node.name.startswith("Test") or any(b.endswith("TestCase") for b in bases)

    def visit(body, prefix):
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test"):
                found[prefix + node.name] = span(node)
            elif isinstance(node, ast.ClassDef) and is_test_class(node):
                visit(node.body, "%s%s::" % (prefix, node.name))

    visit(ast.parse(source).body, "")
    return found


class PytestAdapter(Adapter):
    name = "python"
    granularity = "test"
    extensions = (".py",)
    exclusion_re = re.compile(r"#\s*(pragma\s*:?\s*no\s*(cover|branch)|nocov(er)?\b)", re.I)
    retry_re = re.compile(r"mark\.(flaky|rerun)|@flaky\b|@retry\b|\breruns\s*=")

    def is_test_path(self, path):
        pure = PurePosixPath(path)
        return (self.owns(path) and (pure.name.startswith("test_") or pure.name.endswith("_test.py")
                                     or pure.name == "conftest.py" or "tests" in pure.parts
                                     or "test" in pure.parts))

    def detect(self, tree):
        return any(self.is_test_path(p.relative_to(tree).as_posix()) for p in Path(tree).rglob("*.py"))

    def error_sites(self, source):
        return errorsites.python_sites(source)

    def _ini(self, scratch):
        for name in ("pytest.ini", ".pytest.ini", "pyproject.toml", "tox.ini", "setup.cfg"):
            candidate = self.base_tree / name
            if not candidate.is_file():
                continue
            body = candidate.read_text(errors="replace")
            if name in ("pytest.ini", ".pytest.ini") or "tool.pytest" in body or "[pytest]" in body \
                    or "tool:pytest" in body:
                return candidate
        generated = Path(scratch) / "harness-pytest.ini"
        generated.write_text("[pytest]\n")
        return generated

    def _pytest_args(self, tree, scratch, seed, targets=(), deselect=()):
        args = ["-c", self._ini(scratch), "--rootdir", tree, "-o", "addopts=", "-p", "no:cacheprovider",
                "-p", "no:rerunfailures", "-p", "no:flaky", "-p", "tq_pytest_plugin", "-p", "pytest_randomly",
                "-p", "no:xdist", "--continue-on-collection-errors",
                "-q", "--randomly-seed=%d" % seed]
        for plugin in self.cfg.get("pytest_plugins", []):
            args += ["-p", plugin]
        for item in deselect:
            args += ["--deselect", item]
        return args + list(targets)

    def _env(self, scratch, seed, results):
        env = isolated_env(scratch, seed)
        env.update(PYTHONPATH=str(HARNESS_ROOT / "scripts"), PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",
                   TQ_RESULTS_OUT=str(results), PYTHONDONTWRITEBYTECODE="1")
        return env

    @staticmethod
    def _parse(results, exit_code, output):
        data = _json_file(results, "pytest results (runner output: %s)" % output[-800:])
        if exit_code not in (0, 1, 5) and not data["load_errors"]:
            raise ToolError("pytest exited %d: %s" % (exit_code, output[-800:]))
        return RunResult(outcomes=data["results"], load_errors=data["load_errors"], exit_code=exit_code), data

    def coverage(self, tree, sources, scratch):
        scratch, tree = Path(scratch), Path(tree)
        probes, parsed, index = {}, {}, 1
        for path, change in sources.items():
            source = (tree / path).read_text()
            try:
                new_source, found = _instrument_conditions(source, change.changed_lines, index)
                parsed[path] = _header_lines(source)
            except SyntaxError as exc:
                parsed[path] = str(exc)
                continue
            index += len(found) + 1
            probes.update({i: (path, line, kind) for i, line, kind in found})
            (tree / path).write_text(new_source)
        rc, data_file, report_json, results = (scratch / n for n in ("rc", "data", "cov.json", "results.json"))
        # Written by the harness: a PR's .coveragerc or pyproject omit list is never read.
        rc.write_text("[run]\nbranch = True\nsource = .\nrelative_files = True\ndata_file = %s\n"
                      "[report]\ninclude_namespace_packages = True\n" % data_file)
        env = self._env(scratch, 1, results)
        done = run([self.python, "-m", "coverage", "run", "--rcfile=%s" % rc, "-m", "pytest"]
                   + self._pytest_args(tree, scratch, 1), cwd=tree, env=env, timeout=self.timeout)
        output = text(done.stdout) + text(done.stderr)
        result, raw = self._parse(results, done.returncode, output)
        converted = run([self.python, "-m", "coverage", "json", "--rcfile=%s" % rc, "-o", report_json, "-q"],
                        cwd=tree, env=env, timeout=300)
        if converted.returncode != 0:
            raise ToolError("coverage json failed: %s" % (text(converted.stdout) + text(converted.stderr))[-800:])
        report, out = _json_file(report_json, "coverage report")["files"], {}
        for path in sources:
            if isinstance(parsed.get(path), str):
                out[path] = FileCoverage(parse_error=parsed[path])
            elif path in report:
                out[path] = self._file_coverage(report[path], parsed[path])
        for key, (path, line, kind) in probes.items():
            if path not in out:
                continue
            if kind == "if" and any(b.line == line for b in out[path].branches):
                continue
            seen = raw["conds"].get(str(key), [False, False])
            out[path].branches.append(Branch(line, 2, sum(seen), {line}))
        failed = any(o["status"] == "failed" for o in result.outcomes.values()) or bool(result.load_errors)
        return out, failed

    @staticmethod
    def _file_coverage(data, header):
        cov = FileCoverage(excluded=set(data.get("excluded_lines", [])))
        cov.points.update({(n, 0): True for n in data.get("executed_lines", [])})
        cov.points.update({(n, 0): False for n in data.get("missing_lines", [])})
        grouped = {}
        for pair in data.get("executed_branches", []):
            entry = grouped.setdefault(pair[0], [0, 0])
            entry[0] += 1
            entry[1] += 1
        for pair in data.get("missing_branches", []):
            grouped.setdefault(pair[0], [0, 0])[0] += 1
        for line, (total, covered) in grouped.items():
            cov.branches.append(Branch(line, total, covered, header.get(line, {line})))
        return cov

    def changed_tests(self, ws, scratch):
        changed = ChangedTests()
        for path, change in sorted(ws.changes.items()):
            if change.status == "D" or not self.is_test_path(path) or PurePosixPath(path).name == "conftest.py":
                continue
            source = ws.show(ws.head_sha, path)
            try:
                nodes = _python_test_nodes(source or "")
            except SyntaxError as exc:
                changed.load_errors[path] = str(exc)
                continue
            if not nodes:
                continue
            changed.files.append(path)
            old = ws.show(ws.merge_base, change.old_path or path)
            try:
                before = _python_test_nodes(old) if old is not None else {}
            except SyntaxError:
                before = {}
            significant = {n for n, t in change.added.items() if t.strip() and not t.strip().startswith("#")}
            touched = significant | change.anchors
            outside = {n for n in touched if not any(a <= n <= b for a, b in nodes.values())}
            for name, (first, last) in nodes.items():
                test_id = "%s::%s" % (path, name)
                changed.lines[test_id] = first
                if name not in before:
                    changed.new.add(test_id)
                elif outside or touched & set(range(first, last + 1)):
                    changed.modified.add(test_id)
        return changed

    def run(self, tree, scratch, seed, changed=None, deselect=(), only=()):
        scratch = Path(scratch)
        targets = sorted(changed.wanted) if changed is not None else list(only)
        if changed is not None and not targets:
            return RunResult()
        results = scratch / "results.json"
        done = run([self.python, "-m", "pytest"] + self._pytest_args(tree, scratch, seed, targets, deselect),
                   cwd=tree, env=self._env(scratch, seed, results), timeout=self.timeout)
        return self._parse(results, done.returncode, text(done.stdout) + text(done.stderr))[0]


# ---------------------------------------------------------------- JS, TS / Jest
class JestAdapter(Adapter):
    name = "jest"
    granularity = "file"  # every test in a changed test file is rerun; see README
    extensions = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx")
    exclusion_re = re.compile(r"\b(istanbul|c8|v8)\s+ignore\b|node:coverage\s+(ignore|disable)", re.I)
    retry_re = re.compile(r"\bretryTimes\s*\(")

    TEST_NAME = re.compile(r"\.(test|spec)\.[cm]?[jt]sx?$")
    CONFIG_NAMES = ("jest.config.js", "jest.config.cjs", "jest.config.json")
    UNSUPPORTED_CONFIG = ("jest.config.mjs", "jest.config.ts")
    FORCED_KEYS = ("rootDir", "collectCoverage", "collectCoverageFrom", "coverageDirectory", "coverageProvider",
                   "coverageReporters", "coverageThreshold", "coveragePathIgnorePatterns", "reporters",
                   "cacheDirectory", "watchman", "bail", "testFailureExitCode", "passWithNoTests")

    def is_test_path(self, path):
        pure = PurePosixPath(path)
        return self.owns(path) and (bool(self.TEST_NAME.search(pure.name)) or "__tests__" in pure.parts)

    def detect(self, tree):
        return (Path(tree) / "package.json").is_file()

    def error_sites(self, source):
        return errorsites.js_sites(source)

    def _base_config(self):
        for name in self.UNSUPPORTED_CONFIG:
            if (self.base_tree / name).is_file():
                raise ToolError("%s on the base branch is not readable by the harness; use .js, .cjs or .json" % name)
        config = None
        for name in self.CONFIG_NAMES:
            if (self.base_tree / name).is_file():
                done = run(["node", "-e", "console.log(JSON.stringify(require('./%s')))" % name],
                           cwd=self.base_tree, timeout=60)
                if done.returncode != 0:
                    raise ToolError("cannot load base %s: %s" % (name, text(done.stderr)[-500:]))
                config = json.loads(text(done.stdout))
                break
        package = self.base_tree / "package.json"
        if config is None and package.is_file():
            config = json.loads(package.read_text()).get("jest")
        config = dict(config or {})
        if "projects" in config:
            raise ToolError("Jest projects are not supported by the harness yet")
        for key in self.FORCED_KEYS:
            config.pop(key, None)
        return config

    def _bin(self):
        if not self.jest_bin or not Path(self.jest_bin).is_file():
            raise ToolError("harness Jest not found at %r; pass --jest-bin" % (self.jest_bin,))
        return self.jest_bin

    def _invoke(self, tree, scratch, seed, extra_config, extra_args):
        scratch = Path(scratch)
        results = scratch / "jest-results.json"
        config = self._base_config()
        config.update(rootDir=str(tree), cacheDirectory=str(scratch / "cache"), watchman=False,
                      testLocationInResults=True)
        config.update(extra_config)
        config_path = scratch / "jest.harness.json"
        config_path.write_text(json.dumps(config))
        env = isolated_env(scratch, seed)
        cmd = ["node", self._bin(), "--config", config_path, "--json", "--outputFile", results, "--ci",
               "--randomize", "--seed=%d" % (seed % 2147483647), "--passWithNoTests"] + extra_args
        done = run(cmd, cwd=tree, env=env, timeout=self.timeout)
        if done.returncode not in (0, 1):
            raise ToolError("jest exited %d: %s" % (done.returncode, text(done.stderr)[-800:]))
        data = _json_file(results, "jest results (%s)" % text(done.stderr)[-800:])
        result = RunResult(exit_code=done.returncode)
        for file_result in data.get("testResults", []):
            rel = os.path.relpath(os.path.realpath(file_result["name"]), str(tree))
            cases = file_result.get("assertionResults", [])
            if file_result.get("status") == "failed" and not cases:
                result.load_errors[rel] = (file_result.get("message") or "failed to load")[:2000]
            for case in cases:
                status = {"passed": "passed", "failed": "failed"}.get(case.get("status"), "skipped")
                key = "%s::%s" % (rel, case["fullName"])
                entry = result.outcomes.setdefault(key, {"status": status, "invocations": 1})
                if status == "failed" or entry["status"] == "skipped":
                    entry["status"] = status
                entry["invocations"] = max(entry["invocations"], case.get("invocations") or 1)
        return result

    def coverage(self, tree, sources, scratch):
        scratch, tree = Path(scratch), Path(tree)
        out_dir = scratch / "coverage"
        result = self._invoke(tree, scratch, 1, {
            "collectCoverage": True, "coverageProvider": "babel", "coverageReporters": ["json"],
            "coverageDirectory": str(out_dir), "collectCoverageFrom": sorted(sources),
        }, [])
        report = _json_file(out_dir / "coverage-final.json", "Jest coverage report")
        out = {}
        for key, data in report.items():
            rel = os.path.relpath(os.path.realpath(data.get("path", key)), str(tree))
            if rel in sources:
                out[rel] = self._file_coverage(data)
        failed = any(o["status"] == "failed" for o in result.outcomes.values()) or bool(result.load_errors)
        return out, failed

    @staticmethod
    def _file_coverage(data):
        cov = FileCoverage()
        for key, loc in data["statementMap"].items():
            cov.points[(loc["start"]["line"], loc["start"]["column"])] = data["s"][key] > 0
        for key, branch in data["branchMap"].items():
            counts, loc = data["b"][key], branch["loc"]
            first, last = loc["start"]["line"], loc["end"]["line"]
            locations = branch.get("locations") or []
            if branch.get("type") == "if" and locations and locations[0].get("start", {}).get("line"):
                last = max(first, locations[0]["start"]["line"])  # the condition, not the whole body
            elif branch.get("type") == "switch" and locations and locations[0].get("start", {}).get("line"):
                last = max(first, locations[0]["start"]["line"])
            cov.branches.append(Branch(first, len(counts), sum(1 for c in counts if c > 0),
                                       set(range(first, last + 1))))
        return cov

    def changed_tests(self, ws, scratch):
        changed, scratch, renamed = ChangedTests(), Path(scratch), {}
        for path, change in sorted(ws.changes.items()):
            if change.status != "D" and self.is_test_path(path):
                changed.files.append(path)
                renamed[path] = change.old_path or path
        if not changed.files:
            return changed
        head_dir, base_dir = scratch / "head", scratch / "base"
        head_dir.mkdir(), base_dir.mkdir()
        head_tree = ws.pr_tree()
        head = self._invoke(head_tree, head_dir, 1, {}, ["--runTestsByPath"] + changed.files)
        before = {}
        existing = {p: renamed[p] for p in changed.files if ws.show(ws.merge_base, renamed[p]) is not None}
        if existing:
            base = self._invoke(ws.merge_base_tree(), base_dir, 1, {},
                                ["--runTestsByPath"] + sorted(set(existing.values())))
            if base.load_errors:
                raise ToolError("base versions of changed Jest files failed to load: %s" % sorted(base.load_errors))
            for key in base.outcomes:
                file_part, name = key.split("::", 1)
                before.setdefault(file_part, set()).add(name)
        changed.load_errors.update(head.load_errors)
        for key in head.outcomes:
            file_part, name = key.split("::", 1)
            old_names = before.get(renamed.get(file_part, file_part), set())
            (changed.modified if name in old_names else changed.new).add(key)
        return changed

    def run(self, tree, scratch, seed, changed=None, deselect=(), only=()):
        args = []
        if changed is not None:
            if not changed.files:
                return RunResult()
            return self._invoke(tree, scratch, seed, {}, ["--runTestsByPath"] + sorted(changed.files))
        names = [re.escape(item.split("::", 1)[1]) for item in (deselect or only)]
        if deselect and names:
            args = ["--testNamePattern", "^(?!(?:%s)$)" % "|".join(names)]
        elif only and names:
            args = ["--testNamePattern", "^(?:%s)$" % "|".join(names)]
        return self._invoke(tree, scratch, seed, {}, args)


def make_adapters(cfg, python, jest_bin, base_tree):
    return [cls(cfg, python, jest_bin, base_tree) for cls in (PytestAdapter, JestAdapter)]


def unsupported_paths(paths, adapters):
    owned = lambda p: any(a.owns(p) for a in adapters)
    return [p for p in sorted(paths) if not owned(p) and PurePosixPath(p).suffix in KNOWN_CODE_EXTENSIONS]
