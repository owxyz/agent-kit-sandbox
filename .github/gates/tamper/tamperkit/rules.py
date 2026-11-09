"""Diff rules, one per catalogue pattern. Modes come from rules.yml.

Each rule yields ``Hit`` tuples. "Fresh" lines are changed lines that were not
simply moved from elsewhere in the diff (see ``diffparse._mark_moved``).
"""
from __future__ import annotations

import posixpath
import re
from collections import Counter
from typing import Callable, Dict, Iterable, Iterator, List, NamedTuple, Optional, Tuple

from .diffparse import FileDiff, Hunk, Line
from .languages import Language, is_test_path, language_for, split_code


class Hit(NamedTuple):
    file: str
    line: int
    message: str


REGISTRY: Dict[str, Callable[["Context"], Iterable[Hit]]] = {}


def rule(name: str):
    def register(function):
        REGISTRY[name] = function
        return function
    return register


FIXTURE_PATH = re.compile(
    r"(^|/)(__snapshots__|__fixtures__|fixtures?|snapshots?|goldens?|testdata|test_data|cassettes)/|\.(snap|golden)$"
)
WORKFLOW_PATH = re.compile(r"(^|/)\.github/(workflows|actions|gates|agent-kit)/")
GENERATED_PATH = re.compile(r"\.min\.[cm]?js$|\.map$|(^|/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|uv\.lock)$")
REPORT_NAMES = {
    ".coverage", "coverage.xml", "coverage.json", "coverage-final.json", "coverage-summary.json",
    "lcov.info", "junit.xml", "test-results.xml", "cobertura.xml", "jacoco.xml", "nosetests.xml",
}
REPORT_DIR = re.compile(r"(^|/)(htmlcov|coverage|test-results|test-reports)/[^/]*\.(xml|json|html|info)$")
HARNESS_NAME = re.compile(
    r"^(conftest\.py|jest[.-]setup[^/]*|jest\.global[^/]*|setuptests\.[^/]*|vitest\.setup[^/]*|global-?(setup|teardown)\.[^/]*)$"
)
RUNNER_NAME = re.compile(
    r"^(pytest\.ini|tox\.ini|setup\.cfg|pyproject\.toml|package\.json|\.mocharc[^/]*|karma\.conf[^/]*"
    r"|(jest|vitest|playwright|cypress)\.(config|workspace)[^/]*)$"
)
TOOL_CONFIG_NAME = re.compile(
    r"^(\.coveragerc|pyproject\.toml|setup\.cfg|tox\.ini|mypy\.ini|\.mypy\.ini|pytest\.ini|\.flake8|ruff\.toml|\.ruff\.toml"
    r"|\.pylintrc|pylintrc|codecov\.ya?ml|\.codecov\.ya?ml|\.nycrc[^/]*|package\.json|tsconfig[^/]*\.json"
    r"|\.eslintrc[^/]*|eslint\.config[^/]*|(jest|vitest)\.config[^/]*|\.c8rc[^/]*|pyrightconfig\.json)$"
)
RUNNER_EXCLUDE = re.compile(
    r"--ignore(?:-glob)?\b|--deselect\b|\bnorecursedirs\b|\bcollect_ignore(?:_glob)?\b|-k\s+['\"]?not\b|\btestpaths\b"
    r"|\bpython_(?:files|functions|classes)\b|testPathIgnorePatterns|modulePathIgnorePatterns|\btestMatch\b|\btestRegex\b"
    r"|\btestIgnore\b|passWithNoTests|\|\|\s*true\b"
)
VITEST_EXCLUDE = re.compile(r"\bexclude\s*:")
RUNNER_HARNESS = re.compile(
    r"\bsetupFiles\w*|\bglobalSetup\b|\bglobalTeardown\b|\btestRunner\b|\breporters\b|\baddopts\b[^\n]*\s-p\s"
)
CONFIG_RETRY = re.compile(r"--reruns\b|--retries\b|\bretries\s*[:=][^\n]*[1-9]|\bretry\s*[:=]\s*[1-9]")
TIMEOUT_VALUE = re.compile(r"(?<![A-Za-z_.\-])([A-Za-z_.\-]*timeout[A-Za-z_\-]*)[\"']?\s*[:=(]\s*(\d[\d_]*(?:\.\d+)?)", re.IGNORECASE)
NEW_TIMEOUT_KEYS = re.compile(r"jest\.settimeout|testtimeout", re.IGNORECASE)
EXPECTED_ASSIGN = re.compile(r"^\s*(?:(?:const|let|var)\s+)?(?:expected|want|golden)\w*\s*(?::[^=]+)?=", re.IGNORECASE)
LITERAL = re.compile(r"\"[^\"]*\"|'[^']*'|`[^`]*`|\b\d+(?:\.\d+)?\b|\b(?:True|False|None|true|false|null|undefined)\b")
CONSTANT_RETURN = re.compile(r"^\{?\s*return\s+(?:True|False|true|false|1|0)\s*;?\s*\}?\s*$")
CONSTANT_HASH = re.compile(r"^\{?\s*return\s+(?:-?\d+|hash\(\s*(?:\"\"|''|-?\d+)\s*\))\s*;?\s*\}?\s*$")
THRESHOLD_VALUE = re.compile(r"(?<![\w.\-])[\"']?([A-Za-z_][\w.\-]*)[\"']?\s*[:=]\s*[\"']?(\d+(?:\.\d+)?)%?")
THRESHOLD_FLAG = re.compile(r"--(cov-fail-under|fail-under|max-warnings)[= ]\s*(\d+(?:\.\d+)?)")
HIGHER_IS_STRICTER = {"fail_under", "fail-under", "cov-fail-under", "branches", "lines", "functions", "statements", "target"}
LOWER_IS_STRICTER = {"max-complexity", "max_complexity", "max-warnings", "max_warnings", "threshold"}
STRICT_FLAG = re.compile(
    r"(?<!\w)[\"']?(strict\w*|noimplicit\w+|disallow_\w+|warn_unused_ignores|check_untyped_defs|no_implicit_optional|check-coverage)"
    r"[\"']?\s*[:=]\s*[\"']?(true|false)\b",
    re.IGNORECASE,
)
LINT_OFF = re.compile(r"[\"'][@\w/\-]+[\"']\s*:\s*(?:[\"'](?:off|warn)[\"']|[01]\b)")
LINT_DISABLE_KEY = re.compile(r"^\s*[\"']?(ignore|extend-ignore|per-file-ignores|disable|ignore_errors)[\"']?\s*[:=]")
COVERAGE_CONFIG_EXCLUDE = re.compile(
    r"\bexclude_(?:lines|also)\b|\bomit\b|\bpartial_branches\b|coveragePathIgnorePatterns|collectCoverageFrom[^\n]*!"
)
CONFIG_COMMENT = ("#", ";", "//")
RETRY_WINDOW = 15
# Caps keep per-line lookaround linear on a hostile hunk of many lines.
MAX_BODY_LINES = 200
MAX_GUARD_LOOKBACK = 400


class Context:
    def __init__(self, files: List[FileDiff], suppression_budget: int, max_line_chars: int):
        self.files = files
        self.suppression_budget = suppression_budget
        for diff in files:
            language = language_for(diff.path)
            for line in diff.lines():
                line.oversize = len(line.text) > max_line_chars
                text = line.text[:max_line_chars]
                line.code, line.comment = split_code(language, text) if language else (text, "")

    def code_files(self) -> Iterator[Tuple[FileDiff, Language]]:
        for diff in self.files:
            language = language_for(diff.path)
            if language:
                yield diff, language

    def test_files(self) -> Iterator[Tuple[FileDiff, Language]]:
        for diff, language in self.code_files():
            if is_test_path(diff.path):
                yield diff, language

    def changed_source_paths(self) -> List[str]:
        return [
            posixpath.splitext(diff.path.lower())[0]
            for diff, _ in self.code_files()
            if not is_test_path(diff.path) and not diff.is_deleted
        ]


def base_name(diff: FileDiff) -> str:
    return posixpath.basename(diff.path.lower())


def fresh(diff: FileDiff, kind: str = "+") -> Iterator[Tuple[Hunk, int, Line]]:
    for hunk in diff.hunks:
        for index, line in enumerate(hunk.lines):
            if line.kind == kind and not line.moved:
                yield hunk, index, line


def is_config_comment(line: Line) -> bool:
    return line.text.lstrip().startswith(CONFIG_COMMENT)


def config_text(diff: FileDiff, line: Line) -> str:
    """Return text for key matching: JS config keeps comments out but keys in."""
    if language_for(diff.path):
        return line.code
    return "" if is_config_comment(line) else line.text


def block_body(language: Language, hunk: Hunk, index: int) -> List[str]:
    """Return the code of the block opened on a line, as far as the hunk shows."""
    head = hunk.lines[index]
    following = [line for line in hunk.lines[index + 1:index + 1 + MAX_BODY_LINES] if line.kind != "-"]
    if language.block_style == "indent":
        tail = head.code.rsplit(":", 1)[-1] if ":" in head.code else ""
        body = [tail]
        margin = len(head.text) - len(head.text.lstrip())
        for line in following:
            if not line.text.strip():
                continue
            if len(line.text) - len(line.text.lstrip()) <= margin:
                break
            body.append(line.code)
        return [text for text in body if text.strip()]
    start = head.code.find("{")
    body = []
    depth = 0
    for code in [head.code[start:] if start >= 0 else ""] + [line.code for line in following]:
        depth += code.count("{") - code.count("}")
        body.append(code)
        if depth <= 0:
            break
    if body:
        body[0] = body[0][1:]
        if depth <= 0:
            body[-1] = body[-1].rsplit("}", 1)[0]
    return [text for text in body if text.strip()]


# Test and fixture edits


@rule("test-skipped")
def test_skipped(ctx: Context) -> Iterable[Hit]:
    for diff, language in ctx.test_files():
        for _, _, line in fresh(diff):
            if language.skip.search(line.code):
                yield Hit(diff.path, line.number, "New skip or focus marker in a test file")


def _test_names(ctx: Context, kind: str, include_moved: bool = False) -> Iterator[Tuple[FileDiff, Hunk, int, Line, str]]:
    for diff, language in ctx.test_files():
        for hunk in diff.hunks:
            for index, line in enumerate(hunk.lines):
                if line.kind != kind or (line.moved and not include_moved):
                    continue
                match = language.test_def.match(line.text) if line.code.strip() else None
                if match:
                    yield diff, hunk, index, line, match.group(match.lastindex)


def _is_rename(hunk: Hunk, index: int, added_defs: "set[int]") -> bool:
    """True if only the name changed: the body after the def line is untouched."""
    next_index = index + 1
    while next_index < len(hunk.lines) and hunk.lines[next_index].kind == "+":
        next_index += 1
    adjacent = any(index < position < next_index for position in added_defs)
    return adjacent and (next_index >= len(hunk.lines) or hunk.lines[next_index].kind == " ")


@rule("test-deleted")
def test_deleted(ctx: Context) -> Iterable[Hit]:
    added_positions = {}
    added_names = set()
    for _, hunk, index, _, name in _test_names(ctx, "+"):
        added_positions.setdefault(id(hunk), set()).add(index)
        added_names.add(name)
    for diff, hunk, index, line, name in _test_names(ctx, "-"):
        if name in added_names or _is_rename(hunk, index, added_positions.get(id(hunk), set())):
            continue
        yield Hit(diff.path, line.number, f"Test removed: {name}")


@rule("assertion-weakened")
def assertion_weakened(ctx: Context) -> Iterable[Hit]:
    for diff, language in ctx.test_files():
        for hunk in diff.hunks:
            removed, added = [], []
            for line in hunk.lines:
                if line.moved or line.kind == " " or not language.assertion.search(line.code):
                    continue
                if language.weak_assertion.search(line.code):
                    continue
                (removed if line.kind == "-" else added).append(line)
            if len(removed) > len(added):
                lost = len(removed) - len(added)
                yield Hit(diff.path, removed[0].number, f"{lost} strong assertion(s) removed or weakened in this hunk")
        for _, _, line in fresh(diff):
            if language.tautology.search(line.code):
                yield Hit(diff.path, line.number, "New assertion can never fail")


def _skeleton(text: str) -> str:
    return " ".join(LITERAL.sub("_", text).split())


@rule("expected-value-changed")
def expected_value_changed(ctx: Context) -> Iterable[Hit]:
    for diff, language in ctx.test_files():
        for hunk in diff.hunks:
            removed = Counter()
            for line in hunk.lines:
                if line.kind == "-" and not line.moved and _is_expectation(language, line):
                    removed[_skeleton(line.text)] += 1
            for line in hunk.lines:
                if line.kind != "+" or line.moved or not _is_expectation(language, line):
                    continue
                key = _skeleton(line.text)
                if removed[key] > 0:
                    removed[key] -= 1
                    yield Hit(diff.path, line.number, "Expected value changed in a test")


def _is_expectation(language: Language, line: Line) -> bool:
    return bool(
        language.assertion.search(line.code) or EXPECTED_ASSIGN.match(line.code) or "toMatchInlineSnapshot" in line.code
    )


@rule("fixture-or-snapshot-changed")
def fixture_or_snapshot_changed(ctx: Context) -> Iterable[Hit]:
    for diff in ctx.files:
        if not FIXTURE_PATH.search(diff.path.lower()):
            continue
        if diff.is_deleted or diff.binary or diff.has_removals:
            yield Hit(diff.path, 0, "Existing fixture, snapshot or golden file was changed or deleted")


@rule("xfail-added")
def xfail_added(ctx: Context) -> Iterable[Hit]:
    for diff, language in ctx.test_files():
        for _, _, line in fresh(diff):
            if language.xfail.search(line.code):
                yield Hit(diff.path, line.number, "New expected-failure marker")


@rule("timeout-raised")
def timeout_raised(ctx: Context) -> Iterable[Hit]:
    for diff in ctx.files:
        is_runner = bool(RUNNER_NAME.match(base_name(diff)))
        if not (is_runner or is_test_path(diff.path)):
            continue
        before = {}
        for line in diff.lines():
            if line.kind == "-":
                for key, value in TIMEOUT_VALUE.findall(config_text(diff, line)):
                    before.setdefault(key.lower(), float(value.replace("_", "")))
        for line in diff.lines():
            if line.kind != "+":
                continue
            for key, value in TIMEOUT_VALUE.findall(config_text(diff, line)):
                key, number = key.lower(), float(value.replace("_", ""))
                if key in before:
                    if number > before[key]:
                        yield Hit(diff.path, line.number, f"Timeout raised: {key} {before[key]:g} to {number:g}")
                elif is_runner or NEW_TIMEOUT_KEYS.search(key):
                    yield Hit(diff.path, line.number, f"New runner-wide timeout: {key} = {number:g}")


@rule("retry-added")
def retry_added(ctx: Context) -> Iterable[Hit]:
    for diff, language in ctx.test_files():
        for hunk, index, line in fresh(diff):
            if language.retry_marker.search(line.code):
                yield Hit(diff.path, line.number, "New retry or rerun marker in a test")
            elif language.loop.search(line.code):
                window = [item.code for item in hunk.lines[index + 1:index + 1 + 2 * RETRY_WINDOW] if item.kind == "+"][:RETRY_WINDOW]
                if any(language.assertion.search(code) for code in window) and any(
                    language.retry_signal.search(code) for code in window
                ):
                    yield Hit(diff.path, line.number, "New retry loop around an assertion")
    for diff in ctx.files:
        if RUNNER_NAME.match(base_name(diff)):
            for _, _, line in fresh(diff):
                if CONFIG_RETRY.search(config_text(diff, line)):
                    yield Hit(diff.path, line.number, "Test retries enabled in runner config")


# Error swallowing and over-mocking


@rule("broad-exception-handler")
def broad_exception_handler(ctx: Context) -> Iterable[Hit]:
    for diff, language in ctx.code_files():
        for hunk, index, line in fresh(diff):
            if language.always_swallows.search(line.code):
                yield Hit(diff.path, line.number, "New promise catch discards the error")
            elif language.broad_handler.search(line.code):
                if not any(language.rethrow.search(code) for code in block_body(language, hunk, index)):
                    yield Hit(diff.path, line.number, "New broad handler that does not re-raise")


def _mock_hits_changed_code(style: str, test_path: str, target: str, sources: List[str]) -> bool:
    if style == "dotted":
        parts = target.lower().split(".")
        candidates = {"/".join(parts[:count]) for count in range(1, len(parts) + 1)}
    else:
        spec = target.lower()
        if spec.startswith("."):
            spec = posixpath.normpath(posixpath.join(posixpath.dirname(test_path.lower()), spec))
        spec = spec[2:] if spec.startswith("@/") else spec
        candidates = {posixpath.splitext(spec)[0], spec}
    for source in sources:
        trimmed = source[: -len("/__init__")] if source.endswith("/__init__") else source
        trimmed = trimmed[: -len("/index")] if trimmed.endswith("/index") else trimmed
        if any(trimmed == item or trimmed.endswith("/" + item) for item in candidates):
            return True
    return False


@rule("mock-replaces-changed-code")
def mock_replaces_changed_code(ctx: Context) -> Iterable[Hit]:
    sources = ctx.changed_source_paths()
    for diff, language in ctx.test_files():
        for _, _, line in fresh(diff):
            if not line.code.strip():
                continue
            for match in language.mock_target.finditer(line.text):
                target = next(group for group in match.groups() if group)
                if _mock_hits_changed_code(language.mock_style, diff.path, target, sources):
                    yield Hit(diff.path, line.number, f"New mock replaces code this PR changes: {target}")


# Comparison tampering


def _equality_defs(diff: FileDiff, language: Language) -> Iterator[Tuple[Hunk, int, Line, "re.Match"]]:
    for hunk, index, line in fresh(diff):
        match = language.equality_def.match(line.code)
        if match:
            yield hunk, index, line, match


@rule("equality-always-true")
def equality_always_true(ctx: Context) -> Iterable[Hit]:
    for diff, language in ctx.code_files():
        for _, _, line in fresh(diff):
            if language.equality_direct.match(line.code):
                yield Hit(diff.path, line.number, "Equality or hash replaced by a lambda")
        for hunk, index, line, match in _equality_defs(diff, language):
            method, parameter = match.group(1), match.group(2)
            body = block_body(language, hunk, index)
            if not body:
                continue
            first = body[0].strip()
            if method in ("__hash__", "hashCode"):
                if CONSTANT_HASH.match(first):
                    yield Hit(diff.path, line.number, f"{method} returns a constant")
            elif CONSTANT_RETURN.match(first) or (
                parameter and not any(re.search(rf"\b{re.escape(parameter)}\b", code) for code in body)
            ):
                yield Hit(diff.path, line.number, f"{method} ignores its argument or returns a constant")


@rule("equality-override-new")
def equality_override_new(ctx: Context) -> Iterable[Hit]:
    for diff, language in ctx.code_files():
        if is_test_path(diff.path):
            continue
        for _, _, line, match in _equality_defs(diff, language):
            yield Hit(diff.path, line.number, f"New {match.group(1)} override in non-test code")


@rule("module-level-mutable-state")
def module_level_mutable_state(ctx: Context) -> Iterable[Hit]:
    for diff, language in ctx.code_files():
        if is_test_path(diff.path) or diff.path.lower().endswith(".d.ts"):
            continue
        for _, _, line in fresh(diff):
            if language.module_state.search(line.code):
                yield Hit(diff.path, line.number, "New module-level mutable state in non-test code")


# Harness and runtime tampering


@rule("harness-file-changed")
def harness_file_changed(ctx: Context) -> Iterable[Hit]:
    for diff in ctx.files:
        if HARNESS_NAME.match(base_name(diff)):
            yield Hit(diff.path, 0, "Test harness file changed")
            continue
        language = language_for(diff.path)
        for _, _, line in fresh(diff):
            if language and language.harness_hook.search(line.code):
                yield Hit(diff.path, line.number, "New pytest hook")
            elif RUNNER_NAME.match(base_name(diff)) and RUNNER_HARNESS.search(config_text(diff, line)):
                yield Hit(diff.path, line.number, "Runner setup, reporter or plugin changed")


@rule("test-function-patched")
def test_function_patched(ctx: Context) -> Iterable[Hit]:
    for diff, language in ctx.code_files():
        for _, _, line in fresh(diff):
            if language.patch.search(line.code) or (line.code.strip() and language.patch_text.search(line.text)):
                yield Hit(diff.path, line.number, "Test or assertion function is being replaced")


@rule("early-exit")
def early_exit(ctx: Context) -> Iterable[Hit]:
    for diff, language in ctx.code_files():
        if language.exit_exempt_path.search(diff.path.lower()) and not is_test_path(diff.path):
            continue
        for hunk, index, line in fresh(diff):
            if not (
                language.early_exit.search(line.code)
                or (line.code.strip() and language.early_exit_text.search(line.text))
            ):
                continue
            guarded = language.exit_guard.search(hunk.section) or any(
                language.exit_guard.search(item.text) for item in hunk.lines[max(0, index - MAX_GUARD_LOOKBACK): index + 1] if item.kind != "-"
            )
            if not guarded:
                yield Hit(diff.path, line.number, "New process exit or exit hook")


@rule("timer-override")
def timer_override(ctx: Context) -> Iterable[Hit]:
    for diff, language in ctx.code_files():
        production = not is_test_path(diff.path)
        for _, _, line in fresh(diff):
            if language.timer_hard.search(line.code) or (production and language.timer_soft.search(line.code)):
                yield Hit(diff.path, line.number, "Clock or timer is being overridden")


@rule("runner-config-excludes")
def runner_config_excludes(ctx: Context) -> Iterable[Hit]:
    for diff in ctx.files:
        name = base_name(diff)
        is_runner = bool(RUNNER_NAME.match(name))
        if not (is_runner or name == "conftest.py"):
            continue
        for _, _, line in fresh(diff):
            text = line.text if not is_config_comment(line) else ""
            if RUNNER_EXCLUDE.search(text) or (
                name.startswith(("vitest.", "playwright.")) and VITEST_EXCLUDE.search(text)
            ):
                yield Hit(diff.path, line.number, "Runner config now excludes or narrows tests")


# Quality-gate suppression


def _suppression_count(ctx: Context, kind: str, tally: Counter) -> Tuple[int, Optional[Hit]]:
    total, first = 0, None
    for diff, language in ctx.code_files():
        typed = diff.path.lower().endswith(language.typed_extensions) if language.typed_extensions else False
        for line in diff.lines():
            if line.kind != kind:
                continue
            found = language.suppressions.findall(line.comment)
            if typed and not language.typed_skip_line.search(line.code):
                found += language.typed_suppressions.findall(line.code)
            if found:
                total += len(found)
                if kind == "+":
                    tally.update(" ".join(item.split()) for item in found if isinstance(item, str))
                    first = first or Hit(diff.path, line.number, "")
    return total, first


@rule("suppression-budget")
def suppression_budget(ctx: Context) -> Iterable[Hit]:
    tally: Counter = Counter()
    added, first = _suppression_count(ctx, "+", tally)
    removed, _ = _suppression_count(ctx, "-", Counter())
    delta = added - removed
    if delta > ctx.suppression_budget and first:
        top = ", ".join(f"{name} x{count}" for name, count in tally.most_common(5))
        yield Hit(first.file, first.line, f"Suppressions grew by {delta}; budget is {ctx.suppression_budget} ({top})")


def _values(text: str) -> Iterator[Tuple[str, float]]:
    for key, value in THRESHOLD_VALUE.findall(text) + THRESHOLD_FLAG.findall(text):
        yield key.lower(), float(value)


@rule("threshold-lowered")
def threshold_lowered(ctx: Context) -> Iterable[Hit]:
    for diff in ctx.files:
        name = base_name(diff)
        if not TOOL_CONFIG_NAME.match(name):
            continue
        old_values, new_keys, old_flags = {}, set(), {}
        for line in diff.lines():
            text = config_text(diff, line)
            if line.kind == "-":
                old_values.update(_values(text))
                old_flags.update((key.lower(), value.lower()) for key, value in STRICT_FLAG.findall(text))
            elif line.kind == "+":
                new_keys.update(key for key, _ in _values(text))
        removed_line = {}
        for line in diff.lines():
            text = config_text(diff, line)
            if line.kind == "-":
                for key, _ in _values(text):
                    removed_line.setdefault(key, line.number)
            elif line.kind == "+" and not line.moved:
                for key, value in _values(text):
                    if key in old_values and (
                        (key in HIGHER_IS_STRICTER and value < old_values[key])
                        or (key in LOWER_IS_STRICTER and value > old_values[key])
                    ):
                        yield Hit(diff.path, line.number, f"Threshold loosened: {key} {old_values[key]:g} to {value:g}")
                for key, value in STRICT_FLAG.findall(text):
                    if value.lower() == "false" and old_flags.get(key.lower()) == "true":
                        yield Hit(diff.path, line.number, f"Strictness turned off: {key}")
                if LINT_OFF.search(text) and name.startswith((".eslintrc", "eslint.config")):
                    yield Hit(diff.path, line.number, "Lint rule turned off or downgraded")
                if LINT_DISABLE_KEY.match(text):
                    yield Hit(diff.path, line.number, "Tool config now ignores or disables checks")
        for key, number in removed_line.items():
            if key in HIGHER_IS_STRICTER and key not in new_keys:
                yield Hit(diff.path, number, f"Threshold removed: {key}")


@rule("coverage-exclusion")
def coverage_exclusion(ctx: Context) -> Iterable[Hit]:
    for diff, language in ctx.code_files():
        for _, _, line in fresh(diff):
            if language.coverage_comment.search(line.comment):
                yield Hit(diff.path, line.number, "New coverage-exclusion comment (needs owner approval, P2.3)")
    for diff in ctx.files:
        if TOOL_CONFIG_NAME.match(base_name(diff)):
            for _, _, line in fresh(diff):
                if not is_config_comment(line) and COVERAGE_CONFIG_EXCLUDE.search(line.text):
                    yield Hit(diff.path, line.number, "Coverage config now excludes code")


@rule("test-count-drop")
def test_count_drop(ctx: Context) -> Iterable[Hit]:
    removed = list(_test_names(ctx, "-", include_moved=True))
    added = list(_test_names(ctx, "+", include_moved=True))
    if len(removed) > len(added):
        diff, _, _, line, _ = removed[0]
        yield Hit(diff.path, line.number, f"Test count drops by {len(removed) - len(added)}")


# Check bypass and fake completion


@rule("ci-workflow-changed")
def ci_workflow_changed(ctx: Context) -> Iterable[Hit]:
    for diff in ctx.files:
        if not WORKFLOW_PATH.search(diff.path.lower()):
            continue
        risky = [line for _, _, line in fresh(diff) if re.search(r"continue-on-error\s*:\s*true|^\s*if\s*:\s*false", line.text)]
        if risky:
            for line in risky:
                yield Hit(diff.path, line.number, "Workflow step can no longer fail the check")
        else:
            yield Hit(diff.path, 0, "CI workflow or gate code changed")


@rule("report-artifact-committed")
def report_artifact_committed(ctx: Context) -> Iterable[Hit]:
    for diff in ctx.files:
        if diff.is_deleted:
            continue
        if base_name(diff) in REPORT_NAMES or REPORT_DIR.search(diff.path.lower()):
            yield Hit(diff.path, 0, "Coverage or test report committed; CI ignores agent-supplied reports")


# Engine safety


@rule("unscannable-input")
def unscannable_input(ctx: Context) -> Iterable[Hit]:
    for diff in ctx.files:
        lower = diff.path.lower()
        if GENERATED_PATH.search(lower):
            continue
        is_scanned = language_for(diff.path) or RUNNER_NAME.match(base_name(diff)) or TOOL_CONFIG_NAME.match(base_name(diff))
        if diff.binary and is_scanned:
            yield Hit(diff.path, 0, "Binary change in a code or config file could not be scanned")
            continue
        if is_scanned:
            for line in diff.lines():
                if line.kind == "+" and line.oversize:
                    yield Hit(diff.path, line.number, "Line too long to scan fully")
