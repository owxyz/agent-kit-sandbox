"""Per-language pattern tables.

To add a language, append a ``Language`` to ``LANGUAGES`` and add cases for it
in ``tests/cases.py``. Rules read these tables and hold no language syntax of
their own. Patterns run line by line and must stay free of nested quantifiers,
because they run on untrusted text.
"""
from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass
from typing import Optional, Pattern, Sequence, Tuple


def _rx(*alternatives: str) -> Pattern:
    return re.compile("|".join(f"(?:{alt})" for alt in alternatives))


NEVER = re.compile(r"(?!)")


@dataclass(frozen=True)
class Language:
    name: str
    extensions: Tuple[str, ...]
    quotes: str
    line_comment: str
    block_comment: bool
    block_style: str  # "indent" or "brace"
    test_path: Pattern
    test_def: Pattern  # run on raw text; last group is the test name
    skip: Pattern
    xfail: Pattern
    retry_marker: Pattern
    assertion: Pattern
    weak_assertion: Pattern
    tautology: Pattern
    loop: Pattern
    retry_signal: Pattern
    broad_handler: Pattern
    rethrow: Pattern
    always_swallows: Pattern
    module_state: Pattern
    equality_def: Pattern  # groups: method name, first non-self parameter
    equality_direct: Pattern
    patch: Pattern
    patch_text: Pattern
    early_exit: Pattern
    early_exit_text: Pattern
    exit_guard: Pattern
    exit_exempt_path: Pattern
    timer_hard: Pattern
    timer_soft: Pattern
    harness_hook: Pattern
    suppressions: Pattern
    typed_extensions: Tuple[str, ...]
    typed_suppressions: Pattern
    typed_skip_line: Pattern
    coverage_comment: Pattern
    mock_target: Pattern
    mock_style: str  # "dotted" or "path"


PYTHON = Language(
    name="python",
    extensions=(".py", ".pyi"),
    quotes="'\"",
    line_comment="#",
    block_comment=False,
    block_style="indent",
    test_path=_rx(r"(^|/)(tests?|testing)/", r"(^|/)test_[^/]*\.pyi?$", r"_test\.pyi?$", r"(^|/)conftest\.py$"),
    test_def=re.compile(r"^\s*(?:async\s+)?def\s+(test\w*)\s*\("),
    skip=_rx(
        r"@(?:pytest\.mark\.)?skip(?:if)?\b", r"@unittest\.skip\w*", r"\bpytest\.skip\s*\(",
        r"\bself\.skipTest\s*\(", r"\bpytest\.importorskip\s*\(",
    ),
    xfail=_rx(r"@pytest\.mark\.xfail\b", r"\bpytest\.xfail\s*\(", r"@(?:unittest\.)?expectedFailure\b"),
    retry_marker=_rx(
        r"@(?:pytest\.mark\.)?flaky\b", r"@(?:tenacity\.|retrying\.)?retry\b", r"@backoff\.on_\w+",
        r"\breruns\s*=", r"@pytest\.mark\.rerun\w*", r"\bpytest_rerunfailures\b",
    ),
    assertion=_rx(r"^\s*assert\b", r"\bself\.assert\w+\s*\(", r"\bpytest\.raises\s*\(", r"\bself\.fail\s*\("),
    weak_assertion=_rx(
        r"^\s*assert\s+[\w.]+(?:\([^()]*\))?\s*$", r"^\s*assert\s.*\bis not None\s*$",
        r"\bself\.assert(?:True|IsNotNone|IsNot)\s*\(",
    ),
    tautology=_rx(
        r"^\s*assert\s+(?:True|1)\s*(?:$|,)", r"^\s*assert\s+(\w+)\s*==\s*\1\s*$",
        r"\bself\.assertTrue\s*\(\s*(?:True|1)\s*\)", r"^\s*assert\s+1\s*==\s*1\b",
    ),
    loop=re.compile(r"^\s*(?:for|while)\b"),
    retry_signal=re.compile(r"\bexcept\b|\bcontinue\b|\bsleep\s*\(|\bretry\b"),
    broad_handler=_rx(
        r"^\s*except\s*:", r"^\s*except\b[^:]*\b(?:Exception|BaseException|AssertionError)\b[^:]*:",
        r"\bsuppress\s*\(\s*(?:Exception|BaseException)\b",
    ),
    rethrow=re.compile(r"\braise\b"),
    always_swallows=NEVER,
    module_state=_rx(
        r"^(?!__all__\b)[A-Za-z_]\w*\s*(?::[^=]+)?=\s*(?:\[\s*\]|\{\s*\}|(?:set|dict|list)\(\s*\)"
        r"|(?:collections\.)?(?:defaultdict|deque|Counter|OrderedDict)\(.*\))\s*$",
        r"^\s+global\s+\w+",
    ),
    equality_def=re.compile(r"^\s*(?:async\s+)?def\s+(__eq__|__ne__|__hash__)\s*\(\s*\w+\s*(?:,\s*(\w+))?"),
    equality_direct=re.compile(r"^\s*__(?:eq|ne|hash)__\s*=\s*lambda\b"),
    patch=_rx(
        r"\b(?:unittest\.)?TestCase\.\w+\s*=(?![=>])", r"\bself\.(?:assert\w+|fail|skipTest)\s*=(?![=>])",
        r"\b_?pytest(?:\.\w+)+\s*=(?![=>])", r"\bsetattr\s*\(\s*(?:unittest|_?pytest|TestCase|builtins)\b",
        r"\bmonkeypatch\.setattr\s*\(\s*(?:unittest|_?pytest|TestCase)\b", r"\bbuiltins\.\w+\s*=(?![=>])",
    ),
    patch_text=_rx(
        r"\bsys\.modules\s*\[\s*['\"](?:_?pytest|unittest)", r"\bpatch\s*\(\s*['\"](?:_?pytest|unittest)\.",
        r"\bmonkeypatch\.setattr\s*\(\s*['\"](?:_?pytest|unittest)\.",
    ),
    early_exit=_rx(
        r"\b(?:sys\.exit|os\._exit|os\.abort|pytest\.exit)\s*\(", r"(?<![\w.])(?:exit|quit)\s*\(",
        r"\batexit\.register\b",
    ),
    early_exit_text=NEVER,
    exit_guard=re.compile(r"\bif\s+__name__\s*==\s*['\"]__main__['\"]"),
    exit_exempt_path=_rx(r"(^|/)__main__\.py$", r"(^|/)(bin|cli|scripts|examples?)/", r"(^|/)cli\.py$"),
    timer_hard=_rx(
        r"\btime\.(?:time|sleep|monotonic|perf_counter|process_time)\s*=(?![=>])",
        r"\b(?:datetime|date)\.(?:now|utcnow|today)\s*=(?![=>])", r"\bsetattr\s*\(\s*(?:time|datetime)\b",
    ),
    timer_soft=_rx(r"\bfreeze_time\b", r"\bfreezegun\b", r"\btime_machine\b", r"\bmonkeypatch\.setattr\s*\(\s*time\b"),
    harness_hook=re.compile(
        r"^\s*def\s+pytest_(?:runtest_\w+|collection_\w+|configure|sessionstart|sessionfinish|assertrepr_compare|ignore_collect)\b"
    ),
    suppressions=re.compile(r"\bnoqa\b|\btype:\s*ignore\b|\bpylint:\s*disable\b|\bnosec\b|\bpyright:\s*ignore\b"),
    typed_extensions=(),
    typed_suppressions=NEVER,
    typed_skip_line=NEVER,
    coverage_comment=re.compile(r"\bpragma:\s*no\s*(?:cover|branch)\b"),
    mock_target=_rx(
        r"\bpatch\s*\(\s*['\"]([\w.]+)['\"]", r"\bpatch\.object\s*\(\s*([\w.]+)",
        r"\bmonkeypatch\.setattr\s*\(\s*['\"]([\w.]+)['\"]",
    ),
    mock_style="dotted",
)

JAVASCRIPT = Language(
    name="javascript",
    extensions=(".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"),
    quotes="'\"`",
    line_comment="//",
    block_comment=True,
    block_style="brace",
    test_path=_rx(r"(^|/)(__tests__|tests?|e2e|cypress|spec)/", r"\.(test|spec|cy)\.[cm]?[jt]sx?$"),
    test_def=re.compile(r"^\s*(?:it|test|specify)(?:\.\w+)*\s*\(\s*['\"`]([^'\"`]*)['\"`]"),
    skip=_rx(
        r"\b(?:it|test|describe|context|specify)\.skip\b", r"(?<![\w.])x(?:it|test|describe|context|specify)\s*\(",
        r"\b(?:it|test|describe|context|specify)\.only\b", r"(?<![\w.])f(?:it|describe)\s*\(",
    ),
    xfail=_rx(r"\b(?:it|test)\.failing\b", r"\btest\.fixme\b", r"\btest\.fail\s*\("),
    retry_marker=_rx(r"\bjest\.retryTimes\s*\(", r"\.retries\s*\(", r"\bretry\s*:\s*[1-9]", r"\bretries\s*:\s*[1-9]"),
    assertion=_rx(r"\bexpect\s*\(", r"(?<![\w.])assert\s*[.(]", r"\.should\b"),
    weak_assertion=_rx(
        r"\.toBeDefined\s*\(", r"\.toBeTruthy\s*\(", r"\.not\.toBeNull\s*\(", r"\.not\.toBeUndefined\s*\(",
        r"(?<![\w.])assert\s*\(", r"\bassert\.ok\s*\(",
    ),
    tautology=_rx(
        r"\bexpect\s*\(\s*(true|1)\s*\)\s*\.\s*to(?:Be|Equal|StrictEqual)\s*\(\s*\1\s*\)",
        r"\bexpect\s*\(\s*true\s*\)\s*\.\s*toBeTruthy\s*\(", r"(?<![\w.])assert(?:\.ok)?\s*\(\s*true\s*\)",
    ),
    loop=re.compile(r"^\s*(?:for|while)\s*\(|^\s*do\s*\{"),
    retry_signal=re.compile(r"(?<!\.)\bcatch\b|\bcontinue\b|\bsleep\s*\(|\bsetTimeout\s*\(|\bretry\b"),
    broad_handler=re.compile(r"\bcatch\s*(?:\([^)]{0,200}\))?\s*\{"),
    rethrow=re.compile(r"\bthrow\b|\breject\s*\(|\bnext\s*\(\s*\w"),
    always_swallows=re.compile(r"\.catch\s*\(\s*(?:\(\s*\w*\s*\)|\w+)\s*=>\s*(?:\{\s*\}|null\b|undefined\b)"),
    module_state=_rx(
        r"^(?:export\s+)?let\s+[\w$]+(?![\w$])(?!\s*=\s*require\b)",
        # Older code uses `var` for imports and aliases, so only state-like starts count.
        r"^(?:export\s+)?var\s+[\w$]+(?![\w$])\s*(?:;|,|$|=\s*(?:-?\d|true\b|false\b|null\b|undefined\b|\[\s*\]|\{\s*\}"
        r"|new\s+(?:Map|Set|WeakMap|WeakSet|Array)\b))",
        r"^(?:export\s+)?const\s+[\w$]+\s*(?::[^=]+)?=\s*(?:\[\s*\]|\{\s*\}|new\s+(?:Map|Set|WeakMap|WeakSet|Array)\b)",
    ),
    equality_def=re.compile(
        r"^\s*(?:public\s+|static\s+)*(equals|isEqual|hashCode|asymmetricMatch)\s*\(\s*([\w$]*)[^)]*\)\s*(?::[^{]+)?\{"
    ),
    equality_direct=NEVER,
    patch=_rx(
        r"\b(?:global|globalThis|window)\.(?:expect|it|test|describe|assert|beforeEach|afterEach)\s*=(?![=>])",
        r"(?<![\w.$])expect(?:\.\w+)*\s*=(?![=>])", r"(?<![\w.$])assert\.\w+\s*=(?![=>])",
    ),
    patch_text=_rx(
        r"\bObject\.defineProperty\s*\(\s*(?:global|globalThis|window)\s*,\s*['\"](?:expect|it|test|describe)['\"]",
        r"\bjest\.spyOn\s*\(\s*(?:global|globalThis)\s*,\s*['\"](?:expect|it|test)['\"]",
        r"\brequire\s*\(\s*['\"](?:node:)?assert['\"]\s*\)\.\w+\s*=(?![=>])",
    ),
    early_exit=_rx(r"\bprocess\.(?:exit|abort|reallyExit)\s*\(", r"\bprocess\.kill\s*\(\s*process\.pid\b"),
    early_exit_text=re.compile(r"\bprocess\.(?:on|once)\s*\(\s*['\"](?:exit|beforeExit)['\"]"),
    exit_guard=re.compile(r"\brequire\.main\s*===?\s*module\b"),
    exit_exempt_path=_rx(r"(^|/)(bin|cli|scripts|examples?)/", r"(^|/)cli\.[cm]?[jt]s$"),
    timer_hard=_rx(
        r"\bDate\.now\s*=(?![=>])", r"\bperformance\.now\s*=(?![=>])",
        r"\b(?:global|globalThis|window)\.(?:Date|setTimeout|setInterval|clearTimeout|performance)\s*=(?![=>])",
        r"(?<![\w.$])Date\s*=(?![=>])",
    ),
    timer_soft=re.compile(r"\buseFakeTimers\b|\bmockdate\b|\bMockDate\b"),
    harness_hook=NEVER,
    suppressions=re.compile(r"\beslint-disable|@ts-ignore\b|@ts-expect-error\b|@ts-nocheck\b|\bbiome-ignore\b|\bStryker\s+disable\b"),
    typed_extensions=(".ts", ".tsx", ".mts", ".cts"),
    typed_suppressions=_rx(
        r":\s*any\b", r"\bas\s+any\b", r"<any>", r"\bas\s+unknown\s+as\b", r"\bas\s+(?!const\b)[A-Z]\w*",
        r"[\w)\]]!\s*(?:\.|\[|;|,|\))",
    ),
    typed_skip_line=re.compile(r"^\s*(?:import|export\s*\{)"),
    coverage_comment=re.compile(r"\b(?:istanbul|c8|v8)\s+ignore\b|\bnode:coverage\s+(?:disable|ignore)\b"),
    mock_target=re.compile(r"\b(?:jest|vi)\.(?:mock|doMock|unstable_mockModule)\s*\(\s*['\"`]([^'\"`]+)['\"`]"),
    mock_style="path",
)

LANGUAGES: Sequence[Language] = (PYTHON, JAVASCRIPT)


def language_for(path: str) -> Optional[Language]:
    extension = posixpath.splitext(path.lower())[1]
    for language in LANGUAGES:
        if extension in language.extensions:
            return language
    return None


def is_test_path(path: str) -> bool:
    language = language_for(path)
    return bool(language and language.test_path.search(path.lower()))


def split_code(language: Language, text: str) -> Tuple[str, str]:
    """Return ``(code, comment)``, with string contents blanked in ``code``.

    Works one line at a time and does not track multi-line strings, so a
    docstring line that looks like code may be flagged. Erring that way keeps
    an attacker from hiding code by opening a string on an earlier line.
    """
    if language.block_comment and text.lstrip().startswith("*"):
        return "", text
    code = []
    comment = []
    quote = None
    i = 0
    while i < len(text):
        char = text[i]
        if quote:
            if char == "\\":
                i += 2
                continue
            if char == quote:
                quote = None
                code.append(char)
            i += 1
            continue
        if language.block_comment and text.startswith("/*", i):
            end = text.find("*/", i + 2)
            stop = len(text) if end < 0 else end
            comment.append(text[i + 2:stop])
            i = len(text) if end < 0 else end + 2
            continue
        if text.startswith(language.line_comment, i):
            comment.append(text[i + len(language.line_comment):])
            break
        if char in language.quotes:
            quote = char
        code.append(char)
        i += 1
    return "".join(code), " ".join(comment)
