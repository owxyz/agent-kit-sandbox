"""Locate error-handling code. Python uses the AST; JS/TS uses a comment- and string-aware scan."""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass

END = 10 ** 9


@dataclass
class ErrorSite:
    kind: str
    line: int
    span: tuple  # (first line, last line); the site counts as changed if a changed line is inside
    probe: tuple  # ((line, col), (line, col)); an instrumented statement inside proves execution


ERR_NAME = re.compile(r"(^|_)(e|err|error|errors|exc|exception|failure)($|_)", re.I)
ERR_TYPE = re.compile(r"(Error|Exception|Failure)$|^Err$")


def _looks_like_error(node):
    if isinstance(node, ast.Name):
        return bool(ERR_NAME.search(node.id))
    if isinstance(node, ast.Attribute):
        return bool(ERR_NAME.search(node.attr))
    if isinstance(node, ast.Call):
        func = node.func
        name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
        return bool(ERR_TYPE.search(name))
    if isinstance(node, ast.Tuple):
        return any(_looks_like_error(item) for item in node.elts)
    if isinstance(node, ast.Dict):
        return any(isinstance(k, ast.Constant) and isinstance(k.value, str) and ERR_NAME.search(k.value)
                   for k in node.keys)
    return False


def _line_probe(line):
    return ((line, 0), (line, END))


def python_sites(source):
    sites = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.ExceptHandler):
            first = node.body[0].lineno
            sites.append(ErrorSite("except", node.lineno, (node.lineno, node.end_lineno), _line_probe(first)))
        elif isinstance(node, ast.Raise):
            sites.append(ErrorSite("raise", node.lineno, (node.lineno, node.end_lineno), _line_probe(node.lineno)))
        elif isinstance(node, ast.Return) and node.value is not None and _looks_like_error(node.value):
            sites.append(ErrorSite("error-return", node.lineno, (node.lineno, node.end_lineno),
                                   _line_probe(node.lineno)))
    return sites


def blank_noncode(source):
    """Blank comments and string contents, keeping every offset and newline."""
    out, i, n = list(source), 0, len(source)

    def blank(start, end):
        for k in range(start, min(end, n)):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        ch, pair = source[i], source[i:i + 2]
        if pair == "//":
            end = source.find("\n", i)
            end = n if end < 0 else end
            blank(i, end)
            i = end
        elif pair == "/*":
            end = source.find("*/", i + 2)
            end = n if end < 0 else end + 2
            blank(i, end)
            i = end
        elif ch in "'\"`":
            j = i + 1
            while j < n and source[j] != ch and (ch == "`" or source[j] != "\n"):
                j += 2 if source[j] == "\\" else 1
            blank(i + 1, j)
            i = j + 1
        else:
            i += 1
    return "".join(out)


def _match_close(code, open_index):
    pairs = {"{": "}", "(": ")"}
    opener, closer, depth = code[open_index], pairs[code[open_index]], 0
    for k in range(open_index, len(code)):
        if code[k] == opener:
            depth += 1
        elif code[k] == closer:
            depth -= 1
            if depth == 0:
                return k
    return len(code) - 1


def _position(code):
    starts = [0]
    for index, ch in enumerate(code):
        if ch == "\n":
            starts.append(index + 1)

    def to_pos(offset):
        low, high = 0, len(starts) - 1
        while low < high:
            mid = (low + high + 1) // 2
            if starts[mid] <= offset:
                low = mid
            else:
                high = mid - 1
        return (low + 1, offset - starts[low])

    return to_pos


CATCH_BLOCK = re.compile(r"(?<![.\w$])catch\s*(?:\([^)]*\)\s*)?\{")
CATCH_CALL = re.compile(r"\.catch\s*\(")
THROW = re.compile(r"(?<![.\w$])throw\b")
ERR_RETURN = re.compile(
    r"(?<![.\w$])return\s+(?:new\s+\w*Error\b|Promise\s*\.\s*reject\b|(?:err|error|e)\b(?!\s*[.(=])"
    r"|\{\s*(?:err|error)\b|\[\s*(?:null|undefined)\s*,\s*(?:err|error|e)\b)")
ERR_CALL = re.compile(r"(?<![.\w$])(?:reject|(?:cb|callback|next|done)(?=\s*\(\s*(?:err|error|e)\b))\s*\(")


def js_sites(source):
    code, sites = blank_noncode(source), []
    to_pos = _position(code)
    for match in CATCH_BLOCK.finditer(code):
        close = _match_close(code, match.end() - 1)
        start, end = to_pos(match.start()), to_pos(close)
        sites.append(ErrorSite("catch", start[0], (start[0], end[0]), (to_pos(match.end()), end)))
    for match in CATCH_CALL.finditer(code):
        close = _match_close(code, match.end() - 1)
        start, end = to_pos(match.start()), to_pos(close)
        sites.append(ErrorSite("catch", start[0], (start[0], end[0]), (to_pos(match.end()), end)))
    for pattern, kind in ((THROW, "throw"), (ERR_RETURN, "error-return")):
        for match in pattern.finditer(code):
            pos = to_pos(match.start())
            sites.append(ErrorSite(kind, pos[0], (pos[0], pos[0]), (pos, pos)))
    for match in ERR_CALL.finditer(code):
        pos = to_pos(match.start())
        before = code[max(0, match.start() - 7):match.start()]
        first = (pos[0], pos[1] - 7) if before == "return " else pos
        sites.append(ErrorSite("error-call", pos[0], (pos[0], pos[0]), (first, pos)))
    return sites


def inside(point, probe):
    return probe[0] <= point <= probe[1]
