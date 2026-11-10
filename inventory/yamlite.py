"""A small, dependency-free YAML reader for workflows and the register files.

It covers the YAML that GitHub Actions workflows use: block maps and sequences,
flow collections, quoted, plain and block scalars, comments, anchors and
aliases. Anything else raises YamlError instead of being guessed at.

Scalars follow YAML 1.2 core rules, so `on` stays the string "on" and dates
stay strings. Error messages carry a line number and a reason, never the text
of the line, so a credential pasted into a file cannot leak through an error.
"""
import re

__all__ = ["YamlError", "load"]

_INT = re.compile(r"^[-+]?[0-9]+$")
_FLOAT = re.compile(r"^[-+]?([0-9]+\.[0-9]*|\.[0-9]+)([eE][-+]?[0-9]+)?$")
_BLOCK_HEADER = re.compile(r"^[|>]([+-]?[1-9]?|[1-9][+-])$")
_ESCAPES = {
    "0": "\0", "a": "\a", "b": "\b", "t": "\t", "\t": "\t", "n": "\n",
    "v": "\v", "f": "\f", "r": "\r", "e": "\x1b", " ": " ", '"': '"',
    "/": "/", "\\": "\\",
}


class YamlError(ValueError):
    def __init__(self, line, reason):
        super().__init__("line {}: {}".format(line, reason))
        self.line = line
        self.reason = reason


class _Incomplete(Exception):
    """A flow collection continues on the next line."""


def load(text):
    """Parse one YAML document and return plain Python values."""
    return _Parser(text).parse()


def _scalar(text):
    if text in ("", "~", "null", "Null", "NULL"):
        return None
    if text in ("true", "True", "TRUE"):
        return True
    if text in ("false", "False", "FALSE"):
        return False
    if _INT.match(text):
        return int(text)
    if _FLOAT.match(text):
        return float(text)
    return text


def _quote_end(text, start=0):
    """Index of the quote closing the one at `start`, or -1."""
    quote = text[start]
    i = start + 1
    while i < len(text):
        c = text[i]
        if quote == '"' and c == "\\":
            i += 2
            continue
        if c == quote:
            if quote == "'" and text[i + 1:i + 2] == "'":
                i += 2
                continue
            return i
        i += 1
    return -1


def _unquote(text, line):
    if text[0] == "'":
        return text[1:-1].replace("''", "'")
    body = text[1:-1]
    out = []
    i = 0
    while i < len(body):
        c = body[i]
        if c != "\\":
            out.append(c)
            i += 1
            continue
        esc = body[i + 1:i + 2]
        width = {"x": 2, "u": 4, "U": 8}.get(esc)
        if width:
            digits = body[i + 2:i + 2 + width]
            try:
                out.append(chr(int(digits, 16)))
            except ValueError:
                raise YamlError(line, "invalid escape in double-quoted string")
            i += 2 + width
        elif esc in _ESCAPES and esc:
            out.append(_ESCAPES[esc])
            i += 2
        else:
            raise YamlError(line, "invalid escape in double-quoted string")
    return "".join(out)


def _strip_comment(text):
    if not text:
        return text
    if text[0] in "\"'":
        end = _quote_end(text)
        if end < 0:
            return text
        rest = text[end + 1:]
        match = re.search(r"\s#", rest)
        return text[: end + 1 + match.start()] if match else text
    quote = None
    flow = text[0] in "[{"
    i = 0
    while i < len(text):
        c = text[i]
        if quote:
            if c == quote:
                quote = None
        elif flow and c in "\"'":
            quote = c
        elif c == "#" and (i == 0 or text[i - 1] in " \t"):
            return text[:i].rstrip()
        i += 1
    return text


def _is_document_marker(stripped):
    return stripped == "..." or stripped == "---" or stripped.startswith("--- ")


def _is_dash(stripped):
    return stripped == "-" or stripped.startswith("- ")


def _split_key(stripped, line):
    """Return (key, remainder) when the line is `key: ...`, otherwise None."""
    first = stripped[0]
    if first in "\"'":
        end = _quote_end(stripped)
        if end < 0:
            return None
        after = stripped[end + 1:].lstrip()
        if after.startswith(":") and (len(after) == 1 or after[1] in " \t"):
            return _unquote(stripped[: end + 1], line), after[1:]
        return None
    if first in "[{|>":
        return None
    if first == "?" and (len(stripped) == 1 or stripped[1] == " "):
        raise YamlError(line, "complex mapping keys are not supported")
    i = 0
    while i < len(stripped):
        if stripped.startswith("${{", i):
            end = stripped.find("}}", i)
            if end < 0:
                return None
            i = end + 2
            continue
        c = stripped[i]
        if c == "#" and i > 0 and stripped[i - 1] in " \t":
            return None
        if c == ":" and (i + 1 == len(stripped) or stripped[i + 1] in " \t"):
            key = stripped[:i].rstrip()
            if key[:1] in ("&", "*", "!"):
                raise YamlError(line, "anchors, aliases or tags on keys are not supported")
            return key, stripped[i + 1:]
        i += 1
    return None


class _Flow:
    """Parser for `[a, b]` and `{a: b}` collections."""

    def __init__(self, text, line):
        self.text = text
        self.line = line
        self.i = 0

    def parse(self):
        value = self._value()
        self._ws()
        if self.i != len(self.text):
            raise YamlError(self.line, "unexpected content after flow collection")
        return value

    def _ws(self):
        while self.i < len(self.text) and self.text[self.i] in " \t":
            self.i += 1

    def _peek(self):
        self._ws()
        if self.i >= len(self.text):
            raise _Incomplete()
        return self.text[self.i]

    def _value(self):
        c = self._peek()
        if c == "[":
            return self._seq()
        if c == "{":
            return self._map()
        if c in "\"'":
            return self._quoted()
        return _scalar(self._plain(False))

    def _quoted(self):
        end = _quote_end(self.text, self.i)
        if end < 0:
            raise _Incomplete()
        value = _unquote(self.text[self.i:end + 1], self.line)
        self.i = end + 1
        return value

    def _plain(self, is_key):
        start = self.i
        text = self.text
        while self.i < len(text):
            if text.startswith("${{", self.i):
                end = text.find("}}", self.i)
                if end < 0:
                    raise _Incomplete()
                self.i = end + 2
                continue
            c = text[self.i]
            if c in ",]}":
                break
            if is_key and c == ":" and text[self.i + 1:self.i + 2] in ("", " ", "\t", ",", "}"):
                break
            self.i += 1
        token = text[start:self.i].strip()
        if token[:1] in ("*", "&", "!"):
            raise YamlError(self.line, "anchors, aliases or tags in flow collections are not supported")
        return token

    def _seq(self):
        self.i += 1
        items = []
        while True:
            if self._peek() == "]":
                self.i += 1
                return items
            items.append(self._value())
            c = self._peek()
            if c == ",":
                self.i += 1
            elif c != "]":
                raise YamlError(self.line, "expected ',' or ']' in flow sequence")

    def _map(self):
        self.i += 1
        out = {}
        while True:
            c = self._peek()
            if c == "}":
                self.i += 1
                return out
            key = self._quoted() if c in "\"'" else self._plain(True)
            if key in out:
                raise YamlError(self.line, "duplicate key in flow mapping")
            value = None
            if self._peek() == ":":
                self.i += 1
                if self._peek() not in ",}":
                    value = self._value()
            out[key] = value
            c = self._peek()
            if c == ",":
                self.i += 1
            elif c != "}":
                raise YamlError(self.line, "expected ',' or '}' in flow mapping")


class _Parser:
    def __init__(self, text):
        self.lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
        self.pos = 0
        self.anchors = {}

    def parse(self):
        if not self._next():
            return None
        first = self._strip()
        if first.startswith("%"):
            raise YamlError(self.pos + 1, "YAML directives are not supported")
        if first == "---":
            self.pos += 1
            if not self._next():
                return None
        node = self._node(self._indent())
        if self._next():
            if self._strip() == "...":
                self.pos += 1
                if not self._next():
                    return node
            if self._strip().startswith("---"):
                raise YamlError(self.pos + 1, "multiple YAML documents are not supported")
            raise YamlError(self.pos + 1, "unexpected indentation or content")
        return node

    def _next(self):
        """Move to the next line with content; False at end of input."""
        while self.pos < len(self.lines):
            stripped = self.lines[self.pos].strip()
            if stripped and not stripped.startswith("#"):
                return True
            self.pos += 1
        return False

    def _strip(self):
        return self.lines[self.pos].strip()

    def _indent(self):
        line = self.lines[self.pos]
        count = len(line) - len(line.lstrip(" "))
        if line[count:count + 1] == "\t":
            raise YamlError(self.pos + 1, "tabs cannot be used for indentation")
        return count

    def _node(self, indent):
        stripped = self._strip()
        line = self.pos + 1
        if _is_dash(stripped):
            return self._seq(indent)
        if _split_key(stripped, line) is not None:
            return self._map(indent)
        self.pos += 1
        return self._value(stripped, indent - 1, line)

    def _seq(self, indent):
        items = []
        while self._next() and self._indent() == indent and _is_dash(self._strip()):
            raw = self.lines[self.pos]
            rest = raw[indent + 1:]
            body = rest.strip()
            if not body or body.startswith("#"):
                self.pos += 1
                if self._next() and self._indent() > indent:
                    items.append(self._node(self._indent()))
                else:
                    items.append(None)
            else:
                # Treat `- key: value` as a nested block at the column of `key`.
                item_indent = indent + 1 + len(rest) - len(rest.lstrip(" "))
                self.lines[self.pos] = " " * item_indent + rest.lstrip(" ")
                items.append(self._node(item_indent))
        return items

    def _map(self, indent):
        out = {}
        while self._next() and self._indent() == indent:
            line = self.pos + 1
            stripped = self._strip()
            if _is_document_marker(stripped):
                break
            if _is_dash(stripped):
                raise YamlError(line, "sequence item where a mapping key was expected")
            split = _split_key(stripped, line)
            if split is None:
                raise YamlError(line, "expected a mapping key")
            key, rest = split
            if key == "<<":
                raise YamlError(line, "merge keys are not supported")
            if key in out:
                raise YamlError(line, "duplicate mapping key")
            self.pos += 1
            out[key] = self._value(rest, indent, line)
        return out

    def _value(self, rest, indent, line):
        value = _strip_comment(rest.strip()).strip()
        anchor = None
        if value.startswith("&"):
            parts = value.split(None, 1)
            anchor = parts[0][1:]
            value = parts[1] if len(parts) > 1 else ""
        if value.startswith("!"):
            raise YamlError(line, "YAML tags are not supported")
        if not value:
            node = self._nested(indent)
        elif _BLOCK_HEADER.match(value):
            node = self._block_scalar(value, indent)
        else:
            node = self._inline(value, indent, line)
        if anchor:
            self.anchors[anchor] = node
        return node

    def _nested(self, indent):
        if not self._next():
            return None
        child = self._indent()
        if child > indent:
            return self._node(child)
        if child == indent and _is_dash(self._strip()):
            return self._seq(child)
        return None

    def _inline(self, value, indent, line):
        first = value[0]
        if first == "*":
            name = value[1:].strip()
            if name not in self.anchors:
                raise YamlError(line, "alias refers to an unknown anchor")
            return self.anchors[name]
        if first in "[{":
            return self._flow(value, line)
        if first in "\"'":
            return self._quoted(value, line)
        return self._plain(value, indent, line)

    def _flow(self, text, line):
        while True:
            try:
                return _Flow(text, line).parse()
            except _Incomplete:
                if self.pos >= len(self.lines):
                    raise YamlError(line, "unterminated flow collection")
                text += " " + _strip_comment(self.lines[self.pos].strip())
                self.pos += 1

    def _quoted(self, text, line):
        while _quote_end(text) < 0:
            if self.pos >= len(self.lines):
                raise YamlError(line, "unterminated quoted string")
            text += " " + self.lines[self.pos].strip()
            self.pos += 1
        end = _quote_end(text)
        if text[end + 1:].strip():
            raise YamlError(line, "unexpected content after quoted string")
        return _unquote(text[: end + 1], line)

    def _plain(self, value, indent, line):
        if _split_key(value, line) is not None:
            raise YamlError(line, "a plain value cannot contain ': '")
        parts = [value]
        while self.pos < len(self.lines):
            stripped = self.lines[self.pos].strip()
            if not stripped or stripped.startswith("#") or self._indent() <= indent:
                break
            if _split_key(stripped, self.pos + 1) is not None:
                raise YamlError(self.pos + 1, "unexpected mapping key inside a plain value")
            parts.append(_strip_comment(stripped))
            self.pos += 1
        return _scalar(" ".join(parts)) if len(parts) > 1 else _scalar(value)

    def _block_scalar(self, header, parent):
        chomp = ""
        explicit = None
        for ch in header[1:]:
            if ch in "+-":
                chomp = ch
            else:
                explicit = int(ch)
        content_indent = max(parent, 0) + explicit if explicit else None
        if content_indent is None:
            probe = self.pos
            while probe < len(self.lines) and not self.lines[probe].strip():
                probe += 1
            if probe < len(self.lines):
                found = len(self.lines[probe]) - len(self.lines[probe].lstrip(" "))
                if found > parent:
                    content_indent = found
        body = []
        while self.pos < len(self.lines):
            raw = self.lines[self.pos]
            if not raw.strip():
                body.append(raw[content_indent:] if content_indent else "")
                self.pos += 1
                continue
            if content_indent is None or len(raw) - len(raw.lstrip(" ")) < content_indent:
                break
            body.append(raw[content_indent:])
            self.pos += 1
        trailing = 0
        while body and not body[-1].strip():
            body.pop()
            trailing += 1
        if header[0] == "|":
            text = "\n".join(body)
        else:
            text = _fold(body)
        if not body:
            return ""
        if chomp == "-":
            return text
        if chomp == "+":
            return text + "\n" * max(trailing, 1)
        return text + "\n"


def _fold(lines):
    """Fold line breaks between plain lines; keep every break next to a more-indented line."""
    out = ""
    last = None
    blanks = 0
    for line in lines:
        if not line.strip():
            blanks += 1
            continue
        if last is None:
            out += "\n" * blanks + line
        elif line[:1] in " \t" or last[:1] in " \t":
            out += "\n" * (blanks + 1) + line
        elif blanks:
            out += "\n" * blanks + line
        else:
            out += " " + line
        last = line
        blanks = 0
    return out
