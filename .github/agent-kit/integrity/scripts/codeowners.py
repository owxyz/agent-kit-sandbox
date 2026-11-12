"""Resolve CODEOWNERS the way GitHub does: the last matching pattern wins."""
import re

from common import ToolError


def pattern_regex(pattern):
    anchored = pattern.startswith("/") or "/" in pattern.rstrip("/")
    directory = pattern.endswith("/")
    body = pattern.strip("/")
    output, index = "", 0
    while index < len(body):
        if body.startswith("**/", index):
            output += "(?:.*/)?"
            index += 3
        elif body.startswith("**", index):
            output += ".*"
            index += 2
        elif body[index] == "*":
            output += "[^/]*"
            index += 1
        elif body[index] == "?":
            output += "[^/]"
            index += 1
        else:
            output += re.escape(body[index])
            index += 1
    prefix = "" if anchored else "(?:.*/)?"
    suffix = "/.*" if directory else "(?:/.*)?"
    return re.compile("^%s%s%s$" % (prefix, output, suffix))


class CodeOwners:
    def __init__(self, text):
        self.rules = []
        for raw in text.splitlines():
            line = raw.split(" #", 1)[0].strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            self.rules.append((pattern_regex(parts[0]), parts[1:]))
        if not self.rules:
            raise ToolError("CODEOWNERS has no rules")

    def owners_for(self, path):
        owners = []
        for regex, listed in self.rules:
            if regex.match(path):
                owners = listed
        return owners
