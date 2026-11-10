#!/usr/bin/env python3
"""Fail if agent config references an MCP server that is not approved.

Usage: check_mcp_allowlist.py --allowlist approved-mcp-servers.json --root DIR

An empty list denies every server. Standard library only.
"""
import argparse
import json
import os
import re
import sys

EXACT_VERSION = re.compile(r"^\d+\.\d+\.\d+([-+][0-9A-Za-z.\-+]+)?$")
SKIP_DIRS = {".git", "node_modules", ".trusted"}
TOML_SECTION = re.compile(r"^\[mcp_servers\.\"?([^\]\".]+)\"?\]\s*$")
TOML_VALUE = re.compile(r"^(command|url)\s*=\s*\"([^\"]*)\"\s*$")
TOML_ARGS = re.compile(r"^args\s*=\s*\[(.*)\]\s*$")


def load_allowlist(path):
    """Return ({name: entry}, [problems in the list itself])."""
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    approved, problems = {}, []
    for entry in data.get("servers", []):
        name = entry.get("name")
        if not name:
            problems.append("allowlist: entry has no name")
            continue
        if entry.get("type") == "stdio":
            if not entry.get("package") or not EXACT_VERSION.match(str(entry.get("version", ""))):
                problems.append("allowlist: %s needs a package and exact version" % name)
                continue
        elif entry.get("type") == "http":
            if not str(entry.get("url", "")).startswith("https://"):
                problems.append("allowlist: %s needs an https url" % name)
                continue
        else:
            problems.append("allowlist: %s has an unknown type" % name)
            continue
        approved[name] = entry
    return approved, problems


def is_config_file(root, name):
    parent = os.path.basename(root)
    if name in (".mcp.json", ".claude.json"):
        return True
    if name == "mcp.json" and parent in (".cursor", ".vscode", ".gemini"):
        return True
    if name == "settings.json" and parent == ".gemini":
        return True
    return parent == ".claude" and re.fullmatch(r"settings(\.local)?\.json", name) is not None


def servers_from_json(path):
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        return {}
    servers = {}
    for key in ("mcpServers", "servers"):
        value = data.get(key)
        if isinstance(value, dict):
            servers.update(value)
    return servers


def servers_from_codex_toml(path):
    servers, current = {}, None
    with open(path, encoding="utf-8") as handle:
        for raw in handle:
            line = raw.strip()
            section = TOML_SECTION.match(line)
            if section:
                current = servers.setdefault(section.group(1), {})
                continue
            if line.startswith("["):
                current = None
            elif current is not None:
                value, args = TOML_VALUE.match(line), TOML_ARGS.match(line)
                if value:
                    current[value.group(1)] = value.group(2)
                elif args:
                    current["args"] = re.findall(r"\"([^\"]*)\"", args.group(1))
    return servers


def discover(root):
    """Yield (config path, servers dict or None if unreadable)."""
    for directory, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            path = os.path.join(directory, name)
            try:
                if is_config_file(directory, name):
                    yield path, servers_from_json(path)
                elif name == "config.toml" and os.path.basename(directory) == ".codex":
                    yield path, servers_from_codex_toml(path)
            except (OSError, ValueError):
                yield path, None


def server_matches(server, entry):
    if not isinstance(server, dict):
        return False
    if entry["type"] == "http":
        return server.get("url") == entry["url"]
    tokens = [str(server.get("command", ""))] + [str(a) for a in server.get("args") or []]
    package, version = entry["package"], entry["version"]
    return any(pin in tokens for pin in (
        "%s@%s" % (package, version), "%s==%s" % (package, version), "%s:%s" % (package, version),
    ))


def check(allowlist_path, root):
    approved, violations = load_allowlist(allowlist_path)
    count = 0
    for path, servers in discover(root):
        count += 1
        if servers is None:
            violations.append("%s: unreadable MCP config" % path)
            continue
        for name, server in servers.items():
            if name not in approved:
                violations.append("%s: server not on approved list: %s" % (path, name))
            elif not server_matches(server, approved[name]):
                violations.append("%s: server does not match approved pin: %s" % (path, name))
    return count, violations


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allowlist", required=True)
    parser.add_argument("--root", required=True)
    args = parser.parse_args()
    try:
        count, violations = check(args.allowlist, args.root)
    except (OSError, ValueError) as error:
        print("Cannot read allowlist: %s" % type(error).__name__)
        return 1
    for violation in violations:
        print(violation)
    print("%d MCP config file(s) checked, %d violation(s)." % (count, len(violations)))
    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main())
