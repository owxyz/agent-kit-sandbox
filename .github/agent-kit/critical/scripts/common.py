"""Shared gate plumbing: the findings contract, exit codes and config loading."""
import json
import os
import re
import tempfile

import yaml

EXIT_OK = 0
EXIT_BLOCK = 1
EXIT_TOOL_ERROR = 2

MODES = ("warn", "block")
LANGUAGES = ("python", "javascript", "typescript")
FRAMEWORKS = ("pytest", "node-test")
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class ToolError(Exception):
    """The gate could not reach a verdict. Never treated as a pass."""


def finding(gate, rule, severity, mode, file, line, message):
    return {
        "gate": gate,
        "rule": rule,
        "severity": severity,
        "mode": mode,
        "file": file,
        "line": line,
        "message": message,
    }


def exit_code(findings, tool_error=False):
    """Tool error wins over block: both fail, but 2 says the results are incomplete."""
    if tool_error:
        return EXIT_TOOL_ERROR
    if any(item["mode"] == "block" for item in findings):
        return EXIT_BLOCK
    return EXIT_OK


def write_json(path, data):
    """Write atomically so a crash can't leave a truncated file that parses."""
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    handle, temp = tempfile.mkstemp(dir=directory, suffix=".tmp")
    with os.fdopen(handle, "w") as output:
        json.dump(data, output, indent=2)
        output.write("\n")
    os.replace(temp, path)


def _check_relative(path, label):
    if not isinstance(path, str) or not path or os.path.isabs(path) or ".." in path.split("/"):
        raise ToolError("%s must be a relative path inside the repo" % label)


def _find_placeholder(value):
    if isinstance(value, str):
        return value if "REPLACE_" in value else None
    children = value.values() if isinstance(value, dict) else value if isinstance(value, list) else ()
    for child in children:
        found = _find_placeholder(child)
        if found:
            return found
    return None


def _validate_module(module, seen):
    if not isinstance(module, dict):
        raise ToolError("each module must be a mapping")
    name = module.get("name")
    if not isinstance(name, str) or not SAFE_NAME.match(name):
        raise ToolError("module name %r is invalid" % (name,))
    if name in seen:
        raise ToolError("duplicate module %s" % name)
    seen.add(name)
    if module.get("language") not in LANGUAGES:
        raise ToolError("module %s: language must be one of %s" % (name, ", ".join(LANGUAGES)))
    if not isinstance(module.get("owner"), str) or not module["owner"].strip():
        raise ToolError("module %s: owner is required, because alerts route to it" % name)
    paths = module.get("paths")
    if not isinstance(paths, list) or not paths:
        raise ToolError("module %s: paths must be a non-empty list" % name)
    for path in paths:
        _check_relative(path, "module %s path" % name)
    if "floor" not in module:
        raise ToolError("module %s: floor is required; use null only while measuring" % name)
    floor = module["floor"]
    if floor is not None and (
        isinstance(floor, bool) or not isinstance(floor, (int, float)) or not 0 <= floor <= 100
    ):
        raise ToolError("module %s: floor must be null or between 0 and 100" % name)
    has_runner = (module.get("stryker") or {}).get("testRunner")
    if not module.get("test_command") and not (module["language"] != "python" and has_runner):
        raise ToolError("module %s: test_command is required" % name)


def _validate_suite(suite, names, seen):
    if not isinstance(suite, dict) or suite.get("module") not in names:
        raise ToolError("held-out suite names an unknown module: %r" % (suite,))
    name = suite["module"]
    if name in seen:
        raise ToolError("duplicate held-out suite for %s" % name)
    seen.add(name)
    if suite.get("framework") not in FRAMEWORKS:
        raise ToolError("suite %s: framework must be one of %s" % (name, ", ".join(FRAMEWORKS)))
    if not isinstance(suite.get("image"), str) or not suite["image"]:
        raise ToolError("suite %s: image is required" % name)
    _check_relative(suite.get("tests_path"), "suite %s tests_path" % name)
    _check_relative(suite.get("source_root", "."), "suite %s source_root" % name)
    adapter = suite.get("adapter")
    if not isinstance(adapter, dict):
        raise ToolError("suite %s: adapter is required" % name)
    exports = adapter.get("exports")
    if not isinstance(exports, list) or not exports or not all(
        isinstance(item, str) and IDENTIFIER.match(item) for item in exports
    ):
        raise ToolError("suite %s: adapter.exports must list function names" % name)
    if adapter.get("shim"):
        _check_relative(adapter["shim"], "suite %s adapter.shim" % name)
    elif not isinstance(adapter.get("import"), str) or not adapter["import"]:
        raise ToolError("suite %s: adapter needs import or shim" % name)
    minimum = suite.get("min_tests")
    if isinstance(minimum, bool) or not isinstance(minimum, int) or minimum < 3:
        raise ToolError("suite %s: min_tests must be an integer of at least 3" % name)


def load_config(path):
    """Load and validate the critical-module config. Anything doubtful is a tool error."""
    try:
        with open(path) as source:
            config = yaml.safe_load(source)
    except (OSError, yaml.YAMLError) as error:
        raise ToolError("cannot read config: %s" % type(error).__name__)
    if not isinstance(config, dict) or config.get("version") != 1:
        raise ToolError("config must be a mapping with version: 1")
    placeholder = _find_placeholder(config)
    if placeholder:
        raise ToolError("config still has a placeholder: %s" % placeholder)
    modules = config.get("modules")
    if not isinstance(modules, list) or not modules:
        raise ToolError("config must list at least one critical module")
    seen = set()
    for module in modules:
        _validate_module(module, seen)
    mutation = config.get("mutation") or {}
    if mutation.get("mode", "warn") not in MODES:
        raise ToolError("mutation.mode must be warn or block")
    heldout = config.get("heldout") or {}
    if heldout.get("mode", "block") not in MODES:
        raise ToolError("heldout.mode must be warn or block")
    if "heldout" in config:
        suites = heldout.get("suites")
        if not isinstance(suites, list):
            raise ToolError("heldout.suites must be a list")
        found = set()
        for suite in suites:
            _validate_suite(suite, seen, found)
        missing = sorted(seen - found)
        if missing:
            raise ToolError("critical modules with no held-out suite: %s" % ", ".join(missing))
    return config
