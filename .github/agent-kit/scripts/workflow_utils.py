"""Shared helpers for reading GitHub Actions workflow files as data."""
import os

import yaml

YAML_SUFFIXES = (".yml", ".yaml")


def find_yaml_files(paths):
    """Expand files and directories into a sorted list of YAML files."""
    found = []
    for path in paths:
        if os.path.isfile(path):
            found.append(path)
            continue
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in (".git", "node_modules")]
            found.extend(os.path.join(root, f) for f in files if f.endswith(YAML_SUFFIXES))
    return sorted(found)


def load_yaml(path):
    with open(path, encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def triggers(workflow):
    """Return the set of event names. YAML 1.1 parses a bare `on` key as True."""
    value = workflow.get("on", workflow.get(True))
    if isinstance(value, str):
        return {value}
    if isinstance(value, (list, dict)):
        return set(value)
    return set()


def jobs(workflow):
    value = workflow.get("jobs")
    return value if isinstance(value, dict) else {}


def steps(job):
    value = job.get("steps") if isinstance(job, dict) else None
    return [s for s in value if isinstance(s, dict)] if isinstance(value, list) else []


def as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]
