#!/usr/bin/env python3
"""Check the coding agent's CLI and model as one versioned pair (red-team #15).

agent-pair.json names the agent CLI version and the model it runs, plus the last
real run that verified exactly that pair. A pinned CLI can be refused by a newer
model, as Claude Code 2.1.220 was for claude-opus-5-5, so a task must not start
with a CLI, image or model that differs from a verified pair.

    agent_pair.py check [--pair FILE] [--image IMAGE] [--model MODEL]
    agent_pair.py model [--pair FILE]

`check` exits 0 when the pair is verified and, if given, the image's
`claude --version` and the model match it; 1 otherwise. `model` prints the
pair's model, for the runner's agent command. Standard library only.
"""
import argparse
import json
import os
import re
import subprocess
import sys

DEFAULT_PAIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent-pair.json")
VERSION = re.compile(r"^\d+\.\d+\.\d+$")
MODEL = re.compile(r"^[a-z0-9][a-z0-9.\-]*$")


class PairError(ValueError):
    pass


def load(path=DEFAULT_PAIR):
    """Read and validate a pair file. Raises PairError."""
    try:
        with open(path, encoding="utf-8") as handle:
            pair = json.load(handle)
    except (OSError, ValueError) as exc:
        raise PairError(f"can't read {path}: {exc}") from exc
    return validate(pair)


def validate(pair):
    if not isinstance(pair, dict) or pair.get("schema_version") != 1:
        raise PairError("agent pair: schema_version must be 1")
    cli, model, verified = pair.get("cli"), pair.get("model"), pair.get("verified")
    if not isinstance(cli, dict) or not isinstance(cli.get("package"), str):
        raise PairError("agent pair: cli.package is missing")
    if not isinstance(cli.get("version"), str) or not VERSION.match(cli["version"]):
        raise PairError("agent pair: cli.version must be an exact version like 2.1.322")
    if not isinstance(model, str) or not MODEL.match(model):
        raise PairError("agent pair: model must be an exact model id")
    if not isinstance(verified, dict):
        raise PairError("agent pair: no verified run recorded")
    stale = [k for k, want in (("cli_version", cli["version"]), ("model", model)) if verified.get(k) != want]
    if stale:
        raise PairError("agent pair: {} was verified with {} {}, not {} {}; re-run a real task with this exact "
                        "pair, then record it under verified".format(
                            pair.get("agent", "agent"), verified.get("cli_version"), verified.get("model"),
                            cli["version"], model))
    for key in ("date", "evidence"):
        if not isinstance(verified.get(key), str) or not verified[key].strip():
            raise PairError(f"agent pair: verified.{key} is missing")
    return pair


def image_cli_version(image, docker="docker"):
    """`claude --version` inside the image, with no network."""
    result = subprocess.run([docker, "run", "--rm", "--network", "none", "--entrypoint", "claude", image, "--version"],
                            capture_output=True, text=True, timeout=120, check=False)
    if result.returncode:
        raise PairError(f"`claude --version` failed in {image}: {result.stderr.strip()[-500:]}")
    match = re.match(r"(\d+\.\d+\.\d+)\b", result.stdout.strip())
    if not match:
        raise PairError(f"unexpected `claude --version` output from {image}: {result.stdout.strip()[:200]!r}")
    return match.group(1)


def check(pair, image=None, model=None, docker="docker"):
    """Raise PairError unless the image and model match the verified pair."""
    if model is not None and model != pair["model"]:
        raise PairError(f"model {model} isn't the pair's model {pair['model']}; change both through the eval gate")
    if image is not None:
        found = image_cli_version(image, docker)
        if found != pair["cli"]["version"]:
            raise PairError(f"{image} has {pair['cli']['package']} {found}, but the pair pins "
                            f"{pair['cli']['version']}; rebuild the image or release a new pair")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check")
    c.add_argument("--image", help="agent image to inspect, pinned by digest")
    c.add_argument("--model", help="the model the task will run")
    m = sub.add_parser("model")
    for q in (c, m):
        q.add_argument("--pair", default=DEFAULT_PAIR)
    args = parser.parse_args(argv)
    try:
        pair = load(args.pair)
        if args.cmd == "model":
            print(pair["model"])
            return 0
        check(pair, image=args.image, model=args.model)
    except PairError as exc:
        print(f"agent_pair: {exc}", file=sys.stderr)
        return 1
    print("agent pair OK: {} {} with {}".format(pair["cli"]["package"], pair["cli"]["version"], pair["model"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
