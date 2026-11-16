#!/usr/bin/env python3
"""Runs one agent task in one fresh container (P1.1).

Each task gets its own internal network with no route out, its own proxy and
gateway, and a container that is deleted afterwards. Nothing is reused between
tasks.

Exit codes: the agent's own, or 3 if the agent flagged a human (P2.8), or 2 if
the sandbox could not be set up.
"""
import argparse
import json
import os
import re
import secrets as secrets_module
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "escalation"))

import gateway as gateway_module  # noqa: E402
import flag_ledger  # noqa: E402
import snapshot as snapshot_module  # noqa: E402

CONTROL_IMAGE = "runtime-control:dev"
PROXY_PORT = 3128
EXIT_FLAGGED = 3
EXIT_SETUP = 2
TASK_ID = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,62}$")
HARDENING = [
    "--cap-drop=ALL", "--security-opt=no-new-privileges", "--read-only", "--init",
]


class SandboxError(Exception):
    pass


def docker(*args, **kwargs):
    kwargs.setdefault("capture_output", True)
    kwargs.setdefault("text", True)
    return subprocess.run(["docker"] + list(args), **kwargs)


def must(*args, **kwargs):
    result = docker(*args, **kwargs)
    if result.returncode:
        raise SandboxError("docker {} failed: {}".format(args[0], result.stderr.strip()[:500]))
    return result


class Sandbox:
    """Network, proxy and gateway for one task, removed on exit."""

    def __init__(self, task_id, image, allowlist, model_key=None, github_token=None,
                 repo=None, gateway_config=None, memory="4g", cpus="2", pids=512,
                 workspace_size="4g", control_image=CONTROL_IMAGE, allow_unpinned=False,
                 extra_env=None, upstream_ca_pem=None, task_scope=None,
                 mentions=(), link_hosts=None, canaries=(), agent=None, task_dir=None):
        if not TASK_ID.match(task_id):
            raise SandboxError("task id must match " + TASK_ID.pattern)
        if "@sha256:" not in image and not allow_unpinned:
            raise SandboxError("agent image must be pinned by digest: " + image)
        if github_token and not repo:
            raise SandboxError("a GitHub token needs --repo, so its use can be limited")
        if task_scope is not None and not repo:
            raise SandboxError("a task scope needs --repo")
        if gateway_config is None:
            try:
                gateway_config = gateway_module.build_config(
                    repo or "none/none", extra_ca_pem=upstream_ca_pem, scope=task_scope,
                    mentions=mentions,
                    link_hosts=gateway_module.DEFAULT_LINK_HOSTS + tuple(link_hosts or ()),
                    task_id=task_id, agent=agent,
                )
            except ValueError as exc:
                raise SandboxError(str(exc))
        elif task_scope is not None:
            raise SandboxError("give the task scope in gateway_config, not both")
        self.task_id = task_id
        self.image = image
        self.allowlist = allowlist
        self.secrets = {"model": model_key or "", "github": github_token or ""}
        # Strings planted for this task; a post containing one is refused (GA-12).
        self.secrets["canaries"] = list(canaries)
        self.gateway_config = gateway_config
        self.limits = (memory, cpus, str(pids), workspace_size)
        self.control_image = control_image
        self.extra_env = extra_env or {}
        # Task files (task.md, snapshot.md), mounted read-only at /task (GA-13).
        self.task_dir = os.path.abspath(task_dir) if task_dir else None
        suffix = secrets_module.token_hex(4)
        stem = "agent-{}-{}".format(task_id, suffix)
        self.internal_network = stem + "-int"
        self.egress_network = stem + "-egress"
        self.proxy_name = stem + "-proxy"
        self.gateway_name = stem + "-gateway"
        self.agent_name = stem + "-agent"
        self._gateway_process = None

    def __enter__(self):
        try:
            self.start_infrastructure()
        except BaseException:
            self.teardown()
            raise
        return self

    def __exit__(self, *exc):
        self.teardown()

    def start_infrastructure(self):
        must("network", "create", "--internal", self.internal_network)
        must("network", "create", self.egress_network)
        control = HARDENING + ["--pids-limit=256", "--memory=512m"]
        must(
            "run", "-d", "--name", self.proxy_name,
            "--network", "name={},alias=egress-proxy".format(self.internal_network),
            "--network", self.egress_network,
            "-e", "EGRESS_ALLOWLIST=" + json.dumps(self.allowlist), *control,
            self.control_image, "python", "/opt/sandbox/egress_proxy.py",
        )
        # -i with a pipe delivers the credentials on stdin, so `docker inspect`
        # of the gateway shows no secret either.
        self._gateway_process = subprocess.Popen(
            ["docker", "run", "-i", "--name", self.gateway_name,
             "--network", "name={},alias=gateway".format(self.internal_network),
             "--network", self.egress_network,
             "-e", "GATEWAY_CONFIG=" + json.dumps(self.gateway_config), *control,
             self.control_image, "python", "/opt/sandbox/gateway.py"],
            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        self._gateway_process.stdin.write((json.dumps(self.secrets) + "\n").encode())
        self._gateway_process.stdin.close()
        self._wait_ready(self.proxy_name)
        self._wait_ready(self.gateway_name)

    def _wait_ready(self, name):
        deadline = time.time() + 30
        while time.time() < deadline:
            if '"event": "ready"' in docker("logs", name).stdout:
                return
            time.sleep(0.2)
        raise SandboxError(name + " did not become ready")

    def agent_env(self):
        proxy = "http://egress-proxy:{}".format(PROXY_PORT)
        env = {
            "HTTP_PROXY": proxy, "HTTPS_PROXY": proxy, "http_proxy": proxy, "https_proxy": proxy,
            "NO_PROXY": "gateway", "no_proxy": "gateway",
            "HOME": "/workspace/.home",
            "ANTHROPIC_BASE_URL": "http://gateway:8080",
            "ANTHROPIC_API_KEY": "held-by-gateway",
            "GITHUB_API_URL": "http://gateway:8082",
            "FLAG_FOR_HUMAN_URL": "http://gateway:8083/flag",
            "AGENT_TASK_ID": self.task_id,
            # Git rewrites GitHub URLs to the gateway with no credential to store.
            "GIT_CONFIG_COUNT": "2",
            "GIT_CONFIG_KEY_0": "url.http://gateway:8081/.insteadOf",
            "GIT_CONFIG_VALUE_0": "https://github.com/",
            "GIT_CONFIG_KEY_1": "credential.helper",
            "GIT_CONFIG_VALUE_1": "",
            "GIT_TERMINAL_PROMPT": "0",
        }
        env.update(self.extra_env)
        return env

    def create_agent(self, command):
        memory, cpus, pids, workspace = self.limits
        env_args = []
        for key, value in self.agent_env().items():
            env_args += ["-e", "{}={}".format(key, value)]
        must(
            "create", "--name", self.agent_name, "--network", self.internal_network,
            "--memory", memory, "--cpus", cpus, "--pids-limit", pids,
            "--tmpfs", "/workspace:rw,exec,uid=1000,gid=1000,size=" + workspace,
            "--tmpfs", "/tmp:rw,exec,size=1g", "--workdir", "/workspace",
            "--user", "1000:1000", *HARDENING, *self.task_mount(), *env_args, self.image, *command,
        )
        return self.agent_name

    def task_mount(self):
        if not self.task_dir:
            return []
        if "," in self.task_dir or "=" in self.task_dir:
            raise SandboxError("task dir path can't hold ',' or '=': " + self.task_dir)
        return ["--mount", "type=bind,src={},dst=/task,readonly".format(self.task_dir)]

    def run_agent(self, command, timeout=3600):
        """Run the task to completion and return (exit code, combined output)."""
        self.create_agent(command)
        try:
            result = docker("start", "-a", self.agent_name, timeout=timeout)
            return result.returncode, result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            docker("rm", "-f", self.agent_name)
            return 124, "task timed out after {}s".format(timeout)

    def _events(self, name):
        events = []
        for line in docker("logs", name).stdout.splitlines():
            try:
                events.append(json.loads(line))
            except ValueError:
                continue
        return events

    def proxy_events(self):
        return self._events(self.proxy_name)

    def gateway_events(self):
        return self._events(self.gateway_name)

    def flags(self):
        return [e["flag"] for e in self.gateway_events() if e.get("event") == "flag"]

    def opened_pr(self):
        """The PR number the agent opened during this task, if the gateway read one."""
        numbers = [e.get("pr") for e in self.gateway_events() if e.get("event") == "task-pr"]
        return numbers[-1] if numbers else None

    def model_usage(self):
        """Per-call token usage the gateway logged (GA-14), and the task's totals."""
        calls = [{key: e.get(key) for key in ("model", "status", "unread") + gateway_module.USAGE_KEYS}
                 for e in self.gateway_events() if e.get("event") == "model-usage"]
        totals = {key: sum(call.get(key) or 0 for call in calls) for key in gateway_module.USAGE_KEYS}
        totals["calls"] = len(calls)
        totals["unread_calls"] = sum(1 for call in calls if call.get("unread"))
        return calls, totals

    def gateway_problems(self):
        """Counts of upstream errors (route:exception type) and refusals (by reason).

        Only the gateway's own labels, never request text, so they're safe to print.
        """
        errors, denied = {}, {}
        for event in self.gateway_events():
            if event.get("event") == "gateway-error":
                key = "{}:{}".format(event.get("route"), event.get("error"))
                errors[key] = errors.get(key, 0) + 1
            elif event.get("decision") == "deny":
                key = str(event.get("reason"))
                denied[key] = denied.get(key, 0) + 1
        return errors, denied

    def denied_egress(self):
        return [e for e in self.proxy_events() if e.get("decision") == "deny"]

    def teardown(self):
        for name in (self.agent_name, self.gateway_name, self.proxy_name):
            docker("rm", "-f", "-v", name)
        if self._gateway_process is not None:
            try:
                self._gateway_process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self._gateway_process.kill()
        for network in (self.internal_network, self.egress_network):
            result = docker("network", "rm", network)
            if result.returncode and "not found" not in result.stderr:
                print("sandbox warning: network not removed: " + network, file=sys.stderr)


def read_secret(path):
    if not path:
        return None
    with open(path, encoding="utf-8") as handle:
        return handle.read().strip()


def run_task(args):
    with open(args.allowlist, encoding="utf-8") as handle:
        allowlist = json.load(handle)
    started = time.time()
    scope = None
    if args.issue is not None or args.pr is not None:
        try:
            scope = gateway_module.task_scope(args.agent, issue=args.issue, pr=args.pr)
        except ValueError as exc:
            raise SandboxError(str(exc))
    github_token = read_secret(args.github_token_file)
    task_dir = tempfile.mkdtemp(prefix="agent-task-")
    try:
        left_out = prepare_task_dir(task_dir, args, scope, github_token)
        return run_in_sandbox(args, allowlist, scope, github_token, task_dir, started, left_out)
    finally:
        shutil.rmtree(task_dir, ignore_errors=True)


def prepare_task_dir(task_dir, args, scope, github_token):
    """Write task.md and, for a scoped task, snapshot.md, readable by the agent's uid."""
    os.chmod(task_dir, 0o755)
    if args.task_file:
        shutil.copyfile(args.task_file, os.path.join(task_dir, "task.md"))
    left_out = None
    if scope is not None and github_token:
        github = snapshot_module.GitHub(args.github_api_url, github_token, args.repo)
        try:
            taken = snapshot_module.take(github, scope)
        except snapshot_module.SnapshotError as exc:
            raise SandboxError("snapshot: " + str(exc))
        with open(os.path.join(task_dir, "snapshot.md"), "w", encoding="utf-8") as handle:
            handle.write(snapshot_module.render(taken))
        left_out = taken["left_out"]
    for name in os.listdir(task_dir):
        os.chmod(os.path.join(task_dir, name), 0o644)
    return left_out


def run_in_sandbox(args, allowlist, scope, github_token, task_dir, started, left_out):
    sandbox = Sandbox(
        args.task_id, args.image, allowlist,
        model_key=read_secret(args.model_key_file),
        github_token=github_token, task_dir=task_dir,
        repo=args.repo, memory=args.memory, cpus=args.cpus, control_image=args.control_image,
        upstream_ca_pem=read_secret(args.upstream_ca_file), task_scope=scope,
        mentions=args.allow_mention, link_hosts=args.link_host, agent=args.agent,
    )
    with sandbox:
        code, output = sandbox.run_agent(args.command, timeout=args.timeout)
        flags = sandbox.flags()
        denied = sandbox.denied_egress()
        opened = sandbox.opened_pr()
        calls, usage = sandbox.model_usage()
        gateway_errors, gateway_denied = sandbox.gateway_problems()
    final = EXIT_FLAGGED if flags else code
    sys.stdout.write(output)
    summary = {
        "task_id": args.task_id, "agent": args.agent, "repo": args.repo, "exit_code": final,
        "issue": args.issue, "pr": args.pr if args.pr is not None else opened,
        "agent_exit_code": code, "flags": len(flags), "denied_egress": len(denied),
        "seconds": round(time.time() - started, 1), "usage": usage, "snapshot_left_out": left_out,
        "gateway_errors": gateway_errors, "gateway_denied": gateway_denied,
    }
    print("SANDBOX_RESULT " + json.dumps(summary, sort_keys=True))
    if args.ledger:
        flag_ledger.append_task(args.ledger, summary, flags, model_calls=calls)
    return final


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--agent", required=True, help="Agent identity, set by the trusted caller")
    parser.add_argument("--image", required=True, help="Agent image pinned by digest")
    parser.add_argument("--allowlist", required=True, help="Proxy allowlist JSON")
    parser.add_argument("--repo", help="owner/name the GitHub token is limited to")
    parser.add_argument("--issue", type=int, help="Triggering issue number (gateway task scope)")
    parser.add_argument("--pr", type=int, help="The agent's own PR, on a re-dispatch (gateway task scope)")
    parser.add_argument("--allow-mention", action="append", default=[], metavar="LOGIN",
                        help="A login or org/team the agent may @mention; repeat for more")
    parser.add_argument("--link-host", action="append", default=[], metavar="HOST",
                        help="A host, besides github.com, the agent's links and images may use")
    parser.add_argument("--task-file", help="The task text, mounted read-only at /task/task.md")
    parser.add_argument("--github-api-url", default="https://api.github.com",
                        help="Where the runner reads the issue or PR for /task/snapshot.md")
    parser.add_argument("--model-key-file")
    parser.add_argument("--github-token-file")
    parser.add_argument("--upstream-ca-file", help="Extra CA (PEM) the gateway trusts for upstreams")
    parser.add_argument("--ledger", help="Flag and task ledger file (JSONL), outside the sandbox")
    parser.add_argument("--control-image", default=CONTROL_IMAGE)
    parser.add_argument("--memory", default="4g")
    parser.add_argument("--cpus", default="2")
    parser.add_argument("--timeout", type=int, default=3600)
    parser.add_argument("command", nargs=argparse.REMAINDER, help="-- then the command to run")
    args = parser.parse_args(argv)
    if args.command[:1] == ["--"]:
        args.command = args.command[1:]
    if not args.command:
        parser.error("give the command to run after --")
    try:
        return run_task(args)
    except (SandboxError, OSError, ValueError) as exc:
        print("sandbox error: {}".format(exc), file=sys.stderr)
        return EXIT_SETUP


if __name__ == "__main__":
    sys.exit(main())
