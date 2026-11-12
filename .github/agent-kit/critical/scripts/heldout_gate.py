#!/usr/bin/env python3
"""P2.10: run held-out, composition and property tests against untrusted PR code.

  seal  encrypt a test tree for transport between CI jobs
  open  decrypt a sealed file, for maintainers reading diagnostics
  run   install, then run each suite across a process boundary

The tests and the verdict live in one container. PR code lives in another. Neither
has a network or a shared path; this host process relays validated JSON between
them. README.md states what this does and doesn't protect.

Rules: HLD001 tests failed, HLD002 too few tests ran, HLD003 tests were skipped,
HLD004 results missing or adapter never started, HLD005 PR adapter broke the
protocol or stopped, HLD006 timeout or out of memory, HLD900 tool error.
Exit 0, 1 or 2 per the contract.
"""
import argparse
import base64
import io
import json
import os
import queue
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tarfile
import threading
import xml.etree.ElementTree as ElementTree

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from common import EXIT_OK, ToolError, exit_code, finding, load_config, write_json  # noqa: E402

GATE = "heldout"
KEY_ENV = "HELDOUT_TRANSPORT_KEY"
MAGIC = b"HLD1"
KINDS = ("heldout", "composition", "property")
KIND_PATTERN = re.compile(r"(?:^|[./])(heldout|composition|property)[./]")
TEST_FILE = {"pytest": re.compile(r"^test_.*\.py$"), "node-test": re.compile(r".*\.test\.mjs$")}
OUTPUT_CAP = 5 * 1024 * 1024
RESULTS_CAP = 20 * 1024 * 1024
INSTALL_TIMEOUT = 900
# Codes from docker itself, before the container's program ran.
DOCKER_FAILURES = (125, 126, 127)
OOM_KILLED = 137
FRAME_CAP = 1024 * 1024
READY_TIMEOUT = 60
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def _load_key():
    """Read the key once and remove it from the environment."""
    raw = os.environ.pop(KEY_ENV, "")
    try:
        key = base64.b64decode(raw, validate=True)
    except ValueError:
        key = b""
    if len(key) != 32:
        raise ToolError("%s must be 32 bytes, base64 encoded" % KEY_ENV)
    return key


def _aesgcm(key):
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        raise ToolError("the cryptography package is not installed")
    return AESGCM(key)


def seal_bytes(key, data, aad):
    nonce = secrets.token_bytes(12)
    return MAGIC + nonce + _aesgcm(key).encrypt(nonce, data, aad.encode())


def open_bytes(key, blob, aad):
    from cryptography.exceptions import InvalidTag

    if blob[:4] != MAGIC:
        raise ToolError("not a sealed file")
    try:
        return _aesgcm(key).decrypt(blob[4:16], blob[16:], aad.encode())
    except InvalidTag:
        raise ToolError("sealed file failed authentication: wrong key, wrong run, or altered")


def _pack(directory):
    buffer = io.BytesIO()
    skip_git = lambda info: None if info.name.split("/")[1:2] == [".git"] else info  # noqa: E731
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        archive.add(directory, arcname=".", filter=skip_git)
    return buffer.getvalue()


def _unpack(data, directory):
    os.makedirs(directory, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        if hasattr(tarfile, "data_filter"):
            archive.extractall(directory, filter="data")
        else:
            archive.extractall(directory)


def _make_readable(root):
    """Let the unprivileged container user read a tree. Never follows symlinks."""
    for current, directories, files in os.walk(root):
        for name in directories + files:
            path = os.path.join(current, name)
            if not os.path.islink(path):
                mode = os.stat(path).st_mode
                os.chmod(path, mode | stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH
                         | (0o111 if stat.S_ISDIR(mode) else 0))
    os.chmod(root, 0o755)


def docker_argv(name, image, network, mounts, env, command, interactive=False):
    """Build the sandbox command. The only place that decides container privileges."""
    argv = [
        "docker", "run", "--rm", "--name", name,
        "--network", network,
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pids-limit=512",
        "--memory=2g",
        "--cpus=2",
        "--user=65534:65534",
        "--workdir=/tmp",
        "--tmpfs=/tmp:rw,size=512m,mode=1777",
        "--read-only",
    ]
    if interactive:
        argv.append("--interactive")
    for key in sorted(env):
        argv += ["--env", "%s=%s" % (key, env[key])]
    for source, target, access in mounts:
        argv += ["--mount", "type=bind,source=%s,target=%s%s" % (source, target, ",readonly" if access == "ro" else "")]
    return argv + [image] + command


def _docker_env():
    """The host's environment holds CI tokens; docker needs almost none of it."""
    return {key: os.environ[key] for key in ("PATH", "HOME", "DOCKER_HOST", "DOCKER_CONFIG") if key in os.environ}


def _remove_container(name):
    subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=_docker_env())


def _drain_to_log(stream, log_path):
    """Keep a bounded log of a stream, and keep reading so the writer never blocks."""
    written = 0
    with open(log_path, "wb") as log:
        for chunk in iter(lambda: stream.read(65536), b""):
            if written < OUTPUT_CAP:
                log.write(chunk[: OUTPUT_CAP - written])
                written += len(chunk)


def run_capped(argv, name, timeout, log_path):
    """Run docker with a bounded log on disk. Returns exit code, or None on timeout."""
    env = _docker_env()
    try:
        process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
    except OSError as error:
        raise ToolError("docker could not start: %s" % type(error).__name__)

    reader = threading.Thread(target=_drain_to_log, args=(process.stdout, log_path), daemon=True)
    reader.start()
    try:
        code = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        _remove_container(name)
        process.kill()
        process.wait()
        code = None
    reader.join(timeout=10)
    return code


def _pr_root(suite):
    return "/workspace/pr/" + suite.get("source_root", ".").strip("./")


def adapter_target(suite):
    """What the PR container loads: a shim from the base branch, or the PR's module."""
    adapter = suite["adapter"]
    shim = adapter.get("shim")
    if suite["framework"] == "pytest":
        return os.path.splitext(os.path.basename(shim))[0] if shim else adapter["import"]
    if shim:
        return "/adapter-shim/" + os.path.basename(shim)
    return "%s/%s" % (_pr_root(suite).rstrip("/"), adapter["import"])


def adapter_env(suite):
    env = {"HOME": "/tmp", "HELDOUT_TARGET": adapter_target(suite)}
    if suite["framework"] == "pytest":
        env.update(PYTHONPATH="/adapter-shim:%s:/deps" % _pr_root(suite), PYTHONDONTWRITEBYTECODE="1")
    return env


def adapter_command(suite):
    if suite["framework"] == "pytest":
        return ["python", "/adapter/adapter_server.py"]
    return ["node", "/adapter/adapter_server.mjs"]


def test_command(suite):
    """Move the broker channel to fds 3 and 4, away from the test runner's own output."""
    if suite["framework"] == "pytest":
        runner = [
            "python", "-m", "pytest", "/suite", "--rootdir=/suite", "--import-mode=importlib",
            "-p", "no:cacheprovider", "--junitxml=/results/junit.xml", "-o", "junit_family=xunit2", "-q",
        ]
    else:
        runner = [
            "node", "--test", "--test-isolation=none", "--test-reporter=junit",
            "--test-reporter-destination=/results/junit.xml",
        ] + ["/suite/%s/*.test.mjs" % kind for kind in KINDS]
    return ["sh", "-c", 'exec 3<&0 4>&1 1>&2; exec "$@"', "sh"] + runner


def test_env(suite):
    env = {"HOME": "/tmp"}
    if suite["framework"] == "pytest":
        env.update(
            PYTHONPATH="/tools:/harness",
            PYTHONDONTWRITEBYTECODE="1",
            HYPOTHESIS_STORAGE_DIRECTORY="/tmp/.hypothesis",
        )
    return env


class Broker:
    """Relays calls between the test container and the PR container, in lockstep.

    The PR side may only answer the one outstanding call. Every answer is parsed
    and rebuilt here, so the test side never receives raw bytes from PR code.
    """

    def __init__(self, process, name, exports, call_timeout):
        self.process = process
        self.name = name
        self.exports = set(exports)
        self.call_timeout = call_timeout
        self.frames = queue.Queue()
        self.calls = 0
        self.ready = False
        self.violation = None
        self.timed_out = False
        self.test_error = None
        self.alive = True
        threading.Thread(target=self._read_frames, daemon=True).start()

    def _read_frames(self):
        while True:
            line = self.process.stdout.readline(FRAME_CAP + 1)
            if not line:
                self.frames.put(None)
                return
            self.frames.put(line)

    def wait_ready(self, timeout=READY_TIMEOUT):
        try:
            line = self.frames.get(timeout=timeout)
        except queue.Empty:
            line = None
        self.ready = line is not None and self._parse(line) == {"ready": True}
        if not self.ready:
            self._stop()
        return self.ready

    @staticmethod
    def _parse(line):
        if len(line) > FRAME_CAP or not line.endswith(b"\n"):
            return None
        try:
            frame = json.loads(line)
        except (ValueError, RecursionError):
            return None
        return frame if isinstance(frame, dict) else None

    def _stop(self):
        self.alive = False
        _remove_container(self.name)

    def _fail(self, reason):
        if self.violation is None:
            self.violation = reason
        self._stop()
        return {"fatal": "adapter broke the protocol"}

    def _unexpected(self):
        """Describe anything the PR side produced while no call was outstanding."""
        try:
            line = self.frames.get_nowait()
        except queue.Empty:
            return None
        return "exited during the run" if line is None else "sent output nobody asked for"

    def forward(self, request):
        """Send one validated call to the PR side and return the frame for the test."""
        if not self.alive:
            return {"fatal": "adapter is gone"}
        early = self._unexpected()
        if early:
            return self._fail(early)
        self.calls += 1
        call_id = self.calls
        try:
            payload = {"id": call_id, "fn": request["fn"], "args": request.get("args", [])}
            if request.get("kwargs"):
                payload["kwargs"] = request["kwargs"]
            self.process.stdin.write((json.dumps(payload) + "\n").encode())
            self.process.stdin.flush()
        except OSError:
            return self._fail("stopped accepting calls")
        try:
            line = self.frames.get(timeout=self.call_timeout)
        except queue.Empty:
            self.timed_out = True
            self._stop()
            return {"fatal": "call timed out"}
        if line is None:
            return self._fail("exited during the run")
        frame = self._parse(line)
        if frame is None or frame.get("id") != call_id or ("ok" in frame) == ("raise" in frame):
            return self._fail("sent an invalid frame")
        if "ok" in frame:
            return {"ok": frame["ok"]}
        error = frame["raise"]
        if not isinstance(error, dict) or not isinstance(error.get("type"), str) or not isinstance(error.get("message"), str):
            return self._fail("sent an invalid error")
        return {"raise": {"type": error["type"][:200], "message": error["message"][:2000]}}

    def serve(self, tests):
        """Answer the test container until it finishes."""
        for line in iter(lambda: tests.stdout.readline(FRAME_CAP + 1), b""):
            request = self._parse(line)
            if request is None or not isinstance(request.get("fn"), str):
                self.test_error = "test side sent an invalid call"
                reply = {"fatal": "invalid call"}
            elif request["fn"] not in self.exports:
                self.test_error = "tests called %s, which the adapter contract does not export" % request["fn"]
                reply = {"fatal": "not exported"}
            else:
                reply = self.forward(request)
            try:
                tests.stdin.write((json.dumps(reply) + "\n").encode())
                tests.stdin.flush()
            except OSError:
                return

    def finish(self):
        early = self._unexpected() if self.alive else None
        if early:
            self._fail(early)
        if self.alive:
            self._stop()


def parse_junit(path):
    """Parse the test container's results. Returns None if unusable."""
    try:
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode) or info.st_size > RESULTS_CAP:
            return None
        with open(path, "rb") as source:
            data = source.read()
    except OSError:
        return None
    # Results can quote strings PR code returned, so stay strict.
    if b"<!DOCTYPE" in data or b"<!ENTITY" in data:
        return None
    try:
        root = ElementTree.fromstring(data)
    except ElementTree.ParseError:
        return None
    parsed = {"total": 0, "failed": 0, "skipped": 0, "kinds": {}}
    for case in root.iter("testcase"):
        tags = {child.tag for child in case}
        parsed["total"] += 1
        if tags & {"failure", "error"}:
            parsed["failed"] += 1
        elif "skipped" in tags:
            parsed["skipped"] += 1
        where = "%s %s" % (case.get("classname", ""), case.get("file", ""))
        match = KIND_PATTERN.search(where)
        if match:
            parsed["kinds"][match.group(1)] = parsed["kinds"].get(match.group(1), 0) + 1
    return parsed


def judge(suite, code, parsed, mode, broker):
    """Turn a run into findings. Messages hold counts only, never names or output."""
    name = suite["module"]
    where = "<held-out:%s>" % name

    def block(rule, message):
        return [finding(GATE, rule, "high", mode, where, 0, "%s: %s" % (name, message))]

    if broker.test_error:
        raise ToolError("suite %s: %s" % (name, broker.test_error))
    if not broker.ready:
        return block("HLD004", "PR adapter did not start")
    if broker.violation:
        return block("HLD005", "PR adapter %s" % broker.violation)
    if broker.timed_out:
        return block("HLD006", "a call into PR code timed out")
    if code is None:
        return block("HLD006", "held-out run timed out")
    if code == OOM_KILLED:
        return block("HLD006", "held-out run was killed, likely out of memory")
    if parsed is None or code not in (0, 1) or (code == 1) != bool(parsed["failed"]):
        return block("HLD004", "held-out run produced no valid results")
    found = []
    missing = [kind for kind in KINDS if not parsed["kinds"].get(kind)]
    if parsed["total"] < suite["min_tests"] or missing or not broker.calls:
        detail = "%d tests ran, %d required, %d calls reached PR code" % (parsed["total"], suite["min_tests"], broker.calls)
        if missing:
            detail += "; none ran for: %s" % ", ".join(missing)
        found += block("HLD002", detail)
    if parsed["skipped"]:
        found += block("HLD003", "%d held-out tests were skipped" % parsed["skipped"])
    if parsed["failed"]:
        found += block("HLD001", "%d of %d held-out tests failed" % (parsed["failed"], parsed["total"]))
    return found


class Suite:
    """Paths and stages for one module's held-out suite."""

    def __init__(self, spec, work, pr_dir, config_dir):
        self.spec = spec
        self.name = spec["module"]
        self.root = os.path.join(work, self.name)
        self.pr = os.path.join(self.root, "pr")
        self.tools = os.path.join(self.root, "tools")
        self.deps = os.path.join(self.root, "deps")
        self.tests = os.path.join(self.root, "suite")
        self.results = os.path.join(self.root, "results")
        self.logs = os.path.join(self.root, "logs")
        os.makedirs(self.root)
        shutil.copytree(pr_dir, self.pr, symlinks=True, ignore=shutil.ignore_patterns(".git"))
        _make_readable(self.pr)
        self.adapter = self._trusted_copy(os.path.join(SCRIPT_DIR, "adapter"), "adapter")
        self.harness = self._trusted_copy(os.path.join(SCRIPT_DIR, "harness"), "harness")
        self.shim = os.path.join(self.root, "shim")
        os.makedirs(self.shim)
        shim = spec["adapter"].get("shim")
        if shim:
            shutil.copy(os.path.join(config_dir, shim), self.shim)
        _make_readable(self.shim)
        for directory in (self.tools, self.deps, self.results, self.logs):
            os.makedirs(directory)
        for directory in (self.tools, self.deps, self.results):
            os.chmod(directory, 0o777)

    def _trusted_copy(self, source, name):
        target = os.path.join(self.root, name)
        shutil.copytree(source, target, ignore=shutil.ignore_patterns("__pycache__"))
        _make_readable(target)
        return target

    def _stage(self, stage, network, mounts, env, command, timeout):
        name = "heldout-%s-%s" % (stage, secrets.token_hex(6))
        argv = docker_argv(name, self.spec["image"], network, mounts, env, command)
        return run_capped(argv, name, timeout, os.path.join(self.logs, stage + ".log"))

    def _install(self, stage, command, mounts):
        if not command:
            return
        env = {"HOME": "/tmp", "npm_config_cache": "/tmp/npm", "PIP_DISABLE_PIP_VERSION_CHECK": "1"}
        code = self._stage(stage, "bridge", mounts, env, ["sh", "-c", command], INSTALL_TIMEOUT)
        if code != 0:
            raise ToolError("suite %s: %s install exited %s" % (self.name, stage, code))

    def prepare(self):
        """Install, with network, before any test source exists on this machine."""
        self._install("tools", self.spec.get("tools_install"), [(self.tools, "/tools", "rw")])
        self._install(
            "deps", self.spec.get("deps_install"),
            [(self.pr, "/workspace/pr", "ro"), (self.deps, "/deps", "rw")],
        )
        node_modules = os.path.join(self.pr, "node_modules")
        if self.spec["framework"] == "node-test" and self.spec.get("deps_install") and not os.path.lexists(node_modules):
            os.symlink("/deps/node_modules", node_modules)

    def stage_tests(self, plain):
        """Copy this suite's tests in, refusing a suite that lacks any required kind."""
        source = os.path.join(plain, self.spec["tests_path"])
        pattern = TEST_FILE[self.spec["framework"]]
        for kind in KINDS:
            directory = os.path.join(source, kind)
            names = os.listdir(directory) if os.path.isdir(directory) else []
            if not any(pattern.match(item) for item in names):
                raise ToolError("suite %s has no %s tests in the private repo" % (self.name, kind))
        shutil.copytree(source, self.tests, symlinks=False)
        if self.spec["framework"] == "node-test":
            os.symlink("/tools/node_modules", os.path.join(self.tests, "node_modules"))
        _make_readable(self.tests)

    def adapter_mounts(self):
        return [
            (self.pr, "/workspace/pr", "ro"),
            (self.deps, "/deps", "ro"),
            (self.adapter, "/adapter", "ro"),
            (self.shim, "/adapter-shim", "ro"),
        ]

    def test_mounts(self):
        return [
            (self.tools, "/tools", "ro"),
            (self.harness, "/harness", "ro"),
            (self.tests, "/suite", "ro"),
            (self.results, "/results", "rw"),
        ]

    def execute(self, mode):
        """Start PR code, then the tests. The two mount lists share nothing."""
        adapter_name = "heldout-adapter-%s" % secrets.token_hex(6)
        adapter_argv = docker_argv(
            adapter_name, self.spec["image"], "none", self.adapter_mounts(), adapter_env(self.spec),
            adapter_command(self.spec), interactive=True,
        )
        env = _docker_env()
        try:
            adapter = subprocess.Popen(adapter_argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        except OSError as error:
            raise ToolError("docker could not start: %s" % type(error).__name__)
        threading.Thread(
            target=_drain_to_log, args=(adapter.stderr, os.path.join(self.logs, "adapter.log")), daemon=True,
        ).start()
        settings = self.spec["adapter"]
        broker = Broker(adapter, adapter_name, settings["exports"], settings.get("call_timeout_seconds", 30))
        if not broker.wait_ready():
            adapter.wait()
            if adapter.returncode in DOCKER_FAILURES:
                raise ToolError("suite %s: docker could not start the adapter" % self.name)
            return judge(self.spec, None, None, mode, broker)
        code = self._run_tests(broker)
        broker.finish()
        adapter.wait()
        parsed = parse_junit(os.path.join(self.results, "junit.xml"))
        return judge(self.spec, code, parsed, mode, broker)

    def _run_tests(self, broker):
        name = "heldout-tests-%s" % secrets.token_hex(6)
        argv = docker_argv(
            name, self.spec["image"], "none", self.test_mounts(), test_env(self.spec), test_command(self.spec), interactive=True,
        )
        try:
            tests = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=_docker_env())
        except OSError as error:
            raise ToolError("docker could not start: %s" % type(error).__name__)
        threading.Thread(
            target=_drain_to_log, args=(tests.stderr, os.path.join(self.logs, "test.log")), daemon=True,
        ).start()
        relay = threading.Thread(target=broker.serve, args=(tests,), daemon=True)
        relay.start()
        try:
            code = tests.wait(timeout=self.spec.get("timeout_seconds", 600))
        except subprocess.TimeoutExpired:
            _remove_container(name)
            tests.kill()
            tests.wait()
            code = None
        relay.join(timeout=10)
        if code in DOCKER_FAILURES:
            raise ToolError("suite %s: docker could not run the tests (%d)" % (self.name, code))
        return code


def _write_diagnostics(path, key, aad, work):
    """Seal logs for maintainers. They hold test names and output, so never plain."""
    bundle = os.path.join(work, ".diagnostics")
    os.makedirs(bundle)
    for name in os.listdir(work):
        for part in ("logs", "results"):
            source = os.path.join(work, name, part)
            if os.path.isdir(source):
                shutil.copytree(source, os.path.join(bundle, name, part), symlinks=True)
    with open(path, "wb") as output:
        output.write(seal_bytes(key, _pack(bundle), aad + "|diagnostics"))


def run_suites(config, args):
    if "heldout" not in config:
        raise ToolError("config has no heldout section")
    check = subprocess.run(["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if check.returncode != 0:
        raise ToolError("docker is not available; held-out tests never run outside the sandbox")
    key = _load_key()
    mode = config["heldout"].get("mode", "block")
    os.makedirs(args.work_dir, exist_ok=True)
    work = os.path.abspath(args.work_dir)
    config_dir = os.path.dirname(os.path.abspath(args.config))
    suites = [Suite(spec, work, args.pr_dir, config_dir) for spec in config["heldout"]["suites"]]
    for suite in suites:
        suite.prepare()
    # Decrypt only now: PR install scripts have finished, and they had the network.
    with open(args.bundle, "rb") as source:
        data = open_bytes(key, source.read(), args.aad)
    plain = os.path.join(work, ".plain")
    _unpack(data, plain)
    findings = []
    try:
        for suite in suites:
            suite.stage_tests(plain)
        shutil.rmtree(plain)
        for suite in suites:
            findings += suite.execute(mode)
    finally:
        shutil.rmtree(plain, ignore_errors=True)
        if args.diagnostics:
            _write_diagnostics(args.diagnostics, key, args.aad, work)
    return findings


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("seal", "open"):
        sub = commands.add_parser(name)
        sub.add_argument("--input", required=True)
        sub.add_argument("--output", required=True)
        sub.add_argument("--aad", required=True, help="context the file is bound to, such as run id and commit")
    run = commands.add_parser("run")
    run.add_argument("--config", required=True)
    run.add_argument("--pr-dir", required=True)
    run.add_argument("--bundle", required=True)
    run.add_argument("--aad", required=True)
    run.add_argument("--work-dir", required=True)
    run.add_argument("--findings", required=True)
    run.add_argument("--diagnostics")
    args = parser.parse_args(argv)
    try:
        if args.command == "seal":
            with open(args.output, "wb") as output:
                output.write(seal_bytes(_load_key(), _pack(args.input), args.aad))
            return EXIT_OK
        if args.command == "open":
            with open(args.input, "rb") as source:
                _unpack(open_bytes(_load_key(), source.read(), args.aad), args.output)
            return EXIT_OK
        findings = run_suites(load_config(args.config), args)
        write_json(args.findings, findings)
        print("held-out gate: %d findings" % len(findings))
        return exit_code(findings)
    except (ToolError, OSError, shutil.Error, tarfile.TarError) as error:
        message = str(error) if isinstance(error, ToolError) else type(error).__name__
        if args.command == "run":
            write_json(args.findings, [finding(GATE, "HLD900", "high", "block", "", 0, message)])
        print("tool error: %s" % message, file=sys.stderr)
        return exit_code([], tool_error=True)


if __name__ == "__main__":
    sys.exit(main())
