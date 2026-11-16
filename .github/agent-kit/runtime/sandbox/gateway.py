#!/usr/bin/env python3
"""Credential gateway, running outside the agent container (P1.1, P2.8).

Each port forwards to one fixed upstream and adds a credential the agent never
holds. Credentials arrive once on stdin as a JSON line, so they appear in no
environment variable, argument, mount or image. Anything the agent sends for
authentication is discarded, only listed methods and paths pass, and any
credential echoed by an upstream is masked before the agent sees it.

GitHub goes through here rather than the proxy: a tunnel to github.com would
let an injected agent use a token of its own against any repository.
"""
import base64
import http.client
import json
import re
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te",
    "trailer", "transfer-encoding", "upgrade",
}
# Never forwarded from the agent.
DROPPED_REQUEST_HEADERS = HOP_HEADERS | {
    "authorization", "x-api-key", "cookie", "host", "accept-encoding", "forwarded",
    "x-forwarded-for", "x-forwarded-host", "x-real-ip",
    # A method override could turn an allowed GET into a write upstream.
    "x-http-method-override", "x-http-method", "x-method-override",
}
BAD_PATH = re.compile(r"\.\.|//|\\|%2e|%2f|%5c", re.IGNORECASE)
REPO_NAME = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
GIT_SERVICES = {"git-upload-pack", "git-receive-pack"}
MAX_FLAG_BYTES = 16 * 1024
MAX_FLAGS_PER_TASK = 20
UPSTREAM_TIMEOUT = 600
AGENT_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,38}$")
BRANCH_PREFIX = re.compile(r"^agent/[a-z0-9][a-z0-9-]{0,38}/$")
SCOPE_KEYS = {"issue", "pr", "branch_prefix"}
# GitHub API writes a scoped task may make (GA-09), relative to /repos/<owner>/<name>.
NUMBER = r"([1-9][0-9]{0,9})"
WRITE_RULES = [
    ("POST", re.compile(r"^/issues/" + NUMBER + r"/comments$"), "comment"),
    ("POST", re.compile(r"^/pulls$"), "open-pr"),
    ("PATCH", re.compile(r"^/pulls/" + NUMBER + r"$"), "edit-pr"),
]
# Body keys allowed per write. `issue` on POST /pulls would turn an existing
# issue into a PR, and `head_repo` would open it from another repository.
OPEN_PR_KEYS = {"title", "body", "head", "base", "draft", "maintainer_can_modify"}
EDIT_PR_KEYS = {"title", "body"}
COMMENT_KEYS = {"body"}
MAX_CAPTURE = 1024 * 1024

# Content checks on what the agent posts (GA-12, AP 9.3).
MAX_WRITE_BODY = 256 * 1024     # whole request, after JSON escaping
MAX_FIELD_CHARS = 65536         # GitHub's own limit for a comment or PR body
CHECKED_FIELDS = ("title", "body")
DEFAULT_LINK_HOSTS = ("github.com",)
MENTION_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})(?:/[A-Za-z0-9_.-]{1,100})?$")
LINK_HOST = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")
# Credential shapes: inventory/validate.py's _CREDENTIAL_SHAPES and
# kit/scripts/redact_session_log.py's patterns, kept here because the gateway
# container carries only this file. test_sandbox_unit checks they still cover
# validate.py's.
CREDENTIAL_SHAPES = re.compile(
    r"gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}"
    r"|sk-ant-[A-Za-z0-9_-]{10,}|(?:AKIA|ASIA)[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY"
    r"|xox[abprs]-[A-Za-z0-9-]{10,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}"
)
MIN_LEAK_FORM = 8
# @login or @org/team, not inside an email address or a path.
MENTION = re.compile(r"(?<![A-Za-z0-9_.+/@`-])@([A-Za-z0-9](?:[A-Za-z0-9-]{0,38})(?:/[A-Za-z0-9_.-]+)?)")
MD_IMAGE = re.compile(r"!\[([^\]\n]*)\]\(\s*<?([^)\s>]*)>?(?:\s+(?:\"[^\"\n]*\"|'[^'\n]*'|\([^)\n]*\)))?\s*\)")
MD_LINK = re.compile(r"\[([^\]\n]*)\]\(\s*<?([^)\s>]*)>?(?:\s+(?:\"[^\"\n]*\"|'[^'\n]*'|\([^)\n]*\)))?\s*\)")
MD_REF_DEF = re.compile(r"(?m)^[ \t]{0,3}\[[^\]\n]+\]:[ \t]*<?(\S+?)>?(?:[ \t]+.*)?$")
HTML_TAG = re.compile(r"<[A-Za-z][^>]*>")
HTML_URL_ATTR = re.compile(
    r"(?i)\b(?:src|href|srcset|poster|background|action|data|formaction|xlink:href|cite|longdesc)"
    r"\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]+)")
BARE_URL = re.compile(r"(?i)\b(https?)://([^\s<>\"'()\[\]]+)|(?<![\w.-])(www\.[^\s<>\"'()\[\]]+)")


def task_scope(agent, issue=None, pr=None):
    """What one task may write to (G1.1): its issue, its own PR, its branch prefix.

    `issue` is the triggering issue. `pr` is the agent's own PR when it already
    exists at dispatch (a re-dispatch on that PR); for a new task it is None
    until the agent opens one. The branch prefix comes from the agent name, set
    by the trusted caller, never by the agent.
    """
    if not isinstance(agent, str) or not AGENT_NAME.match(agent):
        raise ValueError("agent must match " + AGENT_NAME.pattern + ": " + repr(agent))
    return check_scope({"issue": issue, "pr": pr, "branch_prefix": "agent/" + agent + "/"})


def check_scope(scope):
    """Return the scope if it is well formed, otherwise raise ValueError."""
    if not isinstance(scope, dict) or set(scope) != SCOPE_KEYS:
        raise ValueError("task scope must have exactly " + ", ".join(sorted(SCOPE_KEYS)))
    for name in ("issue", "pr"):
        number = scope[name]
        if number is not None and (type(number) is not int or number < 1):
            raise ValueError(name + " must be a positive integer: " + repr(number))
    if scope["issue"] is None and scope["pr"] is None:
        raise ValueError("a task scope needs an issue, a PR, or both")
    prefix = scope["branch_prefix"]
    if not isinstance(prefix, str) or not BRANCH_PREFIX.match(prefix):
        raise ValueError("branch prefix must be agent/<agent>/: " + repr(prefix))
    return dict(scope)


def build_config(repo, model_upstream="https://api.anthropic.com",
                 git_upstream="https://github.com",
                 api_upstream="https://api.github.com",
                 allow_insecure_upstream=False, extra_ca_pem=None, scope=None,
                 mentions=(), link_hosts=DEFAULT_LINK_HOSTS, task_id=None, agent=None):
    """Gateway config for one task.

    `scope` is a task_scope() result. The GitHub API route allows only the
    writes in WRITE_RULES within it, and no writes at all without one (GA-09).
    Allowed writes then pass the content checks (GA-12): `mentions` are the
    logins or org/team names the agent may @mention, and `link_hosts` the hosts
    (and their subdomains) its links and images may point to.
    Git ref limits are GA-10. `task_id` and `agent` label each model call's
    usage record (GA-14); the runner, not the agent, supplies them.
    """
    if not REPO_NAME.match(repo) or ".." in repo:
        raise ValueError("repo must be owner/name: " + repo)
    if scope is not None:
        scope = check_scope(scope)
    for name in mentions:
        if not isinstance(name, str) or not MENTION_NAME.match(name):
            raise ValueError("mention must be a login or org/team: " + repr(name))
    for host in link_hosts:
        if not isinstance(host, str) or not LINK_HOST.match(host):
            raise ValueError("link host must be a lower-case host name: " + repr(host))
    if agent is not None and not (isinstance(agent, str) and AGENT_NAME.match(agent)):
        raise ValueError("agent must match " + AGENT_NAME.pattern + ": " + repr(agent))
    if task_id is not None and not (isinstance(task_id, str) and re.match(r"^[A-Za-z0-9_.-]{1,64}$", task_id)):
        raise ValueError("task id must be 1-64 letters, digits, '.', '_' or '-': " + repr(task_id))
    quoted = re.escape(repo)
    return {
        "allow_insecure_upstream": allow_insecure_upstream,
        "labels": {"task_id": task_id, "agent": agent},
        "task_scope": scope,
        "content": {
            "mentions": sorted({name.lower() for name in mentions}),
            "link_hosts": sorted(set(link_hosts)),
        },
        # A private CA for upstreams, such as a corporate model gateway.
        # Public CAs stay trusted as well.
        "extra_ca_pem": extra_ca_pem,
        "flag_port": 8083,
        "routes": [
            {
                "name": "model", "port": 8080, "upstream": model_upstream, "secret": "model",
                "auth": {"header": "x-api-key", "style": "raw"},
                "methods": ["POST"],
                "paths": [r"^/v1/messages(/count_tokens)?$"],
                "max_body": 32 * 1024 * 1024,
                "usage": True,
            },
            {
                "name": "git", "port": 8081, "upstream": git_upstream, "secret": "github",
                "auth": {"header": "Authorization", "style": "git-basic"},
                "methods": ["GET", "POST"],
                "paths": ["(?i)^/" + quoted + r"(\.git)?/(info/refs|git-upload-pack|git-receive-pack)$"],
                "git": True,
                "max_body": 512 * 1024 * 1024,
            },
            {
                "name": "github-api", "port": 8082, "upstream": api_upstream, "secret": "github",
                "auth": {"header": "Authorization", "style": "bearer"},
                "methods": ["GET", "POST", "PATCH"],
                "paths": ["(?i)^/repos/" + quoted + r"(/(pulls|issues|commits|compare)(/[^?]*)?)?$"],
                "max_body": 8 * 1024 * 1024,
                "repo": repo,
                "scoped_writes": True,
            },
        ],
    }


def request_allowed(route, method, target):
    """Return None if the request may pass, otherwise a short reason."""
    if method not in route["methods"]:
        return "method"
    if not target.startswith("/") or BAD_PATH.search(target):
        return "path"
    path, _, query = target.partition("?")
    if not any(re.match(pattern, path) for pattern in route["paths"]):
        return "path"
    if route.get("git"):
        if path.endswith("/info/refs"):
            if method != "GET" or query not in {"service=" + s for s in GIT_SERVICES}:
                return "query"
        elif method != "POST" or query:
            return "method"
    return None


def _no_duplicate_keys(pairs):
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)):
        # GitHub and this check could read a repeated key differently.
        raise ValueError("duplicate key")
    return dict(pairs)


def json_object(body):
    try:
        value = json.loads(body.decode("utf-8"), object_pairs_hook=_no_duplicate_keys)
    except (UnicodeDecodeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def write_allowed(route, scope, pr, method, path, body):
    """Check a GitHub API write against the task scope (GA-09).

    `pr` is the agent's own PR as the gateway knows it now: the scope's, or the
    one the agent opened during this task. Return (None, kind) if the write may
    pass, otherwise (reason, kind).
    """
    if scope is None:
        return "no-scope", None
    rel = path[len("/repos/") + len(route["repo"]):]
    for rule_method, pattern, kind in WRITE_RULES:
        match = pattern.match(rel) if rule_method == method else None
        if match:
            break
    else:
        return "write-not-allowed", None
    fields = json_object(body or b"")
    if fields is None:
        return "body-not-json-object", kind
    if kind == "comment":
        target = int(match.group(1))
        if target not in {scope["issue"], pr} - {None}:
            return "comment-outside-task", kind
        allowed = COMMENT_KEYS
    elif kind == "edit-pr":
        if pr is None or int(match.group(1)) != pr:
            return "not-own-pr", kind
        allowed = EDIT_PR_KEYS
    else:
        if pr is not None:
            return "task-already-has-pr", kind
        why = check_head(fields.get("head"), route["repo"], scope["branch_prefix"])
        if why:
            return why, kind
        allowed = OPEN_PR_KEYS
    extra = set(fields) - allowed
    if extra:
        return "field-not-allowed:" + ",".join(sorted(extra))[:100], kind
    return None, kind


def read_allowed(route, scope, pr, path):
    """GA-13: which GitHub API reads a task may make, relative to its scope.

    Comments and reviews are never read through the gateway: the runner's
    snapshot holds the ones by people with write access. Issues and PRs are
    readable only when they're the task's own; repository code, commits and
    comparisons stay readable, except commit comments and the PRs a commit
    belongs to. Return None if allowed, otherwise a reason.
    """
    rel = path[len("/repos/") + len(route["repo"]):]
    if rel == "" or re.match(r"^/compare/.+$", rel):
        return None
    if re.match(r"^/commits(/[0-9A-Za-z._-]+(/(check-runs|check-suites|status|statuses))?)?$", rel):
        return None
    if scope is None:
        return "no-scope"
    own = {scope["issue"], pr} - {None}
    match = re.match(r"^/issues/" + NUMBER + r"$", rel)
    if match:
        return None if int(match.group(1)) in own else "issue-outside-task"
    match = re.match(r"^/pulls/" + NUMBER + r"(/(files|commits))?$", rel)
    if match:
        return None if pr is not None and int(match.group(1)) == pr else "not-own-pr"
    if re.search(r"/comments$|/reviews$|/comments/|/reviews/|/timeline$|/events$", rel):
        return "comments-in-snapshot"
    return "read-not-allowed"


def check_head(head, repo, prefix):
    if not isinstance(head, str):
        return "head-missing"
    owner, sep, branch = head.rpartition(":")
    if sep and owner.lower() != repo.split("/")[0].lower():
        return "head-other-owner"
    if not branch.startswith(prefix) or len(branch) == len(prefix):
        return "head-outside-prefix"
    if ".." in branch or "//" in branch or branch.endswith("/") or re.search(r"[\s~^:?*\[\\@{]", branch):
        return "head-bad-name"
    return None


MAX_PUSH_COMMANDS = 100
PUSH_COMMAND = re.compile(rb"^(?:([0-9a-f]{40}) ([0-9a-f]{40})|([0-9a-f]{64}) ([0-9a-f]{64})) (refs/[^\x00\n]+)")


class PushRefused(Exception):
    pass


class ChunkReader:
    """Reads exact byte counts from an iterable of chunks, keeping what it read."""

    def __init__(self, chunks):
        self.chunks = iter(chunks or [])
        self.buffer = b""
        self.consumed = []

    def read(self, size):
        while len(self.buffer) < size:
            chunk = next(self.chunks, None)
            if chunk is None:
                raise PushRefused("push-truncated")
            self.buffer += chunk
        data, self.buffer = self.buffer[:size], self.buffer[size:]
        self.consumed.append(data)
        return data

    def at_end(self):
        while not self.buffer:
            chunk = next(self.chunks, None)
            if chunk is None:
                return True
            self.buffer = chunk
        return False

    def rest(self):
        """Every byte, the ones already read first, in the order received."""
        yield b"".join(self.consumed) + self.buffer
        yield from self.chunks


def read_push_commands(reader):
    """Parse the ref-update commands that start a git-receive-pack request.

    They come as pkt-lines before the pack: optional `shallow <oid>` lines, then
    `<old> <new> <ref>` lines (the first carries capabilities after a NUL), then
    a flush. Returns [(old, new, ref)]. Anything unexpected raises PushRefused.
    """
    commands = []
    while True:
        size_text = reader.read(4)
        if not re.fullmatch(rb"[0-9a-f]{4}", size_text):
            raise PushRefused("push-malformed")
        size = int(size_text, 16)
        if size == 0:
            if not commands and reader.at_end():
                # A lone flush: git's probe before a large chunked push. It
                # updates no ref, so it passes with no commands.
                return []
            break
        if size < 5 or size > 65520:
            raise PushRefused("push-malformed")  # 0001 and 0002 are protocol v2, not push
        line = reader.read(size - 4)
        if line.startswith(b"shallow ") and not commands:
            continue
        if line.startswith(b"push-cert"):
            raise PushRefused("push-cert")
        match = PUSH_COMMAND.match(line)
        if not match:
            raise PushRefused("push-malformed")
        old, new = (match.group(1), match.group(2)) if match.group(1) else (match.group(3), match.group(4))
        rest = line[match.end():]
        if rest not in (b"", b"\n") and not (not commands and rest.startswith(b"\x00")):
            raise PushRefused("push-malformed")
        commands.append((old.decode(), new.decode(), match.group(5).decode("utf-8", "replace")))
        if len(commands) > MAX_PUSH_COMMANDS:
            raise PushRefused("push-too-many-refs")
    if not commands:
        raise PushRefused("push-no-commands")
    return commands


def push_allowed(scope, commands):
    """GA-10: a push may only create or update branches under the task's prefix.

    Return None if every command may pass, otherwise a reason naming the first
    one that may not.
    """
    if scope is None:
        return "no-scope"
    if not commands:
        return None  # the probe read_push_commands allows
    prefix = "refs/heads/" + scope["branch_prefix"]
    for old, new, ref in commands:
        if set(new) == {"0"}:
            return "ref-delete:" + ref[:200]
        if not ref.startswith(prefix):
            return "ref-outside-prefix:" + ref[:200]
        branch = ref[len("refs/heads/"):]
        if (len(ref) == len(prefix) or ".." in branch or "//" in branch or branch.endswith(("/", ".", ".lock"))
                or "/." in branch or "@{" in branch or re.search(r"[\x00-\x20\x7f~^:?*\[\\]", branch)):
            return "ref-bad-name:" + ref[:200]
    return None


def url_allowed(url, hosts):
    """True for a relative link, an in-page anchor, or http(s) to an allowed host."""
    url = url.strip()
    if not url or url.startswith("#"):
        return True
    if "\\" in url or any(ord(c) < 33 or ord(c) == 127 for c in url):
        return False
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        has_userinfo = parts.username is not None or parts.password is not None
    except ValueError:
        return False
    if not parts.scheme and not parts.netloc:
        return True  # relative to the repository on github.com
    if parts.scheme not in ("", "http", "https") or has_userinfo:
        return False
    return any(host == allowed or host.endswith("." + allowed) for allowed in hosts)


INLINE_CODE = re.compile(r"(?ms)^[ \t]{0,3}(`{3,}|~{3,})[^\n]*\n.*?^[ \t]{0,3}\1[`~]*[ \t]*$|(`+)[^`\n]+?\2")


def _strip_mentions(text, allowed):
    count = 0

    def one(match):
        nonlocal count
        if match.group(1).lower() in allowed:
            return match.group(0)
        count += 1
        return match.group(1)  # the name stays readable, without the @

    # Mentions in code don't notify anyone, so code is left as written.
    pieces, last = [], 0
    for code in INLINE_CODE.finditer(text):
        pieces.append(MENTION.sub(one, text[last:code.start()]))
        pieces.append(code.group(0))
        last = code.end()
    pieces.append(MENTION.sub(one, text[last:]))
    return "".join(pieces), count


def _strip_links_once(text, hosts, counts):
    def image(match):
        if url_allowed(match.group(2), hosts):
            return match.group(0)
        counts["images"] += 1
        return "[image removed]"

    def link(match):
        if url_allowed(match.group(2), hosts):
            return match.group(0)
        counts["links"] += 1
        return match.group(1)

    def ref_def(match):
        if url_allowed(match.group(1), hosts):
            return match.group(0)
        counts["links"] += 1
        return ""

    def tag(match):
        for value in HTML_URL_ATTR.findall(match.group(0)):
            value = value.strip("\"'")
            urls = [part.split()[0] for part in value.split(",") if part.split()] or [""]
            if not all(url_allowed(url, hosts) for url in urls):
                counts["html"] += 1
                return ""
        return match.group(0)

    def bare(match):
        if match.group(1):
            if url_allowed(match.group(0), hosts):
                return match.group(0)
            counts["urls"] += 1
            scheme = "hxxps" if match.group(1).lower() == "https" else "hxxp"
            return scheme + "://" + match.group(2)
        if url_allowed("https://" + match.group(3), hosts):
            return match.group(0)
        counts["urls"] += 1
        return "www[.]" + match.group(3)[4:]

    text = MD_IMAGE.sub(image, text)
    text = MD_LINK.sub(link, text)
    text = MD_REF_DEF.sub(ref_def, text)
    text = HTML_TAG.sub(tag, text)
    return BARE_URL.sub(bare, text)


def clean_text(text, content):
    """Strip outside mentions, images and links from text the agent posts.

    Returns (text, counts), or (None, counts) if the text doesn't settle, which
    the caller refuses. This is a backstop for the plain case, not a Markdown
    parser: GA-12's content checks stop an obvious leak, not a disguised one.
    """
    counts = {"mentions": 0, "images": 0, "links": 0, "html": 0, "urls": 0}
    hosts = content["link_hosts"]
    for _ in range(5):
        cleaned = _strip_links_once(text, hosts, counts)
        if cleaned == text:
            break
        text = cleaned
    else:
        return None, counts
    text, counts["mentions"] = _strip_mentions(text, set(content["mentions"]))
    return text, counts


def check_content(fields, raw, leak_forms, content):
    """GA-12 checks on an allowed write. Return (reason, fields to send, counts)."""
    if len(raw) > MAX_WRITE_BODY:
        return "body-too-large", None, {}
    texts = [raw.decode("utf-8", "replace")]
    texts += [value for value in fields.values() if isinstance(value, str)]
    for text in texts:
        if CREDENTIAL_SHAPES.search(text):
            return "credential-shape", None, {}
        data = text.encode("utf-8")
        for form, kind in leak_forms:
            if form in data:
                return kind, None, {}
    cleaned, totals = dict(fields), {}
    for key in CHECKED_FIELDS:
        value = fields.get(key)
        if value is None:
            continue
        if not isinstance(value, str):
            return "field-not-text:" + key, None, {}
        if len(value) > MAX_FIELD_CHARS:
            return "field-too-long:" + key, None, {}
        cleaned[key], counts = clean_text(value, content)
        if cleaned[key] is None:
            return "content-unsettled:" + key, None, {}
        for name, number in counts.items():
            if number:
                totals[name] = totals.get(name, 0) + number
    return None, cleaned, totals


def leak_forms(secrets):
    """What a posted body must not contain: the gateway's secrets and the task's canaries."""
    forms = []
    for name, secret in secrets.items():
        values = secret if name == "canaries" else [secret]
        kind = "canary" if name == "canaries" else "gateway-secret"
        for value in values:
            if not isinstance(value, str) or len(value) < MIN_LEAK_FORM:
                continue
            raw = value.encode()
            for form in (raw, base64.b64encode(raw), auth_value("git-basic", value).split(" ", 1)[1].encode()):
                forms.append((form, kind))
    return forms


def auth_value(style, secret):
    if style == "raw":
        return secret
    if style == "bearer":
        return "Bearer " + secret
    if style == "git-basic":
        pair = "x-access-token:" + secret
        return "Basic " + base64.b64encode(pair.encode()).decode()
    raise ValueError("unknown auth style: " + style)


def secret_forms(secrets):
    forms = set()
    for secret in secrets.values():
        if not isinstance(secret, str):
            continue  # canaries: refused in posts, not masked in responses
        forms.add(secret.encode())
        forms.add(auth_value("git-basic", secret).split(" ", 1)[1].encode())
    return sorted(forms, key=len, reverse=True)


USAGE_KEYS = ("input_tokens", "output_tokens", "cache_creation_input_tokens", "cache_read_input_tokens")
MAX_USAGE_LINE = 1024 * 1024        # an SSE data line longer than this isn't read
MAX_USAGE_JSON = 16 * 1024 * 1024   # a plain JSON response longer than this isn't read


class UsageTracker:
    """Reads token usage from a model response as it passes through (GA-14).

    Streamed responses (text/event-stream) carry usage in `message_start`
    (`message.usage`) and `message_delta` (`usage`); later values are running
    totals, so the latest value of each key wins. A plain JSON response carries
    `usage` at the top level. The relay is never held up: chunks are only read.
    """

    def __init__(self, content_type):
        self.stream = "text/event-stream" in (content_type or "").lower()
        self.usage = {}
        self.model = None
        self.line = b""
        self.body = []
        self.size = 0
        self.overflow = False

    def feed(self, chunk):
        if not self.stream:
            self.size += len(chunk)
            if self.size <= MAX_USAGE_JSON:
                self.body.append(chunk)
            else:
                self.overflow, self.body = True, []
            return
        data = self.line + chunk
        lines = data.split(b"\n")
        self.line = lines.pop()
        if len(self.line) > MAX_USAGE_LINE:
            self.line, self.overflow = b"", True
        for line in lines:
            self._sse_line(line.rstrip(b"\r"))

    def _sse_line(self, line):
        if not line.startswith(b"data:"):
            return
        try:
            event = json.loads(line[5:].decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return
        if not isinstance(event, dict):
            return
        message = event.get("message") if isinstance(event.get("message"), dict) else {}
        self._take(message.get("model"), message.get("usage"))
        self._take(None, event.get("usage"))

    def _take(self, model, usage):
        if isinstance(model, str) and self.model is None:
            self.model = model[:100]
        if not isinstance(usage, dict):
            return
        for key in USAGE_KEYS:
            value = usage.get(key)
            if type(value) is int and value >= 0:
                self.usage[key] = value

    def finish(self):
        """Return (model, usage dict) once the response has ended or broken off."""
        if self.stream:
            if self.line:
                self._sse_line(self.line.rstrip(b"\r"))
                self.line = b""
        elif self.body:
            fields = json_object(b"".join(self.body))
            if fields:
                self._take(fields.get("model"), fields.get("usage"))
            self.body = []
        return self.model, dict(self.usage)


class Scrubber:
    """Masks secrets in a stream, keeping length so Content-Length stays true."""

    def __init__(self, forms):
        self.forms = forms
        self.tail = b""

    def _held_back(self, data):
        best = 0
        for form in self.forms:
            for size in range(min(len(form) - 1, len(data)), best, -1):
                if data.endswith(form[:size]):
                    best = size
                    break
        return best

    def feed(self, chunk):
        data = self.tail + chunk
        for form in self.forms:
            data = data.replace(form, b"*" * len(form))
        hold = self._held_back(data)
        self.tail = data[len(data) - hold:] if hold else b""
        return data[:len(data) - hold] if hold else data

    def finish(self):
        data, self.tail = self.tail, b""
        return data


class State:
    def __init__(self, config, secrets):
        self.config = config
        self.secrets = secrets
        self.forms = secret_forms(secrets)
        self.flags = 0
        self.lock = threading.Lock()
        self.scope = config.get("task_scope")
        # The agent's own PR: given at dispatch, or learned when it opens one.
        self.pr = self.scope["pr"] if self.scope else None
        self.opening_pr = False  # a POST /pulls is in flight
        self.opened_pr = False   # one was created, even if its number was unreadable
        self.content = config.get("content") or {
            "mentions": [], "link_hosts": list(DEFAULT_LINK_HOSTS)}
        self.leak_forms = leak_forms(secrets)


def log(**fields):
    # One JSON object per line, so agent text can't forge a log record.
    print(json.dumps(fields, sort_keys=True), flush=True)


def tls_context(config):
    context = ssl.create_default_context()
    if config.get("extra_ca_pem"):
        context.load_verify_locations(cadata=config["extra_ca_pem"])
    return context


def open_upstream(route, config):
    parts = urlsplit(route["upstream"])
    if parts.scheme == "https":
        return http.client.HTTPSConnection(
            parts.hostname, parts.port or 443,
            context=tls_context(config), timeout=UPSTREAM_TIMEOUT,
        )
    if parts.scheme == "http" and config.get("allow_insecure_upstream"):
        return http.client.HTTPConnection(parts.hostname, parts.port or 80, timeout=UPSTREAM_TIMEOUT)
    raise ValueError("upstream must be https")


class BaseHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # requests are logged as JSON instead
        pass

    def reply(self, status, text):
        body = (text + "\n").encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Type", "text/plain")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        self.wfile.write(body)


def body_reader(handler, limit):
    """Return (iterable or None, headers to send) for the request body."""
    if "chunked" in handler.headers.get("Transfer-Encoding", "").lower():
        return read_chunked(handler.rfile, limit), {"Transfer-Encoding": "chunked"}
    length = int(handler.headers.get("Content-Length") or 0)
    if length > limit:
        raise OverflowError
    if not length:
        return None, {"Content-Length": "0"}
    return read_sized(handler.rfile, length), {"Content-Length": str(length)}


def read_sized(stream, length):
    while length:
        chunk = stream.read(min(65536, length))
        if not chunk:
            raise ConnectionError("short request body")
        length -= len(chunk)
        yield chunk


def read_chunked(stream, limit):
    total = 0
    while True:
        size = int(stream.readline(64).split(b";", 1)[0].strip(), 16)
        if size == 0:
            while stream.readline(8192).strip():
                pass
            return
        total += size
        if total > limit:
            raise OverflowError
        yield from read_sized(stream, size)
        stream.readline(8)


def make_proxy_handler(route, state):
    class Handler(BaseHandler):
        def forward(self):
            why = request_allowed(route, self.command, self.path)
            checked = route.get("scoped_writes") and self.command != "GET"
            if not why and route.get("scoped_writes") and self.command == "GET":
                with state.lock:
                    why = read_allowed(route, state.scope, state.pr, self.path.partition("?")[0])
            pushing = (route.get("git") and self.command == "POST"
                       and self.path.partition("?")[0].endswith("/git-receive-pack"))
            if why or not (checked or pushing):
                log(event="gateway", route=route["name"], method=self.command,
                    path=self.path[:300], decision="deny" if why else "allow", reason=why)
                if why:
                    self.reply(403, "Forbidden by gateway policy")
                    return
            limit = min(route["max_body"], MAX_WRITE_BODY) if checked else route["max_body"]
            try:
                body, length_headers = body_reader(self, limit)
                if checked:
                    # A write is judged on its whole body.
                    body = b"".join(body or [])
            except (OverflowError, ValueError, ConnectionError) as exc:
                if checked:
                    log(event="gateway", route=route["name"], method=self.command,
                        path=self.path[:300], decision="deny",
                        reason="body-too-large" if isinstance(exc, OverflowError) else "body-unreadable")
                self.reply(413, "Request body rejected")
                return
            kind = None
            if checked:
                kind, body = self.check_write(body)
                if kind is False:
                    return
                length_headers = {"Content-Length": str(len(body))}
            if pushing:
                body = self.check_push(body)
                if body is False:
                    return
            try:
                self.send_upstream(body, length_headers, kind)
            finally:
                if kind == "open-pr":
                    with state.lock:
                        state.opening_pr = False

        def check_push(self, body):
            """Apply the ref limits (GA-10) and log the decision.

            Return the body to send, unchanged byte for byte, or False if refused.
            """
            commands = []
            encoding = self.headers.get("Content-Encoding", "").strip().lower()
            if encoding not in ("", "identity"):
                why = "push-encoded"  # the commands couldn't be read, so they can't pass
            else:
                reader = ChunkReader(body)
                try:
                    commands = read_push_commands(reader)
                    why = push_allowed(state.scope, commands)
                except PushRefused as exc:
                    why = str(exc)
                except (ConnectionError, ValueError, OverflowError):
                    why = "push-truncated"
            log(event="gateway", route=route["name"], method=self.command,
                path=self.path[:300], decision="deny" if why else "allow", reason=why,
                refs=[ref[:200] for _, _, ref in commands[:20]] or None)
            if why:
                self.reply(403, "Forbidden by gateway policy: " + why)
                return False
            return reader.rest()

        def check_write(self, body):
            """Apply the scope (GA-09) and content checks (GA-12), and log the decision.

            Return (kind, body to send), or (False, None) if refused.
            """
            path = self.path.partition("?")[0]
            stripped = {}
            with state.lock:
                why, kind = write_allowed(route, state.scope, state.pr, self.command, path, body)
            if self.path != path:
                why = why or "query-on-write"
            if not why:
                fields = json_object(body)
                why, cleaned, stripped = check_content(fields, body, state.leak_forms, state.content)
                if not why and cleaned != fields:
                    body = json.dumps(cleaned, ensure_ascii=False).encode("utf-8")
            if not why and kind == "open-pr":
                with state.lock:
                    if state.opening_pr or state.opened_pr:
                        why = "task-already-has-pr"
                    else:
                        state.opening_pr = True
            log(event="gateway", route=route["name"], method=self.command,
                path=self.path[:300], decision="deny" if why else "allow", reason=why,
                write=kind, stripped=stripped or None)
            if why:
                self.reply(403, "Forbidden by gateway policy: " + why)
                return False, None
            return kind, body

        def send_upstream(self, body, length_headers, kind):
            headers = {
                k: v for k, v in self.headers.items()
                if k.lower() not in DROPPED_REQUEST_HEADERS and k.lower() != "content-length"
            }
            headers.update(length_headers)
            headers["Accept-Encoding"] = "identity"  # keeps responses scrubbable
            headers[route["auth"]["header"]] = auth_value(
                route["auth"]["style"], state.secrets[route["secret"]]
            )
            try:
                upstream = open_upstream(route, state.config)
                upstream.request(
                    self.command, self.path, body=body, headers=headers,
                    encode_chunked=headers.get("Transfer-Encoding") == "chunked",
                )
                response = upstream.getresponse()
            except (OSError, http.client.HTTPException, OverflowError, ValueError) as exc:
                log(event="gateway-error", route=route["name"], error=type(exc).__name__)
                self.reply(502, "Upstream request failed")
                return
            if route.get("usage") and self.path.partition("?")[0] == "/v1/messages":
                tracker = UsageTracker(response.getheader("Content-Type"))
                try:
                    self.relay_response(response, observe=tracker.feed)
                finally:
                    # Logged even if the agent hung up: the call is billed either way.
                    self.record_usage(tracker, response.status)
                    upstream.close()
                return
            if kind != "open-pr":
                self.relay_response(response)
                upstream.close()
                return
            captured = None
            try:
                captured = self.relay_response(response, capture=True)
            finally:
                # Recorded even if the agent hung up, since the PR exists either way.
                if 200 <= response.status < 300:
                    self.record_pr(captured)
                upstream.close()

        def record_pr(self, captured):
            """Make the PR the agent just opened its own PR for the rest of the task."""
            fields = json_object(captured) if captured is not None else None
            number = fields.get("number") if fields else None
            if type(number) is not int or number < 1:
                number = None
            with state.lock:
                state.opened_pr = True
                if number is not None:
                    state.pr = number
            log(event="task-pr", pr=number, readable=number is not None)

        def record_usage(self, tracker, status):
            model, usage = tracker.finish()
            labels = state.config.get("labels") or {}
            log(event="model-usage", task_id=labels.get("task_id"), agent=labels.get("agent"),
                status=status, model=model, unread=tracker.overflow or not usage,
                **{key: usage.get(key, 0) for key in USAGE_KEYS})

        def relay_response(self, response, capture=False, observe=None):
            """Relay the response; with capture, also return its raw body (or None if too big).

            `observe`, if given, sees every raw chunk before it is scrubbed.
            """
            kept = [] if capture else None
            kept_size = 0
            scrubber = Scrubber(state.forms)
            self.send_response(response.status)
            length = response.getheader("Content-Length")
            for key, value in response.getheaders():
                if key.lower() in HOP_HEADERS:
                    continue
                masked = value
                for form in state.forms:
                    masked = masked.replace(form.decode(), "*" * len(form))
                self.send_header(key, masked)
            bodyless = self.command == "HEAD" or response.status in (204, 304)
            chunked = length is None and not bodyless
            if chunked:
                self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            if bodyless:
                return b"" if capture else None
            write = self.write_chunk if chunked else self.wfile.write
            while True:
                chunk = response.read1(65536)
                if not chunk:
                    break
                if observe is not None:
                    observe(chunk)
                if kept is not None:
                    kept_size += len(chunk)
                    if kept_size <= MAX_CAPTURE:
                        kept.append(chunk)
                    else:
                        kept = None
                out = scrubber.feed(chunk)
                if out:
                    write(out)
                    self.wfile.flush()
            rest = scrubber.finish()
            if rest:
                write(rest)
            if chunked:
                self.wfile.write(b"0\r\n\r\n")
            return b"".join(kept) if kept is not None else None

        def write_chunk(self, data):
            self.wfile.write(b"%x\r\n%s\r\n" % (len(data), data))

        do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = forward
        do_TRACE = do_CONNECT = forward

    return Handler


def make_flag_handler(state):
    class Handler(BaseHandler):
        def do_POST(self):
            if self.path != "/flag":
                self.reply(404, "Not found")
                return
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = -1
            if not 0 < length <= MAX_FLAG_BYTES:
                self.reply(413, "Flag must be 1 to 16384 bytes")
                return
            try:
                flag = json.loads(self.rfile.read(length).decode())
            except (UnicodeDecodeError, ValueError):
                self.reply(400, "Flag must be JSON")
                return
            if not isinstance(flag, dict):
                self.reply(400, "Flag must be a JSON object")
                return
            with state.lock:
                if state.flags >= MAX_FLAGS_PER_TASK:
                    self.reply(429, "Too many flags for this task")
                    return
                state.flags += 1
            text = json.dumps(flag)
            for form in state.forms:
                text = text.replace(form.decode(), "*" * len(form))
            log(event="flag", flag=json.loads(text))
            self.reply(200, "Flag recorded")

    return Handler


def start(config, secrets):
    state = State(config, secrets)
    servers = []
    for route in config["routes"]:
        if not secrets.get(route["secret"]):
            continue  # an absent credential means that route stays closed
        servers.append(ThreadingHTTPServer(("0.0.0.0", route["port"]), make_proxy_handler(route, state)))
    servers.append(ThreadingHTTPServer(("0.0.0.0", config["flag_port"]), make_flag_handler(state)))
    for server in servers:
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
    return servers


def main():
    import os
    config = json.loads(os.environ["GATEWAY_CONFIG"])
    secrets = json.loads(sys.stdin.readline())
    start(config, secrets)
    log(event="ready")
    threading.Event().wait()


if __name__ == "__main__":
    sys.exit(main())
