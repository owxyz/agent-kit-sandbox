"""GitHub App authentication and the narrow REST surface advisory agents use.

The only write `InstallationClient` will send is creating a check run, and tokens
are minted per repository with the agent's declared permissions.
"""
from __future__ import annotations

import base64
import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

from . import checks

# The ceiling for any advisory agent: read access plus checks, nothing else.
ALLOWED_PERMISSIONS = {"actions": "read", "contents": "read", "metadata": "read", "checks": "write"}
API = "https://api.github.com"
MAX_DOWNLOAD = 32 * 1024 * 1024
JSON_ACCEPT = "application/vnd.github+json"
DIFF_ACCEPT = "application/vnd.github.v3.diff"


class GitHubError(Exception):
    pass


@dataclass
class HttpResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes


Transport = Callable[[str, str, Dict[str, str], Optional[bytes]], HttpResponse]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


_opener = urllib.request.build_opener(_NoRedirect)


def http_transport(method: str, url: str, headers: Dict[str, str], body: Optional[bytes]) -> HttpResponse:
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with _opener.open(request, timeout=60) as response:
            return HttpResponse(response.status, dict(response.headers), response.read(MAX_DOWNLOAD + 1))
    except urllib.error.HTTPError as err:
        return HttpResponse(err.code, dict(err.headers or {}), err.read(65536))


def check_permissions(permissions: Mapping[str, str]) -> None:
    for name, level in permissions.items():
        if ALLOWED_PERMISSIONS.get(name) != level:
            raise ValueError(f"permission not allowed for an advisory agent: {name}={level}")


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def rs256_signer(private_key_pem: str) -> Callable[[bytes], bytes]:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    return lambda message: key.sign(message, padding.PKCS1v15(), hashes.SHA256())


class GitHubApp:
    """One App identity: signs JWTs and mints narrowed installation tokens."""

    def __init__(self, app_id: int, signer: Callable[[bytes], bytes], transport: Transport = http_transport,
                 clock: Callable[[], float] = time.time, api: str = API):
        if not api.startswith("https://"):
            raise ValueError("the GitHub API must be reached over HTTPS")
        self.app_id = int(app_id)
        self._signer = signer
        self._transport = transport
        self._clock = clock
        self._api = api
        self._tokens: Dict[Tuple[int, str, str], Tuple[str, float]] = {}
        self._lock = threading.Lock()

    def _jwt(self) -> str:
        now = int(self._clock())
        head = _b64(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
        claims = _b64(json.dumps({"iat": now - 60, "exp": now + 540, "iss": str(self.app_id)}).encode())
        signing_input = f"{head}.{claims}".encode()
        return f"{head}.{claims}.{_b64(self._signer(signing_input))}"

    def installation(self, installation_id: int, repo: str, permissions: Mapping[str, str]) -> "InstallationClient":
        check_permissions(permissions)
        return InstallationClient(self._token(installation_id, repo, permissions), repo, self._transport, self._clock, self._api)

    def _token(self, installation_id: int, repo: str, permissions: Mapping[str, str]) -> str:
        key = (installation_id, repo, json.dumps(dict(permissions), sort_keys=True))
        now = self._clock()
        with self._lock:
            cached = self._tokens.get(key)
            if cached and cached[1] > now:
                return cached[0]
        body = json.dumps({"repositories": [repo.split("/", 1)[1]], "permissions": dict(permissions)}).encode()
        response = self._transport("POST", f"{self._api}/app/installations/{int(installation_id)}/access_tokens", {
            "Authorization": f"Bearer {self._jwt()}",
            "Accept": JSON_ACCEPT,
            "Content-Type": "application/json",
            "User-Agent": "advisory-service",
        }, body)
        if response.status != 201:
            raise GitHubError(f"installation token request failed: HTTP {response.status}")
        data = json.loads(response.body)
        check_permissions(data.get("permissions", {}))  # refuse a token broader than this service allows
        with self._lock:
            self._tokens[key] = (data["token"], now + 50 * 60)
        return data["token"]


class InstallationClient:
    def __init__(self, token: str, repo: str, transport: Transport, clock: Callable[[], float] = time.time, api: str = API):
        self._token = token
        self.repo = repo
        self._transport = transport
        self._clock = clock
        self._api = api

    def _url(self, path: str) -> str:
        return f"{self._api}/repos/{self.repo}{path}"

    def _send(self, method: str, path: str, accept: str = JSON_ACCEPT, body: Optional[bytes] = None) -> HttpResponse:
        if method != "GET" and not (method == "POST" and path == "/check-runs"):
            raise GitHubError("advisory agents may only create check runs")
        headers = {"Authorization": f"Bearer {self._token}", "Accept": accept, "User-Agent": "advisory-service"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        return self._transport(method, self._url(path), headers, body)

    def list_jobs(self, run_id: int, attempt: int) -> List[Dict[str, Any]]:
        jobs: List[Dict[str, Any]] = []
        for page in range(1, 6):
            response = self._send("GET", f"/actions/runs/{int(run_id)}/attempts/{int(attempt)}/jobs?per_page=100&page={page}")
            if response.status != 200:
                raise GitHubError(f"listing jobs failed: HTTP {response.status}")
            batch = json.loads(response.body).get("jobs", [])
            jobs.extend(batch)
            if len(batch) < 100:
                break
        return jobs

    def job_log(self, job_id: int) -> str:
        response = self._send("GET", f"/actions/jobs/{int(job_id)}/logs", accept=JSON_ACCEPT)
        if response.status == 302:
            location = response.headers.get("Location") or response.headers.get("location") or ""
            if urllib.parse.urlparse(location).scheme != "https":
                raise GitHubError("log redirect was not HTTPS")
            # The redirect is a pre-signed URL on another host: never send the token.
            response = self._transport("GET", location, {"User-Agent": "advisory-service"}, None)
        if response.status != 200:
            raise GitHubError(f"fetching the job log failed: HTTP {response.status}")
        return response.body[:MAX_DOWNLOAD].decode("utf-8", "replace")

    def compare_diff(self, base: str, head: str) -> str:
        spec = urllib.parse.quote(f"{base}...{head}", safe=".")
        response = self._send("GET", f"/compare/{spec}", accept=DIFF_ACCEPT)
        if response.status != 200:
            raise GitHubError(f"fetching the diff failed: HTTP {response.status}")
        return response.body[:MAX_DOWNLOAD].decode("utf-8", "replace")

    def create_check_run(self, spec: checks.CheckRunSpec, head_sha: str) -> int:
        completed = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self._clock()))
        payload = checks.render(spec, head_sha, completed)
        response = self._send("POST", "/check-runs", body=json.dumps(payload).encode())
        if response.status != 201:
            raise GitHubError(f"creating the check run failed: HTTP {response.status}")
        return int(json.loads(response.body)["id"])
