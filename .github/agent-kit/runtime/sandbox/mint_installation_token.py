#!/usr/bin/env python3
"""Mints a GitHub App installation token limited to one repository (P1.1).

See MINTING.md. The token is written to a mode 0600 file and never printed.
Run this outside the sandbox only.
"""
import argparse
import base64
import datetime
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

# P0.2: contents and pull requests only. Request more with --permissions only if the App holds them.
DEFAULT_PERMISSIONS = {"contents": "write", "pull_requests": "write"}
# Agents must not hold these (P0.3, kit install step 7).
FORBIDDEN_PERMISSIONS = {
    "administration", "workflows", "actions", "actions_variables", "secrets",
    "environments", "organization_administration", "members",
}
MAX_LIFETIME_SECONDS = 3700


class MintError(Exception):
    pass


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def keychain_pem(service, account):
    """The App key from the macOS Keychain, stored base64-encoded. Never written to disk."""
    result = subprocess.run(["security", "find-generic-password", "-a", account, "-s", service, "-w"],
                            capture_output=True)
    if result.returncode:
        raise MintError("no Keychain item {!r} for account {!r}".format(service, account))
    try:
        pem = base64.b64decode(result.stdout.strip(), validate=True)
    except ValueError as exc:
        raise MintError("Keychain item {!r} isn't base64".format(service)) from exc
    if b"PRIVATE KEY-----" not in pem:
        raise MintError("Keychain item {!r} doesn't hold a PEM private key".format(service))
    return pem


def app_jwt(app_id, key_path=None, now=None, key_pem=None):
    """Build the App's RS256 JWT, signing with openssl so no key library is needed.

    The key comes from key_path, or from key_pem bytes. Bytes reach openssl
    through a pipe (/dev/fd/N), so they never touch the disk.
    """
    now = int(time.time() if now is None else now)
    header = b64url(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    payload = b64url(json.dumps({"iat": now - 60, "exp": now + 540, "iss": str(app_id)}).encode())
    message = "{}.{}".format(header, payload)
    if key_pem is None:
        result = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", key_path],
            input=message.encode(), capture_output=True,
        )
    else:
        read_end, write_end = os.pipe()
        try:
            # A PEM key is far below the pipe buffer, so this write never blocks.
            os.write(write_end, key_pem)
            os.close(write_end)
            write_end = None
            result = subprocess.run(
                ["openssl", "dgst", "-sha256", "-sign", "/dev/fd/{}".format(read_end)],
                input=message.encode(), capture_output=True, pass_fds=(read_end,),
            )
        finally:
            os.close(read_end)
            if write_end is not None:
                os.close(write_end)
    if result.returncode:
        raise MintError("openssl could not sign with the App key")
    return message + "." + b64url(result.stdout)


def call(method, url, token, scheme, body=None):
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": "{} {}".format(scheme, token),
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "agent-sandbox-runtime",
    })
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raise MintError("GitHub returned HTTP {} for {}".format(exc.code, url.split("?")[0]))
    except urllib.error.URLError as exc:
        raise MintError("could not reach GitHub: {}".format(exc.reason))


def check_api_url(url):
    local = url.startswith(("http://127.0.0.1", "http://localhost"))
    if not url.startswith("https://") and not local:
        raise MintError("--api-url must be https")
    return url.rstrip("/")


def parse_permissions(text):
    if not text:
        return dict(DEFAULT_PERMISSIONS)
    permissions = {}
    for item in text.split(","):
        name, _, level = item.partition("=")
        if level not in ("read", "write"):
            raise MintError("permission must be name=read or name=write: " + item)
        permissions[name.strip()] = level
    return permissions


def verify_response(response, repo, permissions, now=None):
    """Refuse a token that came back broader or longer-lived than requested."""
    if response.get("repository_selection") != "selected":
        raise MintError("token is not limited to selected repositories")
    names = [r.get("full_name", "").lower() for r in response.get("repositories", [])]
    if names != [repo.lower()]:
        raise MintError("token covers unexpected repositories: {}".format(names))
    granted = dict(response.get("permissions", {}))
    # GitHub adds metadata: read to every installation token, requested or not.
    if granted.get("metadata") == "read" and "metadata" not in permissions:
        del granted["metadata"]
    extra = sorted(set(granted) - set(permissions))
    if extra:
        raise MintError("token has permissions that were not requested: {}".format(extra))
    broader = sorted(k for k, level in granted.items() if level != permissions[k])
    if broader:
        raise MintError("token has a different access level than requested for: {}".format(broader))
    expires = datetime.datetime.strptime(response["expires_at"], "%Y-%m-%dT%H:%M:%SZ")
    expires = expires.replace(tzinfo=datetime.timezone.utc).timestamp()
    if expires - (time.time() if now is None else now) > MAX_LIFETIME_SECONDS:
        raise MintError("token lives longer than one hour")


def mint(args):
    if args.repo.count("/") != 1:
        raise MintError("--repo must be exactly one owner/name")
    owner, name = args.repo.split("/")
    permissions = parse_permissions(args.permissions)
    forbidden = sorted(set(permissions) & FORBIDDEN_PERMISSIONS)
    if forbidden:
        raise MintError("permissions agents must not hold: {}".format(forbidden))
    api = check_api_url(args.api_url)
    if args.private_key_keychain:
        jwt = app_jwt(args.app_id, key_pem=keychain_pem(args.private_key_keychain, args.keychain_account))
    else:
        jwt = app_jwt(args.app_id, args.private_key)
    _, installation = call("GET", "{}/repos/{}/{}/installation".format(api, owner, name), jwt, "Bearer")
    _, token = call(
        "POST", "{}/app/installations/{}/access_tokens".format(api, installation["id"]), jwt, "Bearer",
        {"repositories": [name], "permissions": permissions},
    )
    try:
        verify_response(token, args.repo, permissions)
    except MintError:
        # Never leave a refused token live until it expires.
        try:
            call("DELETE", api + "/installation/token", token.get("token", ""), "token")
        except Exception:  # noqa: BLE001 - the refusal below is what matters
            print("warning: could not revoke the refused token; it expires within an hour", file=sys.stderr)
        raise
    descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        handle.write(token["token"])
    print(json.dumps({"repo": args.repo, "expires_at": token["expires_at"], "output": args.output}))
    return 0


def revoke(args):
    with open(args.token_file, encoding="utf-8") as handle:
        token = handle.read().strip()
    call("DELETE", check_api_url(args.api_url) + "/installation/token", token, "token")
    print("revoked")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    mint_parser = commands.add_parser("mint")
    mint_parser.add_argument("--app-id", required=True)
    key_source = mint_parser.add_mutually_exclusive_group(required=True)
    key_source.add_argument("--private-key", help="PEM file for the App")
    key_source.add_argument("--private-key-keychain", metavar="SERVICE",
                            help="macOS Keychain item holding the App key, base64-encoded; it never touches the disk")
    mint_parser.add_argument("--keychain-account", default="owxyz", help="Keychain account (default owxyz)")
    mint_parser.add_argument("--repo", required=True, help="owner/name")
    mint_parser.add_argument("--output", required=True)
    mint_parser.add_argument("--permissions", help="name=level,... default contents and PRs write")
    mint_parser.add_argument("--api-url", default="https://api.github.com")
    mint_parser.set_defaults(run=mint)
    revoke_parser = commands.add_parser("revoke")
    revoke_parser.add_argument("--token-file", required=True)
    revoke_parser.add_argument("--api-url", default="https://api.github.com")
    revoke_parser.set_defaults(run=revoke)
    args = parser.parse_args(argv)
    try:
        return args.run(args)
    except (MintError, OSError, KeyError, ValueError) as exc:
        print("mint error: {}".format(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
