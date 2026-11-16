#!/usr/bin/env python3
"""Allowlisting forward proxy for agent containers (P1.1).

The agent's network has no route out, so this proxy is its only path to any
host that isn't the gateway. A connection is allowed only if the exact host and
port are listed. Addresses are resolved here and the connection goes to the
address that was checked, so a rebinding answer can't redirect it.

HTTPS goes through CONNECT tunnels. Plain HTTP, allowed only for rules marked
plain_http, is parsed request by request so every request is checked.
"""
import asyncio
import ipaddress
import json
import os
import re
import sys
from urllib.parse import urlsplit

LISTEN_PORT = 3128
MAX_HEADER = 16 * 1024
HEADER_TIMEOUT = 10
IDLE_TIMEOUT = 300
# Large enough to publish a package to the mirror.
MAX_PLAIN_BODY = 512 * 1024 * 1024
DROPPED_PLAIN_HEADERS = ("keep-alive", "te", "trailer")
HEX_DIGITS = b"0123456789abcdefABCDEF"
HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")


class Policy:
    def __init__(self, data):
        self.rules = {}
        for rule in data.get("allow", []):
            host = normalize_host(rule["host"])
            if is_ip_literal(host):
                raise ValueError("IP literals are not allowed in the allowlist: " + host)
            self.rules[host] = rule

    def rule_for(self, host, port, plain):
        """Return the matching rule, or None. plain means unencrypted forwarding."""
        host = normalize_host(host)
        if is_ip_literal(host):
            return None
        rule = self.rules.get(host)
        if rule is None or port not in rule.get("ports", []):
            return None
        if plain and not rule.get("plain_http", False):
            return None
        return rule


def normalize_host(host):
    return host.strip().lower().rstrip(".").strip("[]")


def is_ip_literal(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def address_allowed(address, private_ok):
    ip = ipaddress.ip_address(address.split("%", 1)[0])
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    if ip.is_link_local or ip.is_loopback or ip.is_multicast or ip.is_unspecified:
        return False
    return ip.is_global or bool(private_ok and ip.is_private)


def parse_target(method, target):
    """Return (host, port, plain, origin_form), or None if malformed."""
    try:
        if method == "CONNECT":
            host, _, port = target.rpartition(":")
            if not host:
                return None
            return host, int(port), False, None
        parts = urlsplit(target)
        if parts.scheme != "http" or not parts.hostname:
            return None
        origin = (parts.path or "/") + ("?" + parts.query if parts.query else "")
        return parts.hostname, parts.port or 80, True, origin
    except ValueError:
        return None


def plain_request(fields, lines, target):
    """Check and rewrite one proxied HTTP request, or return None to refuse it.

    Each request on a connection passes through here, so a later request can't
    reach the mirror unchecked. Framing that proxies and servers might read
    differently (both length and chunked, conflicting lengths, folded headers)
    is refused outright. Host is set from the checked URL, so a different Host
    header can't pick another site on the same server.
    """
    host, port, _, origin = target
    version = fields[2]
    if version not in ("HTTP/1.1", "HTTP/1.0"):
        return None
    kept, length, chunked, expect = [], None, False, False
    close = version == "HTTP/1.0"
    for line in lines[1:]:
        if not line:
            continue
        if line[0] in " \t" or ":" not in line:
            return None
        name, value = line.split(":", 1)
        lower, value = name.lower(), value.strip()
        if not HEADER_NAME.fullmatch(name):
            return None
        if lower == "content-length":
            if not value.isdigit() or (length is not None and int(value) != length):
                return None
            length = int(value)
            continue
        if lower == "transfer-encoding":
            if value.lower() != "chunked" or chunked:
                return None
            chunked = True
            continue
        if lower == "upgrade":
            return None
        if lower == "expect":
            if value.lower() != "100-continue":
                return None
            expect = True
            continue
        if lower == "connection":
            close = close or "close" in value.lower()
            continue
        if lower == "host" or lower.startswith("proxy-") or lower in DROPPED_PLAIN_HEADERS:
            continue
        kept.append(line)
    if chunked and length is not None:
        return None
    if (length or 0) > MAX_PLAIN_BODY:
        return None
    kept.insert(0, "Host: " + (host if port == 80 else "{}:{}".format(host, port)))
    if chunked:
        kept.append("Transfer-Encoding: chunked")
    elif length is not None:
        kept.append("Content-Length: {}".format(length))
    if close:
        kept.append("Connection: close")
    head = "\r\n".join(["{} {} {}".format(fields[0], origin, version)] + kept + ["", ""])
    return {"head": head.encode("latin-1"), "length": length or 0, "chunked": chunked,
            "expect": expect, "close": close, "method": fields[0]}


def log(**fields):
    print(json.dumps(fields, sort_keys=True), flush=True)


async def relay(reader, writer):
    try:
        while True:
            data = await asyncio.wait_for(reader.read(65536), IDLE_TIMEOUT)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (asyncio.TimeoutError, ConnectionError, OSError):
        pass
    finally:
        try:
            writer.close()
        except (ConnectionError, OSError):
            pass


async def refuse(writer, status, reason):
    body = (reason + "\n").encode()
    writer.write(
        "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n".format(
            status, reason, len(body)
        ).encode() + body
    )
    try:
        await writer.drain()
    except (ConnectionError, OSError):
        pass
    writer.close()


async def read_head(reader, timeout):
    try:
        return await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout)
    except (asyncio.TimeoutError, asyncio.IncompleteReadError,
            asyncio.LimitOverrunError, ConnectionError):
        return None


async def copy_exact(reader, writer, count):
    while count:
        chunk = await asyncio.wait_for(reader.read(min(65536, count)), IDLE_TIMEOUT)
        if not chunk:
            raise ConnectionError("body ended early")
        count -= len(chunk)
        writer.write(chunk)
        await writer.drain()


async def copy_chunked(reader, writer, cap):
    """Copy a chunked body as it is, checking its framing. cap=None means no cap."""
    total = 0
    while True:
        line = await asyncio.wait_for(reader.readuntil(b"\r\n"), IDLE_TIMEOUT)
        size_text = line.split(b";", 1)[0].strip()
        if not size_text or len(size_text) > 16 or any(c not in HEX_DIGITS for c in size_text):
            raise ValueError("bad chunk size")
        size = int(size_text, 16)
        total += size
        if cap is not None and total > cap:
            raise ValueError("body too large")
        writer.write(line)
        if size == 0:
            while True:
                trailer = await asyncio.wait_for(reader.readuntil(b"\r\n"), IDLE_TIMEOUT)
                writer.write(trailer)
                if trailer == b"\r\n":
                    await writer.drain()
                    return
        await copy_exact(reader, writer, size)
        end = await asyncio.wait_for(reader.readexactly(2), IDLE_TIMEOUT)
        if end != b"\r\n":
            raise ValueError("bad chunk end")
        writer.write(end)


async def relay_response(up_reader, writer, method):
    """Copy one response back. Returns True if the connection can carry another request."""
    while True:
        raw = await read_head(up_reader, IDLE_TIMEOUT)
        if raw is None:
            return False
        lines = raw.decode("latin-1").split("\r\n")
        parts = lines[0].split(" ", 2)
        try:
            status = int(parts[1])
        except (IndexError, ValueError):
            return False
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                name, value = line.split(":", 1)
                headers.setdefault(name.strip().lower(), []).append(value.strip())
        writer.write(raw)
        await writer.drain()
        if 100 <= status < 200:
            if status == 101:
                return False
            continue  # an interim response; the real one follows
        close = parts[0] == "HTTP/1.0" or any("close" in v.lower() for v in headers.get("connection", []))
        if method == "HEAD" or status in (204, 304):
            return not close
        if "chunked" in ",".join(headers.get("transfer-encoding", [])).lower():
            await copy_chunked(up_reader, writer, None)
            return not close
        if "content-length" in headers:
            await copy_exact(up_reader, writer, int(headers["content-length"][0]))
            return not close
        await relay(up_reader, writer)  # no length: the body ends when upstream closes
        return False


async def choose_address(host, port, private_ok):
    infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=1)
    addresses = [info[4][0] for info in infos]
    # Every answer must pass: one private record among public ones is a red flag.
    if not addresses or not all(address_allowed(a, private_ok) for a in addresses):
        return None
    return addresses[0]


async def open_checked(host, port, rule, writer):
    """Connect to an allowlisted host's checked address, or refuse the client."""
    try:
        address = await choose_address(host, port, rule.get("private_ok", False))
    except OSError:
        log(event="egress", decision="deny", reason="dns-failed", host=host, port=port)
        await refuse(writer, 502, "Bad Gateway")
        return None
    if address is None:
        log(event="egress", decision="deny", reason="address-not-allowed", host=host, port=port)
        await refuse(writer, 403, "Forbidden")
        return None
    try:
        return await asyncio.wait_for(asyncio.open_connection(address, port), 15)
    except (asyncio.TimeoutError, OSError):
        log(event="egress", decision="deny", reason="connect-failed", host=host, port=port)
        await refuse(writer, 502, "Bad Gateway")
        return None


async def plain_session(policy, reader, writer, raw):
    """Unencrypted forwarding, one checked request at a time on a kept-alive connection."""
    upstream = None
    try:
        while raw is not None:
            lines = raw.decode("latin-1").split("\r\n")
            fields = lines[0].split(" ")
            target = parse_target(fields[0], fields[1]) if len(fields) == 3 and fields[0] != "CONNECT" else None
            request = plain_request(fields, lines, target) if target and target[2] else None
            if request is None:
                log(event="egress", decision="deny", reason="malformed", request=lines[0][:200])
                await refuse(writer, 400, "Bad Request")
                return
            host, port = target[0], target[1]
            rule = policy.rule_for(host, port, True)
            if rule is None:
                log(event="egress", decision="deny", reason="not-allowlisted", host=host, port=port)
                await refuse(writer, 403, "Forbidden")
                return
            key = (normalize_host(host), port)
            if upstream is None or upstream[0] != key:
                if upstream is not None:
                    upstream[2].close()
                    upstream = None
                connection = await open_checked(host, port, rule, writer)
                if connection is None:
                    return
                upstream = (key,) + tuple(connection)
            log(event="egress", decision="allow", host=host, port=port, method=request["method"])
            _, up_reader, up_writer = upstream
            if request["expect"]:
                writer.write(b"HTTP/1.1 100 Continue\r\n\r\n")
                await writer.drain()
            up_writer.write(request["head"])
            if request["chunked"]:
                await copy_chunked(reader, up_writer, MAX_PLAIN_BODY)
            elif request["length"]:
                await copy_exact(reader, up_writer, request["length"])
            await up_writer.drain()
            if not await relay_response(up_reader, writer, request["method"]) or request["close"]:
                return
            raw = await read_head(reader, IDLE_TIMEOUT)
    except (asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError,
            ConnectionError, OSError, ValueError) as exc:
        log(event="egress", decision="closed", reason=type(exc).__name__)
    finally:
        if upstream is not None:
            upstream[2].close()
        writer.close()


async def handle(policy, reader, writer):
    head = await read_head(reader, HEADER_TIMEOUT)
    if head is None:
        writer.close()
        return
    lines = head.decode("latin-1").split("\r\n")
    fields = lines[0].split(" ")
    if fields[0] != "CONNECT":
        await plain_session(policy, reader, writer, head)
        return
    parsed = parse_target(fields[0], fields[1]) if len(fields) == 3 else None
    if parsed is None:
        log(event="egress", decision="deny", reason="malformed", request=lines[0][:200])
        await refuse(writer, 400, "Bad Request")
        return
    host, port = parsed[0], parsed[1]
    rule = policy.rule_for(host, port, False)
    if rule is None:
        log(event="egress", decision="deny", reason="not-allowlisted", host=host, port=port)
        await refuse(writer, 403, "Forbidden")
        return
    connection = await open_checked(host, port, rule, writer)
    if connection is None:
        return
    up_reader, up_writer = connection
    log(event="egress", decision="allow", host=host, port=port)
    writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    await writer.drain()
    await asyncio.gather(relay(reader, up_writer), relay(up_reader, writer))


async def serve(policy):
    async def on_client(reader, writer):
        try:
            await handle(policy, reader, writer)
        except Exception as exc:  # one bad client must not stop the proxy
            log(event="proxy-error", error=type(exc).__name__)
            writer.close()

    server = await asyncio.start_server(on_client, "0.0.0.0", LISTEN_PORT, limit=MAX_HEADER)
    log(event="ready")
    async with server:
        await server.serve_forever()


def main():
    policy = Policy(json.loads(os.environ["EGRESS_ALLOWLIST"]))
    try:
        asyncio.run(serve(policy))
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
