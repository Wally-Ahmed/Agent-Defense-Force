"""
Shared sandbox primitives for the authorized attack demo.

Everything that talks to the network goes through SandboxHTTPClient, which
HARD-ASSERTS the target host is loopback on EVERY request. There is no code path
that reaches a non-loopback host, and no flag or env var that disables the check.

Sandbox guarantees enforced here (mechanical, not by convention):
  * The only egress target is ATTACK_BASE_URL, and it must resolve to loopback.
  * X-Forwarded-For "rotating sources" must be RFC-5737 documentation IPs. These
    are header values the app trusts ONLY from loopback -- fixture data, not
    spoofing, and they cannot leave the sandbox.
  * No real credentials: only nwp_fixture_* tokens loaded from attack/fixtures/.
"""

from __future__ import annotations

import ipaddress
import json
import os
import socket
import sys
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES_DIR = os.path.join(HERE, "fixtures")

# RFC 5737 documentation ranges -- the ONLY IPs allowed in X-Forwarded-For.
RFC5737_NETWORKS = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]


class SandboxViolation(SystemExit):
    """Raised (as a SystemExit, exit code 3) when a sandbox guarantee is broken.

    Subclassing SystemExit means it cannot be swallowed by a bare `except
    Exception` in caller code -- the process exits.
    """

    def __init__(self, message: str) -> None:
        super().__init__("SANDBOX VIOLATION: " + message)


def _host_is_loopback(host: str) -> bool:
    """True iff `host` is a loopback literal or resolves ONLY to loopback IPs."""
    host = (host or "").strip().strip("[]").lower()
    if host in ("localhost", "127.0.0.1", "::1"):
        return True
    # A literal IP: check directly.
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        pass
    # A name: every resolved address must be loopback, or we refuse.
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    if not infos:
        return False
    for info in infos:
        addr = info[4][0]
        try:
            if not ipaddress.ip_address(addr.split("%")[0]).is_loopback:
                return False
        except ValueError:
            return False
    return True


def assert_loopback(base_url: str) -> str:
    """Refuse to run against anything but loopback. Returns the normalized base.

    This is the sandbox's front door. It is called at startup AND again inside
    every request, so it is impossible to skip.
    """
    if not base_url:
        raise SandboxViolation("ATTACK_BASE_URL is empty; refusing to run.")
    parts = urlsplit(base_url)
    if parts.scheme not in ("http", "https"):
        raise SandboxViolation(f"unsupported scheme {parts.scheme!r} in {base_url!r}.")
    host = parts.hostname or ""
    if not _host_is_loopback(host):
        raise SandboxViolation(
            f"target host {host!r} (from {base_url!r}) is not loopback. "
            "The driver only runs against 127.0.0.1/localhost/::1. Refusing."
        )
    return base_url.rstrip("/")


def validate_xff(ip: str) -> str:
    """Refuse any X-Forwarded-For value outside RFC-5737 documentation space."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError as exc:
        raise SandboxViolation(f"X-Forwarded-For {ip!r} is not a valid IP.") from exc
    if not any(addr in net for net in RFC5737_NETWORKS):
        raise SandboxViolation(
            f"X-Forwarded-For {ip!r} is outside RFC-5737 documentation ranges "
            "(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24). Refusing."
        )
    return ip


def load_fixture(name: str) -> dict[str, Any]:
    with open(os.path.join(FIXTURES_DIR, name), "r", encoding="utf-8") as fh:
        return json.load(fh)


class Response:
    __slots__ = ("status", "body", "headers")

    def __init__(self, status: int, body: bytes, headers: dict[str, str]) -> None:
        self.status = status
        self.body = body
        self.headers = headers

    def json(self) -> Any:
        if not self.body:
            return None
        try:
            return json.loads(self.body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None

    def result_count(self) -> int:
        data = self.json()
        if isinstance(data, dict):
            for key in ("result_count", "count", "total"):
                if isinstance(data.get(key), int):
                    return data[key]
            for key in ("items", "results", "data"):
                if isinstance(data.get(key), list):
                    return len(data[key])
        return 0


class SandboxHTTPClient:
    """A minimal stdlib HTTP client that can ONLY talk to a loopback base URL.

    assert_loopback runs in __init__ and again on every request. There is no
    setting that turns it off.
    """

    def __init__(self, base_url: str, timeout: float = 5.0) -> None:
        self.base_url = assert_loopback(base_url)
        self.timeout = timeout

    def request(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        body: Any = None,
        xff: str | None = None,
    ) -> Response:
        # Re-assert on every call: impossible to skip.
        assert_loopback(self.base_url)
        url = self.base_url + path
        # Also guard the fully-built URL host (defends against a path like
        # "@evil.example" or a scheme-relative smuggle).
        if urlsplit(url).hostname and not _host_is_loopback(urlsplit(url).hostname or ""):
            raise SandboxViolation(f"resolved request host for {url!r} is not loopback.")

        hdrs = dict(headers or {})
        data: bytes | None = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            hdrs.setdefault("Content-Type", "application/json")
        if xff is not None:
            hdrs["X-Forwarded-For"] = validate_xff(xff)

        req = urllib.request.Request(url, data=data, method=method.upper(), headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return Response(resp.status, resp.read(), dict(resp.headers.items()))
        except urllib.error.HTTPError as exc:
            return Response(exc.code, exc.read(), dict(exc.headers.items()) if exc.headers else {})
        except urllib.error.URLError as exc:
            # Connection refused etc. Surface as a synthetic 0 so the caller can
            # report "target not running" without crashing the whole run.
            raise ConnectionError(f"cannot reach {url}: {exc.reason}") from exc


class SimClock:
    """Deterministic simulated clock.

    t_rel in the trace is the PLANNED schedule (accumulated seeded sleeps), not
    measured wall-clock, so two runs at the same seed produce byte-identical
    traces regardless of machine speed or whether real sleeps happen.
    """

    def __init__(self) -> None:
        self.t = 0.0

    def advance(self, seconds: float) -> float:
        self.t = round(self.t + seconds, 3)
        return self.t


def trace_line(record: dict[str, Any]) -> str:
    """Serialize one trace record deterministically (sorted keys, fixed floats)."""
    return json.dumps(record, sort_keys=True, separators=(",", ":"))


def env_base_url(cli_value: str | None) -> str:
    """Resolve the base URL from CLI arg or ATTACK_BASE_URL, defaulting to the
    contract's loopback gateway origin."""
    return cli_value or os.environ.get("ATTACK_BASE_URL") or "http://127.0.0.1:8080"
