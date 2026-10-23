"""Tiny HTTP client built on the standard library.

Why not `requests`? One less dependency to vet, and we need to connect to the
exact IPs the safety guard approved (no second DNS lookup), which is easy to do
with http.client.
"""

from __future__ import annotations

import http.client
import socket
import ssl
from dataclasses import dataclass
from urllib.parse import urlsplit

from scanner import __version__
from scanner.safety import AuthorizedTarget, authorize_redirect

USER_AGENT = f"web-security-scanner/{__version__} (permission-based hygiene scan)"
MAX_BODY = 1_000_000
MAX_REDIRECTS = 5
TIMEOUT = 10.0
REDIRECT_CODES = (301, 302, 303, 307, 308)


class FetchError(Exception):
    """The site could not be fetched (network error, timeout, TLS failure...)."""


@dataclass(frozen=True)
class Response:
    target: AuthorizedTarget  # the final target, after redirects
    path: str
    status: int
    headers: tuple[tuple[str, str], ...]  # repeated headers stay separate
    body: bytes
    tls_verified: bool | None  # None for plain http
    redirects: tuple[str, ...] = ()

    def header(self, name: str) -> str | None:
        name = name.lower()
        for key, value in self.headers:
            if key.lower() == name:
                return value
        return None

    def header_all(self, name: str) -> list[str]:
        name = name.lower()
        return [value for key, value in self.headers if key.lower() == name]


class _PinnedConnection(http.client.HTTPConnection):
    """Connects to the already-approved IPs, but still sends the real host name
    for the Host header and for TLS (SNI + certificate check)."""

    def __init__(self, target: AuthorizedTarget, timeout: float, verify: bool):
        super().__init__(target.host, target.port, timeout=timeout)
        self._target = target
        self._verify = verify

    def connect(self) -> None:
        last_error: OSError | None = None
        sock = None
        for ip in self._target.addresses:
            try:
                sock = socket.create_connection((ip, self._target.port), self.timeout)
                break
            except OSError as exc:
                last_error = exc
        if sock is None:
            raise last_error or OSError("no address to connect to")

        if self._target.scheme == "https":
            context = ssl.create_default_context()
            if not self._verify:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            try:
                sock = context.wrap_socket(sock, server_hostname=self._target.host)
            except Exception:
                sock.close()
                raise
        self.sock = sock


def _host_header(target: AuthorizedTarget) -> str:
    host = f"[{target.host}]" if ":" in target.host else target.host
    default = 443 if target.scheme == "https" else 80
    return host if target.port == default else f"{host}:{target.port}"


def _path_of(url: str) -> str:
    parts = urlsplit(url)
    return (parts.path or "/") + (f"?{parts.query}" if parts.query else "")


def _do_request(target, path, timeout, verify, max_body=MAX_BODY):
    conn = _PinnedConnection(target, timeout, verify)
    try:
        conn.request(
            "GET",
            path,
            headers={
                "Host": _host_header(target),
                "User-Agent": USER_AGENT,
                "Accept": "*/*",
                "Connection": "close",
            },
        )
        resp = conn.getresponse()
        body = resp.read(max_body)
        return resp.status, tuple(resp.getheaders()), body
    finally:
        conn.close()


def _request(target, path, timeout, max_body=MAX_BODY):
    """Return (status, headers, body, tls_verified).

    If the certificate does not verify (common on local test sites), fetch
    again without verification so header checks still work, and report
    tls_verified=False so the TLS check can flag it.
    """
    if target.scheme == "https":
        try:
            return (*_do_request(target, path, timeout, True, max_body), True)
        except ssl.SSLCertVerificationError:
            return (*_do_request(target, path, timeout, False, max_body), False)
    return (*_do_request(target, path, timeout, False, max_body), None)


def fetch(target: AuthorizedTarget, allow_hosts=(), timeout: float = TIMEOUT) -> Response:
    """GET the target, following same-host redirects only."""
    current = target
    path = _path_of(target.url)
    redirects: list[str] = []
    try:
        while True:
            status, headers, body, tls_ok = _request(current, path, timeout)
            location = next(
                (v for k, v in headers if k.lower() == "location"), None
            )
            if status in REDIRECT_CODES and location:
                if len(redirects) >= MAX_REDIRECTS:
                    raise FetchError("too many redirects")
                current = authorize_redirect(current, location, allow_hosts)
                path = _path_of(current.url)
                redirects.append(location)
                continue
            return Response(current, path, status, headers, body, tls_ok, tuple(redirects))
    except (OSError, http.client.HTTPException) as exc:
        raise FetchError(f"could not fetch {current.url}: {exc}") from exc


def fetch_once(
    target: AuthorizedTarget, timeout: float = TIMEOUT, max_body: int = MAX_BODY
) -> Response:
    """One GET, redirects NOT followed. Used for probing extra paths."""
    path = _path_of(target.url)
    try:
        status, headers, body, tls_ok = _request(target, path, timeout, max_body)
    except (OSError, http.client.HTTPException) as exc:
        raise FetchError(f"could not fetch {target.url}: {exc}") from exc
    return Response(target, path, status, headers, body, tls_ok)
