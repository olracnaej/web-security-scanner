"""Safety guard: decides whether a target may be scanned at all.

Rules, in order:
1. Only http:// and https:// URLs, no credentials embedded in the URL.
2. Every address the host resolves to is checked, not just the first one.
3. Link-local (cloud metadata), multicast, unspecified, reserved and
   shared-address-space addresses are ALWAYS refused, even if allow-listed.
4. If every address is loopback (127.0.0.0/8, ::1), the target is authorized.
5. Anything else (public or private LAN) needs the exact host name passed
   with --allow-host. No wildcards.

The resolved addresses are returned in AuthorizedTarget so later code can
connect to those exact IPs. That avoids a DNS-rebinding gap between "check"
and "use" (a TOCTOU bug).
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit


class RefusedTarget(Exception):
    """Raised when a target is not allowed to be scanned."""


@dataclass(frozen=True)
class AuthorizedTarget:
    url: str
    scheme: str
    host: str
    port: int
    addresses: tuple[str, ...]
    reason: str  # "loopback" or "allow-listed"


def normalize_allow_hosts(hosts) -> frozenset[str]:
    """Lowercase and validate --allow-host values. Exact names only."""
    cleaned = set()
    for raw in hosts or ():
        host = raw.strip().lower().rstrip(".")
        if not host:
            raise RefusedTarget("empty value in --allow-host")
        if any(ch in host for ch in "*/@ ") or (":" in host and not _is_ip(host)):
            raise RefusedTarget(
                f"--allow-host takes an exact host name, not {raw!r} "
                "(no wildcards, schemes, ports or paths)"
            )
        cleaned.add(host)
    return frozenset(cleaned)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _parse(url: str) -> tuple[str, str, int]:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise RefusedTarget("only http:// and https:// URLs can be scanned")
    if parts.username or parts.password:
        raise RefusedTarget("URLs with embedded credentials are not accepted")
    if not parts.hostname:
        raise RefusedTarget("URL has no host name")
    try:
        port = parts.port
    except ValueError:
        raise RefusedTarget("URL has an invalid port") from None
    if port is None:
        port = 443 if parts.scheme == "https" else 80
    return parts.scheme, parts.hostname.lower().rstrip("."), port


def _resolve(host: str, port: int) -> tuple[str, ...]:
    if _is_ip(host):
        return (host,)
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise RefusedTarget(f"cannot resolve host name {host!r}") from None
    addresses = sorted({info[4][0].split("%")[0] for info in infos})
    if not addresses:
        raise RefusedTarget(f"host name {host!r} has no addresses")
    return tuple(addresses)


def _classify(address: str) -> str:
    """Return 'loopback', 'private', 'public' or 'blocked'."""
    ip = ipaddress.ip_address(address)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped  # ::ffff:169.254.169.254 must not slip through
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        return "blocked"
    if ip.is_private:
        return "private"
    if not ip.is_global:
        return "blocked"  # e.g. 100.64.0.0/10 shared address space
    return "public"


def authorize_target(url: str, allow_hosts=()) -> AuthorizedTarget:
    """Return an AuthorizedTarget or raise RefusedTarget."""
    allowed = normalize_allow_hosts(allow_hosts)
    scheme, host, port = _parse(url)
    addresses = _resolve(host, port)
    kinds = {addr: _classify(addr) for addr in addresses}

    blocked = [addr for addr, kind in kinds.items() if kind == "blocked"]
    if blocked:
        raise RefusedTarget(
            f"{host} resolves to {blocked[0]}, an address that is never scanned "
            "(link-local, multicast, reserved or shared range)"
        )

    if all(kind == "loopback" for kind in kinds.values()):
        reason = "loopback"
    elif host in allowed:
        reason = "allow-listed"
    else:
        raise RefusedTarget(
            f"{host} is not a local address. Only scan sites you own or have "
            f"written permission to test, then re-run with --allow-host {host}"
        )

    return AuthorizedTarget(url, scheme, host, port, addresses, reason)


def authorize_redirect(
    target: AuthorizedTarget, location: str, allow_hosts=()
) -> AuthorizedTarget:
    """Follow a redirect only if it stays on the same host (http->https is fine)."""
    new_url = urljoin(target.url, location)
    scheme, host, port = _parse(new_url)
    if host != target.host:
        raise RefusedTarget(
            f"redirect from {target.host} to {host} refused (different host)"
        )
    upgrade = target.scheme == "http" and scheme == "https" and port == 443
    if port != target.port and not upgrade:
        raise RefusedTarget(f"redirect to a different port ({port}) refused")
    return authorize_target(new_url, allow_hosts)
