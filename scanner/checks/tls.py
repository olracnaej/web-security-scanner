"""TLS checks: certificate validity and expiry, obsolete protocol versions,
plain-HTTP sites and missing HTTP -> HTTPS redirects.

`inspect()` talks to the network and returns a TlsInfo; `analyze()` turns a
TlsInfo into findings. Keeping them apart makes the logic easy to test.
"""

from __future__ import annotations

import socket
import ssl
import warnings
from dataclasses import dataclass
from datetime import datetime, timezone

from scanner.context import ScanContext
from scanner.http import REDIRECT_CODES, FetchError, fetch_once
from scanner.models import Finding, Severity
from scanner.safety import AuthorizedTarget, RefusedTarget, authorize_target

EXPIRY_HIGH_DAYS = 7
EXPIRY_MEDIUM_DAYS = 30
OBSOLETE_VERSIONS = ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1")


@dataclass(frozen=True)
class TlsInfo:
    version: str | None = None          # negotiated version, e.g. "TLSv1.3"
    verify_error: str | None = None     # why the certificate was rejected
    not_after: datetime | None = None   # certificate expiry (only if it verified)
    legacy_accepted: tuple[str, ...] = ()
    error: str | None = None            # handshake could not be done at all


# --------------------------------------------------------------------------
# Network part
# --------------------------------------------------------------------------

def _connect(target: AuthorizedTarget, timeout: float) -> socket.socket:
    last: OSError | None = None
    for ip in target.addresses:
        try:
            return socket.create_connection((ip, target.port), timeout)
        except OSError as exc:
            last = exc
    raise last or OSError("no address to connect to")


def _handshake_version(target, timeout, context) -> str | None:
    sock = _connect(target, timeout)
    try:
        with context.wrap_socket(sock, server_hostname=target.host) as tls:
            return tls.version()
    finally:
        sock.close()


def _unverified_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _accepts_legacy(target, timeout, version_name: str) -> bool:
    """Does the server complete a handshake limited to an obsolete version?
    Depends on the local OpenSSL still being able to speak it; if not, we
    simply report nothing."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            wanted = getattr(ssl.TLSVersion, version_name)
            context = _unverified_context()
            context.minimum_version = wanted
            context.maximum_version = wanted
            context.set_ciphers("ALL:@SECLEVEL=0")
            _handshake_version(target, timeout, context)
        return True
    except (AttributeError, ValueError, ssl.SSLError, OSError):
        return False


def _parse_not_after(cert: dict) -> datetime | None:
    raw = cert.get("notAfter")
    if not raw:
        return None
    return datetime.fromtimestamp(ssl.cert_time_to_seconds(raw), timezone.utc)


def inspect(target: AuthorizedTarget, timeout: float = 10.0) -> TlsInfo:
    verify_error = None
    version = None
    not_after = None
    try:
        sock = _connect(target, timeout)
    except OSError as exc:
        return TlsInfo(error=str(exc))

    try:
        context = ssl.create_default_context()
        with context.wrap_socket(sock, server_hostname=target.host) as tls:
            version = tls.version()
            not_after = _parse_not_after(tls.getpeercert() or {})
    except ssl.SSLCertVerificationError as exc:
        verify_error = exc.verify_message or str(exc)
        try:  # still learn the protocol version from an unverified handshake
            version = _handshake_version(target, timeout, _unverified_context())
        except (ssl.SSLError, OSError):
            pass
    except (ssl.SSLError, OSError) as exc:
        return TlsInfo(error=str(exc))
    finally:
        sock.close()

    legacy = tuple(
        name for name in ("TLSv1", "TLSv1_1")
        if _accepts_legacy(target, timeout, name)
    )
    pretty = tuple(n.replace("_", ".") for n in legacy)
    return TlsInfo(version, verify_error, not_after, pretty)


# --------------------------------------------------------------------------
# Analysis part (no network)
# --------------------------------------------------------------------------

def analyze(info: TlsInfo, local: bool = False, now: datetime | None = None) -> list[Finding]:
    now = now or datetime.now(timezone.utc)
    findings: list[Finding] = []

    if info.error:
        findings.append(Finding(
            "tls.handshake-failed", "Could not complete a TLS handshake", Severity.LOW,
            "The TLS connection used for inspection failed, so the certificate could not be checked.",
            "Check the server's TLS configuration.", info.error))
        return findings

    if info.verify_error:
        message = info.verify_error.lower()
        if "expired" in message:
            check_id, title, severity = "tls.cert-expired", "TLS certificate has expired", Severity.HIGH
        elif "mismatch" in message or "doesn't match" in message:
            check_id, title, severity = ("tls.cert-hostname",
                "TLS certificate does not match the host name", Severity.HIGH)
        elif "self-signed" in message or "self signed" in message:
            check_id, title, severity = "tls.cert-untrusted", "TLS certificate is self-signed", Severity.MEDIUM
        else:
            check_id, title, severity = "tls.cert-untrusted", "TLS certificate is not trusted", Severity.MEDIUM
        description = "Browsers show a full-page warning, and visitors cannot tell the real site from an impostor."
        if local:
            severity = Severity.INFO
            description += " (Expected on a local test site.)"
        findings.append(Finding(
            check_id, title, severity, description,
            "Install a valid certificate (Let's Encrypt is free) and renew it before it expires.",
            info.verify_error))
    elif info.not_after is not None:
        days = (info.not_after - now).days
        if days <= EXPIRY_MEDIUM_DAYS:
            findings.append(Finding(
                "tls.cert-expiring", "TLS certificate expires soon",
                Severity.HIGH if days <= EXPIRY_HIGH_DAYS else Severity.MEDIUM,
                "When the certificate expires, every visitor gets a security warning.",
                "Renew the certificate now and set up automatic renewal.",
                f"expires in {days} day(s), on {info.not_after:%Y-%m-%d}"))

    if info.version in OBSOLETE_VERSIONS:
        findings.append(Finding(
            "tls.obsolete-negotiated", "Connection negotiated an obsolete TLS version",
            Severity.MEDIUM,
            "TLS 1.0 and 1.1 have known weaknesses and are retired.",
            "Allow only TLS 1.2 and TLS 1.3.", f"negotiated {info.version}"))
    if info.legacy_accepted:
        findings.append(Finding(
            "tls.obsolete-accepted", "Server accepts obsolete TLS versions", Severity.MEDIUM,
            "TLS 1.0 and 1.1 have known weaknesses and are retired by all modern browsers.",
            "Allow only TLS 1.2 and TLS 1.3 (nginx: ssl_protocols TLSv1.2 TLSv1.3;).",
            "accepted: " + ", ".join(info.legacy_accepted)))
    return findings


def _redirect_findings(ctx: ScanContext) -> list[Finding]:
    """Does http://host/ send visitors to https://? Standard ports, real hosts only."""
    target = ctx.target
    if target.reason == "loopback" or target.port != 443:
        return []
    host = f"[{target.host}]" if ":" in target.host else target.host
    try:
        http_target = authorize_target(f"http://{host}/", ctx.allow_hosts)
        reply = fetch_once(http_target, ctx.timeout, 4096)
    except (RefusedTarget, FetchError):
        return []  # port 80 closed is fine
    location = reply.header("location") or ""
    if reply.status in REDIRECT_CODES and location.lower().startswith("https://"):
        return []
    if reply.status < 400:
        return [Finding(
            "tls.no-http-redirect", "HTTP version of the site does not redirect to HTTPS",
            Severity.MEDIUM,
            "Visitors who type the plain http:// address stay on an unencrypted connection.",
            "Redirect all http:// requests to https:// (301) in the web server config.",
            f"http://{target.host}/ answered HTTP {reply.status} without redirecting")]
    return []


def check(ctx: ScanContext) -> list[Finding]:
    target = ctx.target
    if target.scheme != "https":
        if target.reason == "loopback":
            return []
        return [Finding(
            "tls.no-https", "Site is served over plain HTTP", Severity.MEDIUM,
            "Everything, including logins and cookies, travels unencrypted and can be read or changed on the way.",
            "Install a TLS certificate and serve the site over HTTPS only.",
            target.url)]
    info = inspect(target, ctx.timeout)
    return analyze(info, local=target.reason == "loopback") + _redirect_findings(ctx)
