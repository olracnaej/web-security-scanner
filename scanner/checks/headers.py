"""Security header checks."""

from __future__ import annotations

import re

from scanner.http import Response
from scanner.models import Finding, Severity

HSTS_MIN_SECONDS = 15_552_000  # 180 days
VERSION_RE = re.compile(r"\d+\.\d+")


def _csp_directives(csp: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for part in csp.split(";"):
        bits = part.strip().split()
        if bits:
            directives.setdefault(bits[0].lower(), [t.lower() for t in bits[1:]])
    return directives


def check(resp: Response) -> list[Finding]:
    findings: list[Finding] = []
    h = resp.header

    # --- HSTS (only meaningful on https) ---------------------------------
    if resp.target.scheme == "https":
        hsts = h("strict-transport-security")
        if hsts is None:
            findings.append(Finding(
                "headers.hsts-missing", "Missing Strict-Transport-Security (HSTS)",
                Severity.MEDIUM,
                "Browsers are not told to always use HTTPS for this site, so a "
                "visitor on a bad network can be downgraded to plain HTTP.",
                "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
            ))
        else:
            match = re.search(r"max-age\s*=\s*(\d+)", hsts, re.I)
            seconds = int(match.group(1)) if match else 0
            if seconds < HSTS_MIN_SECONDS:
                findings.append(Finding(
                    "headers.hsts-weak", "HSTS max-age is too short", Severity.LOW,
                    "A short HSTS lifetime leaves visitors unprotected once it expires.",
                    "Use max-age of at least 15552000 (180 days); 31536000 is common.",
                    f"Strict-Transport-Security: {hsts}",
                ))

    # --- Content-Security-Policy -----------------------------------------
    csp = h("content-security-policy")
    directives: dict[str, list[str]] = {}
    if csp is None:
        findings.append(Finding(
            "headers.csp-missing", "Missing Content-Security-Policy", Severity.MEDIUM,
            "Without a CSP, any script injected into a page (XSS) runs with no "
            "browser-side limits.",
            "Start with: Content-Security-Policy: default-src 'self'; frame-ancestors 'self'",
        ))
    else:
        directives = _csp_directives(csp)
        script_src = directives.get("script-src", directives.get("default-src"))
        if script_src is None:
            findings.append(Finding(
                "headers.csp-no-script-src", "CSP does not restrict scripts", Severity.LOW,
                "The policy has neither script-src nor default-src, so scripts are unrestricted.",
                "Add default-src 'self' (or a script-src) to the policy.",
                f"Content-Security-Policy: {csp}",
            ))
        else:
            protected = any(
                t.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) or t == "'strict-dynamic'"
                for t in script_src
            )
            risky = [t for t in script_src if t == "*" or t == "'unsafe-eval'"
                     or (t == "'unsafe-inline'" and not protected)]
            if risky:
                findings.append(Finding(
                    "headers.csp-weak", "CSP allows risky script sources", Severity.LOW,
                    "Sources like 'unsafe-inline', 'unsafe-eval' or * cancel most of "
                    "the protection a CSP gives against XSS.",
                    "Remove them; use nonces or hashes for inline scripts.",
                    f"script sources: {' '.join(risky)}",
                ))

    # --- Clickjacking -----------------------------------------------------
    xfo = h("x-frame-options")
    if "frame-ancestors" not in directives:
        if xfo is None:
            findings.append(Finding(
                "headers.clickjacking", "Page can be framed (clickjacking)", Severity.MEDIUM,
                "Another site can load this page in an invisible frame and trick "
                "visitors into clicking buttons on it.",
                "Add X-Frame-Options: DENY (or SAMEORIGIN), or CSP frame-ancestors 'self'.",
            ))
        elif xfo.strip().upper() not in ("DENY", "SAMEORIGIN"):
            findings.append(Finding(
                "headers.xfo-invalid", "X-Frame-Options has an ineffective value", Severity.LOW,
                "Only DENY and SAMEORIGIN are honored by modern browsers.",
                "Set X-Frame-Options: DENY or SAMEORIGIN.",
                f"X-Frame-Options: {xfo}",
            ))

    # --- Small headers ----------------------------------------------------
    nosniff = h("x-content-type-options")
    if nosniff is None or nosniff.strip().lower() != "nosniff":
        findings.append(Finding(
            "headers.nosniff", "Missing X-Content-Type-Options: nosniff", Severity.LOW,
            "Browsers may guess file types and run an upload as a script.",
            "Add: X-Content-Type-Options: nosniff",
            f"X-Content-Type-Options: {nosniff}" if nosniff else "",
        ))
    if h("referrer-policy") is None:
        findings.append(Finding(
            "headers.referrer-policy", "Missing Referrer-Policy", Severity.LOW,
            "Full page URLs (which can contain tokens or IDs) may be sent to other sites.",
            "Add: Referrer-Policy: strict-origin-when-cross-origin",
        ))
    if h("permissions-policy") is None:
        findings.append(Finding(
            "headers.permissions-policy", "Missing Permissions-Policy", Severity.INFO,
            "Browser features like camera, microphone and geolocation are not explicitly limited.",
            "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()",
        ))

    # --- Information disclosure ------------------------------------------
    server = h("server")
    if server and VERSION_RE.search(server):
        findings.append(Finding(
            "headers.server-version", "Server header reveals a software version", Severity.LOW,
            "Attackers can look up known vulnerabilities for the exact version.",
            "Hide the version (Apache: ServerTokens Prod, nginx: server_tokens off).",
            f"Server: {server}",
        ))
    for name in ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
        value = h(name)
        if value:
            findings.append(Finding(
                f"headers.{name}", f"{name} header reveals the technology stack", Severity.LOW,
                "This tells attackers which framework and version to target.",
                f"Remove the {name} header (PHP: expose_php = Off).",
                f"{name}: {value}",
            ))

    return findings
