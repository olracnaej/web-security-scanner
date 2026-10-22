"""Cookie flag checks. Cookie VALUES are never stored or printed."""

from __future__ import annotations

from dataclasses import dataclass

from scanner.http import Response
from scanner.models import Finding, Severity

SESSION_HINTS = ("sess", "sid", "token", "auth", "login", "jwt")


@dataclass(frozen=True)
class Cookie:
    name: str
    secure: bool
    httponly: bool
    samesite: str | None

    @property
    def looks_like_session(self) -> bool:
        lowered = self.name.lower()
        return any(hint in lowered for hint in SESSION_HINTS)

    def describe(self) -> str:
        return (
            f"cookie {self.name!r}: Secure={'yes' if self.secure else 'no'}, "
            f"HttpOnly={'yes' if self.httponly else 'no'}, "
            f"SameSite={self.samesite or 'missing'}"
        )


def parse_set_cookie(raw: str) -> Cookie | None:
    parts = [p.strip() for p in raw.split(";")]
    name = parts[0].partition("=")[0].strip()
    if not name:
        return None
    attrs: dict[str, str] = {}
    for part in parts[1:]:
        key, _, value = part.partition("=")
        attrs[key.strip().lower()] = value.strip()
    return Cookie(
        name=name,
        secure="secure" in attrs,
        httponly="httponly" in attrs,
        samesite=attrs.get("samesite") or None,
    )


def check(resp: Response) -> list[Finding]:
    findings: list[Finding] = []
    for raw in resp.header_all("set-cookie"):
        cookie = parse_set_cookie(raw)
        if cookie is None:
            continue
        important = cookie.looks_like_session
        evidence = cookie.describe()

        if resp.target.scheme == "https" and not cookie.secure:
            findings.append(Finding(
                "cookies.no-secure", f"Cookie {cookie.name!r} missing Secure flag",
                Severity.MEDIUM if important else Severity.LOW,
                "The browser may send this cookie over plain HTTP, where it can be stolen.",
                "Add the Secure attribute to the Set-Cookie header.", evidence))
        if not cookie.httponly:
            findings.append(Finding(
                "cookies.no-httponly", f"Cookie {cookie.name!r} missing HttpOnly flag",
                Severity.MEDIUM if important else Severity.LOW,
                "JavaScript on the page can read this cookie, so an XSS bug can steal it.",
                "Add the HttpOnly attribute to the Set-Cookie header.", evidence))
        if cookie.samesite is None:
            findings.append(Finding(
                "cookies.no-samesite", f"Cookie {cookie.name!r} missing SameSite",
                Severity.LOW,
                "Without SameSite, other sites may trigger requests that carry this cookie (CSRF).",
                "Add SameSite=Lax (or Strict).", evidence))
        elif cookie.samesite.lower() == "none" and not cookie.secure:
            findings.append(Finding(
                "cookies.samesite-none-insecure",
                f"Cookie {cookie.name!r} uses SameSite=None without Secure",
                Severity.MEDIUM,
                "Browsers reject SameSite=None cookies that are not Secure, and it widens cross-site exposure.",
                "Add Secure, or use SameSite=Lax.", evidence))
    return findings
