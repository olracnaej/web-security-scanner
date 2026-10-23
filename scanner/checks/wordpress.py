"""WordPress checks. Only runs when the page looks like a WordPress site."""

from __future__ import annotations

import re
from datetime import date

from scanner import data
from scanner.context import ScanContext
from scanner.models import Finding, Severity

MARKERS = (b"/wp-content/", b"/wp-includes/", b"wp-json")
VERSION = rb"([0-9]+(?:\.[0-9]+)+)"
VER_PARAM_RE = re.compile(rb"/wp-includes/[^\"'\s>]*\?ver=" + VERSION)
PLUGIN_RE = re.compile(rb"/wp-content/plugins/([A-Za-z0-9_-]+)/")
README_RE = re.compile(rb"Version\s+" + VERSION)
LOG_LINE_RE = re.compile(rb"\[\d{1,2}-[A-Za-z]{3}-\d{4}|PHP (Warning|Notice|Fatal|Deprecated)")
CONFIG_BACKUPS = (
    "/wp-config.php.bak", "/wp-config.php~", "/wp-config.php.old",
    "/wp-config.php.save", "/wp-config.php.orig", "/wp-config.txt",
)


def is_wordpress(body: bytes) -> bool:
    lowered = body.lower()
    return any(marker in lowered for marker in MARKERS) or b'content="wordpress' in lowered


def generator_version(body: bytes) -> str | None:
    for tag in re.finditer(rb"<meta[^>]*>", body, re.I):
        text = tag.group(0)
        if b"generator" in text.lower():
            found = re.search(rb"wordpress\s+" + VERSION, text, re.I)
            if found:
                return found.group(1).decode()
    return None


def _as_tuple(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def outdated_severity(version: str, today: date | None = None) -> Severity | None:
    """Severity if `version` is behind the current series, else None.
    Returns None when the reference data is too old to trust."""
    today = today or date.today()
    if (today - data.WP_REFERENCE_DATE).days > data.WP_REFERENCE_MAX_AGE_DAYS:
        return None
    try:
        major, minor = (_as_tuple(version) + (0, 0))[:2]
    except ValueError:
        return None
    current_major, current_minor = data.WP_CURRENT_SERIES
    if (major, minor) >= (current_major, current_minor):
        return None
    return Severity.MEDIUM if major < current_major else Severity.LOW


def _listing(body: bytes) -> bool:
    lowered = body[:65536].lower()
    return b"<title>index of" in lowered or b"directory listing for" in lowered


def check(ctx: ScanContext) -> list[Finding]:
    body = ctx.response.body
    if not is_wordpress(body):
        return []
    findings: list[Finding] = []

    # ---- version -------------------------------------------------------
    generator = generator_version(body)
    version = generator
    if generator:
        findings.append(Finding(
            "wordpress.version-exposed", "WordPress version is shown in the page source",
            Severity.LOW,
            "Attackers can match the exact version against known vulnerabilities.",
            "Remove the generator tag: remove_action('wp_head', 'wp_generator');",
            f"generator meta tag: WordPress {generator}"))

    readme = ctx.probe("/readme.html")
    if readme is not None and readme.status == 200 and b"wordpress" in readme.body.lower():
        found = README_RE.search(readme.body)
        shown = found.group(1).decode() if found else None
        version = version or shown
        findings.append(Finding(
            "wordpress.readme", "WordPress readme.html is reachable", Severity.LOW,
            "It confirms the site runs WordPress and often shows the version.",
            "Delete readme.html (it comes back after updates, so block it in the server config).",
            "GET /readme.html returned HTTP 200" + (f", version {shown}" if shown else "")))

    if version is None:
        found = VER_PARAM_RE.search(body)
        version = found.group(1).decode() if found else None

    findings.append(Finding(
        "wordpress.detected", "WordPress detected", Severity.INFO,
        "Knowing the platform tells you which WordPress-specific checks apply.",
        "Keep core, themes and plugins updated.",
        f"version {version}" if version else "version could not be determined"))

    if version:
        severity = outdated_severity(version)
        if severity is not None:
            current = ".".join(map(str, data.WP_CURRENT_SERIES))
            findings.append(Finding(
                "wordpress.outdated", "WordPress is older than the current release series",
                severity,
                "Only the newest WordPress series is officially supported, so older sites "
                "may miss security fixes.",
                "Update WordPress core (back up first).",
                f"detected {version}; current series {current} "
                f"(reference checked {data.WP_REFERENCE_DATE})"))

    # ---- plugins seen in the page --------------------------------------
    plugins = sorted({m.group(1).decode() for m in PLUGIN_RE.finditer(body)})
    if plugins:
        findings.append(Finding(
            "wordpress.plugins", "Plugins visible in the page source", Severity.INFO,
            "Each plugin is extra attack surface and needs its own updates. "
            "Versions were not checked.",
            "Remove unused plugins and keep the rest updated.",
            ", ".join(plugins[:15]) + (" ..." if len(plugins) > 15 else "")))

    # ---- user enumeration ------------------------------------------------
    for path in ("/wp-json/wp/v2/users", "/?rest_route=/wp/v2/users"):
        reply = ctx.probe(path)
        if reply is None or reply.status != 200 or not reply.body.lstrip().startswith(b"["):
            continue
        count = len(re.findall(rb'"slug"\s*:', reply.body))
        if count:
            findings.append(Finding(
                "wordpress.user-enum", "WordPress user list is public", Severity.MEDIUM,
                "Login names are half of a login; attackers use the list for password guessing.",
                "Restrict the REST users endpoint (a security plugin or a small filter does this).",
                f"GET {path} lists {count} user(s)"))
            break

    reply = ctx.probe("/?author=1")
    if reply is not None and reply.status in (301, 302):
        if "/author/" in (reply.header("location") or ""):
            findings.append(Finding(
                "wordpress.author-enum", "Author archive reveals login names", Severity.LOW,
                "Requesting /?author=1 redirects to a URL containing the user name.",
                "Block ?author= requests or redirect them to the home page.",
                "GET /?author=1 redirects to an /author/<name>/ URL"))

    reply = ctx.probe("/xmlrpc.php")
    if reply is not None and b"xml-rpc server accepts post requests only" in reply.body.lower():
        findings.append(Finding(
            "wordpress.xmlrpc", "xmlrpc.php is enabled", Severity.LOW,
            "It lets attackers try many passwords in a single request.",
            "Disable XML-RPC unless you need it (a plugin or one server rule does this).",
            f"GET /xmlrpc.php answered HTTP {reply.status}"))

    # ---- leaked files ------------------------------------------------------
    for path in CONFIG_BACKUPS:
        reply = ctx.probe(path)
        if reply is not None and reply.status == 200 and (
            b"DB_PASSWORD" in reply.body or b"DB_NAME" in reply.body
        ):
            findings.append(Finding(
                "wordpress.config-backup", "wp-config backup is publicly accessible",
                Severity.HIGH,
                "It contains the database name, user and password.",
                "Delete it, then change the database password and the secret keys.",
                f"GET {path} returned HTTP 200 with matching content"))

    reply = ctx.probe("/wp-content/debug.log")
    if reply is not None and reply.status == 200 and LOG_LINE_RE.search(reply.body):
        findings.append(Finding(
            "wordpress.debug-log", "WordPress debug.log is publicly accessible", Severity.MEDIUM,
            "Logs reveal file paths, plugin errors and sometimes private data.",
            "Delete it and set WP_DEBUG_LOG to a path outside the web root.",
            "GET /wp-content/debug.log returned HTTP 200 with log lines"))

    for path in ("/wp-content/uploads/", "/wp-content/plugins/"):
        reply = ctx.probe(path)
        if reply is not None and reply.status == 200 and _listing(reply.body):
            findings.append(Finding(
                "wordpress.directory-listing", f"Directory listing enabled on {path}",
                Severity.MEDIUM,
                "Visitors can browse and download everything in the folder.",
                "Disable directory listing (Options -Indexes) or add an empty index.php.",
                f"GET {path} shows a file listing"))

    return findings
