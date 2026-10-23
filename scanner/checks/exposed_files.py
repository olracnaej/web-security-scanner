"""Exposed files: things that should never be reachable from the web.

A hit needs BOTH an HTTP 200 AND content that looks like the real thing, so
sites that answer 200 to everything ("soft 404") do not cause false alarms.
File contents are NEVER stored or printed, only the path.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from typing import Callable

from scanner.context import ScanContext
from scanner.models import Finding, Severity

Validator = Callable[[bytes], bool]


@dataclass(frozen=True)
class Signature:
    id: str
    path: str
    severity: Severity
    title: str
    why: str
    fix: str
    validator: Validator
    group: str = ""  # only the first hit in a group is reported


def _starts(*prefixes: bytes) -> Validator:
    return lambda body: body.startswith(prefixes)


def _has(*needles: bytes) -> Validator:
    return lambda body: any(n in body for n in needles)


_ENV_LINE = re.compile(rb"^[A-Za-z][A-Za-z0-9_]*\s*=\s*\S", re.M)
_HTPASSWD = re.compile(rb"^\S+:(\$apr1\$|\$2[aby]\$|\{SHA\}|[A-Za-z0-9./]{13})", re.M)
_HTML_START = (b"<!doctype", b"<html", b"<?xml")


def _is_env(body: bytes) -> bool:
    if body[:512].lstrip().lower().startswith(_HTML_START):
        return False
    return bool(_ENV_LINE.search(body[:4096]))


def _is_git_head(body: bytes) -> bool:
    return body.startswith(b"ref:") or bool(re.fullmatch(rb"[0-9a-f]{40}\s*", body))


SQL = _has(b"CREATE TABLE", b"-- MySQL dump", b"INSERT INTO", b"PostgreSQL database dump")
SECRETS_FIX = "Remove the file from the web root and block dot-files and backups in the server config."

SIGNATURES: tuple[Signature, ...] = (
    Signature("git", "/.git/HEAD", Severity.HIGH, ".git folder is publicly accessible",
              "Anyone can download the site's source code and history, often including passwords.",
              "Block access to /.git (nginx: location ~ /\\.git { deny all; }) or do not deploy it.",
              _is_git_head, "git"),
    Signature("git", "/.git/config", Severity.HIGH, ".git folder is publicly accessible",
              "Anyone can download the site's source code and history, often including passwords.",
              "Block access to /.git (nginx: location ~ /\\.git { deny all; }) or do not deploy it.",
              _has(b"[core]"), "git"),
    Signature("env", "/.env", Severity.HIGH, ".env file is publicly accessible",
              "It usually holds database passwords and API keys.",
              SECRETS_FIX + " Then rotate every secret that was in it.", _is_env, "env"),
    Signature("env", "/.env.local", Severity.HIGH, ".env file is publicly accessible",
              "It usually holds database passwords and API keys.",
              SECRETS_FIX + " Then rotate every secret that was in it.", _is_env, "env"),
    Signature("env", "/.env.production", Severity.HIGH, ".env file is publicly accessible",
              "It usually holds database passwords and API keys.",
              SECRETS_FIX + " Then rotate every secret that was in it.", _is_env, "env"),
    Signature("env", "/.env.backup", Severity.HIGH, ".env file is publicly accessible",
              "It usually holds database passwords and API keys.",
              SECRETS_FIX + " Then rotate every secret that was in it.", _is_env, "env"),
    Signature("htpasswd", "/.htpasswd", Severity.HIGH, ".htpasswd file is publicly accessible",
              "It contains password hashes that can be cracked offline.",
              SECRETS_FIX, lambda b: bool(_HTPASSWD.search(b[:4096]))),
    Signature("ssh-key", "/.ssh/id_rsa", Severity.HIGH, "Private SSH key is publicly accessible",
              "Anyone can log in to servers that trust this key.",
              "Remove it immediately and replace the key pair.",
              _has(b"PRIVATE KEY-----")),
    Signature("svn", "/.svn/wc.db", Severity.MEDIUM, ".svn folder is publicly accessible",
              "It exposes source code and file paths.",
              "Do not deploy .svn folders; block them in the server config.",
              _starts(b"SQLite format 3")),
    Signature("ds-store", "/.DS_Store", Severity.LOW, ".DS_Store file is publicly accessible",
              "It lists file and folder names from the developer's Mac.",
              "Delete it and block dot-files in the server config.",
              _starts(b"\x00\x00\x00\x01Bud1")),
    Signature("idea", "/.idea/workspace.xml", Severity.LOW, "IDE project folder is publicly accessible",
              "It reveals project structure and file names.",
              "Do not deploy .idea; block dot-folders in the server config.",
              _has(b"<project")),
    Signature("phpinfo", "/phpinfo.php", Severity.MEDIUM, "phpinfo() page is publicly accessible",
              "It shows the PHP version, modules, paths and server settings to attackers.",
              "Delete the file.", _has(b"phpinfo()", b"PHP Version"), "phpinfo"),
    Signature("phpinfo", "/info.php", Severity.MEDIUM, "phpinfo() page is publicly accessible",
              "It shows the PHP version, modules, paths and server settings to attackers.",
              "Delete the file.", _has(b"phpinfo()", b"PHP Version"), "phpinfo"),
    Signature("backup-zip", "/backup.zip", Severity.HIGH, "Backup archive is publicly accessible",
              "Anyone can download the whole site, including configuration and data.",
              "Remove it from the web root and keep backups elsewhere.", _starts(b"PK\x03\x04")),
    Signature("backup-zip", "/site.zip", Severity.HIGH, "Backup archive is publicly accessible",
              "Anyone can download the whole site, including configuration and data.",
              "Remove it from the web root and keep backups elsewhere.", _starts(b"PK\x03\x04")),
    Signature("backup-zip", "/www.zip", Severity.HIGH, "Backup archive is publicly accessible",
              "Anyone can download the whole site, including configuration and data.",
              "Remove it from the web root and keep backups elsewhere.", _starts(b"PK\x03\x04")),
    Signature("backup-targz", "/backup.tar.gz", Severity.HIGH, "Backup archive is publicly accessible",
              "Anyone can download the whole site, including configuration and data.",
              "Remove it from the web root and keep backups elsewhere.", _starts(b"\x1f\x8b")),
    Signature("sql-dump", "/backup.sql", Severity.HIGH, "Database dump is publicly accessible",
              "It contains the site's data, possibly including user accounts.",
              "Remove it from the web root and keep backups elsewhere.", SQL, "sql"),
    Signature("sql-dump", "/db.sql", Severity.HIGH, "Database dump is publicly accessible",
              "It contains the site's data, possibly including user accounts.",
              "Remove it from the web root and keep backups elsewhere.", SQL, "sql"),
    Signature("sql-dump", "/dump.sql", Severity.HIGH, "Database dump is publicly accessible",
              "It contains the site's data, possibly including user accounts.",
              "Remove it from the web root and keep backups elsewhere.", SQL, "sql"),
    Signature("sql-dump", "/database.sql", Severity.HIGH, "Database dump is publicly accessible",
              "It contains the site's data, possibly including user accounts.",
              "Remove it from the web root and keep backups elsewhere.", SQL, "sql"),
    Signature("php-backup", "/config.php.bak", Severity.HIGH, "PHP source backup is publicly accessible",
              "Backup files are served as plain text, so the code and its passwords can be read.",
              "Delete backup copies from the web root.", _has(b"<?php"), "php-backup"),
    Signature("php-backup", "/config.php.old", Severity.HIGH, "PHP source backup is publicly accessible",
              "Backup files are served as plain text, so the code and its passwords can be read.",
              "Delete backup copies from the web root.", _has(b"<?php"), "php-backup"),
    Signature("php-backup", "/config.php~", Severity.HIGH, "PHP source backup is publicly accessible",
              "Backup files are served as plain text, so the code and its passwords can be read.",
              "Delete backup copies from the web root.", _has(b"<?php"), "php-backup"),
    Signature("server-status", "/server-status", Severity.MEDIUM, "Apache server-status page is public",
              "It shows live requests, client IPs and internal URLs.",
              "Restrict /server-status to localhost.", _has(b"Apache Server Status")),
    Signature("phpmyadmin", "/phpmyadmin/", Severity.MEDIUM, "phpMyAdmin is reachable from the internet",
              "A database admin login page invites password guessing against the database.",
              "Restrict it by IP, put it behind a VPN, or remove it.", _has(b"phpMyAdmin")),
    Signature("adminer", "/adminer.php", Severity.MEDIUM, "Adminer is reachable from the internet",
              "A database admin login page invites password guessing against the database.",
              "Remove it or restrict it by IP.", _has(b"Adminer")),
    Signature("actuator-env", "/actuator/env", Severity.HIGH, "Spring Boot actuator /env is public",
              "It can expose configuration values, including credentials.",
              "Disable or secure actuator endpoints.", _has(b"propertySources", b"activeProfiles")),
    Signature("web-inf", "/WEB-INF/web.xml", Severity.MEDIUM, "Java WEB-INF folder is publicly accessible",
              "It reveals the application's internal configuration.",
              "Block /WEB-INF in the server config.", _has(b"<web-app")),
    Signature("composer", "/composer.json", Severity.LOW, "composer.json is publicly accessible",
              "It lists the PHP libraries and versions in use.",
              "Move it out of the web root or block it.", _has(b'"require"')),
    Signature("package-json", "/package.json", Severity.LOW, "package.json is publicly accessible",
              "It lists the JavaScript libraries and versions in use.",
              "Do not serve it, or block it in the server config.", _has(b'"dependencies"', b'"devDependencies"')),
)


def _listing_finding(ctx: ScanContext) -> list[Finding]:
    body = ctx.response.body[:65536].lower()
    if b"<title>index of" in body or b"directory listing for" in body:
        return [Finding(
            "exposed.directory-listing", "Directory listing is enabled", Severity.MEDIUM,
            "Visitors can browse the folder and download files that were never linked.",
            "Disable it (Apache: Options -Indexes, nginx: autoindex off).",
            ctx.response.target.url)]
    return []


def check(ctx: ScanContext) -> list[Finding]:
    findings = _listing_finding(ctx)

    # Soft-404 baseline: what does a page that cannot exist look like here?
    baseline = ctx.probe(f"/{uuid.uuid4().hex}-scanner-baseline")
    baseline_body = baseline.body if baseline is not None and baseline.status == 200 else None

    reported: set[str] = set()
    for sig in SIGNATURES:
        if sig.group and sig.group in reported:
            continue
        reply = ctx.probe(sig.path)
        if reply is None or reply.status != 200:
            continue
        if baseline_body is not None and reply.body == baseline_body:
            continue
        if not sig.validator(reply.body):
            continue
        if sig.group:
            reported.add(sig.group)
        findings.append(Finding(
            f"exposed.{sig.id}", sig.title, sig.severity, sig.why, sig.fix,
            f"GET {sig.path} returned HTTP 200 with matching content"))
    return findings
