"""Definitions of the three practice sites.

Every password, key and name here is made up. Nothing should ever look like a
real credential, so GitHub secret scanning has nothing to complain about.
"""

from __future__ import annotations

from dataclasses import dataclass, field

Route = tuple[int, list[tuple[str, str]], bytes]


@dataclass(frozen=True)
class Site:
    name: str
    port: int
    summary: str
    banner: str                       # value of the Server header
    routes: dict[str, Route]
    extra_headers: tuple[tuple[str, str], ...] = field(default_factory=tuple)


def _page(title: str, body: str) -> bytes:
    return (
        f"<!doctype html><html><head><title>{title}</title></head><body>"
        f"<h1>{title}</h1>{body}"
        "<p><em>Intentionally insecure test site. For scanner practice only.</em></p>"
        "</body></html>"
    ).encode()


# ---------------------------------------------------------------- 1. bare
BARE = Site(
    name="bare",
    port=8101,
    summary="No security headers, version leaks and sloppy cookies",
    banner="Apache/2.4.41 (Ubuntu)",
    extra_headers=(("X-Powered-By", "PHP/7.4.3"),),
    routes={
        "/": (
            200,
            [
                ("Content-Type", "text/html"),
                ("Set-Cookie", "PHPSESSID=fake-session-value; path=/"),
                ("Set-Cookie", "theme=dark; path=/"),
                ("Set-Cookie", "auth_token=fake-token-value; path=/; SameSite=None"),
            ],
            _page("Bare test site", "<p>No security headers at all.</p>"),
        ),
    },
)

# --------------------------------------------------------------- 2. leaky
_LISTING = _page(
    "Index of /",
    "<ul>"
    '<li><a href=".env">.env</a></li>'
    '<li><a href="backup.sql">backup.sql</a></li>'
    '<li><a href="backup.zip">backup.zip</a></li>'
    '<li><a href="phpinfo.php">phpinfo.php</a></li>'
    "</ul>",
)

LEAKY = Site(
    name="leaky",
    port=8102,
    summary="Exposed .git, .env, backups, phpinfo and a directory listing",
    banner="nginx/1.14.0",
    routes={
        "/": (200, [("Content-Type", "text/html")], _LISTING),
        "/.git/HEAD": (200, [("Content-Type", "text/plain")], b"ref: refs/heads/main\n"),
        "/.git/config": (
            200, [("Content-Type", "text/plain")],
            b"[core]\n\trepositoryformatversion = 0\n\tbare = false\n",
        ),
        "/.env": (
            200, [("Content-Type", "text/plain")],
            b"APP_ENV=production\nDB_PASSWORD=FAKE-not-a-real-password\nFAKE_API_KEY=not-a-real-key\n",
        ),
        "/backup.sql": (
            200, [("Content-Type", "application/sql")],
            b"-- MySQL dump (fake test data)\nCREATE TABLE users (id INT, name TEXT);\n"
            b"INSERT INTO users VALUES (1, 'fake user');\n",
        ),
        "/backup.zip": (
            200, [("Content-Type", "application/zip")],
            b"PK\x03\x04 this is not a real archive, only fake test bytes",
        ),
        "/phpinfo.php": (
            200, [("Content-Type", "text/html")],
            b"<html><head><title>phpinfo()</title></head><body>PHP Version 7.4.3 (fake page)</body></html>",
        ),
    },
)

# ------------------------------------------------------------ 3. wordpress
_WP_HOME = _page(
    "Fake WordPress blog",
    '<link rel="stylesheet" href="/wp-content/plugins/contact-form-7/style.css">'
    '<script src="/wp-content/plugins/woocommerce/app.js"></script>'
    '<script src="/wp-content/plugins/elementor/frontend.js"></script>'
    '<script src="/wp-includes/js/jquery/jquery.min.js?ver=6.4.2"></script>'
    '<link rel="https://api.w.org/" href="/wp-json/">',
).replace(
    b"<head>",
    b'<head><meta name="generator" content="WordPress 6.4.2" />',
)

WORDPRESS = Site(
    name="wordpress",
    port=8103,
    summary="Old WordPress with public users, xmlrpc and a leaked wp-config backup",
    banner="Apache/2.4.41 (Ubuntu)",
    routes={
        "/": (
            200,
            [("Content-Type", "text/html"),
             ("Set-Cookie", "wordpress_test_cookie=WP%20Cookie%20check; path=/")],
            _WP_HOME,
        ),
        "/readme.html": (
            200, [("Content-Type", "text/html")],
            b"<html><body><h1>WordPress</h1><p>Version 6.4.2</p></body></html>",
        ),
        "/wp-json/wp/v2/users": (
            200, [("Content-Type", "application/json")],
            b'[{"id":1,"name":"Fake Admin","slug":"fake-admin"},'
            b'{"id":2,"name":"Fake Editor","slug":"fake-editor"}]',
        ),
        "/?author=1": (301, [("Location", "/author/fake-admin/")], b""),
        "/xmlrpc.php": (
            405, [("Content-Type", "text/plain")],
            b"XML-RPC server accepts POST requests only.",
        ),
        "/wp-config.php.bak": (
            200, [("Content-Type", "text/plain")],
            b"<?php\ndefine('DB_NAME', 'fake_db');\n"
            b"define('DB_PASSWORD', 'FAKE-not-a-real-password');\n",
        ),
        "/wp-content/debug.log": (
            200, [("Content-Type", "text/plain")],
            b"[21-Oct-2026 10:15:02 UTC] PHP Warning:  Undefined variable $demo "
            b"in /var/www/html/wp-content/plugins/demo/demo.php on line 12\n",
        ),
        "/wp-content/uploads/": (
            200, [("Content-Type", "text/html")],
            b"<html><head><title>Index of /wp-content/uploads</title></head>"
            b"<body><h1>Index of /wp-content/uploads</h1></body></html>",
        ),
    },
)

SITES: dict[str, Site] = {s.name: s for s in (BARE, LEAKY, WORDPRESS)}
