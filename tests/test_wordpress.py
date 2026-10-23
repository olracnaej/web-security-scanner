from datetime import date

import pytest

from scanner import data
from scanner.checks import wordpress
from scanner.models import Severity

WP_HOME = b"""<html><head>
<meta name="generator" content="WordPress 6.4.2" />
<link rel="stylesheet" href="/wp-content/plugins/contact-form-7/style.css">
<script src="/wp-content/plugins/woocommerce/app.js"></script>
<script src="/wp-includes/js/jquery.js?ver=6.4.2"></script></head></html>"""


def ids(findings):
    return {f.check_id for f in findings}


def test_non_wordpress_site_is_ignored(serve, make_ctx):
    base = serve({"/": (200, [], b"<html>hello</html>")})
    assert wordpress.check(make_ctx(base)) == []


def test_wordpress_fingerprint_and_exposures(serve, make_ctx):
    base = serve({
        "/": (200, [], WP_HOME),
        "/readme.html": (200, [], b"<h1>WordPress</h1> Version 6.4.2"),
        "/wp-json/wp/v2/users": (200, [], b'[{"id":1,"slug":"admin"},{"id":2,"slug":"ana"}]'),
        "/?author=1": (301, [("Location", "http://x/author/admin/")], b""),
        "/xmlrpc.php": (405, [], b"XML-RPC server accepts POST requests only."),
    })
    found = wordpress.check(make_ctx(base))
    assert ids(found) >= {
        "wordpress.detected", "wordpress.version-exposed", "wordpress.readme",
        "wordpress.plugins", "wordpress.user-enum", "wordpress.author-enum",
        "wordpress.xmlrpc",
    }
    users = next(f for f in found if f.check_id == "wordpress.user-enum")
    assert "2 user(s)" in users.evidence and "admin" not in users.evidence
    plugins = next(f for f in found if f.check_id == "wordpress.plugins")
    assert "contact-form-7" in plugins.evidence and "woocommerce" in plugins.evidence


def test_version_falls_back_to_ver_parameter(serve, make_ctx):
    home = b'<script src="/wp-includes/js/a.js?ver=6.1.1"></script>'
    found = wordpress.check(make_ctx(serve({"/": (200, [], home)})))
    detected = next(f for f in found if f.check_id == "wordpress.detected")
    assert detected.evidence == "version 6.1.1"
    assert "wordpress.version-exposed" not in ids(found)


def test_config_backup_found_without_leaking_password(serve, make_ctx):
    base = serve({
        "/": (200, [], WP_HOME),
        "/wp-config.php.bak": (200, [], b"<?php define('DB_PASSWORD', 'hunter2');"),
    })
    found = wordpress.check(make_ctx(base))
    hit = next(f for f in found if f.check_id == "wordpress.config-backup")
    assert hit.severity == Severity.HIGH
    text = " ".join(f"{f.description} {f.evidence}" for f in found)
    assert "hunter2" not in text


def test_debug_log_and_uploads_listing(serve, make_ctx):
    base = serve({
        "/": (200, [], WP_HOME),
        "/wp-content/debug.log": (200, [], b"[21-Oct-2026 10:00:00 UTC] PHP Warning: x"),
        "/wp-content/uploads/": (200, [], b"<title>Index of /wp-content/uploads</title>"),
    })
    assert ids(wordpress.check(make_ctx(base))) >= {
        "wordpress.debug-log", "wordpress.directory-listing"}


def test_xmlrpc_needs_the_real_message(serve, make_ctx):
    base = serve({"/": (200, [], WP_HOME), "/xmlrpc.php": (405, [], b"Method not allowed")})
    assert "wordpress.xmlrpc" not in ids(wordpress.check(make_ctx(base)))


@pytest.mark.parametrize(
    "version, expected",
    [("6.4.2", Severity.MEDIUM), ("7.0", None), ("7.0.3", None), ("7.1", None)],
)
def test_outdated_severity(version, expected):
    assert wordpress.outdated_severity(version, today=date(2026, 10, 22)) == expected


def test_same_major_older_minor_is_low(monkeypatch):
    monkeypatch.setattr(data, "WP_CURRENT_SERIES", (6, 9))
    assert wordpress.outdated_severity("6.4", today=date(2026, 10, 22)) == Severity.LOW


def test_outdated_check_skipped_when_reference_is_stale():
    far_future = date(2028, 1, 1)
    assert wordpress.outdated_severity("5.0", today=far_future) is None


def test_outdated_finding_appears_in_scan(serve, make_ctx, monkeypatch):
    monkeypatch.setattr(data, "WP_REFERENCE_DATE", date.today())
    found = wordpress.check(make_ctx(serve({"/": (200, [], WP_HOME)})))
    assert "wordpress.outdated" in ids(found)


def test_generator_meta_attribute_order_does_not_matter():
    body = b'<meta content="WordPress 6.2.1" name="generator">'
    assert wordpress.generator_version(body) == "6.2.1"
