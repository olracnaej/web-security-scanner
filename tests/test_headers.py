import pytest

from scanner.checks import headers

GOOD = [
    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
    ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "strict-origin-when-cross-origin"),
    ("Permissions-Policy", "geolocation=()"),
    ("Server", "nginx"),
]


def ids(findings):
    return {f.check_id for f in findings}


def test_well_configured_site_has_no_findings(make_response):
    assert headers.check(make_response(GOOD)) == []


def test_bare_https_site_flags_everything(make_response):
    found = ids(headers.check(make_response([])))
    assert found == {
        "headers.hsts-missing", "headers.csp-missing", "headers.clickjacking",
        "headers.nosniff", "headers.referrer-policy", "headers.permissions-policy",
    }


def test_hsts_not_required_on_plain_http(make_response):
    assert "headers.hsts-missing" not in ids(headers.check(make_response([], scheme="http")))


def test_short_hsts_is_flagged(make_response):
    hdrs = [h for h in GOOD if h[0] != "Strict-Transport-Security"]
    hdrs.append(("Strict-Transport-Security", "max-age=300"))
    assert ids(headers.check(make_response(hdrs))) == {"headers.hsts-weak"}


def test_csp_unsafe_inline_is_flagged(make_response):
    hdrs = [h for h in GOOD if h[0] != "Content-Security-Policy"]
    hdrs.append(("Content-Security-Policy",
                 "script-src 'self' 'unsafe-inline'; frame-ancestors 'none'"))
    assert ids(headers.check(make_response(hdrs))) == {"headers.csp-weak"}


def test_csp_unsafe_inline_ok_with_nonce(make_response):
    hdrs = [h for h in GOOD if h[0] != "Content-Security-Policy"]
    hdrs.append(("Content-Security-Policy",
                 "script-src 'nonce-abc123' 'unsafe-inline'; frame-ancestors 'none'"))
    assert headers.check(make_response(hdrs)) == []


def test_csp_without_script_rules_is_flagged(make_response):
    hdrs = [h for h in GOOD if h[0] != "Content-Security-Policy"]
    hdrs.append(("Content-Security-Policy", "frame-ancestors 'none'"))
    assert ids(headers.check(make_response(hdrs))) == {"headers.csp-no-script-src"}


def test_x_frame_options_alone_satisfies_clickjacking(make_response):
    hdrs = [h for h in GOOD if h[0] != "Content-Security-Policy"]
    hdrs += [("Content-Security-Policy", "default-src 'self'"), ("X-Frame-Options", "DENY")]
    assert headers.check(make_response(hdrs)) == []


def test_obsolete_x_frame_options_value_is_flagged(make_response):
    hdrs = [h for h in GOOD if h[0] != "Content-Security-Policy"]
    hdrs += [("Content-Security-Policy", "default-src 'self'"),
             ("X-Frame-Options", "ALLOW-FROM https://a.example")]
    assert ids(headers.check(make_response(hdrs))) == {"headers.xfo-invalid"}


@pytest.mark.parametrize("value", ["Apache/2.4.41 (Ubuntu)", "BaseHTTP/0.6 Python/3.14.7"])
def test_server_version_is_flagged(make_response, value):
    hdrs = [h for h in GOOD if h[0] != "Server"] + [("Server", value)]
    assert ids(headers.check(make_response(hdrs))) == {"headers.server-version"}


def test_x_powered_by_is_flagged(make_response):
    hdrs = GOOD + [("X-Powered-By", "PHP/7.4.3")]
    assert ids(headers.check(make_response(hdrs))) == {"headers.x-powered-by"}


def test_header_lookup_is_case_insensitive(make_response):
    hdrs = [(k.lower(), v) for k, v in GOOD]
    assert headers.check(make_response(hdrs)) == []
