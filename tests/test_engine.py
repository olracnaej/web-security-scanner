import socket

import pytest

from scanner.engine import run_scan
from scanner.http import FetchError
from scanner.safety import RefusedTarget


def test_scan_of_bare_local_site_finds_header_and_cookie_issues(serve):
    base = serve({"/": (200, [("Set-Cookie", "PHPSESSID=abc; path=/")], b"<html></html>")})
    result = run_scan(base)
    found = {f.check_id for f in result.findings}
    assert {"headers.csp-missing", "headers.clickjacking", "cookies.no-httponly"} <= found
    assert result.response.status == 200
    # worst findings first
    severities = [f.severity for f in result.findings]
    assert severities == sorted(severities, reverse=True)


def test_repeated_set_cookie_headers_are_kept_separate(serve):
    base = serve({"/": (200, [("Set-Cookie", "a=1"), ("Set-Cookie", "b=2")], b"x")})
    assert len(run_scan(base).response.header_all("set-cookie")) == 2


def test_same_host_redirect_is_followed(serve):
    base = serve({
        "/": (302, [("Location", "/home")], b""),
        "/home": (200, [("X-Content-Type-Options", "nosniff")], b"ok"),
    })
    result = run_scan(base)
    assert result.response.path == "/home"
    assert result.response.redirects == ("/home",)


def test_redirect_to_cloud_metadata_is_refused(serve):
    base = serve({"/": (302, [("Location", "http://169.254.169.254/latest/meta-data/")], b"")})
    with pytest.raises(RefusedTarget):
        run_scan(base)


def test_redirect_loop_stops(serve):
    base = serve({"/": (302, [("Location", "/")], b"")})
    with pytest.raises(FetchError, match="too many redirects"):
        run_scan(base)


def test_closed_port_is_a_fetch_error():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    with pytest.raises(FetchError):
        run_scan(f"http://127.0.0.1:{port}/", )


def test_guard_runs_before_any_request():
    with pytest.raises(RefusedTarget):
        run_scan("http://169.254.169.254/")
