import json

from scanner.engine import run_scan
from scanner.report import build_report, to_html, to_json

SECRET_COOKIE = "SuperSecretSessionValue123"
EVIL = "<script>alert('xss')</script>"


def _scan(serve):
    base = serve({"/": (200, [
        ("Set-Cookie", f"PHPSESSID={SECRET_COOKIE}; path=/"),
        ("X-Powered-By", EVIL),
        ("Server", "Apache/2.4.41"),
    ], b"<html></html>")})
    return run_scan(base, delay=0)


def test_json_report_structure(serve):
    report = build_report(_scan(serve))
    assert report["schema_version"] == 1
    assert report["tool"]["name"] == "web-security-scanner"
    assert report["score"]["max"] == 100 and report["score"]["grade"] in "ABCDF"
    assert report["target"]["http_status"] == 200
    assert sum(report["counts"].values()) == len(report["findings"])
    assert report["scanned_at"].endswith("Z")
    assert {"check_id", "title", "severity", "description", "recommendation", "evidence"} <= set(
        report["findings"][0]
    )


def test_json_is_valid_and_round_trips(serve):
    report = build_report(_scan(serve))
    assert json.loads(to_json(report)) == report


def test_cookie_values_never_reach_either_report(serve):
    report = build_report(_scan(serve))
    assert SECRET_COOKIE not in to_json(report)
    assert SECRET_COOKIE not in to_html(report)


def test_html_escapes_everything_the_site_controls(serve):
    page = to_html(build_report(_scan(serve)))
    assert EVIL not in page
    assert "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;" in page
    assert page.count("<script") == 0


def test_html_has_its_own_strict_csp_and_no_external_resources(serve):
    page = to_html(build_report(_scan(serve)))
    # quotes inside an HTML attribute are escaped; browsers decode them
    assert "Content-Security-Policy" in page and "default-src &#x27;none&#x27;" in page
    assert "http://" not in page.replace("http://127.0.0.1", "")
    assert "https://" not in page


def test_html_shows_grade_score_and_groups_by_severity(serve):
    report = build_report(_scan(serve))
    page = to_html(report)
    assert f'<span class="letter">{report["score"]["grade"]}</span>' in page
    assert f'{report["score"]["value"]}/100' in page
    assert page.index("Medium (") < page.index("Low (")
    assert "How the score was calculated" in page


def test_html_for_a_clean_result_says_so():
    from scanner.report import to_html as render
    report = {
        "schema_version": 1, "tool": {"name": "x", "version": "1"}, "scanned_at": "2026-01-01T00:00:00Z",
        "target": {"url": "http://x/", "http_status": 200, "requests_made": 1,
                   "redirects_followed": 0, "tls_verified": None},
        "score": {"value": 100, "max": 100, "grade": "A", "breakdown": {
            k: {"types": 0, "points": 0} for k in ("high", "medium", "low", "info")}},
        "counts": {"high": 0, "medium": 0, "low": 0, "info": 0}, "findings": [],
    }
    assert "No findings" in render(report)
