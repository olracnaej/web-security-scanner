import datetime as dt
import shutil
import ssl
import subprocess
import threading
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from scanner.checks import tls
from scanner.checks.tls import TlsInfo, analyze
from scanner.context import ScanContext
from scanner.engine import run_scan
from scanner.http import Response

NOW = dt.datetime(2026, 10, 22, tzinfo=dt.timezone.utc)


def ids(findings):
    return {f.check_id for f in findings}


def test_healthy_certificate_has_no_findings():
    info = TlsInfo("TLSv1.3", None, NOW + dt.timedelta(days=90))
    assert analyze(info, now=NOW) == []


@pytest.mark.parametrize(
    "message, check_id, severity",
    [
        ("certificate has expired", "tls.cert-expired", "high"),
        ("self-signed certificate", "tls.cert-untrusted", "medium"),
        ("unable to get local issuer certificate", "tls.cert-untrusted", "medium"),
        ("Hostname mismatch, certificate is not valid for 'x'.", "tls.cert-hostname", "high"),
        ("IP address mismatch, certificate is not valid for '1.2.3.4'.", "tls.cert-hostname", "high"),
    ],
)
def test_certificate_problems(message, check_id, severity):
    found = analyze(TlsInfo("TLSv1.3", message), now=NOW)
    assert [(f.check_id, f.severity.label) for f in found] == [(check_id, severity)]
    assert found[0].evidence == message


def test_certificate_problems_are_info_on_local_sites():
    found = analyze(TlsInfo("TLSv1.3", "self-signed certificate"), local=True, now=NOW)
    assert found[0].severity.label == "info"
    assert "local test site" in found[0].description


@pytest.mark.parametrize("days, severity", [(5, "high"), (20, "medium")])
def test_certificate_expiring_soon(days, severity):
    info = TlsInfo("TLSv1.3", None, NOW + dt.timedelta(days=days, hours=1))
    found = analyze(info, now=NOW)
    assert [(f.check_id, f.severity.label) for f in found] == [("tls.cert-expiring", severity)]


def test_obsolete_versions_are_flagged():
    found = analyze(TlsInfo("TLSv1.3", None, NOW + dt.timedelta(days=90),
                            legacy_accepted=("TLSv1", "TLSv1.1")), now=NOW)
    assert ids(found) == {"tls.obsolete-accepted"}
    assert "TLSv1.1" in found[0].evidence
    assert ids(analyze(TlsInfo("TLSv1"), now=NOW)) == {"tls.obsolete-negotiated"}


def test_handshake_error_is_reported():
    assert ids(analyze(TlsInfo(error="connection reset"))) == {"tls.handshake-failed"}


# ---- check(): plain HTTP and redirect handling ---------------------------

def _ctx(make_response, scheme, reason, port=None, **kw):
    resp = make_response([], scheme=scheme)
    target = replace(resp.target, reason=reason, **({"port": port} if port else {}))
    return ScanContext(replace(resp, target=target), **kw)


def test_plain_http_on_a_real_site_is_flagged(make_response):
    found = tls.check(_ctx(make_response, "http", "allow-listed"))
    assert ids(found) == {"tls.no-https"}


def test_plain_http_on_localhost_is_fine(make_response):
    assert tls.check(_ctx(make_response, "http", "loopback")) == []


def _fake_http_side(monkeypatch, make_response, status, headers=()):
    monkeypatch.setattr(tls, "authorize_target", lambda url, allow=(): make_response(scheme="http").target)
    reply = make_response(headers, scheme="http", status=status)
    monkeypatch.setattr(tls, "fetch_once", lambda *a, **k: reply)


def test_missing_http_to_https_redirect(make_response, monkeypatch):
    _fake_http_side(monkeypatch, make_response, 200)
    ctx = _ctx(make_response, "https", "allow-listed", port=443)
    assert ids(tls._redirect_findings(ctx)) == {"tls.no-http-redirect"}


def test_proper_http_to_https_redirect(make_response, monkeypatch):
    _fake_http_side(monkeypatch, make_response, 301, [("Location", "https://example.test/")])
    ctx = _ctx(make_response, "https", "allow-listed", port=443)
    assert tls._redirect_findings(ctx) == []


def test_redirect_check_skipped_for_localhost_and_odd_ports(make_response):
    assert tls._redirect_findings(_ctx(make_response, "https", "loopback", port=443)) == []
    assert tls._redirect_findings(_ctx(make_response, "https", "allow-listed", port=8443)) == []


# ---- real handshake against a throwaway HTTPS server ---------------------

needs_openssl = pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl not installed")


@pytest.fixture
def https_site(tmp_path):
    key, cert = tmp_path / "k.pem", tmp_path / "c.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
         "-out", str(cert), "-days", "2", "-subj", "/CN=localhost"],
        check=True, capture_output=True)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
    ).start()
    yield f"https://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


@needs_openssl
def test_self_signed_server_is_reported_against_a_real_handshake(https_site):
    result = run_scan(https_site)
    cert = next(f for f in result.findings if f.check_id == "tls.cert-untrusted")
    assert cert.severity.label == "info"  # local test site
    assert result.response.tls_verified is False
