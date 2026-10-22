import socket

import pytest

from scanner import safety
from scanner.safety import (
    RefusedTarget,
    authorize_redirect,
    authorize_target,
)


@pytest.fixture
def fake_dns(monkeypatch):
    table = {}

    def fake_getaddrinfo(host, port, type=0, **_):
        if host not in table:
            raise socket.gaierror("unknown host")
        out = []
        for ip in table[host]:
            fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
            out.append((fam, type, 6, "", (ip, port)))
        return out

    monkeypatch.setattr(safety.socket, "getaddrinfo", fake_getaddrinfo)
    return table


# --- allowed -------------------------------------------------------------

def test_loopback_ipv4_literal_is_allowed():
    t = authorize_target("http://127.0.0.1:8001/")
    assert t.reason == "loopback" and t.port == 8001


def test_loopback_ipv6_literal_is_allowed():
    assert authorize_target("http://[::1]:8000/").reason == "loopback"


def test_localhost_name_is_allowed(fake_dns):
    fake_dns["localhost"] = ["127.0.0.1", "::1"]
    t = authorize_target("https://localhost/")
    assert t.reason == "loopback" and t.port == 443


def test_public_host_needs_allow_list(fake_dns):
    fake_dns["example.com"] = ["93.184.216.34"]
    with pytest.raises(RefusedTarget, match="--allow-host example.com"):
        authorize_target("https://example.com/")
    t = authorize_target("https://example.com/", ["Example.com"])
    assert t.reason == "allow-listed"


def test_private_lan_needs_allow_list():
    with pytest.raises(RefusedTarget):
        authorize_target("http://192.168.1.10/")
    assert authorize_target("http://192.168.1.10/", ["192.168.1.10"]).reason == "allow-listed"


# --- always refused ------------------------------------------------------

@pytest.mark.parametrize(
    "ip",
    ["169.254.169.254", "0.0.0.0", "224.0.0.1", "100.64.0.1", "fe80::1",
     "::ffff:169.254.169.254"],
)
def test_never_scanned_addresses_refused_even_if_allow_listed(ip):
    host = f"[{ip}]" if ":" in ip else ip
    with pytest.raises(RefusedTarget, match="never scanned"):
        authorize_target(f"http://{host}/", [ip])


def test_dns_pointing_allowed_name_at_metadata_is_refused(fake_dns):
    fake_dns["sneaky.example"] = ["93.184.216.34", "169.254.169.254"]
    with pytest.raises(RefusedTarget, match="never scanned"):
        authorize_target("http://sneaky.example/", ["sneaky.example"])


def test_mixed_loopback_and_public_still_needs_allow_list(fake_dns):
    fake_dns["mixed.example"] = ["127.0.0.1", "93.184.216.34"]
    with pytest.raises(RefusedTarget):
        authorize_target("http://mixed.example/")


# --- URL and flag validation --------------------------------------------

@pytest.mark.parametrize(
    "url",
    ["ftp://127.0.0.1/", "file:///etc/passwd", "http://user:pw@127.0.0.1/",
     "http:///nohost", "http://127.0.0.1:99999/", "not a url"],
)
def test_bad_urls_refused(url):
    with pytest.raises(RefusedTarget):
        authorize_target(url)


def test_unresolvable_host_refused(fake_dns):
    with pytest.raises(RefusedTarget, match="cannot resolve"):
        authorize_target("http://nope.invalid/")


@pytest.mark.parametrize("bad", ["*.example.com", "https://example.com", "example.com/path", "a b", ""])
def test_allow_host_must_be_exact(bad):
    with pytest.raises(RefusedTarget):
        authorize_target("http://127.0.0.1/", [bad])


# --- redirects -----------------------------------------------------------

def test_redirect_same_host_ok():
    base = authorize_target("http://127.0.0.1:8001/")
    assert authorize_redirect(base, "/login").host == "127.0.0.1"


def test_redirect_to_other_host_refused():
    base = authorize_target("http://127.0.0.1:8001/")
    with pytest.raises(RefusedTarget, match="different host"):
        authorize_redirect(base, "http://169.254.169.254/latest/meta-data/")


def test_redirect_to_other_port_refused():
    base = authorize_target("http://127.0.0.1:8001/")
    with pytest.raises(RefusedTarget, match="port"):
        authorize_redirect(base, "http://127.0.0.1:22/")


def test_http_to_https_upgrade_allowed(fake_dns):
    fake_dns["example.com"] = ["93.184.216.34"]
    base = authorize_target("http://example.com/", ["example.com"])
    assert authorize_redirect(base, "https://example.com/", ["example.com"]).scheme == "https"
