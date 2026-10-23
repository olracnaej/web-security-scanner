"""The practice sites must keep producing the findings the README promises."""

import threading

import pytest

from scanner.engine import run_scan
from test_sites.server import HOST, make_server
from test_sites.sites import SITES

EXPECTED = {
    "bare": {
        "headers.clickjacking", "headers.csp-missing", "headers.nosniff",
        "headers.referrer-policy", "headers.server-version", "headers.x-powered-by",
        "headers.permissions-policy", "cookies.no-httponly", "cookies.no-samesite",
        "cookies.samesite-none-insecure",
    },
    "leaky": {
        "exposed.git", "exposed.env", "exposed.sql-dump", "exposed.backup-zip",
        "exposed.phpinfo", "exposed.directory-listing", "headers.clickjacking",
        "headers.csp-missing", "headers.nosniff", "headers.referrer-policy",
        "headers.server-version", "headers.permissions-policy",
    },
    "wordpress": {
        "wordpress.detected", "wordpress.version-exposed", "wordpress.readme",
        "wordpress.outdated", "wordpress.plugins", "wordpress.user-enum",
        "wordpress.author-enum", "wordpress.xmlrpc", "wordpress.config-backup",
        "wordpress.debug-log", "wordpress.directory-listing", "headers.clickjacking",
        "headers.csp-missing", "headers.nosniff", "headers.referrer-policy",
        "headers.server-version", "headers.permissions-policy", "cookies.no-httponly",
        "cookies.no-samesite",
    },
}
HIGH_COUNT = {"bare": 0, "leaky": 4, "wordpress": 1}


@pytest.fixture
def running():
    servers = []

    def _start(name):
        server = make_server(name, port=0)  # port 0: any free port
        threading.Thread(
            target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
        ).start()
        servers.append(server)
        return server, f"http://{HOST}:{server.server_address[1]}"

    yield _start
    for server in servers:
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize("name", list(SITES))
def test_site_produces_exactly_the_documented_findings(running, name):
    _, url = running(name)
    result = run_scan(url, delay=0)
    assert {f.check_id for f in result.findings} == EXPECTED[name]
    highs = [f for f in result.findings if f.severity.label == "high"]
    assert len(highs) == HIGH_COUNT[name]


@pytest.mark.parametrize("name", list(SITES))
def test_sites_listen_on_localhost_only(running, name):
    server, _ = running(name)
    assert HOST == "127.0.0.1"
    assert server.server_address[0] == "127.0.0.1"


def test_every_fake_secret_is_obviously_fake():
    for site in SITES.values():
        for _, _, body in site.routes.values():
            lowered = body.lower()
            if b"password" in lowered or b"api_key" in lowered:
                assert b"fake" in lowered, f"{site.name}: secret not marked FAKE"


def test_ports_are_distinct():
    ports = [site.port for site in SITES.values()]
    assert len(ports) == len(set(ports))
