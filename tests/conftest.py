import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from scanner.context import ScanContext
from scanner.http import Response, fetch
from scanner.safety import AuthorizedTarget, authorize_target


@pytest.fixture(autouse=True)
def no_delay(monkeypatch):
    """Tests should not wait between probes."""
    monkeypatch.setattr("scanner.context.DEFAULT_DELAY", 0)


@pytest.fixture
def make_response():
    """Build a Response without any network, for unit-testing checks."""

    def _make(headers=(), scheme="https", status=200):
        port = 443 if scheme == "https" else 80
        target = AuthorizedTarget(
            f"{scheme}://127.0.0.1/", scheme, "127.0.0.1", port, ("127.0.0.1",), "loopback"
        )
        return Response(
            target, "/", status, tuple(headers), b"", True if scheme == "https" else None
        )

    return _make


@pytest.fixture
def serve():
    """Start a throwaway local web server. Returns its base URL.

    routes: {path: (status, [(header, value), ...], body_bytes)}
    A "*" route answers every path that has no route of its own.
    """
    servers = []

    def _serve(routes):
        class Handler(BaseHTTPRequestHandler):
            server_version = "demo"
            sys_version = ""

            def do_GET(self):
                status, headers, body = (
                    routes.get(self.path) or routes.get("*") or (404, [], b"not found")
                )
                self.send_response(status)
                for name, value in headers:
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(
            target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
        ).start()
        servers.append(server)
        return f"http://127.0.0.1:{server.server_address[1]}"

    yield _serve
    for server in servers:
        server.shutdown()
        server.server_close()


@pytest.fixture
def make_ctx():
    """Fetch a served site and return a ScanContext ready for check(ctx)."""

    def _make(base_url, **kwargs):
        response = fetch(authorize_target(base_url))
        return ScanContext(response, **kwargs)

    return _make
