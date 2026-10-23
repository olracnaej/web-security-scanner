"""Tiny web server that serves one of the practice sites."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from test_sites.sites import SITES, Site

HOST = "127.0.0.1"  # fixed on purpose: these sites must never face a network


def make_server(name: str, port: int | None = None) -> ThreadingHTTPServer:
    """Create (but do not start) the server for a site. port=0 picks a free one."""
    site: Site = SITES[name]

    class Handler(BaseHTTPRequestHandler):
        def version_string(self) -> str:
            return site.banner

        def do_GET(self):
            status, headers, body = (
                site.routes.get(self.path) or (404, [("Content-Type", "text/plain")], b"not found")
            )
            self.send_response(status)
            for key, value in (*site.extra_headers, *headers):
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):
            print(f"[{site.name}] {self.address_string()} {fmt % args}")

    return ThreadingHTTPServer((HOST, site.port if port is None else port), Handler)
