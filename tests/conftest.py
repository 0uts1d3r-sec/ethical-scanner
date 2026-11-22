"""Shared fixtures: a tiny local HTTP server, so no test touches the internet."""
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import ethical_scanner as core  # noqa: E402


class _Handler(BaseHTTPRequestHandler):
    routes = {}

    def log_message(self, *args):
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        status, body, headers = self.routes.get(parsed.path, (404, "", {}))
        if callable(body):
            body = body(parse_qs(parsed.query))
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body.encode())


@pytest.fixture
def serve():
    """serve({"/path": (status, body_or_callable, {headers})}) -> base URL."""
    servers = []

    def _serve(routes):
        handler = type("Handler", (_Handler,), {"routes": routes})
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        return f"http://127.0.0.1:{server.server_port}"

    yield _serve
    for server in servers:
        server.shutdown()
        server.server_close()


@pytest.fixture
def scan():
    """Run the scan engine synchronously and return the finished engine."""

    def _scan(url, sql=None, xss=None):
        engine = core.ScanEngine(
            url,
            sql or core.DEFAULT_SQL_PAYLOADS,
            xss or core.DEFAULT_XSS_PAYLOADS,
            log_callback=lambda msg, kind="info": None,
            vuln_callback=lambda vuln: None,
            cms_callback=lambda cms: None,
            done_callback=lambda results, cms: None,
        )
        engine.run()
        return engine

    return _scan
