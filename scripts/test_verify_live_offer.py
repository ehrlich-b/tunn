#!/usr/bin/env python3
"""Small loopback-only checkpoint fixtures, including outbound request guards."""

import ast
from contextlib import redirect_stdout
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import unittest
from unittest.mock import patch
import urllib.parse


SCRIPT = Path(__file__).with_name("verify-live-offer.py")
spec = importlib.util.spec_from_file_location("verify_live_offer", SCRIPT)
verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)
VERSION = "v1.2.3"
BINARIES = {"tunn-linux-amd64": b"fixture binary one\x00", "tunn-darwin-arm64": b"fixture binary two\xff"}
CHECKS = ("version", "checksums", "pricing", "about", "mcp")


class Fixture(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_HEAD(self):
        # The actual upgrade handler accepts GET only.
        self.send_error(405)

    def do_GET(self):
        self.server.requests.append((self.command, self.headers["Host"], self.path))
        case = self.server.case
        status, headers = 200, {}
        names = [*BINARIES, "SHA256SUMS", "checksums.txt"]
        # Match the absolute public URLs emitted by stage-release.py while the
        # matching download tree is served only by this loopback server.
        asset_base = "https://tunn.to"
        if case == "same_origin_assets":
            asset_base = self.server.base
        elif case == "relative_assets":
            asset_base = ""
        feed = {"tag_name": "v9.9.9" if case == "version" else VERSION,
                "assets": [{"name": name, "browser_download_url":
                            asset_base + f"/dl/{VERSION}/{name}"} for name in names]}
        if case == "foreign_asset":
            feed["assets"][0]["browser_download_url"] = "http://outside.invalid/binary"
        if case == "canonical_wrong_path":
            feed["assets"][0]["browser_download_url"] = "https://tunn.to/account"
        if case == "canonical_query":
            feed["assets"][0]["browser_download_url"] += "?download=1"
        if case == "canonical_fragment":
            feed["assets"][0]["browser_download_url"] += "#binary"
        if case == "missing_assets":
            feed["assets"] = []
        if self.path == "/dl/latest.json":
            body = json.dumps(feed).encode()
        elif self.path in (f"/dl/{VERSION}/SHA256SUMS", f"/dl/{VERSION}/checksums.txt"):
            body = "".join(f"{hashlib.sha256(data).hexdigest()}  {name}\n"
                           for name, data in BINARIES.items()).encode()
            if case == "missing_checksum":
                body = body.splitlines(keepends=True)[0]
        elif self.path.startswith(f"/dl/{VERSION}/") and self.path.rsplit("/", 1)[-1] in BINARIES:
            name = self.path.rsplit("/", 1)[-1]
            body = b"corrupt" if case == "checksums" and name == next(iter(BINARIES)) else BINARIES[name]
        elif self.path == "/pricing":
            body = b'<h1>Pro</h1><a href="/upgrade?period=monthly">Go <b>Pro</b> monthly</a>'
            if case == "pricing":
                body += b"<p>Checkout is not available yet. Free tunnels still work.</p>"
            if case == "missing_offer":
                body = b"<h1>Pro</h1>"
            if case == "foreign_offer":
                body = body.replace(b"/upgrade?period=monthly", b"http://outside.invalid/upgrade?period=monthly")
        elif self.path == "/upgrade?period=monthly":
            status, body = 302, b""
            headers["Location"] = "/auth/login?return_to=%2Fupgrade%3Fperiod%3Dmonthly"
            if case == "bad_redirect":
                headers["Location"] = "/auth/login?return_to=%2Faccount"
            if case == "foreign_redirect":
                headers["Location"] = "http://outside.invalid/login"
            if case == "checkout_503":
                status = 503
        elif self.path == "/about":
            body = b"<h1>Operator facts</h1><dd>Confirmed operator</dd>"
            if case == "about":
                body += b"<dd>Being <em>confirmed</em></dd>"
            if case == "about_404":
                status = 404
        elif self.path == "/mcp-to-claude":
            body = b"<h1>Connect MCP</h1>"
            if case == "mcp":
                body += b"<p>Experimental: connections to Claude.ai and ChatGPT have not yet been verified end to end.</p>"
            if case == "foreign_page_redirect":
                status, headers["Location"] = 302, "http://outside.invalid/mcp"
        else:
            status, body = 404, b"Unexpected request"
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)


class LiveOfferTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
        cls.server.base = f"http://127.0.0.1:{cls.server.server_port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def run_case(self, case, failed=()):
        self.server.case, self.server.requests = case, []
        output = io.StringIO()
        connect = socket.create_connection
        open_request = verify.urllib.request.OpenerDirector.open
        outbound = []

        def guarded_connect(address, *args, **kwargs):
            self.assertEqual(address, ("127.0.0.1", self.server.server_port))
            return connect(address, *args, **kwargs)

        def guarded_open(opener, request, *args, **kwargs):
            self.assertEqual(verify.origin(request.full_url), verify.origin(self.server.base))
            self.assertIn(request.get_method(), ("GET", "HEAD"))
            self.assertIsNone(request.data)
            self.assertIsNone(request.get_header("Authorization"))
            self.assertIsNone(request.get_header("Cookie"))
            self.assertEqual(kwargs.get("timeout"), 10)
            outbound.append(request.full_url)
            return open_request(opener, request, *args, **kwargs)

        with patch.object(socket, "create_connection", guarded_connect), patch.object(
                verify.urllib.request.OpenerDirector, "open", guarded_open), redirect_stdout(output):
            code = verify.main([self.server.base, "--expect-version", VERSION])
        lines = output.getvalue().splitlines()
        self.assertEqual(code, int(bool(failed)), lines)
        self.assertEqual(len(lines), len(CHECKS), lines)
        for name, line in zip(CHECKS, lines):
            self.assertTrue(line.startswith(f"{'FAIL' if name in failed else 'PASS'}: {name}"), lines)
        self.assertTrue(outbound)
        for method, host, path in self.server.requests:
            self.assertIn(method, ("GET", "HEAD"))
            self.assertEqual(host, urllib.parse.urlsplit(self.server.base).netloc)
            self.assertFalse(path.startswith(("/login", "/auth/")))
        print(f"fixture={case}\n" + output.getvalue(), end="")

    def test_passing_and_one_failure_per_check(self):
        self.run_case("passing")
        for check in CHECKS:
            with self.subTest(check=check):
                self.run_case(check, (check,))

    def test_download_url_formats(self):
        for case in ("same_origin_assets", "relative_assets"):
            with self.subTest(case=case):
                self.run_case(case)

    def test_rejects_missing_proof_and_unsafe_urls(self):
        cases = {"foreign_asset": "checksums", "missing_assets": "checksums",
                 "canonical_wrong_path": "checksums", "canonical_query": "checksums",
                 "canonical_fragment": "checksums",
                 "missing_checksum": "checksums", "missing_offer": "pricing",
                 "foreign_offer": "pricing", "bad_redirect": "pricing",
                 "foreign_redirect": "pricing", "checkout_503": "pricing",
                 "about_404": "about", "foreign_page_redirect": "mcp"}
        for case, check in cases.items():
            with self.subTest(case=case):
                self.run_case(case, (check,))

    def test_cli(self):
        for case in ("passing", "mcp"):
            with self.subTest(case=case):
                self.server.case, self.server.requests = case, []
                result = subprocess.run([sys.executable, str(SCRIPT), self.server.base,
                                         "--expect-version", VERSION], capture_output=True, text=True,
                                        timeout=10, env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
                self.assertEqual(result.returncode, int(case != "passing"), result.stderr)
                self.assertEqual(len(result.stdout.splitlines()), 5)
                self.assertEqual(result.stdout.count("FAIL:"), int(case != "passing"))

    def test_standard_library_only(self):
        tree = ast.parse(SCRIPT.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module]
            else:
                continue
            for name in names:
                self.assertIn(name.split(".")[0], sys.stdlib_module_names)


if __name__ == "__main__":
    unittest.main(verbosity=2)
