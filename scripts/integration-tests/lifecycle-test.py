#!/usr/bin/env python3
"""Exercise the existing device-login/endpoint-token MCP lifecycle on loopback.

This is a synthetic HTTP consumer, not evidence of hosted UI acceptance or of
the planned expiring, per-consumer grant product. No DNS or external API is used.
"""

import http.client
import json
import os
from pathlib import Path
import signal
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from http.cookies import SimpleCookie
from urllib.parse import urlencode, urljoin, urlsplit


ROOT = Path(__file__).resolve().parents[2]
DOMAIN = "tunn.local.127.0.0.1.nip.io"
ENDPOINT = "lifecycle"
FIXTURE = ROOT / "scripts/integration-tests/fixtures/mcp-echo-server.py"


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


class Lifecycle:
    def __init__(self, work):
        self.work = work
        self.processes = []
        self.logs = {}
        self.cookies = {}
        self.port, self.oidc_port, self.grpc_port = free_port(), free_port(), free_port()
        self.base = f"https://{DOMAIN}:{self.port}"
        self.endpoint = f"https://{ENDPOINT}.{DOMAIN}:{self.port}/mcp"
        self.tls = ssl.create_default_context(cafile=str(ROOT / "certs/cert.pem"))
        self.env = {
            key: value for key, value in os.environ.items()
            if not key.startswith(("TUNN_", "FLY_"))
        }
        self.env.update({
            "TUNN_ENV": "dev",
            "TUNN_PUBLIC_MODE": "false",
            "TUNN_DOMAIN": DOMAIN,
            "TUNN_PUBLIC_ADDR": f"{DOMAIN}:{self.port}",
            "TUNN_SERVER_ADDR": f"127.0.0.1:{self.port}",
            "TUNN_HTTP2_ADDR": f"127.0.0.1:{self.port}",
            "TUNN_HTTP3_ADDR": f"127.0.0.1:{self.port}",
            "TUNN_INTERNAL_GRPC_PORT": f"127.0.0.1:{self.grpc_port}",
            "TUNN_MOCK_OIDC_ADDR": f"127.0.0.1:{self.oidc_port}",
            "TUNN_MOCK_OIDC_ISSUER": f"http://127.0.0.1:{self.oidc_port}",
            "TUNN_NODE_ADDRESSES": "",
            "TUNN_CONFIG_DIR": str(work / "config"),
            "TUNN_DB_PATH": str(work / "login.db"),
            "TUNN_JWT_SECRET": "synthetic-lifecycle-jwt-secret",
        })

    def start(self, name, args):
        logfile = self.work / f"{name}.log"
        self.logs[name] = logfile
        with logfile.open("ab") as output:
            process = subprocess.Popen(
                [str(ROOT / "bin/tunn"), *args], cwd=self.work, env=self.env,
                stdout=output, stderr=subprocess.STDOUT, start_new_session=True,
            )
        self.processes.append(process)
        return process

    @staticmethod
    def stop(process):
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=6)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=3)

    def wait(self, label, ready, process, timeout=12):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            require(process.poll() is None, f"{label} exited before readiness")
            if ready():
                return
            time.sleep(0.05)
        raise AssertionError(f"timed out waiting for {label}")

    def request(self, url, method="GET", body=None, headers=None, browser=False):
        parsed = urlsplit(url)
        # Even redirects are constrained to the exact local test origins.
        require(
            (parsed.scheme, parsed.hostname, parsed.port) in {
                ("https", DOMAIN, self.port),
                ("https", f"{ENDPOINT}.{DOMAIN}", self.port),
                ("http", "127.0.0.1", self.oidc_port),
            }, "request escaped the loopback fixture",
        )
        if parsed.scheme == "https":
            connection = http.client.HTTPSConnection(
                "127.0.0.1", parsed.port, context=self.tls, timeout=29,
            )
        else:
            connection = http.client.HTTPConnection("127.0.0.1", parsed.port, timeout=5)
        request_headers = {"Host": parsed.netloc, **(headers or {})}
        if browser and parsed.scheme == "https":
            request_headers["Cookie"] = "; ".join(
                f"{key}={value}" for key, value in self.cookies.items()
            )
        try:
            connection.request(method, parsed.path + ("?" + parsed.query if parsed.query else ""),
                               body=body, headers=request_headers)
            response = connection.getresponse()
            response_headers = dict((key.lower(), value) for key, value in response.getheaders())
            data = response.read().decode()
            if browser and "set-cookie" in response_headers:
                cookie = SimpleCookie(response_headers["set-cookie"])
                self.cookies.update((key, item.value) for key, item in cookie.items())
            return response.status, response_headers, data
        finally:
            connection.close()

    def browse(self, url):
        for _ in range(8):
            status, headers, body = self.request(url, browser=True)
            if status in (301, 302, 303, 307, 308):
                url = urljoin(url, headers["location"])
                continue
            require(status == 200, f"browser fixture returned {status}")
            return body
        raise AssertionError("login exceeded eight redirects")

    def start_relay(self):
        relay = self.start("relay", [
            "-mode=host", f"-cert={ROOT / 'certs/cert.pem'}",
            f"-key={ROOT / 'certs/key.pem'}",
        ])

        def healthy():
            try:
                return self.request(self.base + "/health")[0] == 200
            except OSError:
                return False

        self.wait("TLS relay", healthy, relay)
        return relay

    def rpc(self, request_id, method, params, token, session=""):
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if token:
            headers["Tunn-Authorization"] = f"Bearer {token}"
        if session:
            headers["Mcp-Session-Id"] = session
        return self.request(self.endpoint, "POST", json.dumps({
            "jsonrpc": "2.0", "id": request_id, "method": method, "params": params,
        }), headers)

    def echo(self, request_id, text, token, session):
        status, _, body = self.rpc(request_id, "tools/call", {
            "name": "echo", "arguments": {"text": text},
        }, token, session)
        require(status == 200, f"echo returned {status}")
        result = json.loads(body)
        require(result.get("id") == request_id, "echo response ID changed")
        require(result["result"]["content"][0]["text"] == "tunn-e2e:" + text,
                "echo result changed")

    def run(self):
        relay = self.start_relay()
        status, _, body = self.request(self.base + "/api/device/code", "POST")
        require(status == 200, "device code creation failed")
        device = json.loads(body)
        poll_url = self.base + "/api/device/token?" + urlencode({"code": device["device_code"]})
        require(json.loads(self.request(poll_url)[2])["error"] == "authorization_pending",
                "device token was issued before authorization")
        login_page = self.browse(device["verification_uri_complete"])
        require("Continue with Mock Login" in login_page, "mock login option missing")
        login_query = urlencode({"device_user_code": device["user_code"]})
        confirmation = self.browse(self.base + "/auth/mock?" + login_query)
        require("Authorize Device" in confirmation, "device confirmation missing")
        require(json.loads(self.request(poll_url)[2])["error"] == "authorization_pending",
                "OAuth login skipped explicit device authorization")
        status, _, _ = self.request(
            self.base + "/auth/device/authorize", "POST",
            urlencode({"code": device["user_code"]}),
            {"Content-Type": "application/x-www-form-urlencoded"}, browser=True,
        )
        require(status == 200, "explicit device authorization failed")
        login_token = json.loads(self.request(poll_url)[2])["access_token"]
        print("PASS device login and explicit authorization", flush=True)

        # Feed the JWT returned by the real login API directly to the CLI;
        # never read or replace the developer's ~/.tunn/token.
        publisher = self.start("publisher", [
            "mcp", "--name", ENDPOINT, "--secret", login_token,
            "--tools", "echo", "--", sys.executable, str(FIXTURE),
        ])
        registered = lambda: self.logs["publisher"].read_text().count("tunnel registered successfully")
        self.wait("authenticated publisher", lambda: registered() >= 1, publisher)
        require("creator=dev@example.com" in self.logs["relay"].read_text(),
                "relay did not authenticate the logged-in owner")
        token_path = self.work / "config/endpoints" / f"{ENDPOINT}.token"
        token = token_path.read_text().strip()
        require(token_path.stat().st_mode & 0o777 == 0o600, "endpoint token mode is not 0600")
        require(self.rpc(0, "tools/list", {}, "")[0] == 401, "missing token accepted")
        require(self.rpc(0, "tools/list", {}, "wrong-token")[0] == 401, "wrong token accepted")

        status, headers, body = self.rpc(1, "initialize", {
            "protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "tunn-lifecycle-consumer", "version": "1"},
        }, token)
        require(status == 200 and json.loads(body)["result"]["serverInfo"]["name"] == "tunn-e2e",
                "MCP connection failed")
        session = headers["mcp-session-id"]
        status, _, _ = self.request(self.endpoint, "POST", json.dumps({
            "jsonrpc": "2.0", "method": "notifications/initialized",
        }), {"Content-Type": "application/json", "Mcp-Session-Id": session,
             "Tunn-Authorization": f"Bearer {token}"})
        require(status == 202, "MCP initialized notification failed")
        require(self.rpc(2, "tools/list", {}, token, "wrong-session")[0] == 404,
                "wrong MCP session accepted")
        status, _, body = self.rpc(2, "tools/list", {}, token, session)
        require(status == 200 and [tool["name"] for tool in json.loads(body)["result"]["tools"]] == ["echo"],
                "tool allow-list was not enforced")
        started = time.monotonic()
        self.echo(3, "hello", token, session)
        print(f"PASS private connect, discovery, echo ({(time.monotonic() - started) * 1000:.1f} ms)", flush=True)
        status, _, body = self.rpc(4, "tools/call", {"name": "dangerous"}, token, session)
        require(status == 200 and json.loads(body)["error"]["code"] == -32001,
                "disallowed tool reached the fixture")

        old_token = token
        rotation = subprocess.run(
            [str(ROOT / "bin/tunn"), "token", "--rotate", ENDPOINT],
            cwd=self.work, env=self.env, capture_output=True, text=True, timeout=5,
        )
        require(rotation.returncode == 0, "token rotation command failed")
        token = rotation.stdout.strip()
        require(token and token != old_token, "rotation reused the token")
        self.wait("old token revocation",
                  lambda: self.rpc(5, "tools/list", {}, old_token, session)[0] == 401,
                  publisher, timeout=5)
        self.echo(6, "rotated", token, session)
        print("PASS rotation revokes the old token and accepts the new one", flush=True)

        self.stop(relay)
        started = time.monotonic()
        relay = self.start_relay()
        self.wait("publisher reconnect", lambda: registered() >= 2, publisher)
        self.echo(7, "after-reconnect", token, session)
        require(self.rpc(8, "tools/list", {}, old_token, session)[0] == 401,
                "relay restart restored the revoked token")
        print(f"PASS relay reconnect ({time.monotonic() - started:.2f} s); revocation survives", flush=True)

        started = time.monotonic()
        status, _, body = self.rpc(9, "tools/call", {
            "name": "echo", "arguments": {"stall": True},
        }, token, session)
        elapsed = time.monotonic() - started
        require(status == 504, f"stalled call returned {status}, expected 504")
        error = json.loads(body)
        require(error.get("id") == 9 and error["error"]["code"] == -32603,
                "timeout did not return a correlated JSON-RPC error")
        require(24 <= elapsed < 29, f"25-second call window took {elapsed:.2f} s")
        print(f"PASS stalled call returns a correlated 504 ({elapsed:.2f} s)", flush=True)
        self.echo(10, "after-timeout", token, session)
        status, _, body = self.rpc(11, "tools/call", {
            "name": "echo", "arguments": {"exit": True},
        }, token, session)
        require(status == 502, f"child exit returned {status}, expected 502")
        # The CLI tears down the tunnel when its child exits. The relay can
        # observe that disconnect before the adapter's JSON-RPC error arrives;
        # the transport boundary promises 502, not an RPC body on disconnect.
        require(publisher.wait(timeout=5) != 0, "publisher silently accepted child exit")
        self.wait("offline endpoint",
                  lambda: self.rpc(12, "tools/list", {}, token, session)[0] == 503,
                  relay, timeout=5)
        print("PASS recovery after timeout; child exit returns 502, then offline 503", flush=True)

    def close(self, failed):
        for process in reversed(self.processes):
            self.stop(process)
        if failed:
            # Logs can contain fixture tokens. Retain them privately for local
            # diagnosis, but do not dump them into CI or coordinator output.
            print(f"Private diagnostic logs: {self.work}", file=sys.stderr)


def main():
    scratch = ROOT / ".scratch"
    scratch.mkdir(exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="lifecycle-", dir=scratch))
    lifecycle = Lifecycle(work)
    failed = True
    try:
        lifecycle.run()
        failed = False
    finally:
        lifecycle.close(failed)
        if not failed:
            shutil.rmtree(work)
    print("PASS local endpoint-token lifecycle; hosted UI and expiring grants remain untested")


if __name__ == "__main__":
    main()
