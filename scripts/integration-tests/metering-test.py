#!/usr/bin/env python3
"""Real relay/publisher/CLI grant lifecycle, confined to loopback and local SQLite."""
import base64
from datetime import datetime, timezone
import hashlib
import hmac
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
DOMAIN = "metering.test"
OWNER = "owner@example.com"
JWT_SECRET = "local-metering-fixture-signing-key"


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def owner_jwt():
    def encode(value):
        return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=")
    signing = encode({"alg": "HS256", "typ": "JWT"}) + b"." + encode({
        "email": OWNER, "iat": int(time.time()), "exp": int(time.time()) + 3600,
    })
    signature = base64.urlsafe_b64encode(
        hmac.new(JWT_SECRET.encode(), signing, hashlib.sha256).digest()
    ).rstrip(b"=")
    return (signing + b"." + signature).decode()


class Target(BaseHTTPRequestHandler):
    calls = []
    lock = threading.Lock()

    def log_message(self, *_):
        pass

    def do_GET(self):
        self.send_response(204)
        self.end_headers()

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        with self.lock:
            self.calls.append((body, dict(self.headers)))
        self.send_response(200)
        self.send_header("Content-Length", "6")
        self.end_headers()
        self.wfile.write(b"abcdef")


class Fixture:
    def __init__(self, work):
        self.work = work
        self.port, self.internal_port = free_port(), free_port()
        self.target = ThreadingHTTPServer(("127.0.0.1", 0), Target)
        self.thread = threading.Thread(target=self.target.serve_forever, daemon=True)
        self.thread.start()
        self.processes = []
        self.logs = []
        self.jwt = owner_jwt()
        self.owner_file = work / "owner.jwt"
        self.owner_file.write_text(self.jwt)
        self.owner_file.chmod(0o600)
        self.tls = ssl.create_default_context(cafile=str(ROOT / "certs/cert.pem"))
        self.env = {k: v for k, v in os.environ.items() if not k.startswith(("TUNN_", "FLY_"))}
        self.env.update({
            "TUNN_ENV": "dev", "TUNN_DOMAIN": DOMAIN,
            "TUNN_LOGIN_NODE": "true", "TUNN_PUBLIC_MODE": "false",
            "TUNN_SERVER_ADDR": f"127.0.0.1:{self.port}",
            "TUNN_PUBLIC_ADDR": f"127.0.0.1:{self.port}",
            "TUNN_HTTP2_ADDR": f"127.0.0.1:{self.port}",
            "TUNN_HTTP3_ADDR": f"127.0.0.1:{self.port}",
            "TUNN_INTERNAL_GRPC_PORT": f"127.0.0.1:{self.internal_port}",
            "TUNN_MOCK_OIDC_ADDR": "", "TUNN_JWT_SECRET": JWT_SECRET,
            "TUNN_DB_PATH": str(work / "relay.db"), "TUNN_NODE_ADDRESSES": "",
            "TUNN_CERT_FILE": str(ROOT / "certs/cert.pem"),
            "TUNN_KEY_FILE": str(ROOT / "certs/key.pem"),
        })

    def start(self, name, *args):
        log = self.work / f"{name}.log"
        self.logs.append(log)
        with log.open("ab") as output:
            process = subprocess.Popen([str(ROOT / "bin/tunn"), *args], cwd=self.work,
                                       env=self.env, stdout=output, stderr=subprocess.STDOUT,
                                       start_new_session=True)
        self.processes.append(process)
        return process

    @staticmethod
    def stop(process):
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=3)

    def request(self, token, body=b"1234", ready=False):
        # No wildcard DNS: connect to the literal loopback IP and set Host.
        conn = http.client.HTTPSConnection("127.0.0.1", self.port, context=self.tls, timeout=3)
        try:
            conn.request("GET" if ready else "POST", "/ready" if ready else "/api", body=None if ready else body,
                         headers={"Host": f"api.{DOMAIN}", "Tunn-Authorization": "Bearer " + token,
                                  "Authorization": "Bearer upstream-fixture"})
            response = conn.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            conn.close()

    def wait_publisher(self):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            require(all(p.poll() is None for p in self.processes if p is not self.old_relay),
                    "a fixture process exited before readiness")
            try:
                if self.request(self.jwt, ready=True)[0] == 204:
                    return
            except (OSError, http.client.HTTPException):
                pass
            time.sleep(0.1)  # Short, bounded local startup/reconnect readiness.
        raise AssertionError("publisher did not become ready within 30 seconds")

    def cli(self, *args):
        result = subprocess.run([str(ROOT / "bin/tunn"), *args, "--server", f"https://127.0.0.1:{self.port}",
                                 "--owner-token-file", str(self.owner_file), "--insecure"],
                                cwd=self.work, env=self.env, capture_output=True, text=True, timeout=15)
        require(result.returncode == 0, "CLI failed: " + result.stderr)
        return result.stdout

    def create(self, *limits):
        return json.loads(self.cli("grant", "create", "api", "--expires", "1h", *limits))

    def usage(self, grant):
        month = datetime.now(timezone.utc).strftime("%Y-%m")
        output = json.loads(self.cli("usage", "api", "--month", month))
        caller = "grant:" + grant["grant"]["id"]
        rows = [row for row in output.get("usage", []) if row["caller"] == caller]
        require(len(rows) == 1, "grant has no unique usage row")
        window = json.loads(self.cli("usage", "--tunnel", "api", "--since", "1h"))
        window_rows = [row for row in window.get("usage", []) if row["caller"] == caller]
        require(not window.get("usage_truncated") and window_rows == rows,
                "duration usage disagrees with durable monthly usage")
        return rows[0]

    def run(self):
        self.old_relay = None
        relay = self.start("relay", "-mode=host")
        self.start("publisher", "serve", "--id=api", "--allow=" + OWNER, "--secret=" + self.jwt,
                   f"http://127.0.0.1:{self.target.server_port}")
        self.wait_publisher()
        first = self.create("--monthly-requests", "2", "--monthly-bytes", "20")
        for remaining in (1, 0):
            status, headers, body = self.request(first["token"])
            require(status == 200 and body == b"abcdef", "grant request failed")
            require(headers.get("Tunn-Requests-Remaining") == str(remaining), "request boundary header incorrect")
        status, headers, _ = self.request(first["token"])
        require(status == 429 and headers.get("Tunn-Limit-Reason") == "request_budget" and headers.get("Retry-After"),
                "request budget did not reject at its boundary")
        row = self.usage(first)
        require((row["requests"], row["admitted_requests"], row["request_bytes"], row["response_bytes"]) == (3, 2, 8, 12),
                "streamed caller meter is inaccurate")
        byte_limited = self.create("--monthly-bytes", "10")
        require(self.request(byte_limited["token"])[0] == 200, "last allowed body bytes failed")
        status, headers, _ = self.request(byte_limited["token"])
        require(status == 429 and headers.get("Tunn-Limit-Reason") == "byte_budget", "byte budget boundary failed")
        row = self.usage(byte_limited)
        require((row["requests"], row["admitted_requests"], row["request_bytes"], row["response_bytes"]) == (2, 1, 4, 6),
                "byte boundary charged a denied request body")
        second = self.create("--monthly-requests", "10", "--monthly-bytes", "100")
        require(self.request(second["token"])[0] == 200, "second grant was affected by first grant")
        self.cli("grant", "revoke", "api", second["grant"]["id"])
        status, headers, _ = self.request(second["token"])
        require(status == 403 and headers.get("Tunn-Limit-Reason") == "grant_revoked", "revocation failed")
        expiring = json.loads(self.cli("grant", "create", "api", "--expires", "2s"))
        time.sleep(2.1)
        status, headers, _ = self.request(expiring["token"])
        require(status == 403 and headers.get("Tunn-Limit-Reason") == "grant_expired", "expiry failed")
        durable = self.create("--monthly-requests", "2", "--monthly-bytes", "40")
        require(self.request(durable["token"])[0] == 200, "durable grant's first request failed")
        self.stop(relay)
        self.old_relay = relay
        self.start("relay-restarted", "-mode=host")
        self.wait_publisher()
        require(self.request(first["token"])[0] == 429, "request budget reset on relay restart")
        require(self.request(second["token"])[0] == 403, "revocation disappeared on relay restart")
        require(self.request(durable["token"])[0] == 200, "remaining grant budget lost on restart")
        require(self.request(durable["token"])[0] == 429, "request budget overspent after restart")
        row = self.usage(durable)
        require((row["requests"], row["admitted_requests"], row["request_bytes"], row["response_bytes"]) == (3, 2, 8, 12),
                "usage ledger did not survive restart")
        listed = json.loads(self.cli("grant", "list", "api"))
        by_id = {grant["id"]: grant for grant in listed.get("grants", [])}
        require(second["grant"]["id"] in by_id and by_id[second["grant"]["id"]].get("revoked"),
                "grant listing lost durable revocation")
        require(all("token_sha256" not in grant for grant in by_id.values()),
                "grant listing exposed credential digests")
        owner_usage = json.loads(self.cli("usage"))
        totals = owner_usage["owner_usage"]
        require(totals["owner"] == OWNER and totals["total_bytes"] == sum(
            row.get("request_bytes", 0) + row.get("response_bytes", 0)
            for row in owner_usage.get("usage", [])), "per-user byte totals disagree")
        # Keep both rate requests in the same fixed UTC minute.
        if time.time() % 60 > 57:
            time.sleep(60 - time.time() % 60 + 0.1)
        limited = self.create("--rate", "1")
        require(self.request(limited["token"])[0] == 200, "rate grant's first request failed")
        status, headers, _ = self.request(limited["token"])
        require(status == 429 and headers.get("Tunn-Limit-Reason") == "request_rate", "request rate did not enforce")
        with Target.lock:
            require(all(body == b"1234" and "Tunn-Authorization" not in headers
                        and headers.get("Authorization") == "Bearer upstream-fixture"
                        for body, headers in Target.calls), "payload or auth forwarding changed")
        require(b"tunn_gr_" not in (self.work / "relay.db").read_bytes(), "plaintext grant token reached SQLite")
        print("Metering loopback E2E passed: CLI, independent grants, budgets, expiry, revocation, rate, restart, bytes.")

    def close(self):
        for process in reversed(self.processes):
            self.stop(process)
        self.target.shutdown()
        self.target.server_close()
        self.thread.join(timeout=3)


def main():
    scratch = ROOT / ".scratch"
    scratch.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="metering-", dir=scratch) as directory:
        fixture = None
        try:
            fixture = Fixture(Path(directory))
            fixture.run()
        except Exception:
            if fixture:
                for log in fixture.logs:
                    print(f"{log.name}:\n{log.read_text()[-8000:]}")
            raise
        finally:
            if fixture:
                fixture.close()


if __name__ == "__main__":
    main()
