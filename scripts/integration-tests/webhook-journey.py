#!/usr/bin/env python3
"""Signed raw-byte webhook deliveries and deliberate inspector replay on loopback.

No provider account or network service is used. Set TUNN_WEBHOOK_EVIDENCE to
retain process logs and a JSON receipt; otherwise fixtures are temporary.
"""
import base64
import gzip
import hashlib
import hmac
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import signal
import shutil
import socket
import sqlite3
import ssl
import subprocess
import tempfile
import threading
import time
from urllib.parse import urlsplit
import uuid

ROOT = Path(__file__).resolve().parents[2]
SECRET = b"offline-webhook-signing-secret"
JWT_SECRET = "offline-relay-authentication-secret"
OWNER = "webhooks@example.test"
AUTHORITY = "webhooks.webhook.test"


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def digest(data):
    return hmac.new(SECRET, data, hashlib.sha256).hexdigest()


def sign(provider, body, timestamp):
    if provider == "stripe":
        return {"Stripe-Signature": f"t={timestamp},v1=" + digest(str(timestamp).encode() + b"." + body)}
    if provider == "github":
        return {"X-Hub-Signature-256": "sha256=" + digest(body)}
    return {"X-Slack-Request-Timestamp": str(timestamp),
            "X-Slack-Signature": "v0=" + digest(b"v0:" + str(timestamp).encode() + b":" + body)}


class Origin(BaseHTTPRequestHandler):
    calls = []
    fixed = False

    def log_message(self, *_):
        pass

    def do_GET(self):
        self.send_response(204)
        self.end_headers()

    def do_POST(self):
        # Verify the received bytes, before any JSON, UTF-8 or gzip decoding.
        body = self.rfile.read(int(self.headers["Content-Length"]))
        provider = self.path.split("/", 3)[2]
        valid, fresh = False, True
        if provider == "stripe":
            parts = self.headers.get("Stripe-Signature", "").split(",")
            timestamps = [p[2:] for p in parts if p.startswith("t=")]
            timestamp = timestamps[0] if len(timestamps) == 1 else "0"
            expected = digest(timestamp.encode() + b"." + body)
            valid = any(hmac.compare_digest(p[3:], expected) for p in parts if p.startswith("v1="))
            fresh = abs(time.time() - int(timestamp)) <= 300
        elif provider == "github":
            valid = hmac.compare_digest(self.headers.get("X-Hub-Signature-256", ""), "sha256=" + digest(body))
        elif provider == "slack":
            timestamp = self.headers.get("X-Slack-Request-Timestamp", "0")
            expected = "v0=" + digest(b"v0:" + timestamp.encode() + b":" + body)
            valid = hmac.compare_digest(self.headers.get("X-Slack-Signature", ""), expected)
            fresh = abs(time.time() - int(timestamp)) <= 300
        headers = {key.lower(): self.headers.get_all(key) for key in self.headers.keys()}
        status = 401 if not valid or not fresh else 200 if self.fixed else 500
        self.calls.append({"path": self.path, "headers": headers, "body": body,
                           "valid": valid, "fresh": fresh, "status": status})
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.end_headers()


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def jwt():
    def encode(value):
        return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=")
    message = encode({"alg": "HS256", "typ": "JWT"}) + b"." + encode({
        "email": OWNER, "iat": int(time.time()), "exp": int(time.time()) + 3600})
    return (message + b"." + base64.urlsafe_b64encode(hmac.new(
        JWT_SECRET.encode(), message, hashlib.sha256).digest()).rstrip(b"=")).decode()


class Journey:
    def __init__(self, work):
        self.work = work
        self.processes = []
        self.origin = None
        self.port = free_port()
        self.receipt = []
        self.env = {k: v for k, v in os.environ.items() if not k.startswith(("TUNN_", "FLY_"))}
        self.env.update({"TUNN_ENV": "dev", "TUNN_DOMAIN": "webhook.test",
                         "TUNN_SERVER_ADDR": f"127.0.0.1:{self.port}",
                         "TUNN_PUBLIC_ADDR": f"127.0.0.1:{self.port}",
                         "TUNN_HTTP2_ADDR": f"127.0.0.1:{self.port}",
                         "TUNN_HTTP3_ADDR": f"127.0.0.1:{self.port}", "TUNN_HTTP3": "off",
                         "TUNN_INTERNAL_GRPC_PORT": f"127.0.0.1:{free_port()}",
                         "TUNN_MOCK_OIDC_ADDR": "", "TUNN_LOGIN_NODE": "true",
                         "TUNN_PUBLIC_MODE": "false", "TUNN_JWT_SECRET": JWT_SECRET,
                         "TUNN_DB_PATH": str(work / "relay.db"), "TUNN_NODE_ADDRESSES": "",
                         "TUNN_CONFIG_DIR": str(work / "config"),
                         "TUNN_CERT_FILE": str(work / "cert.pem"),
                         "TUNN_KEY_FILE": str(work / "key.pem")})

    def start(self, name, *args):
        with (self.work / f"{name}.log").open("wb") as output:
            child = subprocess.Popen([str(self.work / "tunn"), *args], cwd=self.work,
                                     env=self.env, stdin=subprocess.DEVNULL, stdout=output,
                                     stderr=subprocess.STDOUT, start_new_session=True)
        self.processes.append(child)
        return child

    def wait(self, operation, message):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            require(all(p.poll() is None for p in self.processes), "fixture process exited: " + message)
            try:
                result = operation()
                if result:
                    return result
            except (OSError, http.client.HTTPException, sqlite3.OperationalError):
                pass
            time.sleep(0.05)
        raise AssertionError("fixture readiness timeout: " + message)

    def request(self, path, body=None, headers=None):
        conn = http.client.HTTPSConnection("127.0.0.1", self.port, context=self.tls, timeout=10)
        try:
            conn.putrequest("GET" if body is None else "POST", path,
                            skip_host=True, skip_accept_encoding=True)
            conn.putheader("Host", AUTHORITY)
            if body is not None:
                for key, values in headers.items():
                    for value in values:
                        conn.putheader(key, value)
            conn.endheaders(body)
            response = conn.getresponse()
            response.read()
            return response.status
        finally:
            conn.close()

    def api(self, path, data=None):
        conn = http.client.HTTPConnection(self.inspector.hostname, self.inspector.port, timeout=10)
        try:
            payload = None if data is None else json.dumps(data).encode()
            conn.request("GET" if data is None else "POST", path, payload,
                         {"X-Tunn-Inspector-Token": self.inspector.fragment,
                          "Content-Type": "application/json"})
            response = conn.getresponse()
            raw = response.read()
            return response.status, json.loads(raw) if response.status == 200 else raw.decode()
        finally:
            conn.close()

    def event(self, after):
        def terminal():
            status, events = self.api("/api/events")
            require(status == 200, "inspector list denied")
            return events[-1] if events and events[-1]["id"] > after else None
        return self.wait(terminal, "terminal inspector event")

    def run(self):
        subprocess.run(["go", "build", "-p", "2", "-o", str(self.work / "tunn"), "."], cwd=ROOT, check=True)
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", str(self.work / "key.pem"), "-out", str(self.work / "cert.pem"),
                        "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.tls = ssl.create_default_context(cafile=str(self.work / "cert.pem"))
        self.origin = ThreadingHTTPServer(("127.0.0.1", 3000), Origin)
        threading.Thread(target=self.origin.serve_forever, daemon=True).start()
        self.start("relay", "-mode=host")
        def seed():
            with sqlite3.connect(self.work / "relay.db") as db:
                if not db.execute("SELECT 1 FROM sqlite_master WHERE name='account_emails'").fetchone():
                    return False
                account = str(uuid.uuid4())
                now = int(time.time())
                db.execute("INSERT INTO accounts(id,primary_email,plan,created_at) VALUES(?,?,?,?)",
                           (account, OWNER, "free", now))
                db.execute("INSERT INTO account_emails(account_id,email,verified_via,added_at) VALUES(?,?,?,?)",
                           (account, OWNER, "github", now))
                return True
        self.wait(seed, "relay account schema")
        self.start("publisher", "3000", "--public", "--inspect", "--inspect-body",
                   "--id=webhooks", "--secret=" + jwt(), "--json")
        self.wait(lambda: self.request("/ready") == 204, "public publisher route")
        match = re.search(r"Local inspector: (http://127\.0\.0\.1:\d+/#\w+)",
                          (self.work / "publisher.log").read_text())
        require(match, "publisher did not print inspector URL")
        self.inspector = urlsplit(match[1])
        cases = [("one-byte", b"x", None), ("one-mib", b"x" * 1048576, None),
                 ("binary", bytes(range(256)) * 4, None),
                 ("gzip", gzip.compress(b'{"event":"created"}\n', mtime=0), "gzip"),
                 ("non-utf8", b"\xff\xfe\x80\xc0\x00\r\n", None)]
        last_id = self.api("/api/events")[1][-1]["id"]
        for provider in ("stripe", "github", "slack"):
            for label, body, encoding in cases:
                path = f"/hooks/{provider}/%2Fdelivery%20event?value=a%2Fb&tag=x%20y&tag=%FF"
                headers = {"Content-Length": [str(len(body))], "Content-Type": ["application/octet-stream"],
                           "Accept-Encoding": ["identity"], "User-Agent": ["webhook-journey"],
                           "X-Delivery": ["first,with-comma", "second"]}
                if encoding:
                    headers["Content-Encoding"] = [encoding]
                headers.update({key: [value] for key, value in sign(provider, body, int(time.time())).items()})
                Origin.fixed = label != "one-byte"
                status = self.request(path, body, headers)
                original = Origin.calls[-1]
                require(status == (500 if label == "one-byte" else 200), f"{provider}/{label}: status {status}")
                require(original["valid"] and original["fresh"] and original["body"] == body and
                        original["path"] == path and original["headers"]["x-delivery"] == headers["X-Delivery"],
                        "raw body, signature, repeated field or request URI changed")
                event = self.event(last_id)
                require(event["status"] == status and event["request_bytes"] == len(body), "capture count/status changed")
                if label == "one-mib":
                    before = len(Origin.calls)
                    require(event["truncated"] and not event["reconstructable"], "large capture not truncated")
                    require(self.api(f'/api/events/{event["id"]}/prepare', {})[0] == 409,
                            "truncated capture prepared a replay")
                    require(len(Origin.calls) == before, "truncated replay dispatched")
                else:
                    require(base64.b64decode(event["body"]) == body, "captured body differs")
                    Origin.fixed = True  # The app's handler is repaired before deliberate replay.
                    code, action = self.api(f'/api/events/{event["id"]}/prepare', {})
                    require(code == 200, "complete repeated-header capture cannot prepare replay")
                    captured = original["headers"]
                    reconstructed = {key: captured[key.lower()][-1] for key in event["headers"]}
                    repeated = {key: captured[key.lower()] for key in event["headers"]
                                if len(captured[key.lower()]) > 1}
                    code, replay = self.api(f'/api/events/{event["id"]}/replay', {
                        "action": action["action"], "path": path, "headers": reconstructed,
                        "header_values": repeated})
                    require(code == 200 and replay["status"] == 200 and replay["replay_of"] == event["id"],
                            f"unlabelled or failed replay: {replay}")
                    delivered = Origin.calls[-1]
                    require(delivered["valid"] and delivered["fresh"] and delivered["path"] == original["path"] and
                            delivered["headers"] == original["headers"] and delivered["body"] == original["body"],
                            "replay path, headers or body differed")
                    # Replayed custom values must remain redacted on subsequent capture.
                    require(replay["headers"]["X-Delivery"] == "[redacted]", "replay leaked custom values")
                    last_id = replay["id"]
                last_id = max(last_id, event["id"])
                row = {"provider": provider, "fixture": label, "bytes": len(body),
                       "sha256": hashlib.sha256(body).hexdigest(), "status": status,
                       "replay": "refused-truncated" if label == "one-mib" else "identical-200"}
                self.receipt.append(row)
                print("PASS", json.dumps(row), flush=True)
        body = b"stale-but-correctly-signed"
        headers = {"Content-Length": [str(len(body))], **{key: [value] for key, value in
                   sign("stripe", body, int(time.time()) - 600).items()}}
        require(self.request("/hooks/stripe/stale", body, headers) == 401 and Origin.calls[-1]["valid"] and
                not Origin.calls[-1]["fresh"], "origin did not reject stale Stripe timestamp")
        # A negative control proves the origin checks signatures, not just fixtures.
        headers["Stripe-Signature"] = [headers["Stripe-Signature"][0][:-1] + "z"]
        require(self.request("/hooks/stripe/tampered", body, headers) == 401 and not Origin.calls[-1]["valid"],
                "origin accepted invalid signature")
        receipt = {"result": "PASS", "deliveries": self.receipt, "stale_stripe": "origin-401",
                   "tampered_signature": "origin-401", "transport": "CLI public + inspect; loopback TLS relay"}
        (self.work / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        print("PASS: signed webhook journey, exact replay, truncation and origin freshness")

    def close(self):
        for child in reversed(self.processes):
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGTERM)
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait(timeout=3)
        if self.origin:
            self.origin.shutdown()
            self.origin.server_close()


def main():
    evidence = os.environ.get("TUNN_WEBHOOK_EVIDENCE")
    with tempfile.TemporaryDirectory(prefix="webhook-", dir=os.environ.get("TUNN_WEBHOOK_WORK")) as temporary:
        # Persist logs/receipt in a separate unique directory when requested.
        work = Path(temporary).resolve()
        retained = Path(tempfile.mkdtemp(prefix="run-", dir=evidence)) if evidence else None
        fixture = Journey(work)
        try:
            fixture.run()
        except Exception:
            for log in work.glob("*.log"):
                print(f"{log.name}:\n{log.read_text()[-8000:]}")
            raise
        finally:
            fixture.close()
            if retained:
                for artifact in [*work.glob("*.log"), work / "receipt.json"]:
                    if artifact.exists():
                        shutil.copy2(artifact, retained / artifact.name)


if __name__ == "__main__":
    main()
