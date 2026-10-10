#!/usr/bin/env python3
"""Read-only remote checks; run before and after Bryan restarts the publishers.

Never prints tokens, response bodies, SSH output, or subprocess logs. Requires
explicit credential paths; there is no automatic login or credential discovery.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request

from kit import private_file
from runner import NoRedirect, stop_process


MAX_BODY = 1024 * 1024


def read_token(path, endpoint=False):
    token = private_file(path).read_text().strip()
    if not token or any(c.isspace() for c in token):
        raise ValueError("token file is empty or contains whitespace")
    if endpoint and not re.fullmatch(r"tunn_ep_[A-Za-z0-9_-]{43}", token):
        raise ValueError("expected a generated endpoint token")
    return token


class HTTP:
    def __init__(self):
        # HTTPS verification stays enabled; ignore proxy env and refuse redirects
        # so credentials cannot leave the explicitly named tunn endpoint.
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def request(self, url, method="GET", data=None, token="", headers=None):
        headers = dict(headers or {})
        if token:
            headers["Tunn-Authorization"] = "Bearer " + token
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            response = self.opener.open(request, timeout=30)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            body = response.read(MAX_BODY + 1)
            if len(body) > MAX_BODY:
                raise ValueError("canary response exceeds 1 MiB")
            return response.code, response.headers, body


def rpc(http, url, method, params, token, request_id):
    params = dict(params)
    params["_meta"] = {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": {"name": "tunn-ai-hosts-canary", "version": "1"},
        "io.modelcontextprotocol/clientCapabilities": {},
    }
    payload = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
    status, _, body = http.request(url, "POST", json.dumps(payload).encode(), token, {
        "Content-Type": "application/json", "Accept": "application/json",
        "Mcp-Protocol-Version": "2026-07-28", "Mcp-Method": method,
    })
    if status != 200:
        raise ValueError(f"MCP {method} returned HTTP {status}")
    value = json.loads(body)
    if value.get("id") != request_id or "result" not in value or "error" in value:
        raise ValueError(f"MCP {method} did not return a matching success response")
    return value["result"]


def ssh_command(args):
    return ["ssh", "-F", "/dev/null", "-p", str(args.listen_port), "-i", str(args.identity_file),
            "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
            "-o", "ForwardAgent=no", "-o", "ClearAllForwardings=yes",
            "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=5",
            "-o", "ConnectionAttempts=1", "-o", f"HostKeyAlias={args.host}-tunn",
            "-o", f"UserKnownHostsFile={args.known_hosts}",
            f"{args.ssh_user}@127.0.0.1", "printf 'tunn-ai-hosts-ok\\n'; hostname"]


def ssh_probe(args, ssh_token_path):
    env = {k: v for k, v in os.environ.items() if not k.startswith("TUNN_")}
    env.update(TUNN_ENV="prod", TUNN_DOMAIN="tunn.to", TUNN_SERVER_ADDR="tunn.to:443",
               TUNN_PUBLIC_MODE="false", TUNN_SECRET="")
    process = subprocess.Popen([
        str(args.tunn_binary), "--verbosity=error", "connect", "--listen",
        f"127.0.0.1:{args.listen_port}", "--token-file", str(ssh_token_path), f"{args.host}-ssh",
    ], env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, start_new_session=True)
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            announcement = b""
            ready_deadline = time.monotonic() + 5
            while not announcement.endswith(b"\n"):
                remaining = ready_deadline - time.monotonic()
                if remaining <= 0 or not selector.select(timeout=remaining):
                    raise ValueError("connector did not announce its loopback listener")
                chunk = os.read(process.stdout.fileno(), 4096)
                if not chunk or len(announcement) + len(chunk) > 4096:
                    raise ValueError("invalid connector announcement")
                announcement += chunk
            expected = f"tcp://127.0.0.1:{args.listen_port} -> https://{args.host}-ssh.tunn.to/_tunn/connect\n"
            if announcement.decode() != expected:
                raise ValueError("connector did not bind the expected loopback listener")
        deadline = time.monotonic() + args.reconnect_timeout
        delay = 1
        while True:
            if process.poll() is not None:
                raise ValueError("tunn connector exited (check that the local port is free)")
            try:
                result = subprocess.run(ssh_command(args), stdin=subprocess.DEVNULL,
                                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=12)
                lines = result.stdout.decode(errors="replace").splitlines()
                if process.poll() is None and result.returncode == 0 and lines == ["tunn-ai-hosts-ok", args.expected_hostname]:
                    return
            except subprocess.TimeoutExpired:
                pass
            if time.monotonic() >= deadline:
                raise ValueError("SSH command failed: check endpoint token, key, pinned host key, and hostname")
            time.sleep(min(delay, max(0, deadline - time.monotonic())))
            delay = min(delay * 2, 10)
    finally:
        stop_process(process)
        process.stdout.close()


def evidence(args, ssh_token, wt_token):
    return {"host": args.host, "hostname": args.expected_hostname,
            "token_lifecycle": args.token_lifecycle,
            "tools": sorted(args.expected_tools.split(",")), "dashboard_path": args.dashboard_path,
            "dashboard_marker": args.dashboard_marker,
            "ssh_digest": hashlib.sha256(ssh_token.encode()).hexdigest(),
            "wt_digest": hashlib.sha256(wt_token.encode()).hexdigest()}


def check_restart(previous, current):
    for key in ("host", "hostname", "tools", "dashboard_path", "dashboard_marker"):
        if previous.get(key) != current[key]:
            raise ValueError("baseline belongs to a different canary configuration")
    lifecycle = current["token_lifecycle"]
    if previous.get("token_lifecycle", "rotate") != lifecycle:
        raise ValueError("baseline belongs to a different token lifecycle")
    for key in ("ssh_digest", "wt_digest"):
        if lifecycle == "rotate" and previous.get(key) == current[key]:
            raise ValueError("after phase requires newly copied SSH and MCP tokens from restarted publishers")
        if lifecycle == "preserve" and previous.get(key) != current[key]:
            raise ValueError("host-mode recovery must preserve the existing SSH and MCP token digests")


def run(args, http=None):
    token_dir = Path(args.token_dir)
    ssh_path = token_dir / f"{args.host}-ssh.token"
    ssh_token = read_token(ssh_path, endpoint=True)
    wt_token = read_token(token_dir / f"{args.host}-wt.token", endpoint=True)
    dashboard_token = read_token(args.dashboard_token_file)
    current = evidence(args, ssh_token, wt_token)
    if args.phase == "after":
        previous = json.loads(private_file(args.receipt).read_text())
        check_restart(previous, current)
    elif Path(args.receipt).exists():
        raise ValueError("baseline receipt already exists; choose a new receipt path")
    http = http or HTTP()
    urls = {suffix: f"https://{args.host}-{suffix}.tunn.to" for suffix in ("ssh", "wt", "dashboard")}
    for token in ("", "tunn_ep_deliberately-wrong-canary-token"):
        status, _, _ = http.request(urls["ssh"] + "/_tunn/connect", "CONNECT", token=token,
                                    headers={"Tunn-Protocol": "tcp/1"})
        if status != 401:
            raise ValueError(f"SSH endpoint accepted missing/wrong token (HTTP {status})")
        status, _, _ = http.request(urls["wt"] + "/mcp", "POST", b"{}", token,
                                    {"Content-Type": "application/json"})
        if status != 401:
            raise ValueError(f"MCP endpoint accepted missing/wrong token (HTTP {status})")
    print("PASS SSH/MCP reject missing and wrong endpoint credentials", flush=True)
    ssh_probe(args, ssh_path)
    print("PASS fresh TCP connector and pinned SSH command/hostname", flush=True)
    discover = rpc(http, urls["wt"] + "/mcp", "server/discover", {}, wt_token, 1)
    if "2026-07-28" not in discover.get("supportedVersions", []):
        raise ValueError("MCP discovery did not advertise the canary protocol")
    tools = rpc(http, urls["wt"] + "/mcp", "tools/list", {}, wt_token, 2)
    names = sorted(tool["name"] for tool in tools["tools"])
    if names != current["tools"] or tools.get("nextCursor"):
        raise ValueError("MCP discovery differs from the reviewed exact tool list")
    print("PASS private MCP discovery and exact tools/list", flush=True)
    dashboard_url = urls["dashboard"] + args.dashboard_path
    status, _, _ = http.request(dashboard_url)
    if status != 302:
        raise ValueError(f"unauthenticated dashboard did not require browser login (HTTP {status})")
    status, _, body = http.request(dashboard_url, token=dashboard_token)
    if status != 200 or args.dashboard_marker.encode() not in body:
        raise ValueError("authenticated dashboard did not return the expected page marker")
    print("PASS HTTPS dashboard denies anonymous access and serves the expected page", flush=True)
    if args.phase == "after":
        description = "refreshed" if args.token_lifecycle == "rotate" else "preserved"
        print(f"PASS all three endpoints after publisher restart with {description} capabilities", flush=True)
    else:
        receipt = Path(args.receipt)
        with receipt.open("x") as output:
            output.write(json.dumps(current, indent=2) + "\n")
        receipt.chmod(0o600)
        print(f"PASS baseline saved; Bryan restarts publishers, then run --phase after with {args.token_lifecycle} token lifecycle", flush=True)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=("before", "after"), required=True)
    parser.add_argument("--token-lifecycle", choices=("rotate", "preserve"), default="rotate",
                        help="rotate for the legacy kit; preserve only for persistent host mode")
    parser.add_argument("--host", choices=("forge", "rig"), required=True)
    parser.add_argument("--tunn-binary", type=Path, required=True)
    parser.add_argument("--token-dir", type=Path, required=True)
    parser.add_argument("--dashboard-token-file", type=Path, required=True)
    parser.add_argument("--ssh-user", required=True)
    parser.add_argument("--identity-file", type=Path, required=True)
    parser.add_argument("--known-hosts", type=Path, required=True)
    parser.add_argument("--expected-hostname", required=True)
    parser.add_argument("--expected-tools", required=True)
    parser.add_argument("--dashboard-path", default="/")
    parser.add_argument("--dashboard-marker", required=True)
    parser.add_argument("--listen-port", type=int, default=2222)
    parser.add_argument("--reconnect-timeout", type=int, default=90)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args(argv)
    if not 1 <= args.listen_port <= 65535 or not 1 <= args.reconnect_timeout <= 180:
        parser.error("invalid listen port or reconnect timeout")
    if not re.fullmatch(r"[a-z_][a-z0-9_-]*", args.ssh_user):
        parser.error("ssh-user must be a Linux username")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", args.expected_hostname):
        parser.error("expected-hostname must be a hostname")
    if not all(re.fullmatch(r"[A-Za-z0-9_.-]+", t) for t in args.expected_tools.split(",")):
        parser.error("expected-tools must contain exact tool names")
    if not args.dashboard_path.startswith("/") or args.dashboard_path.startswith("//") or any(c in args.dashboard_path for c in "\r\n"):
        parser.error("dashboard-path must be an absolute HTTP path")
    if not args.dashboard_marker or len(args.dashboard_marker) > 200:
        parser.error("supply a short distinctive dashboard page marker")
    for path in (args.tunn_binary, args.token_dir, args.dashboard_token_file,
                 args.identity_file, args.known_hosts, args.receipt):
        if not path.is_absolute():
            parser.error("all file paths must be absolute")
    return args


if __name__ == "__main__":
    os.umask(0o077)
    try:
        arguments = parse_args()
        private_file(arguments.identity_file)
        private_file(arguments.known_hosts)
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, lambda *_: sys.exit(130))
        run(arguments)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        # Do not echo exception text: HTTP errors or child output can contain credentials.
        print("FAIL canary; review the last PASS, permissions, configured identity, and host-side private logs", file=sys.stderr)
        sys.exit(1)
