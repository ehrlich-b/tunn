#!/usr/bin/env python3
"""One publisher supervisor, or all three in a foreground WSL session."""

import argparse
import base64
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.request

from kit import Config, SERVICES, check_private_directory, private_directory, private_file


def redacted(text):
    text = re.sub(r"tunn_ep_[A-Za-z0-9_-]+", "[endpoint credential]", text)
    text = re.sub(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "[JWT credential]", text)
    return re.sub(r"(?i)(authorization\s*:\s*(?:bearer|basic)\s+)\S+", r"\1[credential]", text)


class PrivateRotatingFileHandler(RotatingFileHandler):
    def _open(self):
        stream = super()._open()
        os.fchmod(stream.fileno(), 0o600)
        return stream


def log_for(state, service):
    logs = private_directory(state / "logs")
    logger = logging.getLogger(f"ai-hosts.{service}")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    handler = PrivateRotatingFileHandler(logs / f"{service}.log", maxBytes=1024*1024, backupCount=3)
    Path(handler.baseFilename).chmod(0o600)
    handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
    logger.addHandler(handler)
    return logger


def stop_process(process):
    # Also clean up descendants when the immediate child has already exited.
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        process.wait(timeout=3)
        return
    try:
        process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        pass
    # A reaped group leader can leave a child holding the output pipe open.
    # Kill any survivors, including descendants that ignored SIGTERM.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=3)


def capture_output(stream, logger):
    pending = b""
    discarding = False
    while True:
        chunk = os.read(stream.fileno(), 4096)
        if not chunk:
            if pending and not discarding:
                logger.info("%s", redacted(pending.decode(errors="replace")))
            return
        for segment in chunk.splitlines(keepends=True):
            complete = segment.endswith((b"\n", b"\r"))
            if not discarding:
                pending += segment
                if len(pending) > 4096:
                    logger.info("[overlong child output omitted]")
                    pending = b""
                    discarding = True
            if complete:
                if pending:
                    logger.info("%s", redacted(pending.decode(errors="replace").rstrip()))
                pending = b""
                discarding = False


def validate_credentials(credentials):
    check_private_directory(credentials)
    token_path = private_file(credentials / "token")
    # Local diagnostic only; the relay performs actual signature validation.
    try:
        parts = token_path.read_text().strip().split(".")
        claims = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
        if claims["exp"] <= time.time():
            raise ValueError("login expired; Bryan must run tunn login again")
    except (IndexError, KeyError, TypeError, json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ValueError("expected a tunn login JWT with an expiration") from error


def supervise(config, service, state, credentials, stopping):
    import fcntl  # Linux/WSL and macOS; never run this on native Windows.
    logger = log_for(state, service)
    lock_path = state / f"{service}.lock"
    with lock_path.open("a") as lock:
        lock_path.chmod(0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError(f"{service}: publisher already supervised")
        delay = 5
        while not stopping.is_set():
            validate_credentials(credentials)
            for key in ("tunn_binary", "wt_binary"):
                if not os.access(config.data[key], os.X_OK):
                    raise ValueError(f"{key}: executable missing")
            started = time.monotonic()
            process = subprocess.Popen(config.command(service), cwd=config.data["work_dir"],
                                       env=config.environment(credentials), stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, start_new_session=True)
            status_path = state / f"{service}.json"
            status_path.write_text(json.dumps({"supervisor": os.getpid(), "child": process.pid}))
            status_path.chmod(0o600)
            logger.info("publisher started")

            reader = threading.Thread(target=capture_output, args=(process.stdout, logger), daemon=True)
            reader.start()
            try:
                while process.poll() is None and not stopping.wait(0.5):
                    pass
            finally:
                stop_process(process)
                reader.join(timeout=3)
                process.stdout.close()
                status_path.unlink(missing_ok=True)
            if stopping.is_set():
                return
            if time.monotonic() - started > 60:
                delay = 5
            logger.info("publisher exited (%s); retry in %ss", process.returncode, delay)
            stopping.wait(delay)
            delay = min(delay * 2, 60)


def health(config, state, credentials):
    check_private_directory(state)
    validate_credentials(credentials)
    for service in SERVICES:
        status = json.loads(private_file(state / f"{service}.json").read_text())
        os.kill(status["supervisor"], 0)
        os.kill(status["child"], 0)
    for suffix in ("ssh", "wt"):
        private_file(credentials / "endpoints" / f"{config.host}-{suffix}.token")
    with socket.create_connection(("127.0.0.1", 22), timeout=3) as connection:
        if not connection.recv(255).startswith(b"SSH-"):
            raise ValueError("local port 22 did not return an SSH banner")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    url = f"http://127.0.0.1:{config.data['dashboard_port']}{config.data['dashboard_path']}"
    with opener.open(url, timeout=3) as response:
        if response.status != 200:
            raise ValueError("local dashboard health path must return 200")
    print("PASS local publishers, token permissions/expiry, SSH banner, dashboard")
    print("Remote access and wt tools require canary.py.")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=(*SERVICES, "all", "health", "check"))
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    config = Config(args.config)
    if args.action == "check":
        for service in SERVICES:
            print(" ".join(config.command(service)))
        return
    state, credentials = config.paths()
    if args.action == "health":
        health(config, state, credentials)
        return
    private_directory(state)
    validate_credentials(credentials)
    stopping = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stopping.set())
    if args.action != "all":
        supervise(config, args.action, state, credentials, stopping)
        return
    # WSL foreground fallback; failure of one supervisor stops the whole group.
    errors = []

    def run(service):
        try:
            supervise(config, service, state, credentials, stopping)
        except Exception as error:
            errors.append(error)
            stopping.set()

    threads = [threading.Thread(target=run, args=(service,)) for service in SERVICES]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    if errors:
        raise errors[0]


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"ai-hosts: {redacted(str(error))}", file=sys.stderr)
        sys.exit(1)
