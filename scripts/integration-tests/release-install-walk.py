#!/usr/bin/env python3
"""Install a staged release over loopback HTTPS and compare real CLI notices."""

import argparse
import functools
import hashlib
import http.server
import json
import os
from pathlib import Path
import shlex
import ssl
import subprocess
import tempfile
import threading

REPO = Path(__file__).resolve().parents[2]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def walk(stage, baseline, work_parent, log):
    def emit(value):
        print(value, flush=True)
        log.write(str(value) + "\n")
        log.flush()

    def run(args, env, cwd=REPO):
        emit("$ " + shlex.join(map(str, args)))
        result = subprocess.run(args, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, timeout=180)
        emit(result.stdout.rstrip())
        emit(f"exit={result.returncode}")
        if result.returncode:
            raise RuntimeError("command failed")
        return result.stdout

    env = {k: v for k, v in os.environ.items() if not k.startswith(("TUNN_", "FLY_"))}
    for name in ("TMPDIR", "GOTMPDIR", "GOCACHE"):
        value = Path(env[name]).resolve()
        assert REPO.parent not in value.parents and value != REPO.parent, name
    # Resolve the module cache before the empty HOME hides Go's user settings.
    # The relay fixture must keep using the prepared cache for offline runs.
    env.update(json.loads(run(["go", "env", "-json", "GOMODCACHE"], env)))
    # This is the unchanged installer from the selected main baseline.
    main_installer = subprocess.check_output(["git", "show", "c877489c:install.sh"], cwd=REPO)
    assert main_installer == (REPO / "install.sh").read_bytes()
    emit("Main install.sh SHA256=" + digest(REPO / "install.sh"))
    sums = dict((line.split()[1], line.split()[0])
                for line in (baseline.parent / "SHA256SUMS").read_text().splitlines())
    assert digest(baseline) == sums[baseline.name], "v0.1.5 checksum mismatch"
    emit("Retained released v0.1.5 SHA256=" + digest(baseline))
    assert run([baseline, "version"], env) == "tunn v0.1.5\n"
    manifest = json.loads((stage / "manifest.json").read_text())
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip()
    assert manifest["source_commit"] == head and manifest["tag"] == "v0.1.6"
    record = next(r for r in manifest["assets"] if r["name"] == "tunn-linux-amd64")
    work_parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="install-walk-", dir=work_parent) as tmp:
        work = Path(tmp)
        home = work / "home"
        home.mkdir()
        assert not list(home.iterdir())
        env.update(HOME=str(home), XDG_CONFIG_HOME=str(home / ".config"),
                   TUNN_CONFIG_DIR=str(home / ".tunn"), NO_COLOR="1", NO_PROXY="*",
                   TUNN_ENV="dev", TUNN_PUBLIC_MODE="false")
        cert, key = work / "cert.pem", work / "key.pem"
        run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-days", "1",
             "-nodes", "-keyout", key, "-out", cert, "-subj", "/CN=127.0.0.1",
             "-addext", "subjectAltName=IP:127.0.0.1"], env, work)

        class Handler(http.server.SimpleHTTPRequestHandler):
            def log_message(self, message, *args):
                emit("loopback HTTPS " + message % args)

        handler = functools.partial(Handler, directory=str(stage / "downloads"))
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            env.update(TUNN_DOWNLOAD_BASE=f"https://127.0.0.1:{server.server_port}",
                       CURL_CA_BUNDLE=str(cert), SSL_CERT_FILE=str(cert))
            emit("Empty HOME=" + str(home))
            emit("TUNN_DOWNLOAD_BASE=" + env["TUNN_DOWNLOAD_BASE"])
            run(["sh", REPO / "install.sh"], env, work)
            installed = home / ".local/bin/tunn"
            assert digest(installed) == record["sha256"], "installed bytes differ from stage"
            emit("Installed candidate SHA256=" + digest(installed))
            assert run([installed, "version"], env, work) == "tunn v0.1.6\n"
            env.update(TUNN_INSTALLED_CLI=str(installed), TUNN_RELEASE_CLI=str(baseline))
            emit("Local dev relay: synthetic Free account already keeps first-project; "
                 "both clients start second-project and forward a real HTTP request.")
            run(["go", "test", "-p", "2", "-count=1", "-timeout=120s", "-v",
                 "./internal/host", "-run",
                 "^(TestPlanLimitInstalledCLI|TestPlanLimitReleasedCLI)$/^local$/^second-name$"], env)
            emit("PASS: installed v0.1.6 displays Pro $5 and monthly checkout; "
                 "released v0.1.5 does not; both second-name tunnels forward HTTP.")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", required=True, type=Path)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--work-parent", required=True, type=Path)
    parser.add_argument("--log", required=True, type=Path)
    args = parser.parse_args()
    with args.log.open("w") as log:
        walk(args.stage.resolve(), args.baseline.resolve(), args.work_parent.resolve(), log)
