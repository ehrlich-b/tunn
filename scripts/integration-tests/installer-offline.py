#!/usr/bin/env python3
"""Exercise the real installer and build version without network or credentials.

Pass --output DIR to retain the /dl fixture, curl receipts and installed binary.
The curl substitute copies only allowlisted fixture files and cannot use sockets.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile


REPO = Path(__file__).resolve().parents[2]
TAG = "v0.0.123"
BASE = "https://offline.invalid/dl"


def run(args, env, cwd, expected=0):
    result = subprocess.run(args, env=env, cwd=cwd, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=180)
    print(f"$ {' '.join(map(str, args))}\nexit={result.returncode}\n{result.stdout}{result.stderr}", flush=True)
    assert result.returncode == expected, result
    return result


def smoke(root):
    system = platform.system().lower()
    arch = {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}[platform.machine()]
    assert system in ("linux", "darwin"), "installer supports Linux and Darwin"
    asset = f"tunn-{system}-{arch}"
    release = root / "dl" / TAG
    release.mkdir(parents=True)
    binary = release / asset
    env = dict(os.environ, GOPROXY="off", GOSUMDB="off", GOTOOLCHAIN="local")
    run(["nice", "-n", "10", "go", "build", "-p", "2", "-ldflags", f"-X main.version={TAG}", "-o", str(binary), "."], env, REPO)
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    sums = release / "SHA256SUMS"
    sums.write_text(f"{digest}  {asset}\n")
    (root / "dl" / "latest.json").write_text(json.dumps({"tag_name": TAG, "draft": False, "prerelease": False}) + "\n")

    # This is a transport substitute, not an HTTP server: no DNS, TLS, or socket
    # can escape the fixture, and the production HTTPS restrictions stay intact.
    shim = root / "shim"
    shim.mkdir()
    curl = shim / "curl"
    curl.write_text("""#!/usr/bin/env python3
import json, os, pathlib, shutil, sys
args = sys.argv[1:]
base = 'https://offline.invalid/dl/'
url = args[-1]
with open(os.environ['OFFLINE_CALLS'], 'a') as log:
    log.write(json.dumps({'url': url, 'args': args}) + '\\n')
assert args[args.index('--proto') + 1] == '=https'
assert args[args.index('--proto-redir') + 1] == '=https'
assert url.startswith(base), url
path = url[len(base):]
assert path in ('latest.json', os.environ['OFFLINE_TAG'] + '/' + os.environ['OFFLINE_ASSET'], os.environ['OFFLINE_TAG'] + '/SHA256SUMS'), path
shutil.copyfile(pathlib.Path(os.environ['OFFLINE_DL']) / path, args[args.index('-o') + 1])
""")
    curl.chmod(0o755)
    sandbox = root / "sandbox"
    sandbox.mkdir()
    home = sandbox / "home"
    home.mkdir()
    install = root / "installed"
    calls = root / "requests.jsonl"
    env.update(HOME=str(home), XDG_CONFIG_HOME=str(home / "config"), TUNN_CONFIG_DIR=str(home / "tunn"),
               TUNN_DOWNLOAD_BASE=BASE, TUNN_INSTALL_DIR=str(install), PATH=f"{shim}:{os.environ['PATH']}",
               OFFLINE_DL=str(root / "dl"), OFFLINE_CALLS=str(calls), OFFLINE_TAG=TAG, OFFLINE_ASSET=asset,
               HTTP_PROXY="http://127.0.0.1:1", HTTPS_PROXY="http://127.0.0.1:1", ALL_PROXY="http://127.0.0.1:1")
    run(["sh", str(REPO / "install.sh")], env, sandbox)
    installed = install / "tunn"
    assert hashlib.sha256(installed.read_bytes()).hexdigest() == digest
    for args in (["--version"], ["version"]):
        result = run([str(installed), *args], env, sandbox)
        assert result.stdout == f"tunn {TAG}\n" and not result.stderr, result
    for args in (["--unknown"], ["--version", "--unknown"], ["--unknown", "--version"],
                 ["version", "--unknown"], ["version", "extra"], ["--version", "extra"]):
        run([str(installed), *args], env, sandbox, expected=2)
    assert not list(home.iterdir()), "version queries wrote credentials or configuration"

    # A service with a missing login must retain the carrier's non-restarting
    # exit status rather than starting enrollment or retrying the network.
    env.update(TUNN_ENV="dev", TUNN_PUBLIC_MODE="", TUNN_SECRET="", TUNN_SERVER_ADDR="127.0.0.1:1")
    missing = run([str(installed), "3000"], env, sandbox, expected=78)
    assert "tunn login" in missing.stderr and "TUNN_CONFIG_DIR=" in missing.stderr

    sums.write_text(f"{'0' * 64}  {asset}\n")
    for target in (install, root / "refused"):
        env["TUNN_INSTALL_DIR"] = str(target)
        result = run(["sh", str(REPO / "install.sh")], env, sandbox, expected=1)
        assert "Unable to download a verified tunn release" in result.stderr
        if target == install:
            assert hashlib.sha256(installed.read_bytes()).hexdigest() == digest, "existing binary overwritten"
            assert [p.name for p in install.iterdir()] == ["tunn"], "temporary install leaked"
        else:
            assert not target.exists(), "bad checksum created an installation"
    receipts = [json.loads(line) for line in calls.read_text().splitlines()]
    expected_urls = [BASE + "/latest.json", BASE + f"/{TAG}/{asset}", BASE + f"/{TAG}/SHA256SUMS"]
    assert [r["url"] for r in receipts] == expected_urls * 3, receipts
    # Leave the retained fixture valid for independent checksum verification.
    sums.write_text(f"{digest}  {asset}\n")
    print("PASS: offline release installation, both version commands, unknown flags, service login exit, checksum refusal and atomicity", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.output:
        root = args.output.resolve()
        root.mkdir(parents=True, exist_ok=False)
        smoke(root)
    else:
        with tempfile.TemporaryDirectory(prefix="tunn-installer-offline-") as temp:
            smoke(Path(temp))
