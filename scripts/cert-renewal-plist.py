#!/usr/bin/env python3
"""Render or atomically install a daily certificate-renewal launchd job."""
import argparse
import os
from pathlib import Path
import plistlib
import sys
import tempfile


def render(home):
    repo = Path(__file__).resolve().parents[1]
    log = str(home / ".config/tunn/cert-renewal.log")
    return plistlib.dumps({
        "Label": "com.ehrlich.tunn-cert-renewal",
        "ProgramArguments": [str(repo / "renew-certs.sh")],
        "WorkingDirectory": str(repo),
        "EnvironmentVariables": {
            "HOME": str(home),
            "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
            **{key: value for key, value in os.environ.items()
               if key in {"TUNN_CERT_DOMAIN", "TUNN_FLY_APP", "TUNN_CERT_EMAIL"}},
        },
        "RunAtLoad": True,
        "StartInterval": 86400,
        "ThrottleInterval": 3600,
        "StandardOutPath": log,
        "StandardErrorPath": log,
    })


def install(destination, data):
    # Stage beside the destination so replacement is atomic and never follows
    # an existing destination symlink. Nothing touches the old job on failure.
    fd, name = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    staged = Path(name)
    try:
        with os.fdopen(fd, "wb") as output:
            os.fchmod(output.fileno(), 0o600)
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        with staged.open("rb") as source:
            plistlib.load(source)
        os.replace(staged, destination)
    finally:
        staged.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--install", action="store_true", help="replace the installed job atomically")
    args = parser.parse_args()
    home = Path.home()
    data = render(home)
    if args.install:
        install(home / "Library/LaunchAgents/com.ehrlich.tunn-cert-renewal.plist", data)
    else:
        sys.stdout.buffer.write(data)


if __name__ == "__main__":
    main()
