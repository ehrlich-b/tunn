#!/usr/bin/env python3
"""Render a daily certificate-renewal launchd job for this checkout."""
import os
from pathlib import Path
import plistlib
import sys

home = Path.home()
repo = Path(__file__).resolve().parents[1]
log = str(home / ".config/tunn/cert-renewal.log")
plistlib.dump({
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
}, sys.stdout.buffer)
