#!/usr/bin/env python3
"""Loopback request-header conformance; build JS and the Python helper first.

Uses the production relay/publishers through the existing disposable fixtures.
Requires Node dependencies and TUNN_PYTHON_HELPER, with uvicorn in TUNN_PYTHON.
"""
import os
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parents[2]
env = os.environ.copy()
env.setdefault('TUNN_PYTHON', 'python3')
env.setdefault('TUNN_PYTHON_HELPER', str(root / 'bin/tunn-python-bridge'))
env['PYTHONPATH'] = str(root / 'sdk/python/src')
env['PYTHONDONTWRITEBYTECODE'] = '1'
if not Path(env['TUNN_PYTHON_HELPER']).is_file():
    raise SystemExit('missing rebuilt helper: run make build-python-helper')
if (root / 'proto/tunnel.proto').read_bytes() != (root / 'sdk/js/proto/tunnel.proto').read_bytes():
    raise SystemExit('vendored JS request schema differs')

commands = [
    (root, ['go', 'test', '-p', '2', '-race', '-count=1', '-run', 'Test(RepeatedApplicationRequestHeaders|RequestHeader)', './internal/common', './internal/client', './internal/host']),
    (root / 'sdk/js', ['node', '--test', '--test-name-pattern=repeated request fields|malformed singleton fields', 'test/sdk.test.mjs']),
    (root, ['go', 'test', '-p', '2', '-race', '-tags=pythonsdk', '-count=1', '-run', '^TestPythonSDKRepeatedRequestHeaders$', './internal/host']),
]
for cwd, command in commands:
    print('+', ' '.join(command), flush=True)
    subprocess.run(['nice', '-n', '10', *command], cwd=cwd, env=env, check=True)
print('PASS: Go/JS/Python repeated request headers, Cookie, filtering, framing and legacy negotiation')
