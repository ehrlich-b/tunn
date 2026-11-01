#!/usr/bin/env python3
"""Ensure a failed navigation terminates the recorder and its browser."""
import json
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory() as directory:
    env = dict(os.environ, PLAYWRIGHT_BROWSERS_PATH='/work/cache/ms-playwright')
    process = subprocess.Popen(['node', str(root / 'scripts/demo/record.cjs'), directory],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True, start_new_session=True, env=env)
    try:
        stdout, stderr = process.communicate(json.dumps({'type': 'login', 'url': 'http://127.0.0.1:1/'}) + '\n', timeout=30)
        assert 'ready' in stdout, (stdout, stderr)
        assert process.returncode != 0, (stdout, stderr)
        assert 'ERR_UNSAFE_PORT' in stderr, stderr
    finally:
        if process.poll() is None:
            import signal
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
print('PASS: recorder exits after a navigation error')
