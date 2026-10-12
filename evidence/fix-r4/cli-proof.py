"""Check the built CLI's actual stderr against a synthetic local owner API."""
import http.server
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading

instructions = (
    'unverified claim: prove ownership with TXT '
    '_tunn-verification.apps.example.com = dv-caller.tunn.test '
    'and retry add within 24 hours'
)
requests = []

class OwnerAPI(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        requests.append((self.path, self.headers.get('Authorization'), body))
        self.send_response(409)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write((instructions + '\n').encode())

    def log_message(self, *args):
        pass

with http.server.ThreadingHTTPServer(('127.0.0.1', 0), OwnerAPI) as server:
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(dir=os.environ['GOTMPDIR']) as directory:
            token = Path(directory) / 'owner-token'
            token.write_text('owner-token')
            token.chmod(0o600)
            env = dict(os.environ, TUNN_ENV='dev')
            result = subprocess.run([
                '.scratch/tunn-cli', 'domain', 'add', '*.apps.example.com',
                '--tunnel', 'dashboard', '--server',
                f'http://127.0.0.1:{server.server_port}',
                '--owner-token-file', str(token),
            ], env=env, capture_output=True, text=True, timeout=30)
            print(f'CLI exit={result.returncode}')
            print('CLI stderr:\n' + result.stderr)
            assert result.returncode == 1, result
            assert result.stdout == '', result.stdout
            assert 'owner API returned HTTP 409: ' + instructions in result.stderr
            assert requests == [('/api/domains', 'Bearer owner-token', {
                'name': '*.apps.example.com', 'tunnel': 'dashboard'
            })], requests
            print('PASS: actual CLI stderr retains the complete competing TXT proof')
    finally:
        server.shutdown()
        thread.join()
