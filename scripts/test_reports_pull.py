import http.server
import json
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest

SCRIPT = Path(__file__).with_name('reports-pull.py')
class Handler(http.server.BaseHTTPRequestHandler):
    fail = False
    def do_GET(self):
        if self.fail:
            self.send_error(500); return
        assert self.headers['Authorization'] == 'Bearer secret'
        since = int(self.path.split('since=')[1])
        data = json.dumps([{'id': i, 'text': 'example'} for i in (1, 2, 3) if i > since][:1]).encode()
        self.send_response(200); self.end_headers(); self.wfile.write(data)
    def log_message(self, *args): pass
class PullTest(unittest.TestCase):
    def test_retry_and_no_duplicates(self):
        server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close); self.addCleanup(server.shutdown)
        with tempfile.TemporaryDirectory() as d:
            token = Path(d)/'token'; token.write_text('TUNN_REPORTS_TOKEN=secret\n')
            inbox = Path(d)/'inbox'
            cmd = ['python3', str(SCRIPT), '--token-file', str(token), '--inbox', str(inbox), '--url', f'http://127.0.0.1:{server.server_port}/ops/reports']
            Handler.fail = True
            self.assertNotEqual(subprocess.run(cmd, capture_output=True).returncode, 0)
            self.assertFalse(inbox.exists())
            Handler.fail = False
            subprocess.run(cmd, check=True); subprocess.run(cmd, check=True)
            self.assertEqual([json.loads(line)['id'] for line in inbox.read_text().splitlines()], [1, 2, 3])
if __name__ == '__main__': unittest.main()
