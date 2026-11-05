#!/usr/bin/env python3
"""Offline release/operator contract tests with disposable Git and round scripts."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).with_name('sales-release.py').resolve()


class SalesRelease(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / 'repo'
        (self.repo / 'scripts').mkdir(parents=True)
        (self.repo / 'scripts/sales-release.py').write_bytes(SCRIPT.read_bytes())
        (self.repo / 'internal/host/templates').mkdir(parents=True)
        (self.repo / 'internal/host/templates/home.html').write_text('Selling')
        for cmd in (['git', 'init', '-q'], ['git', 'config', 'user.name', 'Bryan Ehrlich'],
                    ['git', 'config', 'user.email', 'ehrlich.bryan@gmail.com'],
                    ['git', 'add', '.'], ['git', 'commit', '-qm', 'Prepare local fixture.']):
            subprocess.run(cmd, cwd=self.repo, check=True)
        self.sha = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=self.repo, text=True).strip()
        subprocess.run(['git', 'update-ref', 'refs/remotes/origin/main', self.sha], cwd=self.repo, check=True)
        self.feed = self.root / 'prior.json'
        self.feed.write_text('{"tag_name":"v0.1.5"}')
        self.receipt = self.root / 'receipt.json'
        self.receipt.write_text(json.dumps({'source': self.sha, 'command': 'local fragment', 'exit_code': 0, 'selected_tests': 1}))
        self.manifest = self.root / 'manifest.json'
        self.log = self.root / 'calls'
        self.round = self.root / 'round'
        self.round.write_text('''#!/usr/bin/env python3
import hashlib,json,os,pathlib,sys
m=json.loads(pathlib.Path(sys.argv[3]).read_text())
with open(os.environ['CALLS'],'a') as f: f.write(sys.argv[1]+'\\n')
if sys.argv[1]=='--check':
 if os.environ.get('FAIL_CHECK'): sys.exit(7)
 print(json.dumps({'previous_image': m['previous']['image'] if not os.environ.get('STALE') else 'stale', 'previous_feed_sha256':m['previous']['feed']['sha256']}))
else: sys.exit(int(os.environ.get('FAIL_APPLY','0')))
''')
        self.round.chmod(0o755)
        self.assertEqual(self.generate().returncode, 0)

    def call(self, *args, **env):
        return subprocess.run(['python3', '-B', 'scripts/sales-release.py', *map(str, args)],
                              cwd=self.repo, env=dict(os.environ, CALLS=str(self.log), **env), text=True, capture_output=True)

    def generate(self, *extra):
        return self.call('generate', '--source', self.sha, '--previous-image', 'registry/tunn@sha256:' + 'a'*64,
                         '--previous-tag', 'v0.1.5', '--previous-feed', self.feed, '--config-name', 'TUNN_DOWNLOAD_DIR',
                         '--receipt', self.receipt, '--output', self.manifest, *extra)

    def operate(self, *args, **env):
        return self.call('operate', '--manifest', self.manifest, '--round-script', self.round, *args, **env)

    def change(self, fn):
        m = json.loads(self.manifest.read_text()); fn(m)
        self.manifest.write_text(json.dumps(m))

    def no_calls(self):
        self.assertFalse(self.log.exists())

    def test_relay_only_dry_run(self):
        self.assertIsNone(json.loads(self.manifest.read_text())['client'])
        r = self.operate(); self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('--check', r.stdout); self.assertIn('--apply', r.stdout)
        self.assertIn('DRY RUN', r.stdout); self.no_calls()

    def test_wrong_source(self):
        self.change(lambda m: m.update(relay_sha='b'*40))
        self.assertNotEqual(self.operate().returncode, 0); self.no_calls()

    def test_dirty_source(self):
        (self.repo / 'dirty').write_text('x')
        self.assertNotEqual(self.operate().returncode, 0); self.no_calls()

    def test_unlanded_source(self):
        self.change(lambda m: m.update(main_ref='refs/heads/missing'))
        self.assertNotEqual(self.operate().returncode, 0); self.no_calls()

    def test_absent_prior_release(self):
        self.change(lambda m: m.update(previous={}))
        self.assertNotEqual(self.operate().returncode, 0); self.no_calls()

    def test_changed_prior_feed(self):
        self.feed.write_text('{}')
        self.assertNotEqual(self.operate().returncode, 0); self.no_calls()

    def test_missing_and_changed_assets(self):
        asset = self.root / 'asset'; asset.write_text('tiny')
        import hashlib
        self.change(lambda m: m.update(client={'stage': str(self.root), 'tag': 'v1.0.0', 'files':
                    [{'path': str(asset), 'sha256': hashlib.sha256(b'tiny').hexdigest()}]}))
        asset.write_text('changed')
        self.assertNotEqual(self.operate().returncode, 0)
        self.change(lambda m: m['client']['files'][0].update(path=str(self.root / 'missing-asset')))
        self.assertNotEqual(self.operate().returncode, 0); self.no_calls()

    def test_failed_check(self):
        r = self.operate('--operator-apply', FAIL_CHECK='1')
        self.assertEqual(r.returncode, 7)
        self.assertEqual(self.log.read_text(), '--check\n')

    def test_prior_state_mismatch(self):
        self.assertNotEqual(self.operate('--operator-apply', STALE='1').returncode, 0)
        self.assertEqual(self.log.read_text(), '--check\n')

    def test_guarded_apply_fake_only(self):
        r = self.operate('--operator-apply'); self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.log.read_text(), '--check\n--apply\n')

    def test_apply_failure_propagates(self):
        self.assertEqual(self.operate('--operator-apply', FAIL_APPLY='9').returncode, 9)

    def test_empty_receipt(self):
        r = json.loads(self.receipt.read_text()); r['selected_tests'] = 0
        self.receipt.write_text(json.dumps(r))
        import hashlib
        self.change(lambda m: m['receipts'][0].update(sha256=hashlib.sha256(self.receipt.read_bytes()).hexdigest()))
        self.assertNotEqual(self.operate().returncode, 0); self.no_calls()

    def test_config_values_refused(self):
        self.change(lambda m: m.update(configuration_names=['TUNN_KEY=value']))
        self.assertNotEqual(self.operate().returncode, 0); self.no_calls()


if __name__ == '__main__':
    unittest.main(verbosity=2)
