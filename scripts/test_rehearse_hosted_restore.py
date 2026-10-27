#!/usr/bin/env python3
import importlib.util
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('rehearsal', Path(__file__).with_name('rehearse-hosted-restore.py'))
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)

class RehearsalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.path = r.fixture(self.root)
        self.m = json.loads(self.path.read_text())
    def tearDown(self):
        self.temp.cleanup()
    def save(self):
        self.path.write_text(json.dumps(self.m))
    def rehash(self, name):
        self.m['files'][name] = r.digest(self.root / name)
        self.save()
    def test_rehearsal(self):
        self.assertEqual(r.restore(self.path)['result'], 'synthetic-pass')
    def test_boolean_integer_fields_rejected(self):
        for field in ('version', 'backup_sequence', 'reconciliation_through'):
            original = self.m[field]; self.m[field] = True; self.save()
            with self.subTest(field=field), self.assertRaises(ValueError): r.restore(self.path)
            self.m[field] = original
        self.save()
        p = self.root / 'reconciliation.json'; rec = json.loads(p.read_text())
        rec['revocations'][0]['seq'] = True; p.write_text(json.dumps(rec)); self.rehash(p.name)
        with self.assertRaises(ValueError): r.restore(self.path)
    def test_inconsistent_database_and_wal(self):
        # A different SQLite database paired with the fixture WAL, with hashes updated.
        db = self.root / 'snapshot.sqlite'
        other = self.root / 'other.sqlite'
        con = sqlite3.connect(other); con.execute('PRAGMA page_size=8192'); con.execute('CREATE TABLE unrelated(id INTEGER)'); con.commit(); con.close()
        db.write_bytes(other.read_bytes())
        self.rehash(db.name)
        with self.assertRaises((ValueError, sqlite3.Error)): r.restore(self.path)
    def test_symlink_rejected(self):
        p = self.root / 'reconciliation.json'; p.unlink(); p.symlink_to(self.path)
        with self.assertRaises(OSError): r.restore(self.path)
    def test_bad_hash_shape(self):
        self.m['files']['snapshot.sqlite'] = 'invalid'; self.save()
        with self.assertRaisesRegex(ValueError, 'invalid SHA-256'): r.restore(self.path)
    def test_oversized_input(self):
        p = self.root / 'snapshot.sqlite'
        with p.open('wb') as f: f.truncate(r.MAX_INPUT_BYTES + 1)
        with self.assertRaisesRegex(ValueError, 'bounded regular file'): r.restore(self.path)
    def test_same_page_size_unrelated_database(self):
        other = self.root / 'other.sqlite'
        con = sqlite3.connect(other)
        con.execute('PRAGMA page_size=4096')
        con.execute('CREATE TABLE unrelated(id INTEGER)')
        con.commit(); con.close()
        (self.root / 'snapshot.sqlite').write_bytes(other.read_bytes())
        self.rehash('snapshot.sqlite')
        with self.assertRaisesRegex(ValueError, 'unrecognized synthetic fixture base'):
            r.restore(self.path)
    def test_hash_mismatch(self):
        (self.root / 'snapshot.sqlite').write_bytes(b'bad')
        with self.assertRaises(ValueError): r.restore(self.path)
    def test_corrupt_wal_even_with_updated_hash(self):
        p = self.root / 'snapshot.sqlite-wal'
        data = bytearray(p.read_bytes()); data[-1] ^= 1; p.write_bytes(data)
        self.rehash(p.name)
        with self.assertRaises(ValueError): r.restore(self.path)
    def test_truncated_wal(self):
        p = self.root / 'snapshot.sqlite-wal'; p.write_bytes(p.read_bytes()[:-1]); self.rehash(p.name)
        with self.assertRaises(ValueError): r.restore(self.path)
    def test_provenance(self):
        self.m['source'] = 'production'; self.save()
        with self.assertRaises(ValueError): r.restore(self.path)
    def test_forged_production_receipt(self):
        self.m['kind'] = 'production'; self.save()
        with self.assertRaises(ValueError): r.restore(self.path)
    def test_missing_reconciliation(self):
        p = self.root / 'reconciliation.json'; rec = json.loads(p.read_text()); del rec['refunds']; p.write_text(json.dumps(rec)); self.rehash(p.name)
        with self.assertRaises(ValueError): r.restore(self.path)
    def test_empty_refunds(self):
        p = self.root / 'reconciliation.json'; rec = json.loads(p.read_text()); rec['refunds'] = []; p.write_text(json.dumps(rec)); self.rehash(p.name)
        with self.assertRaisesRegex(ValueError, 'required post-backup events missing'): r.restore(self.path)
    def test_empty_revocations(self):
        p = self.root / 'reconciliation.json'; rec = json.loads(p.read_text()); rec['revocations'] = []; p.write_text(json.dumps(rec)); self.rehash(p.name)
        with self.assertRaisesRegex(ValueError, 'required post-backup events missing'): r.restore(self.path)
    def test_stale_revocations(self):
        p = self.root / 'reconciliation.json'; rec = json.loads(p.read_text()); rec['revocations'][0]['seq'] = 1; p.write_text(json.dumps(rec)); self.rehash(p.name)
        with self.assertRaises(ValueError): r.restore(self.path)
    def test_missing_required_state(self):
        db = self.root / 'snapshot.sqlite'
        con = sqlite3.connect(db)
        con.execute('PRAGMA wal_autocheckpoint=0')
        con.execute('DELETE FROM usage'); con.commit()
        self.rehash('snapshot.sqlite'); self.rehash('snapshot.sqlite-wal')
        with self.assertRaisesRegex(ValueError, 'required state missing: usage'):
            r.restore(self.path)
        con.close()

    def test_altered_baseline_account_and_revocation_rejected(self):
        mutations = (
            "UPDATE accounts SET paid=0 WHERE id='synthetic-a'",
            "UPDATE accounts SET revoked=0 WHERE id='synthetic-b'",
            "UPDATE revocations SET seq=0 WHERE account='synthetic-b'",
            "UPDATE accounts SET paid=NULL, revoked='invalid' WHERE id='synthetic-b'",
            "UPDATE accounts SET paid=0 WHERE id='synthetic-c'",
        )
        for sql in mutations:
            with self.subTest(sql=sql), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                manifest = r.fixture(root)
                m = json.loads(manifest.read_text())
                con = sqlite3.connect(root / 'snapshot.sqlite')
                try:
                    con.execute('PRAGMA wal_autocheckpoint=0')
                    con.execute(sql); con.commit()
                    for name in ('snapshot.sqlite', 'snapshot.sqlite-wal'):
                        m['files'][name] = r.digest(root / name)
                    manifest.write_text(json.dumps(m))
                    with self.assertRaisesRegex(ValueError, 'baseline state verification failed'):
                        r.restore(manifest)
                    result = subprocess.run([sys.executable, '-B', str(Path(r.__file__)),
                                             '--no-network', '--manifest', str(manifest)],
                                            capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertNotIn('synthetic-pass', result.stdout)
                finally:
                    con.close()

if __name__ == '__main__': unittest.main()
