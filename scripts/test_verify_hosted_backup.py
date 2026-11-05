#!/usr/bin/env python3
"""Small, exclusively synthetic backup verification fixtures."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location('backup_verifier', Path(__file__).with_name('verify-hosted-backup.py'))
v = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(v)


def fixture(path):
    schema = json.loads(v.SCHEMA.read_text())
    con = sqlite3.connect(path)
    con.execute('BEGIN')
    for table in schema['tables'].values():
        con.execute(table['sql'])
        for index in table['indexes']:
            con.execute(index)
    con.execute("INSERT INTO accounts(id,primary_email,created_at) VALUES('secret-account-id','private@example.invalid',1793836800)")
    con.execute("INSERT INTO used_magic_tokens(jti,expires_at) VALUES('secret-token',1793836801)")
    con.commit()
    con.close()


class VerifierTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='tunn-verifier-test-')
        self.root = Path(self.temp.name)
        self.db = self.root / 'backup ?#%.sqlite'
        fixture(self.db)

    def tearDown(self):
        self.temp.cleanup()

    def cli(self, expected, *options):
        proc = subprocess.run([sys.executable, '-B', str(Path(v.__file__)), str(self.db), *options],
                              capture_output=True, text=True, timeout=120)
        self.assertEqual(proc.returncode, expected, proc.stderr)
        for secret in ('private@example.invalid', 'secret-account-id', 'secret-token', str(self.db)):
            self.assertNotIn(secret, proc.stdout + proc.stderr)
        if expected:
            self.assertEqual(proc.stdout, '')
        return proc

    def test_good_read_only_receipt(self):
        before = hashlib.sha256(self.db.read_bytes()).hexdigest()
        self.db.chmod(0o400)
        receipt = json.loads(self.cli(v.OK).stdout)
        self.assertEqual(receipt['tables']['accounts'], {
            'row_count': 1, 'newest_timestamps': {'created_at': '2026-11-05T00:00:00+00:00'}})
        self.assertEqual(receipt['tables']['used_magic_tokens']['row_count'], 1)
        self.assertEqual(before, hashlib.sha256(self.db.read_bytes()).hexdigest())
        self.assertEqual(list(self.root.iterdir()), [self.db])
        # Assert the actual connection uses the required read-only URI.
        connect = sqlite3.connect
        with patch.object(v.sqlite3, 'connect', wraps=connect) as mocked:
            v.verify(self.db)
            args, kwargs = mocked.call_args
            self.assertTrue(args[0].endswith('?mode=ro&immutable=1'))
            self.assertTrue(kwargs['uri'])
        print('good=0; source hash unchanged; no sidecars; mode=ro; receipt redacted')

    def test_truncated(self):
        self.db.write_bytes(self.db.read_bytes()[:150])
        self.cli(v.INTEGRITY)
        print('truncated=2')

    def test_wrong_schema(self):
        con = sqlite3.connect(self.db)
        con.execute('ALTER TABLE accounts ADD COLUMN unrelated TEXT')
        con.commit(); con.close()
        self.cli(v.SCHEMA_MISMATCH)
        print('wrong-schema=3')

    def test_uncheckpointed_wal(self):
        con = sqlite3.connect(self.db)
        try:
            con.execute('PRAGMA journal_mode=WAL')
            con.execute('PRAGMA wal_autocheckpoint=0')
            con.execute("INSERT INTO used_magic_tokens VALUES('wal-secret-token',1793836802)")
            con.commit()
            before = {p.name: p.read_bytes() for p in self.root.iterdir()}
            self.cli(v.WAL)
            self.assertEqual(before, {p.name: p.read_bytes() for p in self.root.iterdir()})
            print('uncheckpointed-WAL=4; source and sidecars unchanged')
        finally:
            con.close()

    def test_missing_and_symlink(self):
        missing = self.root / 'missing'
        with self.assertRaises(v.Rejected) as rejected:
            v.verify(missing)
        self.assertEqual(rejected.exception.code, v.INPUT)
        self.assertFalse(missing.exists())
        link = self.root / 'link'
        link.symlink_to(self.db)
        with self.assertRaises(v.Rejected) as rejected:
            v.verify(link)
        self.assertEqual(rejected.exception.code, v.INPUT)

    def test_table_trigger_index_mismatches(self):
        for sql in ("CREATE TABLE unrelated(value TEXT)",
                    "DROP TABLE account_usage", "DROP INDEX idx_accounts_primary_email",
                    "CREATE TRIGGER secret_trigger AFTER INSERT ON accounts BEGIN SELECT 1; END"):
            with self.subTest(sql=sql), tempfile.TemporaryDirectory() as temp:
                db = Path(temp) / 'fixture.sqlite'
                fixture(db)
                con = sqlite3.connect(db); con.execute(sql); con.commit(); con.close()
                with self.assertRaises(v.Rejected) as rejected:
                    v.verify(db)
                self.assertEqual(rejected.exception.code, v.SCHEMA_MISMATCH)

    def test_timestamp_values_do_not_leak(self):
        con = sqlite3.connect(self.db)
        con.execute("UPDATE accounts SET created_at='private@example.invalid'")
        con.commit(); con.close()
        receipt = json.loads(self.cli(v.OK).stdout)
        self.assertIsNone(receipt['tables']['accounts']['newest_timestamps']['created_at'])

    def test_newest_text_timestamp_uses_utc_order(self):
        cases = (
            # Text MAX picks the later wall clock, which is the older instant.
            (('2026-11-05T12:00:00+02:00', '2026-11-05T11:30:00Z'),
             '2026-11-05T11:30:00+00:00'),
            # Offsets can move the newest instant onto a different UTC date.
            (('2026-11-05T23:30:00-02:00', '2026-11-06T00:30:00Z'),
             '2026-11-06T01:30:00+00:00'),
            # Space separators, naive UTC and fractional seconds also normalize.
            (('2026-11-05 12:00:00.500000', '2026-11-05T12:00:00Z',
              '2026-11-05T12:00:00.050000+00:00'),
             '2026-11-05T12:00:00.500000+00:00'),
            # Invalid values must not hide a valid timestamp or leak contents.
            (('private@example.invalid', '2026-11-05T12:00:00Z',
              '9999-12-31T23:59:59-23:00'), '2026-11-05T12:00:00+00:00'),
            (('private@example.invalid', 'not-a-time'), None),
            ((), None),
        )
        for values, expected in cases:
            with self.subTest(values=values):
                with sqlite3.connect(self.db) as con:
                    con.execute('DELETE FROM ops_checkout_intents')
                    con.executemany('INSERT INTO ops_checkout_intents VALUES(?,?,?)',
                                    [(str(i), 'secret-account-id', value)
                                     for i, value in enumerate(values)])
                before = self.db.read_bytes()
                receipt = json.loads(self.cli(v.OK).stdout)
                self.assertEqual(receipt['tables']['ops_checkout_intents'], {
                    'row_count': len(values), 'newest_timestamps': {'created_at': expected}})
                self.assertEqual(self.db.read_bytes(), before)
        print('checked newest TEXT timestamp: UTC offsets, date rollover, fractions, invalid and empty values')

    def test_newest_timestamp_with_mixed_sqlite_storage(self):
        # SQLite normally sorts TEXT after INTEGER regardless of the instant.
        with sqlite3.connect(self.db) as con:
            con.execute("INSERT INTO accounts(id,primary_email,created_at) VALUES(?,?,?)",
                        ('another-secret-id', 'private@example.invalid', '2026-11-04T23:00:00Z'))
        receipt = json.loads(self.cli(v.OK).stdout)
        self.assertEqual(receipt['tables']['accounts'], {
            'row_count': 2, 'newest_timestamps': {'created_at': '2026-11-05T00:00:00+00:00'}})
        print('newest mixed INTEGER/TEXT timestamp uses chronological UTC order')

    def test_relay_failure_is_distinct(self):
        r = v.rehearsal()
        before = self.db.read_bytes()
        with patch.object(v, 'rehearsal', return_value=r), patch.object(r, 'build_relay', side_effect=OSError('private build diagnostic')):
            with self.assertRaises(v.Rejected) as rejected:
                v.verify(self.db, start_relay=True)
        self.assertEqual(rejected.exception.code, v.RELAY)
        self.assertNotIn('private', rejected.exception.reason)
        self.assertEqual(self.db.read_bytes(), before)


class RelayTests(unittest.TestCase):
    def test_fixture_boot_and_current_schema(self):
        r = v.rehearsal()
        with tempfile.TemporaryDirectory(prefix='tunn-relay-verifier-test-') as temp:
            root = Path(temp)
            binary = r.build_relay(root)
            empty = root / 'current.sqlite'
            # Real relay startup creates the current schema independently of the
            # committed reference, so a schema change cannot silently go stale.
            with patch.dict(os.environ, {'TUNN_SMTP_HOST': 'must-not-be-used.invalid',
                                         'HTTPS_PROXY': 'http://must-not-be-used.invalid:9',
                                         'FLY_APP_NAME': 'must-not-be-used'}):
                with r.loopback_relay(binary, empty, root / 'reference-runtime') as boot:
                    self.assertEqual(boot['readyz_status'], 200)
            con = sqlite3.connect(empty)
            self.assertEqual(v.schema_of(con), json.loads(v.SCHEMA.read_text())['tables'])
            con.close()
            db = root / 'fixture.sqlite'
            fixture(db)
            before = db.read_bytes()
            proc = subprocess.run([sys.executable, '-B', str(Path(v.__file__)), str(db), '--start-relay'],
                                  capture_output=True, text=True, timeout=600)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            receipt = json.loads(proc.stdout)
            self.assertEqual(receipt['relay'], {'readyz_status': 200, 'bind': '127.0.0.1'})
            self.assertEqual(db.read_bytes(), before)
            self.assertFalse(Path(str(db) + '-wal').exists())
            self.assertNotIn('private@example.invalid', proc.stdout + proc.stderr)
            print('HEAD schema matches reference; --start-relay fixture /readyz=200; source unchanged; inherited service/proxy config excluded')


if __name__ == '__main__':
    unittest.main()
