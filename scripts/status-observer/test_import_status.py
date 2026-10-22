"""Synthetic offline inputs; no real service history or network access."""
import json
from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import unittest

from import_status import import_status
from observer import parse_stamp

FIXTURE = Path(__file__).parent / 'testdata/synthetic/raw/2026-10-01.jsonl'
NOW = parse_stamp('2026-10-01T12:02:10Z')


class ImportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'raw').mkdir()
        self.source = self.root / 'raw/2026-10-01.jsonl'
        self.original = FIXTURE.read_bytes()
        self.source.write_bytes(self.original)
        self.db = self.root / 'disposable.db'

    def run_import(self, now=NOW):
        return import_status(self.root, self.db, 'https://tunn.to', now, True)

    def test_exact_originals_scope_and_gaps(self):
        report = self.run_import()
        self.assertTrue(report['synthetic'])
        self.assertEqual(report['status_minutes'], 2)
        self.assertEqual(report['endpoint_records'], {path: 2 for path in ('/healthz', '/readyz', '/', '/dl/latest.json')})
        self.assertEqual(self.source.read_bytes(), self.original)
        with closing(sqlite3.connect(self.db)) as db:
            self.assertEqual(b''.join(row[0] for row in db.execute('SELECT raw FROM observer_records ORDER BY source,line')), self.original)
            self.assertEqual(db.execute('SELECT DISTINCT timestamp FROM observer_records ORDER BY timestamp').fetchall(), [('2026-10-01T12:00:05.123456Z',), ('2026-10-01T12:02:05.123456Z',)])
            self.assertEqual(db.execute('SELECT health,ready FROM status_samples ORDER BY minute').fetchall(), [(1, 1), (1, 1)])
        with self.assertRaises(FileExistsError):
            self.run_import()
        print('SYNTHETIC: exact timestamps, originals, four endpoint scopes, two observed minutes with a gap; overwrite refused')

    def test_duplicates_worst_and_order_independent(self):
        failed = json.loads(self.original.splitlines()[0])
        failed.update(ok=False, status=503, error='http_error')
        extra = (json.dumps(failed) + '\n').encode()
        for index, content in enumerate((self.original + extra, extra + self.original)):
            self.source.write_bytes(content)
            self.db = self.root / f'duplicates-{index}.db'
            self.assertEqual(self.run_import()['status_minutes'], 2)
            with closing(sqlite3.connect(self.db)) as db:
                self.assertEqual(db.execute('SELECT health,ready FROM status_samples ORDER BY minute').fetchall(), [(0, 1), (1, 1)])
        print('SYNTHETIC: duplicate failures win in either input order')

    def test_incomplete_collection_unknown(self):
        self.source.write_bytes(b''.join(self.original.splitlines(keepends=True)[1:]))
        self.assertEqual(self.run_import()['status_minutes'], 1)
        print('SYNTHETIC: unpaired health/readiness minute excluded')

    def test_corrupt_tail_future_mixed_origin_and_invalid(self):
        for name, content in [('tail', self.original + b'{'), ('unterminated', self.original.rstrip(b'\n')),
                              ('future', self.original.replace(b'2026-10-01', b'2026-10-02')),
                              ('origin', self.original.replace(b'https://tunn.to', b'https://other.example')),
                              ('inconsistent', self.original.replace(b'"ok": true', b'"ok": false'))]:
            with self.subTest(name=name):
                self.source.write_bytes(content)
                self.db = self.root / f'{name}.db'
                with self.assertRaises(ValueError):
                    self.run_import()
                self.assertFalse(self.db.exists())
                self.assertEqual(self.source.read_bytes(), content)
        print('SYNTHETIC: corrupt tail, future, foreign origin and inconsistent records fail before database creation')

    def test_empty_input_unknown(self):
        self.source.write_bytes(b'')
        self.assertEqual(self.run_import()['status_minutes'], 0)
        with closing(sqlite3.connect(self.db)) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM status_samples').fetchone()[0], 0)
        print('SYNTHETIC: empty input stays unknown')

    def test_old_history_not_backfilled(self):
        self.assertEqual(self.run_import(parse_stamp('2027-02-01T00:00:00Z'))['status_minutes'], 0)
        with closing(sqlite3.connect(self.db)) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM observer_records').fetchone()[0], 8)
        print('SYNTHETIC: records outside retention archived without manufacturing history')


if __name__ == '__main__':
    unittest.main()
