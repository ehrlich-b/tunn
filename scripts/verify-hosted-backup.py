#!/usr/bin/env python3
"""Verify a quiescent standalone SQLite backup without exposing customer rows."""
import argparse
from contextlib import closing
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import tempfile


SCHEMA = Path(__file__).with_name('hosted-backup-schema.json')
OK, INTEGRITY, SCHEMA_MISMATCH, WAL, INPUT, RELAY = 0, 2, 3, 4, 5, 6
# Integer timestamps default to Unix seconds. These columns' writers use
# Unix milliseconds; use column metadata rather than guessing from magnitude.
MILLISECOND_COLUMNS = {
    'app_device_invitations': {'expires'},
    'app_device_leases': {'expires'},
    'app_devices': {'expires', 'revoked'},
    'endpoint_policy_buckets': {'expires'},
    'meter_grants': {'expires'},
    'sharing_audit': {'decided_at', 'expires'},
}


class Rejected(Exception):
    def __init__(self, code, reason):
        self.code, self.reason = code, reason


def quote(name):
    return '"' + name.replace('"', '""') + '"'


def schema_of(con):
    """Canonical table definitions and indexes; never return database values."""
    result = {}
    for name, sql in con.execute("SELECT name, sql FROM sqlite_schema WHERE type='table' AND name NOT GLOB 'sqlite_*' ORDER BY name"):
        result[name] = {
            'sql': re.sub(r'\s+', ' ', sql).strip(),
            'indexes': sorted(re.sub(r'\s+', ' ', row[0]).strip() for row in con.execute(
                'SELECT sql FROM sqlite_schema WHERE type=\'index\' AND tbl_name=? AND sql IS NOT NULL', (name,))),
        }
    return result


def triggers_of(con):
    return {name: re.sub(r'\s+', ' ', sql).strip() for name, sql in con.execute(
        "SELECT name, sql FROM sqlite_schema WHERE type='trigger' ORDER BY name")}


def rehearsal():
    spec = importlib.util.spec_from_file_location('restore_rehearsal', Path(__file__).with_name('rehearse-hosted-restore.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def timestamp(value, units_per_second=1):
    # Never echo arbitrary TEXT stored in a time column, or ids disguised as dates.
    try:
        if type(value) is int and 0 <= value < 253402300800 * units_per_second:
            seconds, fraction = divmod(value, units_per_second)
            return (datetime.fromtimestamp(seconds, timezone.utc) + timedelta(
                microseconds=fraction * (1000000 // units_per_second))).isoformat()
        if isinstance(value, str) and re.fullmatch(r'\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d{1,9})?(?:Z|[+-]\d\d:\d\d)?', value):
            date = datetime.fromisoformat(value.replace('Z', '+00:00'))
            return date.replace(tzinfo=date.tzinfo or timezone.utc).astimezone(timezone.utc).isoformat()
    except (ValueError, OverflowError, OSError):
        pass
    return None


def verify(path, start_relay=False):
    path = path.absolute()
    try:
        if not stat.S_ISREG(path.lstat().st_mode):
            raise Rejected(INPUT, 'input must be a regular non-symlink file')
        # A committed snapshot must be self-contained. Do not replay or checkpoint
        # a WAL, nor silently ignore one via immutable=1.
        for suffix in ('-wal', '-journal'):
            sidecar = Path(str(path) + suffix)
            if sidecar.is_symlink() or (sidecar.exists() and sidecar.stat().st_size):
                raise Rejected(WAL, 'uncheckpointed sidecar; obtain a consistent standalone backup')
        with path.open('rb') as source:
            header = source.read(100)
        if len(header) != 100 or header[:16] != b'SQLite format 3\x00':
            raise Rejected(INTEGRITY, 'SQLite integrity check failed')
        expected = json.loads(SCHEMA.read_text())
        # immutable suppresses SQLite's sidecar creation even for a read-only WAL
        # header. This is safe only for the offline, quiescent copy required here.
        with closing(sqlite3.connect(path.as_uri() + '?mode=ro&immutable=1', uri=True)) as con:
            con.execute('PRAGMA query_only=ON')
            if con.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
                raise Rejected(INTEGRITY, 'SQLite integrity check failed')
            if (schema_of(con) != expected['tables'] or triggers_of(con) != expected['triggers'] or
                    con.execute("SELECT 1 FROM sqlite_schema WHERE type='view' LIMIT 1").fetchone()):
                raise Rejected(SCHEMA_MISMATCH, 'database schema differs from the current standalone relay schema')
            con.create_function('utc_timestamp', 2, timestamp)
            tables = {}
            for table, columns in expected['timestamps'].items():
                newest = {}
                for column in columns:
                    units_per_second = 1000 if column in MILLISECOND_COLUMNS.get(table, ()) else 1
                    # Normalize each value before MAX: local times and mixed
                    # SQLite storage classes do not sort by instant. UTC ISO
                    # strings sort chronologically; invalid values become NULL.
                    newest[column] = con.execute(
                        'SELECT MAX(utc_timestamp(' + quote(column) + ', ?)) FROM ' + quote(table),
                        (units_per_second,)).fetchone()[0]
                tables[table] = {'row_count': con.execute('SELECT COUNT(*) FROM ' + quote(table)).fetchone()[0],
                                 'newest_timestamps': newest}
            receipt = {'tables': tables}
            if start_relay:
                r = rehearsal()
                with tempfile.TemporaryDirectory(prefix='tunn-backup-boot-') as temp:
                    root = Path(temp)
                    db = root / 'copy.sqlite'
                    # Use SQLite backup from the verified read-only transaction;
                    # never give the relay write access to the supplied file.
                    with closing(sqlite3.connect(db)) as target:
                        con.backup(target)
                    try:
                        binary = r.build_relay(root)
                        with r.loopback_relay(binary, db, root / 'runtime') as boot:
                            receipt['relay'] = boot
                    except (OSError, ValueError, subprocess.SubprocessError):
                        raise Rejected(RELAY, 'relay build or loopback readiness failed') from None
            return receipt
    except sqlite3.Error:
        raise Rejected(INTEGRITY, 'SQLite integrity check failed') from None
    except OSError:
        raise Rejected(INPUT, 'input or schema file unavailable') from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('file', type=Path)
    parser.add_argument('--start-relay', action='store_true')
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.file, args.start_relay), sort_keys=True))
    except Rejected as exc:
        # Static diagnostics only: SQLite errors and paths can contain secrets.
        parser.exit(exc.code, exc.reason + '\n')


if __name__ == '__main__':
    main()
