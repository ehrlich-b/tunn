#!/usr/bin/env python3
"""Import a locked observer snapshot into a NEW disposable public status database."""

import argparse
from collections import defaultdict
from contextlib import closing, nullcontext
from datetime import datetime
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import sqlite3

from observer import PATHS, UTC, base_url, parse_stamp, stamp


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def import_status(directory, destination, origin, now, synthetic=False):
    origin = base_url(origin)
    records, sources = [], []
    # The observer holds this same lock across all four appends. Never create or
    # alter anything in the source directory, including the lock file.
    lock_path = directory / '.observer.lock'
    with lock_path.open('rb') if lock_path.exists() else nullcontext() as lock:
        if lock is not None:
            fcntl.flock(lock, fcntl.LOCK_EX)
        for path in sorted((directory / 'raw').glob('*.jsonl')):
            data = path.read_bytes()
            sources.append({'file': path.name, 'sha256': hashlib.sha256(data).hexdigest()})
            for number, line in enumerate(data.splitlines(keepends=True), 1):
                try:
                    row = json.loads(line, object_pairs_hook=unique)
                    checked = parse_stamp(row['timestamp'])
                    status = row['status']
                    if (type(row['version']) is not int or row['version'] != 1
                            or row['origin'] != origin or row['method'] != 'GET'
                            or row['path'] not in PATHS or type(row['ok']) is not bool
                            or not (status is None or type(status) is int and 100 <= status <= 599)
                            or row['ok'] != (status == 200)
                            or type(row['latency_ms']) not in (int, float)
                            or not math.isfinite(row['latency_ms']) or row['latency_ms'] < 0
                            or checked > now or checked.year < 1970
                            or not line.endswith(b'\n')):
                        raise ValueError('invalid or future observation')
                except (KeyError, ValueError, TypeError, OverflowError, AttributeError) as exc:
                    raise ValueError(f'{path.name}:{number}: invalid observation; no database written') from exc
                records.append((checked, row, path.name, number, line))
    # Validate ALL inputs before creating any output. An existing destination,
    # including a symlink or hard link to an original, is never opened for write.
    fd = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(fd)
    slots = defaultdict(list)
    counts = {path: 0 for path in PATHS}
    for checked, row, *_ in records:
        counts[row['path']] += 1
        if row['path'] in ('/healthz', '/readyz'):
            slots[int(checked.timestamp()) // 60].append((checked, row))
    samples = []
    for minute, bucket in sorted(slots.items()):
        # Each collection has one timestamp. An incomplete collection makes the
        # whole minute unknown, even if another duplicate collection is complete.
        groups = defaultdict(set)
        for checked, row in bucket:
            groups[checked].add(row['path'])
        if any(paths != {'/healthz', '/readyz'} for paths in groups.values()):
            continue
        latest = max(checked for checked, _ in bucket)
        if (now - latest).total_seconds() > 90 * 86400:
            continue
        samples.append((minute, int(latest.timestamp()),
                        all(row['ok'] for _, row in bucket if row['path'] == '/healthz'),
                        all(row['ok'] for _, row in bucket if row['path'] == '/readyz')))
    with closing(sqlite3.connect(destination)) as db, db:
        db.executescript('''
CREATE TABLE status_meta (id INTEGER PRIMARY KEY CHECK(id=1), origin TEXT NOT NULL);
CREATE TABLE status_samples (minute INTEGER PRIMARY KEY, checked INTEGER NOT NULL, health INTEGER NOT NULL CHECK(health IN (0,1)), ready INTEGER NOT NULL CHECK(ready IN (0,1)));
CREATE TABLE status_incidents (id INTEGER PRIMARY KEY AUTOINCREMENT, started INTEGER NOT NULL, resolved INTEGER, title TEXT NOT NULL, note TEXT NOT NULL);
CREATE TABLE observer_records (source TEXT NOT NULL, line INTEGER NOT NULL, timestamp TEXT NOT NULL, origin TEXT NOT NULL, path TEXT NOT NULL, raw BLOB NOT NULL, PRIMARY KEY(source,line));
CREATE TABLE observer_sources (source TEXT PRIMARY KEY, sha256 TEXT NOT NULL);
''')
        db.execute('INSERT INTO status_meta VALUES(1,?)', (origin,))
        db.executemany('INSERT INTO observer_records VALUES(?,?,?,?,?,?)',
                       [(source, number, row['timestamp'], row['origin'], row['path'], line)
                        for _, row, source, number, line in records])
        db.executemany('INSERT INTO observer_sources VALUES(?,?)',
                       [(source['file'], source['sha256']) for source in sources])
        db.executemany('INSERT INTO status_samples VALUES(?,?,?,?)', samples)
        if synthetic:
            db.execute('INSERT INTO status_incidents(started,title,note) VALUES(?,?,?)',
                       (int(now.timestamp()), 'Synthetic fixture', 'Local test observations; not service availability evidence.'))
    return {'synthetic': synthetic, 'imported_at': stamp(now), 'origin': origin,
            'sources': sources, 'endpoint_records': counts, 'status_minutes': len(samples),
            'status_scope': ['/healthz', '/readyz'], 'other_scope': ['/', '/dl/latest.json'],
            'note': 'Only checked minutes; gaps remain unknown. No elapsed observation clock is changed.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data-dir', type=Path, required=True)
    parser.add_argument('--db', type=Path, required=True)
    parser.add_argument('--origin', default='https://tunn.to')
    parser.add_argument('--synthetic', action='store_true')
    parser.add_argument('--now', help='fixture clock, requires --synthetic')
    args = parser.parse_args()
    if args.now and not args.synthetic:
        parser.error('--now requires --synthetic')
    try:
        now = parse_stamp(args.now) if args.now else datetime.now(UTC)
        result = import_status(args.data_dir, args.db, args.origin, now, args.synthetic)
    except (ValueError, OSError, sqlite3.Error) as exc:
        parser.exit(1, str(exc) + '\n')
    print(json.dumps(result, sort_keys=True, indent=2, allow_nan=False))


if __name__ == '__main__':
    main()
