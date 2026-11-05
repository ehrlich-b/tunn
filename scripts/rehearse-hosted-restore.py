#!/usr/bin/env python3
"""Offline synthetic restore rehearsal. Never accepts hosted customer data."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import re
import sqlite3
import struct
import tempfile
import time
import socket
import ssl
import subprocess
import urllib.error
import urllib.request
import zipfile
from contextlib import contextmanager


REPO = Path(__file__).resolve().parents[1]


def build_relay(root):
    """Build committed HEAD, without local edits or installing anything."""
    binary = root / 'tunn'
    archive = root / 'head.zip'
    with archive.open('wb') as output:
        subprocess.run(['git', 'archive', '--format=zip', 'HEAD'], cwd=REPO,
                       check=True, stdout=output, stderr=subprocess.DEVNULL, timeout=30)
    source = root / 'source'
    with zipfile.ZipFile(archive) as snapshot:
        snapshot.extractall(source)
    env = dict(os.environ, GOWORK='off')
    subprocess.run(['go', 'build', '-p', '2', '-o', str(binary), '.'], cwd=source, env=env,
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   timeout=600)
    return binary


@contextmanager
def loopback_relay(binary, database, root):
    """Run an isolated login relay; callers must supply a disposable database.

    No dotenv, inherited provider configuration, discovery, ACME, SMTP or OIDC.
    Output stays private because startup diagnostics can contain database values.
    """
    root.mkdir(mode=0o700)
    cert, key = root / 'cert.pem', root / 'key.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                    '-keyout', str(key), '-out', str(cert), '-days', '1',
                    '-subj', '/CN=localhost'], check=True, timeout=30,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # Reserve different ports until both numbers have been selected.
    with socket.socket() as public, socket.socket() as internal:
        public.bind(('127.0.0.1', 0))
        internal.bind(('127.0.0.1', 0))
        addr = '127.0.0.1:' + str(public.getsockname()[1])
        internal_addr = '127.0.0.1:' + str(internal.getsockname()[1])
    env = {k: v for k, v in os.environ.items() if k in ('PATH', 'SYSTEMROOT', 'TMPDIR')}
    env.update({'TUNN_ENV': 'dev', 'TUNN_DOMAIN': 'localhost',
                'TUNN_LOGIN_NODE': 'true', 'TUNN_DB_PATH': str(database),
                'TUNN_HTTP2_ADDR': addr, 'TUNN_HTTP3_ADDR': addr, 'TUNN_HTTP3': 'off',
                'TUNN_INTERNAL_GRPC_PORT': internal_addr, 'TUNN_PUBLIC_ADDR': addr,
                'TUNN_SERVER_ADDR': addr, 'TUNN_MOCK_OIDC_ADDR': '',
                'TUNN_CERT_FILE': str(cert), 'TUNN_KEY_FILE': str(key)})
    # Ignore proxy variables and redirects, even on a configured operator Mac.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                         urllib.request.HTTPSHandler(context=context))
    process = subprocess.Popen([str(binary), '-mode=host', '-verbosity=none'], cwd=root,
                               env=env, stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise ValueError('relay exited before readiness')
            try:
                with opener.open('https://' + addr + '/readyz', timeout=1) as response:
                    if response.status == 200 and response.read(16) == b'ok':
                        break
            except (OSError, urllib.error.URLError):
                pass
            time.sleep(0.05)
        else:
            raise ValueError('relay readiness timed out')
        yield {'readyz_status': 200, 'bind': '127.0.0.1'}
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


MAX_INPUT_BYTES = 64 * 1024 * 1024
# The generated fixture's empty, 4096-byte SQLite base, independent of its manifest.
FIXTURE_BASE_SHA256 = '352a9bb23c329c5a9bf235baf56917358b5b64b03f1a11d261fadae9c3cdb721'


def read_input(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_INPUT_BYTES:
            raise ValueError('input must be a bounded regular file')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read(MAX_INPUT_BYTES + 1)
        if len(data) > MAX_INPUT_BYTES:
            raise ValueError('input too large')
        return data
    finally:
        os.close(fd)


def digest(path):
    return hashlib.sha256(read_input(path)).hexdigest()


def wal_check(data):
    if len(data) < 32:
        raise ValueError('missing or truncated WAL')
    magic, version, page_size = struct.unpack('>III', data[:12])
    if magic not in (0x377f0682, 0x377f0683) or version != 3007000:
        raise ValueError('invalid WAL header')
    if page_size == 1:
        page_size = 65536
    if page_size < 512 or page_size > 65536 or page_size & (page_size - 1):
        raise ValueError('invalid WAL page size')
    if (len(data) - 32) % (24 + page_size):
        raise ValueError('truncated WAL frame')
    endian = '<' if magic == 0x377f0682 else '>'
    def checksum(buf, s1=0, s2=0):
        words = struct.unpack(endian + str(len(buf) // 4) + 'I', buf)
        for i in range(0, len(words), 2):
            s1 = (s1 + words[i] + s2) & 0xffffffff
            s2 = (s2 + words[i + 1] + s1) & 0xffffffff
        return s1, s2
    s1, s2 = checksum(data[:24])
    if (s1, s2) != struct.unpack('>II', data[24:32]):
        raise ValueError('WAL header checksum mismatch')
    salt = data[16:24]
    committed = False
    for off in range(32, len(data), 24 + page_size):
        frame = data[off:off + 24 + page_size]
        if frame[8:16] != salt or struct.unpack('>I', frame[:4])[0] == 0:
            raise ValueError('WAL frame provenance mismatch')
        s1, s2 = checksum(frame[:8] + frame[24:], s1, s2)
        if (s1, s2) != struct.unpack('>II', frame[16:24]):
            raise ValueError('WAL frame checksum mismatch')
        committed = struct.unpack('>I', frame[4:8])[0] != 0
    if not committed:
        raise ValueError('WAL has no final commit')


def fixture(root):
    root.mkdir(parents=True, exist_ok=True)
    db = root / 'backup.sqlite'
    con = sqlite3.connect(db)
    con.execute('PRAGMA journal_mode=WAL')
    con.execute('PRAGMA wal_autocheckpoint=0')
    con.executescript('''CREATE TABLE accounts(id TEXT PRIMARY KEY, paid INTEGER, suspended INTEGER, revoked INTEGER);
CREATE TABLE reservations(account TEXT, name TEXT);
CREATE TABLE receipts(account TEXT, status TEXT);
CREATE TABLE usage(account TEXT, amount INTEGER);
CREATE TABLE revocations(account TEXT, seq INTEGER);
CREATE TABLE refunds(account TEXT, seq INTEGER);
INSERT INTO accounts VALUES ('synthetic-a',1,0,0),('synthetic-b',0,1,1),('synthetic-c',1,0,0);
INSERT INTO reservations VALUES ('synthetic-a','fixture.tunn');
INSERT INTO receipts VALUES ('synthetic-b','pending');
INSERT INTO usage VALUES ('synthetic-a',42);
INSERT INTO revocations VALUES ('synthetic-b',1);''')
    con.commit()
    # Copy while the writer holds the WAL open, before SQLite checkpoints it.
    shutil.copyfile(db, root / 'snapshot.sqlite')
    shutil.copyfile(str(db) + '-wal', root / 'snapshot.sqlite-wal')
    con.close()
    reconciliation = {'kind':'synthetic', 'backup_sequence':1, 'through_sequence':2,
                      'revocations':[{'account':'synthetic-a','seq':2}],
                      'refunds':[{'account':'synthetic-c','seq':2}]}
    (root / 'reconciliation.json').write_text(json.dumps(reconciliation))
    manifest = {'version':1, 'kind':'synthetic', 'source':'generated-fixture',
                'key_references':['synthetic:key-not-secret'], 'backup_sequence':1,
                'reconciliation_through':2, 'files':{}}
    for name in ('snapshot.sqlite','snapshot.sqlite-wal','reconciliation.json'):
        manifest['files'][name] = digest(root / name)
    (root / 'manifest.json').write_text(json.dumps(manifest, indent=2))
    return root / 'manifest.json'


def restore(manifest_path):
    start = time.monotonic()
    root = manifest_path.parent
    m = json.loads(read_input(manifest_path))
    if type(m.get('version')) is not int or m['version'] != 1 or m.get('kind') != 'synthetic' or m.get('source') != 'generated-fixture':
        raise ValueError('only synthetic generated-fixture manifests are accepted')
    if m.get('key_references') != ['synthetic:key-not-secret']:
        raise ValueError('synthetic key reference required')
    if type(m.get('backup_sequence')) is not int or type(m.get('reconciliation_through')) is not int:
        raise ValueError('manifest sequences must be integers')
    names = ('snapshot.sqlite','snapshot.sqlite-wal','reconciliation.json')
    if set(m.get('files', {})) != set(names):
        raise ValueError('required files missing')
    inputs = {}
    for name in names:
        if not isinstance(m['files'][name], str) or not re.fullmatch(r'[0-9a-f]{64}', m['files'][name]):
            raise ValueError('invalid SHA-256 digest')
        inputs[name] = read_input(root / name)
        if hashlib.sha256(inputs[name]).hexdigest() != m['files'][name]:
            raise ValueError('hash mismatch: ' + name)
    wal_check(inputs[names[1]])
    base = inputs[names[0]]
    wal = inputs[names[1]]
    if hashlib.sha256(base).hexdigest() != FIXTURE_BASE_SHA256:
        raise ValueError('unrecognized synthetic fixture base')
    if len(base) < 100 or base[:16] != b'SQLite format 3\x00':
        raise ValueError('invalid SQLite base')
    base_page = int.from_bytes(base[16:18], 'big') or 65536
    if base_page == 1:
        base_page = 65536
    wal_page = int.from_bytes(wal[8:12], 'big')
    if base_page != wal_page:
        raise ValueError('inconsistent database and WAL page sizes')
    rec = json.loads(inputs[names[2]])
    if (type(rec.get('backup_sequence')) is not int or type(rec.get('through_sequence')) is not int
            or rec.get('kind') != 'synthetic' or rec.get('backup_sequence') != m.get('backup_sequence')
            or rec.get('through_sequence') != m.get('reconciliation_through')
            or not isinstance(rec.get('revocations'), list) or not isinstance(rec.get('refunds'), list)
            or rec['through_sequence'] <= rec['backup_sequence']):
        raise ValueError('missing or stale reconciliation')
    with tempfile.TemporaryDirectory(prefix='tunn-restore-') as temp:
        db = Path(temp) / 'restored.sqlite'
        db.write_bytes(base)
        Path(str(db) + '-wal').write_bytes(wal)
        con = sqlite3.connect(db)
        try:
            if con.execute('PRAGMA integrity_check').fetchone() != ('ok',):
                raise ValueError('SQLite integrity check failed')
            for table in ('accounts','reservations','receipts','usage','revocations'):
                if not con.execute('SELECT 1 FROM ' + table + ' LIMIT 1').fetchone():
                    raise ValueError('required state missing: ' + table)
            # Check the baseline before reconciliation can overwrite a damaged value.
            if (con.execute('SELECT id, paid, suspended, revoked FROM accounts ORDER BY id').fetchall() != [
                    ('synthetic-a', 1, 0, 0), ('synthetic-b', 0, 1, 1), ('synthetic-c', 1, 0, 0)]
                    or con.execute('SELECT account, seq FROM revocations ORDER BY account, seq').fetchall() != [
                        ('synthetic-b', 1)]):
                raise ValueError('synthetic baseline state verification failed')
            if not rec['revocations'] or not rec['refunds']:
                raise ValueError('required post-backup events missing')
            for kind in ('revocations', 'refunds'):
                for item in rec[kind]:
                    if not (type(item.get('seq')) is int and rec['backup_sequence'] < item['seq'] <= rec['through_sequence']):
                        raise ValueError('invalid reconciliation sequence')
                    field = 'revoked' if kind == 'revocations' else 'paid'
                    value = 1 if kind == 'revocations' else 0
                    if con.execute('UPDATE accounts SET ' + field + '=? WHERE id=?', (value, item.get('account'))).rowcount != 1:
                        raise ValueError('unknown reconciliation account')
                    con.execute('INSERT INTO ' + kind + ' VALUES (?,?)', (item['account'], item['seq']))
            con.commit()
            if (con.execute('SELECT id, paid, suspended, revoked FROM accounts ORDER BY id').fetchall() != [
                    ('synthetic-a', 1, 0, 1), ('synthetic-b', 0, 1, 1), ('synthetic-c', 0, 0, 0)]
                    or con.execute('SELECT account, seq FROM revocations ORDER BY account, seq').fetchall() != [
                        ('synthetic-a', 2), ('synthetic-b', 1)]):
                raise ValueError('synthetic reconciled state verification failed')
            checks = [
                ("SELECT revoked FROM accounts WHERE id='synthetic-a'", (1,)),
                ("SELECT paid FROM accounts WHERE id='synthetic-c'", (0,)),
                ("SELECT suspended FROM accounts WHERE id='synthetic-b'", (1,)),
                ("SELECT status FROM receipts WHERE account='synthetic-b'", ('pending',)),
                ("SELECT amount FROM usage WHERE account='synthetic-a'", (42,)),
                ("SELECT name FROM reservations WHERE account='synthetic-a'", ('fixture.tunn',)),
                ("SELECT seq FROM revocations WHERE account='synthetic-a'", (2,)),
                ("SELECT seq FROM refunds WHERE account='synthetic-c'", (2,)),
            ]
            for query, expected in checks:
                if con.execute(query).fetchone() != expected:
                    raise ValueError('synthetic state verification failed')

        finally:
            con.close()
    return {'result':'synthetic-pass', 'elapsed_seconds':round(time.monotonic()-start, 6),
            'hosted_rpo_rto':'unresolved', 'live_t07':'BLOCKED'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--no-network', action='store_true', required=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--synthetic', action='store_true')
    group.add_argument('--manifest', type=Path)
    args = parser.parse_args()
    try:
        if args.synthetic:
            with tempfile.TemporaryDirectory(prefix='tunn-fixture-') as temp:
                result = restore(fixture(Path(temp)))
        else:
            result = restore(args.manifest)
        print(json.dumps(result, sort_keys=True))
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error, AssertionError) as exc:
        parser.exit(1, 'rehearsal rejected: ' + str(exc) + '\n')

if __name__ == '__main__':
    main()
