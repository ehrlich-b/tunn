#!/usr/bin/env python3
"""Verify staged files and independently reproduce their binaries from a commit."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

ASSETS = ('tunn-linux-amd64', 'tunn-linux-arm64', 'tunn-darwin-amd64', 'tunn-darwin-arm64')
REPO = Path(__file__).resolve().parents[1]

def call(*args, **kwargs):
    return subprocess.check_output(args, text=True, **kwargs).strip()

def check(root, expected):
    manifest = json.loads((root / 'manifest.json').read_text())
    if manifest['source_commit'] != expected or len(expected) != 40:
        raise ValueError('wrong source')
    tag = manifest['tag']
    release = root / 'downloads' / tag
    records = manifest['assets']
    if len(records) != 4 or {r['name'] for r in records} != set(ASSETS):
        raise ValueError('wrong asset inventory')
    feed = root / 'downloads' / 'latest.json'
    data = json.loads(feed.read_text())
    if data['tag_name'] != tag or {a['name'] for a in data['assets']} != set(ASSETS + ('SHA256SUMS', 'checksums.txt')):
        raise ValueError('stale feed')
    sums = ''.join(f"{r['sha256']}  {r['name']}\n" for r in records)
    for name in ('SHA256SUMS', 'checksums.txt'):
        if (release / name).read_text() != sums:
            raise ValueError('checksum alias mismatch')
    with tempfile.TemporaryDirectory() as temp:
        checkout = Path(temp) / 'source'
        call('git', 'clone', '--quiet', '--no-hardlinks', '--no-checkout', str(REPO), str(checkout))
        call('git', 'checkout', '--quiet', '--detach', expected, cwd=checkout)
        for record in records:
            name = record['name']
            artifact = release / name
            digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
            if digest != record['sha256'] or artifact.stat().st_size != record['size']:
                raise ValueError('artifact mismatch: ' + name)
            if feed.stat().st_mtime_ns < artifact.stat().st_mtime_ns:
                raise ValueError('feed predates asset')
            _, system, arch = name.split('-')
            target = Path(temp) / name
            env = dict(os.environ, CGO_ENABLED='0', GOOS=system, GOARCH=arch)
            call('go', 'build', '-p', '2', '-trimpath', '-buildvcs=true', '-ldflags', f'-s -w -X main.version={tag}', '-o', str(target), '.', cwd=checkout, env=env)
            if hashlib.sha256(target.read_bytes()).hexdigest() != digest:
                raise ValueError('binary does not reproduce from source: ' + name)
    for name in ('SHA256SUMS', 'checksums.txt'):
        if feed.stat().st_mtime_ns < (release / name).stat().st_mtime_ns:
            raise ValueError('feed predates checksums')
    print('PASS: staged assets reproduce from', expected)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('source')
    args = parser.parse_args()
    try:
        check(args.root, args.source)
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f'release contract failed: {exc}\n')
