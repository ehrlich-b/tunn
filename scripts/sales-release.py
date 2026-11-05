#!/usr/bin/env python3
"""Prepare and verify a local sales-release manifest; never publish assets."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess

REPO = Path(__file__).resolve().parents[1]


def git(*args):
    return subprocess.check_output(['git', *args], cwd=REPO, text=True).strip()


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def record(path):
    path = Path(path).resolve(strict=True)
    if not path.is_file():
        raise ValueError('expected a regular local file')
    return {'path': str(path), 'sha256': digest(path)}


def verify_file(item):
    if record(item['path']) != item:
        raise ValueError('local input changed')


def templates():
    # Bind path names as well as bytes, in stable order.
    h = hashlib.sha256()
    for name in sorted(git('ls-files', 'internal/host/templates').splitlines()):
        h.update(name.encode() + b'\0' + (REPO / name).read_bytes() + b'\0')
    return h.hexdigest()


def source_check(source, main_ref):
    if not re.fullmatch('[0-9a-f]{40}', source):
        raise ValueError('full source SHA required')
    if git('rev-parse', 'HEAD') != source or git('status', '--porcelain'):
        raise ValueError('requires clean selected source HEAD')
    subprocess.run(['git', 'merge-base', '--is-ancestor', source, main_ref], cwd=REPO, check=True)


def validate(m):
    if m['version'] != 1:
        raise ValueError('unsupported manifest')
    source_check(m['relay_sha'], m['main_ref'])
    if templates() != m['template_sha256']:
        raise ValueError('template digest changed')
    prior = m['previous']
    if not re.fullmatch(r'[A-Za-z0-9./:_-]+@sha256:[0-9a-f]{64}', prior['image']):
        raise ValueError('immutable previous image required')
    verify_file(prior['feed'])
    if json.loads(Path(prior['feed']['path']).read_text())['tag_name'] != prior['tag']:
        raise ValueError('previous feed tag changed')
    if not m['configuration_names'] or any(not re.fullmatch(r'TUNN_[A-Z0-9_]+', n) for n in m['configuration_names']):
        raise ValueError('configuration names only; no values')
    if not m['receipts']:
        raise ValueError('fragment receipts required')
    for item in m['receipts']:
        verify_file(item)
        r = json.loads(Path(item['path']).read_text())
        if r['source'] != m['relay_sha'] or r['exit_code'] != 0 or r['selected_tests'] <= 0 or not r['command']:
            raise ValueError('failed, empty or wrong-source fragment receipt')
    if m['client'] is not None:
        c = m['client']
        for item in c['files']:
            verify_file(item)
        stage = Path(c['stage'])
        metadata = json.loads((stage / 'manifest.json').read_text())
        if metadata['source_commit'] != m['relay_sha'] or metadata['tag'] != c['tag']:
            raise ValueError('wrong client source/tag')
        for asset in metadata['assets']:
            path = stage / 'downloads' / c['tag'] / asset['name']
            if asset['name'] not in ('tunn-linux-amd64', 'tunn-linux-arm64', 'tunn-darwin-amd64', 'tunn-darwin-arm64'):
                raise ValueError('invalid staged asset name')
            if digest(path) != asset['sha256'] or path.stat().st_size != asset['size']:
                raise ValueError('stage metadata disagrees with asset')
        if len(metadata['assets']) != 4:
            raise ValueError('incomplete client inventory')
        # Reuse the mirror inventory/checksum validator; no rebuild or provider call.
        subprocess.run(['go', 'run', '-p', '2', './cmd/check-downloads', str(stage / 'downloads')], cwd=REPO, check=True)


def generate(args):
    source_check(args.source, args.main_ref)
    client = None
    if args.client_stage:
        stage = args.client_stage.resolve(strict=True)
        metadata = json.loads((stage / 'manifest.json').read_text())
        files = [stage / 'manifest.json', stage / 'downloads/latest.json']
        files += [stage / 'downloads' / metadata['tag'] / n for n in
                  ('tunn-linux-amd64', 'tunn-linux-arm64', 'tunn-darwin-amd64', 'tunn-darwin-arm64', 'SHA256SUMS', 'checksums.txt')]
        client = {'stage': str(stage), 'tag': metadata['tag'], 'files': [record(p) for p in files]}
    m = {'version': 1, 'relay_sha': args.source, 'main_ref': args.main_ref,
         'template_sha256': templates(), 'configuration_names': args.config_name,
         'previous': {'image': args.previous_image, 'tag': args.previous_tag, 'feed': record(args.previous_feed)},
         'receipts': [record(p) for p in args.receipt], 'client': client}
    validate(m)
    with args.output.open('x') as f:
        json.dump(m, f, indent=2)
        f.write('\n')


def operate(args):
    manifest = args.manifest.resolve(strict=True)
    m = json.loads(manifest.read_text())
    validate(m)
    script = args.round_script.resolve(strict=True)
    if not script.is_file() or not os.access(script, os.X_OK):
        raise ValueError('explicit executable round script required')
    commands = [[str(script), '--check', '--manifest', str(manifest)],
                [str(script), '--apply', '--manifest', str(manifest)]]
    print('1. PASS clean landed source, templates, receipts, previous image/feed and optional client files', flush=True)
    for i, cmd in enumerate(commands, 2):
        print(f'{i}. {shlex.join(cmd)}', flush=True)
    print('Rollback (operator only): ' + shlex.join([str(script), '--rollback', '--manifest', str(manifest)]), flush=True)
    if not args.operator_apply:
        print('DRY RUN: zero round-script calls; hosted state unverified')
        return
    # stdout is a metadata-only JSON contract; never echo arbitrary script output.
    checked = subprocess.run(commands[0], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    prior = json.loads(checked.stdout)
    expected = {'previous_image': m['previous']['image'], 'previous_feed_sha256': m['previous']['feed']['sha256']}
    if prior != expected:
        raise ValueError('round check prior image/feed mismatch')
    validate(m)  # Revalidate local inputs after the external check.
    subprocess.run(commands[1], check=True)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='mode', required=True)
    g = sub.add_parser('generate')
    g.add_argument('--source', required=True)
    g.add_argument('--main-ref', default='refs/remotes/origin/main')
    g.add_argument('--previous-image', required=True)
    g.add_argument('--previous-tag', required=True)
    g.add_argument('--previous-feed', required=True, type=Path)
    g.add_argument('--config-name', action='append', required=True)
    g.add_argument('--receipt', action='append', required=True, type=Path)
    g.add_argument('--client-stage', type=Path)
    g.add_argument('--output', required=True, type=Path)
    o = sub.add_parser('operate')
    o.add_argument('--round-script', required=True, type=Path)
    o.add_argument('--manifest', required=True, type=Path)
    o.add_argument('--operator-apply', action='store_true')
    args = p.parse_args()
    try:
        (generate if args.mode == 'generate' else operate)(args)
    except subprocess.CalledProcessError as e:
        p.exit(e.returncode or 1, 'Sales release refused: command failed\n')
    except (ValueError, OSError, KeyError, TypeError) as e:
        p.exit(1, 'Sales release refused: invalid or unavailable local inputs\n')


if __name__ == '__main__':
    main()
