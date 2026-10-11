#!/usr/bin/env python3
"""Finite rehearsal. Default is offline and does not bind any socket."""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

from external_operator import external_reads, validate_external
from oracle import reconcile
from overlay import write_overlay

REPO = Path(__file__).resolve().parents[2]
BASE = '642c06e7d4c28213fcb9a5a9850a6abfd111ab0b'

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def git(*args):
    return subprocess.check_output(['git', *args], cwd=REPO, text=True).strip()

def sanitize(text):
    text = re.sub(r'tunn_(?:mcp|ep)_[A-Za-z0-9_-]+', '[REDACTED-TOKEN]', text)
    text = re.sub(r'Bearer\s+[^\s"<>]+', 'Bearer [REDACTED]', text)
    text = re.sub(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', '[REDACTED-JWT]', text)
    return text.replace('PRIVATE-PROMPT-SENTINEL-DO-NOT-LOG', '[REDACTED-PROMPT]')

def environment(work):
    scratch = REPO / '.scratch'
    toolchain = scratch / 'toolchain/go'
    if not (toolchain / 'bin/go').is_file() or not (scratch / 'cache/mod').is_dir():
        raise ValueError('REQUIRED-UNRUN: clone-local offline Go staging is missing')
    env = {key: os.environ[key] for key in ('PATH', 'HOME', 'USER', 'LANG', 'LC_ALL') if key in os.environ}
    env.update({'GOROOT': str(toolchain), 'PATH': str(toolchain / 'bin') + ':' + env.get('PATH', ''),
        'GOTOOLCHAIN': 'local', 'GOPROXY': 'off', 'GOSUMDB': 'off', 'GOTELEMETRY': 'off',
        'GOFLAGS': '-p=2', 'GOMAXPROCS': '2', 'GOCACHE': str(scratch / 'cache/build'),
        'GOMODCACHE': str(scratch / 'cache/mod'), 'GOPATH': str(work / 'gopath'),
        'GOTMPDIR': str(work / 'tmp'), 'TMPDIR': str(work / 'tmp'),
        'npm_config_cache': str(work / 'cache/npm'), 'npm_config_offline': 'true',
        'PYTHONDONTWRITEBYTECODE': '1'})
    for name in ('gopath', 'tmp', 'cache/npm'):
        (work / name).mkdir(parents=True, exist_ok=True)
    return env

def run_gate(name, args, work, env, timeout=600, json_tests=False):
    prefix = ['taskpolicy', '-b', 'nice', '-n', '15'] if sys.platform == 'darwin' else ['nice', '-n', '15']
    start = time.monotonic()
    try:
        result = subprocess.run(prefix + args, cwd=REPO, env=env, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
        output, status = result.stdout, result.returncode
    except subprocess.TimeoutExpired:
        output, status = 'REQUIRED-UNRUN: bounded gate timeout; do not restart an existing job\n', -1
    log = work / (name + '.log')
    log.write_text(sanitize(output))
    missing = status == -1 or 'module lookup disabled by GOPROXY=off' in output or 'go: downloading' in output
    tests = []
    if json_tests:
        for line in output.splitlines():
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if event.get('Action') == 'pass' and event.get('Test'):
                tests.append(event['Test'])
        if not tests and status == 0:
            status = 1
            output += '\nFAIL: zero tests is not a passing gate\n'
            log.write_text(sanitize(output))
    state = 'REQUIRED-UNRUN' if missing else ('PASS' if status == 0 else 'FAIL')
    return {'state': state, 'command': args, 'exitCode': status, 'passedTests': len(tests),
            'tests': tests, 'seconds': round(time.monotonic()-start, 3),
            'log': log.relative_to(REPO).as_posix(), 'logSHA256': digest(log)}

def identities(work, env):
    paths = sorted(p for p in (REPO / 'examples/mcp-project-reader').rglob('*') if p.is_file())
    paths += sorted(p for p in (REPO / 'scripts/mcp-workflow').rglob('*') if p.is_file() and '__pycache__' not in p.parts)
    source = {p.relative_to(REPO).as_posix(): digest(p) for p in paths}
    source['Makefile'] = digest(REPO / 'Makefile')
    canonical = json.dumps(source, sort_keys=True, separators=(',', ':')).encode()
    return {'baseSHA': BASE, 'headSHA': git('rev-parse', 'HEAD'), 'freshUpstream': None,
            'sourceFiles': source, 'sourceManifestSHA256': hashlib.sha256(canonical).hexdigest(),
            'goVersion': subprocess.check_output(['go', 'version'], env=env, text=True).strip(),
            'moduleSHA256': digest(REPO / 'go.mod'), 'sumSHA256': digest(REPO / 'go.sum'),
            'client': {'name': 'independent-Go-JSON-RPC-consumer', 'version': '1',
                       'sourceSHA256': digest(REPO / 'scripts/mcp-workflow/client/client.go')}}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=('in-memory', 'external-host'), default='in-memory')
    parser.add_argument('--scratch', help='new empty directory under this clone .scratch')
    parser.add_argument('--endpoint')
    parser.add_argument('--token-file')
    parser.add_argument('--allow-external', action='store_true')
    parser.add_argument('--fixture', choices=('harbor/day1', 'harbor/day2', 'ridge'), default='harbor/day1')
    options = parser.parse_args()
    # Refuse live options before opening token files, creating receipts or making calls.
    validate_external(options.mode, options.endpoint, options.token_file, options.allow_external)
    work = Path(options.scratch) if options.scratch else REPO / '.scratch' / ('mcp-rehearsal-' + time.strftime('%Y%m%d-%H%M%S'))
    work = work.resolve()
    if not work.is_relative_to((REPO / '.scratch').resolve()) or work == (REPO / '.scratch').resolve():
        raise ValueError('receipt root must be private scratch beneath this clone')
    if work.exists() and any(work.iterdir()):
        raise ValueError('receipt root must be new/empty; prior receipts are immutable')
    work.mkdir(parents=True, exist_ok=True)
    env = environment(work)
    receipt = {'schema': 1, 'mode': options.mode, 'scope': 'fixture-only',
        'identities': identities(work, env), 'gates': {}, 'outsideAcceptance': {
            'loopbackBuiltServer': {'state': 'REQUIRED-UNRUN', 'reason': 'worker forbids socket binds and native-server acceptance'},
            'hostedClientSetup': {'state': 'REQUIRED-UNRUN', 'reason': 'staged docs do not identify an already-selected hosted client/version'},
            'hostedFirstTaskConsentRevocation': {'state': 'REQUIRED-UNRUN', 'reason': 'requires Bryan with selected hosted client and candidate'},
            'nextDayRepeat': {'state': 'REQUIRED-UNRUN', 'reason': 'changed-fixture software result does not prove next-day hosted use'},
        }}
    if options.mode == 'external-host':
        output = external_reads(options.endpoint, options.token_file)
        oracle = reconcile(output, REPO / 'examples/mcp-project-reader/fixtures' / options.fixture, options.fixture)
        # Only exact verified supplied-fixture text is retained, never arbitrary remote source.
        (work / 'operator-output.json').write_text(json.dumps(output, indent=2) + '\n')
        receipt['gates']['operatorFixtureOracle'] = oracle
    else:
        overlay = write_overlay(REPO, work / 'overlay.json')
        commands = [
            ('reader', ['go', 'test', '-p', '2', '-json', '-race', '-count=1', '-timeout=60s', './examples/mcp-project-reader/...'], True),
            ('client', ['go', 'test', '-p', '2', '-json', '-race', '-count=1', '-timeout=30s', './scripts/mcp-workflow/client'], True),
            ('python', [sys.executable, '-m', 'unittest', 'discover', '-s', 'scripts/mcp-workflow', '-p', 'test_*.py', '-v'], False),
            ('transport', ['go', 'test', '-p', '2', '-overlay', str(overlay), '-json', '-race', '-count=1', '-timeout=60s', '-run', '^TestWave8Reader', './internal/host'], True),
            ('reader-binary', ['make', '-j1', 'build-mcp-project-reader', 'MCP_READER_BINARY=' + str(work / 'mcp-project-reader')], False),
            ('client-binary', ['go', 'test', '-c', '-o', str(work / 'client.test'), './scripts/mcp-workflow/client'], False),
            ('sdk-unit', ['make', '-j1', 'test-sdk-unit'], False),
            ('vet', ['make', '-j1', 'vet'], False),
            ('command-compatibility', ['go', 'test', '-p', '2', '-json', '-count=1', '-timeout=30s', '-overlay', str(overlay), '-run', '^Test(MCPCommandShorthand|Wave8ReaderCommand)$', '.'], True),
        ]
        env['WAVE8_READER_OUTPUT'] = str(work / 'tunneled-harbor-day1.json')
        for name, args, is_json in commands:
            gate_env = dict(env)
            if name == 'reader':
                args = ['go', 'test', '-p', '2', './examples/mcp-project-reader/...']
                gate_env['GOFLAGS'] = '-p=2 -json -race -count=1 -timeout=60s'
            if name == 'sdk-unit':
                gate_env['GOFLAGS'] = '-p=2 -v'
            gate = run_gate(name, args, work, gate_env, json_tests=is_json)
            if name == 'sdk-unit':
                log_text = (work / (name + '.log')).read_text()
                gate['tests'] = re.findall(r'^\s*--- PASS: (\S+)', log_text, re.MULTILINE)
                gate['passedTests'] = len(gate['tests'])
                if not gate['tests'] and gate['state'] == 'PASS':
                    gate['state'] = 'FAIL'
            if name == 'python':
                log_text = (work / (name + '.log')).read_text()
                match = re.search(r'Ran (\d+) tests?', log_text)
                gate['passedTests'] = int(match.group(1)) if match else 0
                if not gate['passedTests'] and gate['state'] == 'PASS':
                    gate['state'] = 'FAIL'
            receipt['gates'][name] = gate
        # Distinct source snapshots add evidence; none is claimed as actual next-day use.
        for fixture in ('harbor/day1', 'harbor/day2', 'ridge'):
            filename = 'tunneled-' + fixture.replace('/', '-') + '.json'
            if fixture != 'harbor/day1':
                env['WAVE8_READER_FIXTURE'] = fixture
                env['WAVE8_READER_OUTPUT'] = str(work / filename)
                args = ['go', 'test', '-p', '2', '-overlay', str(overlay), '-json', '-race', '-count=1', '-timeout=30s', '-run', '^TestWave8ReaderReceipt$', './internal/host']
                receipt['gates']['transport-' + fixture.replace('/', '-')] = run_gate('transport-' + fixture.replace('/', '-'), args, work, env, json_tests=True)
            evidence = work / filename
            try:
                output = json.loads(evidence.read_text())
                oracle = reconcile(output, REPO / 'examples/mcp-project-reader/fixtures' / fixture, fixture)
                oracle['outputSHA256'] = digest(evidence)
                receipt['gates']['oracle-' + fixture.replace('/', '-')] = oracle
            except (OSError, ValueError, KeyError):
                receipt['gates']['oracle-' + fixture.replace('/', '-')] = {'state': 'FAIL' if evidence.exists() else 'REQUIRED-UNRUN', 'reason': 'missing or inconsistent tool-returned evidence'}
        for label, path in [('server', work / 'mcp-project-reader'), ('client', work / 'client.test')]:
            receipt['identities'][label + 'Binary'] = {'state': 'PASS', 'sha256': digest(path), 'executed': False} if path.is_file() else {'state': 'REQUIRED-UNRUN'}
        receipt['gates']['source-diff'] = run_gate('source-diff', ['git', 'diff', '--check'], work, env)
    receipt['candidateAcceptance'] = 'externally pending'
    receipt['outcome'] = 'complete-local' if all(g['state'] == 'PASS' for g in receipt['gates'].values()) else 'partial'
    destination = work / 'receipt.json'
    destination.write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
    os.chmod(destination, 0o600)
    print(json.dumps({'outcome': receipt['outcome'], 'candidateAcceptance': receipt['candidateAcceptance'],
                      'receipt': str(destination), 'sha256': digest(destination)}, sort_keys=True))
    return 0 if receipt['outcome'] == 'complete-local' else 1

if __name__ == '__main__':
    try:
        sys.exit(main())
    except ValueError as error:
        # Local validation messages only; remote error bodies are never printed.
        print('mcp-workflow: ' + str(error), file=sys.stderr)
        sys.exit(2)
