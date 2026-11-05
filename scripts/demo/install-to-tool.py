#!/usr/bin/env python3
"""Measure a staged local release from installation to an OAuth MCP call."""
import argparse
import functools
import http.server
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('demo', ROOT / 'scripts/demo/mcp-first-call.py')
demo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(demo)
fixture = demo.fixture
LABEL = 'local fixture; Claude.ai, phone apps and ChatGPT not run'


def command(args, **kwargs):
    return subprocess.run(args, check=True, timeout=90, **kwargs)


def measure(kind, work, downloads, control):
    home = work / 'home'
    home.mkdir()
    run = fixture.Lifecycle(work)
    run.env.update(HOME=str(home), TUNN_CONFIG_DIR=str(home / '.tunn'),
                   TUNN_SERVER_ADDR=f'{fixture.DOMAIN}:{run.port}', SSL_CERT_FILE=str(fixture.ROOT / 'certs/cert.pem'),
                   CURL_CA_BUNDLE=str(fixture.ROOT / 'certs/cert.pem'), NO_PROXY='*',
                   PLAYWRIGHT_BROWSERS_PATH='/work/cache/ms-playwright')
    opener = work / 'xdg-open'
    opener.write_text('#!/bin/sh\nexit 0\n')
    opener.chmod(0o755)
    run.env['PATH'] = str(home / '.local/bin') + os.pathsep + str(work) + os.pathsep + os.environ['PATH']
    run.start_relay()
    try:
        start = time.monotonic()
        env = dict(run.env, TUNN_DOWNLOAD_BASE=downloads if control != 'install' else downloads + '/missing')
        command(['sh', str(ROOT / 'install.sh')], env=env, stdout=subprocess.DEVNULL)
        install = time.monotonic() - start
        executable = home / '.local/bin/tunn'
        if control == 'path':
            wrong = work / 'wrong'
            wrong.mkdir()
            (wrong / 'tunn').write_text('#!/bin/sh\nexit 1\n')
            (wrong / 'tunn').chmod(0o755)
            run.env['PATH'] = str(wrong) + os.pathsep + run.env['PATH']
        resolved = Path(__import__('shutil').which('tunn', path=run.env['PATH'])).resolve()
        if resolved != executable.resolve():
            raise RuntimeError('wrong tunn executable on PATH')
        # Lifecycle's process and log management, using the installed binary.
        def start_cli(name, args):
            log = work / (name + '.log')
            run.logs[name] = log
            with log.open('ab') as out:
                proc = subprocess.Popen(['tunn', *args], cwd=work, env=run.env, stdout=out, stderr=subprocess.STDOUT, start_new_session=True)
            run.processes.append(proc)
            return proc
        mark = time.monotonic()
        login = start_cli('login', ['--dev', 'login'])
        run.wait('login URL', lambda: bool(re.search(r'https://\S+\?\S+', run.logs['login'].read_text())), login)
        url = re.search(r'https://\S+\?\S+', run.logs['login'].read_text()).group()
        command(['node', str(ROOT / 'scripts/demo/browser.cjs'), 'login', url, str(work / 'state.json')], env=run.env)
        if login.wait(timeout=30): raise RuntimeError('login failed')
        login_seconds = time.monotonic() - mark
        if kind == 'http':
            port = fixture.free_port()
            server = subprocess.Popen([str(fixture.ROOT / 'bin/mcp-echo-http'), '-addr', f'127.0.0.1:{port}'], env=run.env, start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            run.processes.append(server)
            def listening():
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.2): return True
                except OSError: return False
            run.wait('HTTP server', listening, server)
            args = ['mcp', '--name', 'tools', f'http://127.0.0.1:{port}/mcp']
        else:
            args = ['mcp', '--tools', 'echo', '--', 'python3', str(ROOT / 'examples/mcp/echo.py')]
        mark = time.monotonic()
        publisher = start_cli('publisher', args)
        run.wait('Connector URL', lambda: 'Connector URL:' in run.logs['publisher'].read_text(), publisher, timeout=30)
        publish = time.monotonic() - mark
        endpoint = re.search(r'Connector URL: (https://\S+)', run.logs['publisher'].read_text()).group(1)
        checker = start_cli('checker', ['connector-check', '--oauth', '--expect-tools', 'echo', '--call-tool', 'missing' if control == 'tool' else 'echo', '--arguments', '{"message":"hello"}', endpoint])
        run.wait('consent URL', lambda: bool(re.search(r'https://\S+/oauth/authorize\?\S+', run.logs['checker'].read_text())), checker, timeout=30)
        url = re.search(r'https://\S+/oauth/authorize\?\S+', run.logs['checker'].read_text()).group()
        mark = time.monotonic()
        command(['node', str(ROOT / 'scripts/demo/browser.cjs'), 'consent', url, str(work / 'state.json')], env=run.env)
        consent = time.monotonic() - mark
        if checker.wait(timeout=30): raise RuntimeError('tool call failed')
        output = run.logs['checker'].read_text()
        if 'PASS: harmless allowed tool call' not in output: raise RuntimeError('tool call not confirmed')
        return dict(install_seconds=install, login_seconds=login_seconds, publish_seconds=publish,
                    oauth_consent_seconds=consent, first_tool_call_seconds=time.monotonic() - start)
    finally:
        run.close(False)


def main():
    parser = argparse.ArgumentParser(description=LABEL)
    parser.add_argument('--control', choices=['install', 'tool', 'path'])
    args = parser.parse_args()
    print(LABEL, flush=True)
    lane = ROOT.parent
    with tempfile.TemporaryDirectory(prefix='install-to-tool-', dir=lane) as tmp:
        base = Path(tmp)
        stage = base / 'stage'
        head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
        command(['python3', str(ROOT / 'scripts/stage-release.py'), '--tag', 'v0.0.0', '--source', head, '--output', str(stage), '--proposed'], cwd=ROOT)
        fixture.ROOT = base
        (base / 'certs').mkdir()
        command(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-days', '1', '-nodes', '-keyout', str(base / 'certs/key.pem'), '-out', str(base / 'certs/cert.pem'), '-subj', '/CN=' + fixture.DOMAIN, '-addext', 'subjectAltName=DNS:' + fixture.DOMAIN + ',DNS:*.' + fixture.DOMAIN + ',IP:127.0.0.1'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        (base / 'bin').mkdir()
        # Relay uses the same staged binary; it is fixture setup, outside the clock.
        (base / 'bin/tunn').symlink_to(stage / 'downloads/v0.0.0/tunn-linux-amd64')
        command(['go', 'build', '-p', '2', '-o', str(base / 'bin/mcp-echo-http'), './examples/mcp/go-http'], cwd=ROOT)
        handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(stage / 'downloads'))
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(base / 'certs/cert.pem', base / 'certs/key.pem')
        server.socket = context.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        downloads = f'https://127.0.0.1:{server.server_port}'
        results = {}
        for kind in ('stdio', 'http') if not args.control else ('stdio',):
            results[kind] = []
            for i in range(3 if not args.control else 1):
                work = base / f'{kind}-{i}'
                work.mkdir()
                results[kind].append(measure(kind, work, downloads, args.control))
        if not args.control:
            output = lane / 'evidence/timings.json'
            output.parent.mkdir(exist_ok=True)
            output.write_text(json.dumps({'label': LABEL, 'head': head, 'runs': results}, indent=2) + '\n')
            print(json.dumps({'label': LABEL, 'runs': results}, indent=2))


if __name__ == '__main__':
    main()
