#!/usr/bin/env python3
"""Run local MCP customer commands against the existing dev relay fixture."""
import importlib.util
import json
import socket
import os
from pathlib import Path
import re
import queue
import threading
import shutil
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('lifecycle', ROOT / 'scripts/integration-tests/lifecycle-test.py')
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


def run_once(kind, record=False):
    with tempfile.TemporaryDirectory(prefix='tunn-demo-') as temp:
        work = Path(temp)
        run = fixture.Lifecycle(work)
        # Prevent a desktop browser from opening; Playwright handles the printed URL.
        (work / 'xdg-open').write_text('#!/bin/sh\nexit 0\n')
        (work / 'xdg-open').chmod(0o755)
        run.env.update({'TUNN_SERVER_ADDR': f'{fixture.DOMAIN}:{run.port}', 'PATH': str(work) + os.pathsep + os.environ['PATH'],
                        'SSL_CERT_FILE': str(ROOT / 'certs/cert.pem'),
                        'NO_PROXY': '*', 'PLAYWRIGHT_BROWSERS_PATH': '/work/cache/ms-playwright'})
        recorder = None
        messages = queue.Queue()
        def read_recorder():
            for line in recorder.stdout:
                messages.put(line.strip())
            messages.put(None)
        def receive():
            try:
                message = messages.get(timeout=30)
            except queue.Empty:
                raise RuntimeError('video recorder timed out') from None
            if message is None:
                raise RuntimeError('video recorder exited unexpectedly')
            return message
        def event(kind, **data):
            recorder.stdin.write(json.dumps({'type': kind, **data}) + '\n')
            recorder.stdin.flush()
            if receive() != 'ok':
                raise RuntimeError('video recorder failed')
        try:
            if record:
                recorder = subprocess.Popen(['node', str(ROOT / 'scripts/demo/record.cjs'), str(work)], env=run.env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, start_new_session=True)
                threading.Thread(target=read_recorder, daemon=True).start()
                if receive() != 'ready':
                    raise RuntimeError('video recorder failed to start')
            run.start_relay()
            started = time.monotonic()
            login = run.start('login', ['--dev', 'login'])
            run.wait('login URL', lambda: bool(re.search(r'https://\S+\?\S+', run.logs['login'].read_text())), login)
            url = re.search(r'https://\S+\?\S+', run.logs['login'].read_text()).group()
            if recorder:
                event('terminal', text='$ tunn --dev login\n' + run.logs['login'].read_text())
                event('login', url=url)
            else:
                subprocess.run(['node', str(ROOT / 'scripts/demo/browser.cjs'), 'login', url, str(work / 'state.json')], env=run.env, check=True, timeout=30)
            if login.wait(timeout=30):
                raise RuntimeError('login failed')
            print(run.logs['login'].read_text(), flush=True)
            login_seconds = time.monotonic() - started
            server_seconds = None
            if kind == 'http':
                server_started = time.monotonic()
                port = fixture.free_port()
                server = subprocess.Popen([str(ROOT / 'bin/mcp-echo-http'), '-addr', f'127.0.0.1:{port}'], cwd=ROOT, env=run.env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
                run.processes.append(server)
                def listening():
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=0.2):
                            return True
                    except OSError:
                        return False
                run.wait('HTTP server', listening, server)
                server_seconds = round(time.monotonic() - server_started, 3)
                args = ['mcp', '--name', 'tools', f'http://127.0.0.1:{port}/mcp']
            else:
                args = ['mcp', '--tools', 'echo', '--', 'python3', str(ROOT / 'examples/mcp/echo.py')]
            started = time.monotonic()
            publisher = run.start('publisher', args)
            run.wait('Connector URL', lambda: 'Connector URL:' in run.logs['publisher'].read_text(), publisher, timeout=30)
            publish_seconds = time.monotonic() - started
            output = run.logs['publisher'].read_text()
            print(output, flush=True)
            endpoint = re.search(r'Connector URL: (https://\S+)', output).group(1)
            if recorder:
                event('terminal', text='$ tunn mcp --tools echo -- python3 examples/mcp/echo.py\n' + output + '\n$ tunn connector-check --oauth --expect-tools echo --call-tool echo --arguments '
                      + repr('{"message":"hello"}') + ' ' + endpoint)
            check_started = time.monotonic()
            checker = run.start('checker', ['connector-check', '--oauth', '--expect-tools', 'echo', '--call-tool', 'echo', '--arguments', '{"message":"hello"}', endpoint])
            run.wait('consent URL', lambda: bool(re.search(r'https://\S+/oauth/authorize\?\S+', run.logs['checker'].read_text())), checker, timeout=30)
            url = re.search(r'https://\S+/oauth/authorize\?\S+', run.logs['checker'].read_text()).group()
            if recorder:
                event('consent', url=url)
            else:
                subprocess.run(['node', str(ROOT / 'scripts/demo/browser.cjs'), 'consent', url, str(work / 'state.json')], env=run.env, check=True, timeout=30)
            if checker.wait(timeout=30):
                raise RuntimeError('connector check failed')
            first_call_seconds = time.monotonic() - started
            check_seconds = time.monotonic() - check_started
            check_output = run.logs['checker'].read_text()
            print(check_output, flush=True)
            recorder_final_event_seconds = None
            if recorder:
                event('terminal', text='$ tunn connector-check --oauth --expect-tools echo --call-tool echo --arguments '
                      + repr('{"message":"hello"}') + ' ' + endpoint + '\n' + check_output)
                recorder_final_event_seconds = round(time.monotonic() - started, 3)
            if recorder:
                recorder.stdin.close()
                video = receive()
                if recorder.wait(timeout=30) or not video:
                    raise RuntimeError('video recorder failed to finish')
                shutil.copyfile(video, os.environ['TUNN_DEMO_VIDEO'])
                recorder = None
            return {'server_seconds': server_seconds, 'login_seconds': round(login_seconds, 3), 'publish_seconds': round(publish_seconds, 3), 'connector_check_seconds': round(check_seconds, 3), 'first_call_seconds': round(first_call_seconds, 3), 'recorder_final_event_seconds': recorder_final_event_seconds, 'commands_typed': 4 if kind == 'http' else 3}
        except Exception:
            for name, path in run.logs.items():
                print(f'{name}: {path.read_text()}', file=sys.stderr)
            raise
        finally:
            if recorder and recorder.poll() is None:
                os.killpg(recorder.pid, signal.SIGKILL)
                recorder.wait()
            run.close(False)

def main():
    if not (ROOT / 'certs/cert.pem').exists():
        subprocess.run(['bash', 'scripts/gen-test-certs.sh'], cwd=ROOT, check=True)
    for output, package in [('tunn', '.'), ('mcp-echo-http', './examples/mcp/go-http')]:
        subprocess.run(['go', 'build', '-p', '2', '-o', str(ROOT / 'bin' / output), package], cwd=ROOT, check=True)
    results = {kind: [run_once(kind, record=(kind == 'stdio' and i == 0 and bool(os.environ.get('TUNN_DEMO_VIDEO')))) for i in range(3)] for kind in ('stdio', 'http')}
    print(json.dumps(results, indent=2))
    if os.environ.get('TUNN_DEMO_TIMINGS'):
        Path(os.environ['TUNN_DEMO_TIMINGS']).write_text(json.dumps(results, indent=2) + '\n')

if __name__ == '__main__':
    main()
