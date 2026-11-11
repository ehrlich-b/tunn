#!/usr/bin/env python3
"""Walk a checkout-built release to its Pro offer using disposable local fixtures.

No browser or hosted service is contacted. The printed tunn.to URL is sent to
our TLS relay at 127.0.0.1, preserving its hostname, path and query with
the fixture port. Stripe's fixture Payment Link is inspected as a redirect only; payment is outside this walk.
"""

import argparse
import functools
import hashlib
import html
import http.server
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import select
import socket
import socketserver
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
from urllib.parse import parse_qs, urlencode, urlsplit

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('lifecycle', Path(__file__).with_name('lifecycle-test.py'))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
fixture.DOMAIN = 'tunn.to'
TAG = 'v0.0.123'
CHECKOUT = 'https://buy.stripe.com/install_to_offer_fixture'
OFFER = ("This name won't be kept while you're offline. Free keeps 1 name; "
         'Pro keeps 10 for $5 a month or $48 a year. Upgrade: '
         'https://tunn.to/upgrade?period=monthly. Pricing: https://tunn.to/pricing')


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def command(args, env, cwd=ROOT):
    result = subprocess.run(list(map(str, args)), cwd=cwd, env=env,
                            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=180)
    require(result.returncode == 0, f'{args[0]} exit {result.returncode}: {result.stderr}')
    return result.stdout + result.stderr


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class Downloads(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        self.server.receipts.append(self.path)
        super().do_GET()


class RelayProxy(socketserver.StreamRequestHandler):
    """Only CONNECT to this relay is allowed; DNS is never consulted."""
    def handle(self):
        request = self.rfile.readline().decode().strip()
        while self.rfile.readline() not in (b'\r\n', b'\n', b''):
            pass
        if request != f'CONNECT tunn.to:{self.server.relay_port} HTTP/1.1':
            self.wfile.write(b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n')
            return
        with socket.create_connection(('127.0.0.1', self.server.relay_port), timeout=5) as upstream:
            self.wfile.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            self.wfile.flush()
            peers = [self.connection, upstream]
            while True:
                readable, _, _ = select.select(peers, [], [], 30)
                if not readable:
                    return
                for peer in readable:
                    data = peer.recv(65536)
                    if not data:
                        return
                    (upstream if peer is self.connection else self.connection).sendall(data)


class Walk(fixture.Lifecycle):
    def __init__(self, work, client, relay, cert_dir):
        super().__init__(work, client, cert_dir)
        self.relay = relay
        self.proxy = socketserver.ThreadingTCPServer(('127.0.0.1', 0), RelayProxy)
        self.proxy.daemon_threads = True
        self.proxy.relay_port = self.port
        threading.Thread(target=self.proxy.serve_forever, daemon=True).start()
        self.step = 'setup'
        self.steps = []
        self.env = {k: v for k, v in self.env.items()
                    if k.lower() not in ('http_proxy', 'https_proxy', 'all_proxy', 'no_proxy')}
        self.env.update(HOME=str(work / 'home'), TMPDIR=str(work),
                        SSL_CERT_FILE=str(cert_dir / 'cert.pem'),
                        CURL_CA_BUNDLE=str(cert_dir / 'cert.pem'), NO_PROXY='127.0.0.1,localhost', NO_COLOR='1',
                        HTTPS_PROXY=f'http://127.0.0.1:{self.proxy.server_address[1]}',
                        TUNN_SERVER_ADDR=f'tunn.to:{self.port}',
                        TUNN_BILLING_ENABLED='true', TUNN_STRIPE_WEBHOOK_SECRET='fixture-only',
                        TUNN_STRIPE_CHECKOUT_URL_MONTHLY=CHECKOUT,
                        TUNN_LOGIN_NODE='true')
        (work / 'home').mkdir()
        shim = work / 'shim'
        shim.mkdir()
        # The CLI always tries an OS opener. Intercept it; no UI is launched.
        for name in ('xdg-open', 'open'):
            path = shim / name
            path.write_text('#!/bin/sh\nexit 0\n')
            path.chmod(0o755)
        self.env['PATH'] = str(shim) + os.pathsep + self.env['PATH']

    def mark(self, name):
        self.step = name

    def passed(self, **details):
        self.steps.append(dict(step=self.step, status='PASS', **details))
        print('PASS: ' + self.step, flush=True)

    def start(self, name, args):
        # Inherited lifecycle handles process groups, readiness and cleanup.
        original = self.binary
        if name == 'relay':
            self.binary = self.relay
        try:
            return super().start(name, args)
        finally:
            self.binary = original

    def close(self, failed):
        super().close(failed)
        self.proxy.shutdown()
        self.proxy.server_close()

    def reservations(self):
        with sqlite3.connect(self.env['TUNN_DB_PATH']) as db:
            return [r[0] for r in db.execute('SELECT subdomain FROM reserved_subdomains ORDER BY subdomain')]

    def run(self):
        self.mark('install')
        downloads = self.work / 'downloads'
        release = downloads / TAG
        release.mkdir(parents=True)
        arch = {'x86_64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64'}[platform.machine()]
        asset = f'tunn-{platform.system().lower()}-{arch}'
        # This is the only release asset the installer can select.
        (release / asset).write_bytes(self.binary.read_bytes())
        sha = digest(release / asset)
        (release / 'SHA256SUMS').write_text(f'{sha}  {asset}\n')
        (downloads / 'latest.json').write_text(json.dumps(dict(tag_name=TAG, draft=False, prerelease=False)))
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), functools.partial(Downloads, directory=str(downloads)))
        server.daemon_threads = True
        server.receipts = []
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert_dir / 'cert.pem', self.cert_dir / 'key.pem')
        server.socket = context.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.env.update(TUNN_DOWNLOAD_BASE=f'https://127.0.0.1:{server.server_port}',
                        TUNN_INSTALL_DIR=str(self.work / 'installed'))
        try:
            output = command(['sh', ROOT / 'install.sh'], self.env, self.work)
        finally:
            server.shutdown()
            server.server_close()
        installed = self.work / 'installed/tunn'
        require(digest(installed) == sha, 'installed binary differs from checkout build')
        require(server.receipts == ['/latest.json', f'/{TAG}/{asset}', f'/{TAG}/SHA256SUMS'], 'installer download sequence changed')
        self.binary = installed
        require(command([installed, '--version'], self.env, self.work).strip() == f'tunn {TAG}', 'installed version mismatch')
        self.passed(sha256=sha, requests=server.receipts, output=output)

        self.mark('fixture-sign-in')
        self.start_relay()
        login = self.start('login', ['login'])
        self.wait('login URL', lambda: bool(re.search(r'https://\S+/login\?\S+', self.logs['login'].read_text())), login)
        url = re.search(r'https://\S+/login\?\S+', self.logs['login'].read_text()).group()
        code = parse_qs(urlsplit(url).query)['code'][0]
        self.browse(url)
        confirmation = self.browse(self.base + '/auth/mock?' + urlencode(dict(device_user_code=code)))
        csrf = re.search(r'name="csrf_token" value="([^"]+)"', confirmation)
        require(csrf is not None, 'device confirmation omitted CSRF token')
        status, _, _ = self.request(self.base + '/auth/device/authorize', 'POST',
            urlencode(dict(code=code, csrf_token=html.unescape(csrf.group(1)))),
            {'Content-Type': 'application/x-www-form-urlencoded', 'Origin': self.base}, browser=True)
        require(status == 200 and login.wait(timeout=15) == 0, 'installed CLI login failed')
        require('Signed in as dev@example.com' in self.logs['login'].read_text(), 'fixture owner mismatch')
        status, _, body = self.request(self.base + '/api/billing/status', browser=True)
        require(status == 200 and json.loads(body)['plan'] == 'free', 'fixture account is not Free')
        self.passed(owner='dev@example.com', plan='free', explicit_device_authorization=True)

        # An actual local app lets CLI health reach Online without any DNS.
        origin = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Downloads)
        origin.daemon_threads = True
        origin.receipts = []
        threading.Thread(target=origin.serve_forever, daemon=True).start()
        try:
            for name in ('first-preview', 'second-preview'):
                self.mark('first-name-kept' if name == 'first-preview' else 'second-name-offer')
                publisher = self.start(name, ['http', f'http://127.0.0.1:{origin.server_port}', '--name', name])
                self.wait(name + ' Online', lambda: 'Online' in self.logs[name].read_text(), publisher)
                output = self.logs[name].read_text()
                if name == 'first-preview':
                    require(OFFER not in output and self.reservations() == [name], 'first name was not kept without an offer')
                    self.stop(publisher)
                    require(self.reservations() == [name], 'first name lost while offline')
                    self.passed(reservations=self.reservations(), output=output)
                else:
                    require(OFFER in output, 'missing exact Pro offer text in installed client output')
                    require(self.reservations() == ['first-preview'], 'second name unexpectedly kept')
                    self.passed(offer_text=OFFER, output=output, reservations=self.reservations())
                    link = re.search(r'https://[^\s]+/upgrade\?period=monthly', output).group()
        finally:
            origin.shutdown()
            origin.server_close()

        self.mark('offer-link-checkout')
        parsed = urlsplit(link)
        require(parsed.scheme == 'https' and parsed.netloc == 'tunn.to', 'unexpected printed offer authority')
        # Rebase only the port for the unprivileged local relay; never connect
        # to the public tunn.to service or follow the Stripe destination.
        local = self.base + parsed.path + '?' + parsed.query
        status, headers, _ = self.request(local, browser=True)
        destination = urlsplit(headers.get('location', ''))
        query = parse_qs(destination.query)
        require(status == 303 and destination.scheme + '://' + destination.netloc + destination.path == CHECKOUT,
                f'offer link did not redirect toward configured fixture checkout: status {status}')
        require(query.get('prefilled_email') == ['dev@example.com'] and query.get('client_reference_id'), 'checkout lacks account-bound reference')
        self.passed(printed_link=link, fixture_url=local, transport=f'127.0.0.1:{self.port}', status_code=status,
                    location=headers['location'], checkout_followed=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, default=Path(os.environ.get('TUNN_INSTALL_TO_OFFER_EVIDENCE', ROOT.parent / 'evidence/install-to-offer.json')))
    parser.add_argument('--client', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--relay', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--cert-dir', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    output = args.evidence.resolve()
    require(not output.is_relative_to(ROOT), 'evidence must be outside checkout')
    output.parent.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, GOPROXY='off', GOSUMDB='off', GOTOOLCHAIN='local', TMPDIR=str(ROOT.parent))
    with tempfile.TemporaryDirectory(prefix='install-to-offer-', dir=ROOT.parent) as tmp:
        work = Path(tmp)
        report = dict(head=command(['git', 'rev-parse', 'HEAD'], env).strip(), steps=[])
        if args.client:
            walk = Walk(work, args.client, args.relay, args.cert_dir)
            try:
                walk.run()
                report['status'] = 'PASS'
            except Exception as error:
                report.update(status='FAIL', failing_step=walk.step, error=str(error))
                print(f'FAIL: {walk.step}: {error}', flush=True)
            finally:
                walk.close(False)
                report['steps'] = walk.steps
                output.write_text(json.dumps(report, indent=2) + '\n')
            return 0 if report['status'] == 'PASS' else 1

        cert_dir = work / 'certs'
        cert_dir.mkdir()
        command(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                 '-keyout', cert_dir / 'key.pem', '-out', cert_dir / 'cert.pem', '-subj', '/CN=tunn.to',
                 '-addext', 'subjectAltName=DNS:tunn.to,DNS:*.tunn.to,IP:127.0.0.1'], env)
        client = work / 'tunn'
        command(['go', 'build', '-p', '2', '-ldflags', f'-X main.version={TAG}', '-o', client, '.'], env)
        positive = work / 'positive'
        positive.mkdir()
        walk = Walk(positive, client, client, cert_dir)
        try:
            walk.run()
            report.update(status='PASS', steps=walk.steps)
        except Exception as error:
            report.update(status='FAIL', steps=walk.steps, failing_step=walk.step, error=str(error))
            for name, log in walk.logs.items():
                (output.parent / (name + '-diagnostic.log')).write_text(log.read_text())
            print(f'FAIL: {walk.step}: {error}', flush=True)
        finally:
            walk.close(False)
            output.write_text(json.dumps(report, indent=2) + '\n')
        if report['status'] != 'PASS':
            return 1

        # A Go overlay changes only the temporary client build, never the relay
        # or checkout. Suppress both the human callback and fallback printing.
        source = ROOT / 'internal/client/serve.go'
        text = source.read_text()
        needle = 'if regResp.Notice != "" {'
        require(text.count(needle) == 1, 'offer-removal mutation no longer matches one site')
        mutated = work / 'serve.go'
        mutated.write_text(text.replace(needle, 'if false {'))
        overlay = work / 'overlay.json'
        overlay.write_text(json.dumps({'Replace': {str(source): str(mutated)}}))
        variant = work / 'tunn-without-offer'
        command(['go', 'build', '-p', '2', '-overlay', overlay, '-ldflags', f'-X main.version={TAG}', '-o', variant, '.'], env)
        negative_output = output.with_name(output.stem + '-without-offer.json')
        result = subprocess.run([sys.executable, str(Path(__file__).resolve()), '--client', str(variant),
            '--relay', str(client), '--cert-dir', str(cert_dir), '--evidence', str(negative_output)],
            env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=90)
        negative = json.loads(negative_output.read_text())
        report['negative_control'] = dict(exit_code=result.returncode, evidence=negative_output.name,
                                         output=result.stdout + result.stderr, failing_step=negative.get('failing_step'))
        if result.returncode != 1 or negative.get('failing_step') != 'second-name-offer':
            report.update(status='FAIL', failing_step='offer-removal-control',
                          error='offer-removal control did not fail specifically at second-name-offer')
            output.write_text(json.dumps(report, indent=2) + '\n')
            print('FAIL: offer-removal-control', flush=True)
            return 1
        report['negative_control']['status'] = 'PASS'
        output.write_text(json.dumps(report, indent=2) + '\n')
        print('PASS: offer-removal control fails at second-name-offer', flush=True)
        return 0


if __name__ == '__main__':
    sys.exit(main())
