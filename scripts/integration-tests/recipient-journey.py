#!/usr/bin/env python3
"""Clean Chromium recipient journey using checksummed staged CLI/relay binaries.

No production contact: TLS, publisher, origin and IdP transport all use loopback.
The external Google consent/token/userinfo service is mocked; the relay's state,
PKCE, verified identity, account cookies and edge policy are real. No bypass
headers, injected sessions or source-built substitute processes are used.
"""
import argparse
import base64
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import math
import os
from pathlib import Path
import platform
import signal
import socket
import ssl
import subprocess
import threading
import time
import uuid
from urllib.parse import parse_qs, urlencode, urlsplit

REQUIRED = {
    'artifact', 'owner_only', 'anonymous_return', 'uninvited', 'invitee',
    'stranger', 'websocket_updates', 'revocation', 'stream_cutoff',
    'named_reconnect', 'publisher_stop', 'screenshots',
}
STATES = ('owner-only', 'return-sign-in', 'uninvited', 'sharing-zero',
          'sharing-one', 'invitee-updates', 'stranger-denied', 'revoked-denied',
          'reconnected', 'publisher-stopped', 'sharing-eight', 'sharing-limit')


def require(value, message):
    if not value:
        raise AssertionError(message)


def command(*args, **kw):
    return subprocess.check_output(['nice', '-n', '10', *map(str, args)], text=True, **kw).strip()


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


DENIALS = {'before-invite', 'stranger', 'stranger-upgrade', 'revoked', 'revoked-upgrade', 'revoked-after-reconnect'}


def validate(report):
    require(set(report['cases']) == REQUIRED, 'missing or unexpected required cases')
    require(all(v == 'PASS' for v in report['cases'].values()), 'required case failed or skipped')
    require(type(report['stream_cutoff_ms']) in (int, float) and math.isfinite(report['stream_cutoff_ms']) and 0 <= report['stream_cutoff_ms'] <= 5000, 'stream cutoff exceeded five seconds')
    require(report['physical_evidence'] == 'PENDING', 'fixture cannot qualify physical devices')
    expected = {f'{state}-{width}-{theme}.png' for state in STATES for width in (390, 1440) for theme in ('light', 'dark')}
    require(set(report['screenshots']) == expected, 'missing required screenshots')
    for name, item in report['screenshots'].items():
        p = Path(report['output']) / name
        require(p.is_file() and digest(p) == item['sha256'], 'screenshot changed: ' + name)
        require(int.from_bytes(p.read_bytes()[16:20], 'big') == item['width'] and item['width'] in (390, 1440), 'wrong screenshot width')
        require(item['horizontal_overflow'] is False, 'horizontal overflow: ' + name)
    require(report['idp_exchanges'] == 3, 'missing external identity exchange')
    require(len(report['denials']) == len(DENIALS) and {d['label'] for d in report['denials']} == DENIALS, 'missing or duplicate denials')
    require(all(d['origin_before'] == d['origin_after'] for d in report['denials']), 'denied traffic reached origin')
    require(report['head'] == command('git', 'rev-parse', 'HEAD'), 'stale source head')
    require(digest(Path(report['binary'])) == report['binary_sha256'], 'staged binary changed')
    manifest = json.loads(Path(report['manifest']).read_text())
    require(manifest['source_commit'] == report['head'] and any(a['sha256'] == report['binary_sha256'] and a['name'] == Path(report['binary']).name for a in manifest['assets']), 'manifest mismatch')


class Origin(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        self.server.hits.append(self.path)
        if self.path.startswith('/ws'):
            accept = base64.b64encode(hashlib.sha1((self.headers['Sec-WebSocket-Key'] +
                '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
            self.send_response(101)
            self.send_header('Upgrade', 'websocket')
            self.send_header('Connection', 'Upgrade')
            self.send_header('Sec-WebSocket-Accept', accept)
            self.end_headers()
            try:
                for tick in range(1000):
                    body = f'Update {tick}'.encode()
                    self.wfile.write(bytes([0x81, len(body)]) + body)
                    self.wfile.flush()
                    time.sleep(.1)
            except (OSError, ValueError):
                pass
            return
        body = b'''<!doctype html><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Recipient fixture</title><style>body{font:18px system-ui;margin:24px;max-width:60rem}li{padding:8px}</style>
<h1>Project updates</h1><p>Local fixture app</p><p id="live">Connecting</p><ul>'''
        body += b''.join(f'<li>Customer research and prototype milestone {i}</li>'.encode() for i in range(1, 10))
        body += b'''</ul><script>window.updates=0;window.closedAt=0;
window.socket=new WebSocket('wss://'+location.host+'/ws');
socket.onmessage=e=>{updates++;document.querySelector('#live').textContent=e.data};
socket.onclose=()=>{closedAt=performance.now();document.querySelector('#live').textContent='Disconnected'};</script>'''
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class Identity:
    """CONNECT sink accepts only the two Google service authorities, never dials out."""
    def __init__(self, cert, key):
        self.codes, self.tokens = {}, {}
        self.exchanges = 0
        self.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.tls.load_cert_chain(cert, key)
        identity = self

        class Proxy(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_CONNECT(self):
                if self.path not in ('oauth2.googleapis.com:443', 'openidconnect.googleapis.com:443'):
                    self.send_error(403)
                    return
                self.send_response(200)
                self.end_headers()
                wrapped = identity.tls.wrap_socket(self.connection, server_side=True)
                try:
                    Service(wrapped, self.client_address, self.server)
                finally:
                    wrapped.close()

        class Service(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def reply(self, data):
                body = json.dumps(data).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                require(self.path == '/token', 'unexpected token request')
                data = parse_qs(self.rfile.read(int(self.headers['Content-Length'])).decode())
                email, challenge, callback = identity.codes.pop(data['code'][0])
                got = base64.urlsafe_b64encode(hashlib.sha256(data['code_verifier'][0].encode()).digest()).decode().rstrip('=')
                require(got == challenge and data['redirect_uri'][0] == callback, 'PKCE/return binding failed')
                require(data['client_id'] == ['fixture-id'] and data['client_secret'] == ['fixture-secret'], 'wrong fixture client')
                token = uuid.uuid4().hex
                identity.tokens[token] = email
                identity.exchanges += 1
                self.reply({'access_token': token})

            def do_GET(self):
                require(self.path == '/v1/userinfo', 'unexpected identity request')
                email = identity.tokens[self.headers['Authorization'].removeprefix('Bearer ')]
                self.reply({'sub': 'fixture:' + email, 'email': email, 'email_verified': True, 'hd': 'example.com'})

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Proxy)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def consent(self, url, email):
        q = parse_qs(urlsplit(url).query)
        require(q['code_challenge_method'] == ['S256'], 'missing PKCE challenge')
        code = uuid.uuid4().hex
        self.codes[code] = email, q['code_challenge'][0], q['redirect_uri'][0]
        callback = q['redirect_uri'][0] + '?' + urlencode({'state': q['state'][0], 'code': code})
        return f'<h1>Mocked Google consent</h1><p>{email}</p><a href="{callback}">Approve verified email</a>'


class Journey:
    def __init__(self, args):
        self.args, self.output = args, args.output.resolve()
        require(not self.output.is_relative_to(Path.cwd()), 'evidence must be outside checkout')
        self.output.mkdir(parents=True, exist_ok=False)
        self.output.chmod(0o700)
        self.processes, self.cases, self.shots, self.denials = [], {}, {}, []
        self.port, self.grpc = free_port(), free_port()
        self.apex = f'https://tunn.test:{self.port}'
        self.app = f'https://recipient.tunn.test:{self.port}'
        manifest = json.loads((args.release / 'manifest.json').read_text())
        self.head = command('git', 'rev-parse', 'HEAD')
        require(manifest['source_commit'] == self.head, 'release must match committed HEAD')
        arch = {'x86_64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64'}[platform.machine()]
        name = f'tunn-{platform.system().lower()}-{arch}'
        self.binary = (args.release / 'downloads' / manifest['tag'] / name).resolve()
        asset = next(x for x in manifest['assets'] if x['name'] == name)
        require(digest(self.binary) == asset['sha256'], 'release checksum mismatch')
        provenance = command('go', 'version', '-m', self.binary)
        require(f'vcs.revision={self.head}' in provenance and 'vcs.modified=false' in provenance, 'unclean release build')
        (self.output / 'build-info.txt').write_text(provenance + '\n')
        self.cases['artifact'] = 'PASS'
        cert, key = self.output / 'cert.pem', self.output / 'key.pem'
        command('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
                '-keyout', key, '-out', cert, '-subj', '/CN=tunn.test', '-addext',
                'subjectAltName=DNS:tunn.test,DNS:*.tunn.test,IP:127.0.0.1,DNS:oauth2.googleapis.com,DNS:openidconnect.googleapis.com',
                stderr=subprocess.DEVNULL)
        pub = subprocess.check_output(['openssl', 'x509', '-in', cert, '-pubkey', '-noout'])
        der = subprocess.check_output(['openssl', 'pkey', '-pubin', '-outform', 'der'], input=pub)
        self.spki = base64.b64encode(hashlib.sha256(der).digest()).decode()
        self.cert, self.key = cert, key
        self.identity = Identity(cert, key)
        self.origin = ThreadingHTTPServer(('127.0.0.1', 0), Origin)
        origin_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        origin_tls.load_cert_chain(cert, key)
        self.origin.socket = origin_tls.wrap_socket(self.origin.socket, server_side=True)
        self.origin.daemon_threads = True
        self.origin.hits = []
        threading.Thread(target=self.origin.serve_forever, daemon=True).start()
        self.env = {k: v for k, v in os.environ.items() if not k.startswith(('TUNN_', 'FLY_')) and k.lower() not in ('http_proxy', 'https_proxy', 'all_proxy', 'no_proxy')}
        self.env.update(TUNN_ENV='prod', TUNN_DOMAIN='tunn.test', TUNN_PUBLIC_ADDR=f'tunn.test:{self.port}',
            TUNN_HTTP2_ADDR=f'127.0.0.1:{self.port}', TUNN_HTTP3_ADDR=f'127.0.0.1:{self.port}',
            TUNN_INTERNAL_GRPC_PORT=f'127.0.0.1:{self.grpc}', TUNN_SERVER_ADDR=f'127.0.0.1:{self.port}',
            TUNN_CERT_FILE=str(cert), TUNN_KEY_FILE=str(key), TUNN_LOGIN_NODE='true',
            TUNN_DB_PATH=str(self.output / 'accounts.db'), TUNN_CONFIG_DIR=str(self.output / 'publisher-config'),
            TUNN_JWT_SECRET='disposable-recipient-fixture-secret', TUNN_GOOGLE_CLIENT_ID='fixture-id',
            TUNN_GOOGLE_CLIENT_SECRET='fixture-secret', SSL_CERT_FILE=str(cert),
            HTTPS_PROXY=f'http://127.0.0.1:{self.identity.server.server_port}', NO_PROXY='localhost,127.0.0.1,.tunn.test')

    def start(self, name, *args):
        with (self.output / (name + '.log')).open('ab') as log:
            proc = subprocess.Popen(['nice', '-n', '10', str(self.binary), *args], cwd=self.output,
                env=self.env, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        self.processes.append(proc)
        return proc

    @staticmethod
    def stop(proc):
        if proc.poll() is None:
            os.killpg(proc.pid, signal.SIGTERM)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait(timeout=3)

    def api(self, path, method='GET', body=None):
        tls = ssl.create_default_context(cafile=str(self.cert))
        conn = http.client.HTTPSConnection('127.0.0.1', self.port, context=tls, timeout=5)
        conn.request(method, path, body=body, headers={'Host': f'tunn.test:{self.port}'})
        res = conn.getresponse()
        data = res.read()
        conn.close()
        require(res.status == 200, f'API {path.split("?")[0]} returned {res.status}')
        return data if path == "/health" else json.loads(data)

    def run(self):
        from playwright.sync_api import sync_playwright
        relay = self.start('relay', '-mode=host')
        deadline = time.monotonic() + 15
        while True:
            require(relay.poll() is None, 'relay exited before readiness (see private relay.log)')
            try:
                self.api('/health')
                break
            except (OSError, ValueError):
                require(time.monotonic() < deadline, 'relay readiness timeout')
                time.sleep(.1)
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True, executable_path=self.args.chromium, args=[
                '--no-proxy-server', '--host-resolver-rules=MAP *.tunn.test 127.0.0.1, MAP tunn.test 127.0.0.1, MAP * ~NOTFOUND',
                '--ignore-certificate-errors-spki-list=' + self.spki])
            try:
                self.browse(browser)
            finally:
                browser.close()
        report = dict(version=1, head=self.head, output=str(self.output), cases=self.cases,
            binary=str(self.binary), binary_sha256=digest(self.binary), manifest=str((self.args.release / 'manifest.json').resolve()), screenshots=self.shots,
            stream_cutoff_ms=self.cutoff, origin_hits=self.origin.hits, denials=self.denials, idp_exchanges=self.identity.exchanges,
            environment='Loopback TLS relay/publisher/origin; mocked Google consent/token/userinfo; Chromium viewport emulation, no physical phone',
            physical_evidence='PENDING')
        validate(report)
        (self.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'cases': self.cases, 'stream_cutoff_ms': self.cutoff, 'report': str(self.output / 'report.json'), 'physical_evidence': 'PENDING'}))

    def browse(self, browser):
        def person(email):
            ctx = browser.new_context(viewport={'width': 1440, 'height': 900})
            ctx.set_default_timeout(10000)
            # All other HTTP requests are restricted to our exact loopback authorities.
            def local_only(route):
                u = urlsplit(route.request.url)
                if u.hostname in ('tunn.test', 'recipient.tunn.test') and u.port == self.port:
                    route.continue_()
                else:
                    route.abort()
            ctx.route('**/*', local_only)
            # More recently registered route takes precedence.
            def consent(route):
                # Intercept before the external redirect; Chromium does not route
                # redirected hops independently. Only the IdP response is replaced.
                u = urlsplit(route.request.url)
                conn = http.client.HTTPSConnection('127.0.0.1', self.port,
                    context=ssl.create_default_context(cafile=str(self.cert)), timeout=5)
                conn.request('GET', u.path + '?' + u.query,
                    headers={**route.request.headers, 'Host': f'tunn.test:{self.port}'})
                response = conn.getresponse()
                require(response.status == 302, 'Google authorization did not redirect')
                location = response.getheader('Location')
                require(location.startswith('https://accounts.google.com/'), 'unexpected provider')
                cookies = [v for k, v in response.getheaders() if k.lower() == 'set-cookie']
                response.read()
                conn.close()
                route.fulfill(status=200, headers={'content-type': 'text/html',
                    'set-cookie': '\n'.join(cookies)}, body=self.identity.consent(location, email))
            ctx.route('**/auth/google?*', consent)
            return ctx, ctx.new_page()

        def login(page):
            page.get_by_role('link', name='Continue with Google').click()
            page.get_by_role('link', name='Approve verified email').click()

        def capture(page, state):
            for theme in ('light', 'dark'):
                page.emulate_media(color_scheme=theme)
                for width, height in ((390, 844), (1440, 900)):
                    page.set_viewport_size({'width': width, 'height': height})
                    name = f'{state}-{width}-{theme}.png'
                    page.screenshot(path=str(self.output / name), full_page=True)
                    self.shots[name] = {'sha256': digest(self.output / name), 'width': width,
                        'horizontal_overflow': page.evaluate('document.documentElement.scrollWidth > innerWidth')}
            page.emulate_media(color_scheme='light')
            page.set_viewport_size({'width': 1440, 'height': 900})

        def loaded(page):
            page.get_by_role('heading', name='Project updates').wait_for()
            page.wait_for_function('window.updates >= 2')

        def denied(page, label):
            before = len(self.origin.hits)
            response = page.goto(self.app + '/' + label)
            require(response.status == 403, label + ' was not denied')
            require('Access denied' in page.locator('body').inner_text(), label + ' denial missing')
            require(len(self.origin.hits) == before, label + ' reached origin')
            self.denials.append(dict(label=label, status=response.status, origin_before=before, origin_after=len(self.origin.hits)))

        def people(page, expected):
            rows = page.locator('form.sharing-person')
            actual = rows.locator('input[name=email]').evaluate_all('(nodes) => nodes.map(n => n.value)')
            require(sorted(actual) == sorted(expected), f'wrong sharing identities: {actual}')
            require(rows.count() == len(expected), 'incorrect person row count')
            for email in expected:
                row = rows.filter(has=page.locator('input[name=email][value="' + email + '"]'))
                require(row.count() == 1 and row.locator('button[name=action][value=unshare]').count() == 1, 'missing person control: ' + email)

        owner_ctx, owner = person('owner@example.com')
        code = self.api('/api/device/code', 'POST')
        owner.goto(code['verification_uri_complete'])
        login(owner)
        owner.get_by_role('button', name='Authorize', exact=True).click()
        token = self.api('/api/device/token?' + urlencode({'code': code['device_code'], 'durable': '1'}))['access_token']
        # Publisher uses only a credential issued after actual browser approval.
        def publish(name):
            proc = self.start(name, f'https://127.0.0.1:{self.origin.server_port}', '--name', 'recipient', '--secret', token, '--json')
            deadline = time.monotonic() + 15
            while not any(json.loads(line).get('type') == 'route' for line in
                    (self.output / (name + '.log')).read_text().splitlines() if line.startswith('{')):
                require(proc.poll() is None and time.monotonic() < deadline, 'publisher failed registration')
                owner.wait_for_timeout(100)
            return proc
        publisher = publish('publisher')
        owner.goto(self.app)
        loaded(owner)
        capture(owner, 'owner-only')
        self.cases['owner_only'] = 'PASS'
        alice_ctx, alice = person('alice@example.com')
        before = len(self.origin.hits)
        alice.goto(self.app + '/recipient-return?from=phone')
        require('/auth/login' in alice.url, 'anonymous resource did not require login')
        capture(alice, 'return-sign-in')
        login(alice)
        require(alice.url == self.app + '/recipient-return?from=phone', 'login lost original return URL')
        require('Access denied' in alice.locator('body').inner_text(), 'uninvited recipient was admitted')
        require(len(self.origin.hits) == before, 'uninvited return reached origin')
        denied(alice, 'before-invite')
        capture(alice, 'uninvited')
        self.cases.update(anonymous_return='PASS', uninvited='PASS')
        owner.goto(self.apex + '/account/sharing?tunnel=recipient')
        owner.get_by_role('heading', name='Share access', exact=True).wait_for()
        people(owner, [])
        capture(owner, 'sharing-zero')
        owner.get_by_label('Email', exact=True).fill('alice@example.com')
        owner.get_by_role('button', name='Share', exact=True).click()
        owner.get_by_role('button', name='Remove access for alice@example.com', exact=True).wait_for()
        people(owner, ['alice@example.com'])
        capture(owner, 'sharing-one')
        alice.goto(self.app + '/recipient-return?from=phone')
        loaded(alice)
        capture(alice, 'invitee-updates')
        require(alice.url.endswith('/recipient-return?from=phone'), 'invitee return changed')
        self.cases.update(invitee='PASS', websocket_updates='PASS')
        stranger_ctx, stranger = person('stranger@example.com')
        stranger.goto(self.app)
        before = len(self.origin.hits)
        login(stranger)
        require('Access denied' in stranger.locator('body').inner_text(), 'stranger login admitted')
        require(len(self.origin.hits) == before, 'stranger callback reached origin')
        denied(stranger, 'stranger')
        before = len(self.origin.hits)
        stranger.evaluate('''() => {window.deniedWS=false; const s=new WebSocket('wss://'+location.host+'/ws?stranger'); s.onerror=()=>window.deniedWS=true;}''')
        stranger.wait_for_function('window.deniedWS')
        require(len(self.origin.hits) == before, 'stranger upgrade reached origin')
        self.denials.append(dict(label='stranger-upgrade', origin_before=before, origin_after=len(self.origin.hits)))
        capture(stranger, 'stranger-denied')
        self.cases['stranger'] = 'PASS'
        require(alice.evaluate('socket.readyState === WebSocket.OPEN && closedAt === 0'), 'invitee stream closed before revocation')
        tick = alice.evaluate('updates')
        alice.wait_for_function('(tick) => updates > tick', arg=tick)
        started = time.monotonic()
        owner.get_by_role('button', name='Remove access for alice@example.com', exact=True).click()
        alice.wait_for_function('window.closedAt > 0', timeout=5000)
        self.cutoff = round((time.monotonic() - started) * 1000, 2)
        require(self.cutoff <= 5000, 'revoked stream survived five seconds')
        denied(alice, 'revoked')
        # A fresh WebSocket upgrade from the revoked session must also stop at edge.
        before = len(self.origin.hits)
        alice.evaluate('''() => {window.deniedWS=false; const s=new WebSocket('wss://'+location.host+'/ws?revoked'); s.onerror=()=>window.deniedWS=true;}''')
        alice.wait_for_function('window.deniedWS')
        require(len(self.origin.hits) == before, 'revoked upgrade reached origin')
        self.denials.append(dict(label='revoked-upgrade', origin_before=before, origin_after=len(self.origin.hits)))
        capture(alice, 'revoked-denied')
        self.cases.update(revocation='PASS', stream_cutoff='PASS')
        self.stop(publisher)
        publisher = publish('publisher-reconnect')
        owner.goto(self.app)
        loaded(owner)
        denied(alice, 'revoked-after-reconnect')
        capture(owner, 'reconnected')
        self.cases['named_reconnect'] = 'PASS'
        # Re-add Alice, then reconnect without --allow: durable web grants persist.
        owner.goto(self.apex + '/account/sharing?tunnel=recipient')
        owner.get_by_label('Email', exact=True).fill('alice@example.com')
        owner.get_by_role('button', name='Share', exact=True).click()
        self.stop(publisher)
        publisher = publish('publisher-grant-reconnect')
        alice.goto(self.app)
        loaded(alice)
        self.stop(publisher)
        alice.wait_for_function('window.closedAt > 0', timeout=5000)
        before = len(self.origin.hits)
        response = alice.goto(self.app + '/publisher-stopped')
        require(response.status == 503, 'stopped publisher did not return offline 503')
        require(len(self.origin.hits) == before, 'stopped publisher request reached origin')
        capture(alice, 'publisher-stopped')
        self.cases['publisher_stop'] = 'PASS'
        # Exercise realistic volume and the existing 64-person resource bound.
        owner.goto(self.apex + '/account/sharing?tunnel=recipient')
        for i in range(1, 64):
            # Stay below the existing 60/minute mutation bound, without changing it.
            if i == 48:
                owner.wait_for_timeout(61000)
            owner.get_by_label('Email', exact=True).fill(
                f'research-collaborator-with-long-name-{i:02}@example.com')
            with owner.expect_response(lambda r: r.request.method == 'POST') as submitted:
                owner.get_by_role('button', name='Share', exact=True).click()
            require(submitted.value.status == 303, f'fixture share {i} failed')
            if i == 7:
                owner.reload()
                people(owner, ['alice@example.com'] + [f'research-collaborator-with-long-name-{n:02}@example.com' for n in range(1, 8)])
                owner.locator('details.sharing-more').evaluate('(el) => el.open = true')
                capture(owner, 'sharing-eight')
        owner.reload()
        people(owner, ['alice@example.com'] + [f'research-collaborator-with-long-name-{n:02}@example.com' for n in range(1, 64)])
        owner.locator('details.sharing-more').evaluate('(el) => el.open = true')
        capture(owner, 'sharing-limit')
        self.cases['screenshots'] = 'PASS'
        require(self.identity.exchanges == 3, 'identity fixture did not exchange all three identities')
        for ctx in (owner_ctx, alice_ctx, stranger_ctx):
            ctx.close()

    def close(self):
        for proc in reversed(self.processes):
            self.stop(proc)
        self.origin.shutdown()
        self.identity.server.shutdown()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--chromium')
    parser.add_argument('--verify', type=Path)
    args = parser.parse_args()
    if args.verify:
        def unique(pairs):
            result = {}
            for k, v in pairs:
                require(k not in result, 'duplicate JSON key: ' + k)
                result[k] = v
            return result
        validate(json.loads(args.verify.read_text(), object_pairs_hook=unique))
        print('PASS: complete committed-artifact report; no skipped required cases; physical acceptance pending')
        return
    require(args.release and args.output, '--release and --output are required')
    journey = Journey(args)
    try:
        journey.run()
    finally:
        journey.close()


if __name__ == '__main__':
    main()
