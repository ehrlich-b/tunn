#!/usr/bin/env python3
"""Run the official SDK clients against a disposable TLS relay and tunn mcp.

Dependencies are fetched separately into TUNN_MCP_CLIENTS_SCRATCH; this command
never installs anything or contacts a hosted client. All artifacts live outside
this checkout. HTTPS callbacks are intercepted in Chromium before any network.
"""
import base64
import hashlib
import html
import importlib.util
import json
import os
from pathlib import Path
import queue
import re
import secrets
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import parse_qs, urlencode, urlsplit

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('lifecycle', HERE.parent / 'lifecycle-test.py')
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
fixture.ENDPOINT = 'tools'


def outside(name, default):
    path = Path(os.environ.get(name, default)).resolve()
    if path == ROOT or ROOT in path.parents:
        raise RuntimeError(name + ' must be outside the checkout')
    path.mkdir(parents=True, exist_ok=True)
    return path


class Journey(fixture.Lifecycle):
    def login_and_publish(self):
        self.start_relay()
        status, _, body = self.request(self.base + '/api/device/code', 'POST')
        assert status == 200
        device = json.loads(body)
        self.browse(device['verification_uri_complete'])
        confirmation = self.browse(self.base + '/auth/mock?' + urlencode({'device_user_code':device['user_code']}))
        csrf = html.unescape(re.search(r'name="csrf_token" value="([^"]+)"', confirmation)[1])
        status, _, _ = self.request(self.base + '/auth/device/authorize', 'POST',
            urlencode({'code':device['user_code'],'csrf_token':csrf}),
            {'Content-Type':'application/x-www-form-urlencoded','Origin':self.base},browser=True)
        assert status == 200
        poll = self.base + '/api/device/token?' + urlencode({'code':device['device_code'],'durable':'1'})
        token = json.loads(self.request(poll)[2])['access_token']
        publisher = self.start('publisher', ['mcp','--name','tools','--secret',token,
            '--tools','echo','--',sys.executable,str(ROOT / 'examples/mcp/echo.py')])
        self.wait('tunn mcp publisher',lambda:'Connector URL:' in self.logs['publisher'].read_text(),publisher)
        self.endpoint = re.search(r'Connector URL: (https://\S+)',self.logs['publisher'].read_text())[1]

    def consent(self, url, callback, screenshot):
        value = {'url':url,'callback':callback,'base':self.base,'cookies':self.cookies,
                 'oidc_port':self.oidc_port,'screenshot':str(screenshot)}
        result = subprocess.run(['node',str(HERE / 'browser.cjs')],input=json.dumps(value),
            text=True,capture_output=True,env=self.env,timeout=30)
        if result.returncode:
            raise RuntimeError(result.stderr)
        return json.loads(result.stdout)

    def expire(self, access):
        with sqlite3.connect(self.work / 'login.db') as db:
            row = db.execute('SELECT id,data FROM meter_grants WHERE digest=?',(hashlib.sha256(access.encode()).digest(),)).fetchone()
            assert row, 'access grant missing'
            data = json.loads(row[1])
            data['expires_at'] = int(time.time()*1000)-1000
            db.execute('UPDATE meter_grants SET expires=?,data=? WHERE id=?',
                (data['expires_at'],json.dumps(data).encode(),row[0]))
        status, _, _ = self.request(self.endpoint,'POST','{}',{
            'Authorization':'Bearer '+access,'Content-Type':'application/json'})
        assert status == 401, f'expired access returned {status}'

    def sdk(self, name, command, evidence):
        stderr = self.work / (name + '.stderr')
        with stderr.open('w') as errors:
            child = subprocess.Popen(command+[self.endpoint],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                stderr=errors,text=True,env=self.env,cwd=self.work,start_new_session=True)
        self.processes.append(child)
        messages = queue.Queue()
        def read():
            for line in child.stdout:
                messages.put(line)
            messages.put(None)
        threading.Thread(target=read,daemon=True).start()
        result = None
        while True:
            try: line = messages.get(timeout=45)
            except queue.Empty: raise RuntimeError(name+' timed out: '+stderr.read_text()) from None
            if line is None: break
            event = json.loads(line)
            if event['event'] == 'authorize':
                answer = self.consent(event['url'],event['callback'],evidence / (name+'-consent-390.png'))
            elif event['event'] == 'expire':
                self.expire(event['access'])
                answer = {'expired_access_status':401}
            elif event['event'] == 'result':
                result = event
                continue
            else: raise AssertionError('unknown child event')
            child.stdin.write(json.dumps(answer)+'\n')
            child.stdin.flush()
        assert child.wait(timeout=5) == 0, name+': '+stderr.read_text()
        assert result
        result.pop('event')
        result.update(consent_width=390,expired_access_status=401,screenshot=name+'-consent-390.png')
        return result

    def token(self, form):
        status, _, body = self.request(self.base+'/oauth/token','POST',urlencode(form),
                                      {'Content-Type':'application/x-www-form-urlencoded'})
        return status,json.loads(body)

    def replay(self, callback, index, evidence):
        status, _, body = self.request(self.base+'/oauth/register','POST',json.dumps({
            'client_name':'Hosted callback replay','redirect_uris':[callback],
            'grant_types':['authorization_code','refresh_token'],'token_endpoint_auth_method':'none'}),
            {'Content-Type':'application/json'})
        assert status == 201, body
        client = json.loads(body)['client_id']
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
        query = dict(response_type='code',client_id=client,redirect_uri=callback,resource=self.endpoint,
                     state=secrets.token_urlsafe(24),code_challenge=challenge,code_challenge_method='S256',scope='mcp')
        consent = self.consent(self.base+'/oauth/authorize?'+urlencode(query),callback,
                               evidence / f'callback-{index}-consent-390.png')
        code = parse_qs(urlsplit(consent['callback']).query)['code'][0]
        form = dict(grant_type='authorization_code',client_id=client,redirect_uri=callback,
                    resource=self.endpoint,code=code,code_verifier=verifier)
        for field, value in [('resource',self.endpoint.replace('tools.','wrong.')),('code_verifier','x'*43)]:
            denied, problem = self.token({**form,field:value})
            assert denied == 400 and problem['error'] == 'invalid_grant'
        status, tokens = self.token(form)
        assert status == 200 and tokens['refresh_token']
        status, problem = self.token(form)
        assert status == 400 and problem['error'] == 'invalid_grant'
        self.expire(tokens['access_token'])
        refresh = dict(grant_type='refresh_token',client_id=client,resource=self.endpoint,refresh_token=tokens['refresh_token'])
        status, renewed = self.token(refresh)
        assert status == 200 and renewed['access_token'] != tokens['access_token']
        assert renewed['refresh_token'] != tokens['refresh_token']
        # Verify the renewed token reaches the publisher's real echo server.
        headers = {'Authorization':'Bearer '+renewed['access_token'],'Content-Type':'application/json','Accept':'application/json, text/event-stream'}
        status, session_headers, body = self.request(self.endpoint,'POST',json.dumps({'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-03-26','capabilities':{},'clientInfo':{'name':'callback-replay','version':'1'}}}),headers)
        assert status == 200 and json.loads(body)['result']['serverInfo']['name'] == 'tunn-echo-demo'
        with sqlite3.connect(self.work / 'login.db') as db:
            assert db.execute('DELETE FROM mcp_oauth_clients WHERE id=?',(client,)).rowcount == 1
        for grant in [form,{**refresh,'refresh_token':renewed['refresh_token']}]:
            status, problem = self.token(grant)
            assert status == 401 and problem['error'] == 'invalid_client'
        return {'callback':callback,'registration_status':201,'consent_width':390,'code_exchange_status':200,
                'expired_access_status':401,'refresh_status':200,'refresh_rotated':True,
                'deleted_client_code_status':401,'deleted_client_refresh_status':401,
                'deleted_client_error':'invalid_client','controls':{'wrong_resource':400,'wrong_pkce':400,'reused_code':400}}


def main():
    scratch = outside('TUNN_MCP_CLIENTS_SCRATCH',str(ROOT.parent / 'scratch'))
    evidence = outside('TUNN_MCP_CLIENTS_EVIDENCE',str(ROOT.parent / 'evidence'))
    modules = scratch / 'node/node_modules'
    assert (modules / '@modelcontextprotocol/sdk/package.json').exists(), 'Fetch SDKs as described in README.md first'
    assert (scratch / 'python/mcp').exists(), 'Fetch Python wheels as described in README.md first'
    work = Path(tempfile.mkdtemp(prefix='mcp-clients-',dir=scratch))
    work.chmod(0o700)
    cert_dir = work / 'certs'
    cert_dir.mkdir()
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-sha256','-days','2','-nodes',
        '-keyout',str(cert_dir/'key.pem'),'-out',str(cert_dir/'cert.pem'),'-subj','/CN='+fixture.DOMAIN,
        '-addext','subjectAltName=DNS:'+fixture.DOMAIN+',DNS:*.'+fixture.DOMAIN+',IP:127.0.0.1'],
        check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    binary = work / 'tunn'
    subprocess.run(['go','build','-p','2','-o',str(binary),'.'],cwd=ROOT,check=True)
    run = Journey(work,binary=binary,cert_dir=cert_dir)
    # The CLI uses the relay's canonical name for certificate validation; the
    # dev fixture hostname resolves to loopback. SDK/browser DNS is pinned locally.
    run.env.update(TUNN_SERVER_ADDR=f'{fixture.DOMAIN}:{run.port}',NO_PROXY='*',
        SSL_CERT_FILE=str(cert_dir/'cert.pem'),NODE_EXTRA_CA_CERTS=str(cert_dir/'cert.pem'),
        PYTHONPATH=str(scratch/'python'),TUNN_MCP_NODE_MODULES=str(modules),
        TUNN_PLAYWRIGHT_MODULE=os.environ.get('TUNN_PLAYWRIGHT_MODULE',str(modules/'playwright')),PLAYWRIGHT_BROWSERS_PATH='/work/cache/ms-playwright')
    results = {'hosted_clients':{'claude_web':'unverified','claude_phone':'unverified','chatgpt':'unverified'},
               'fixture':'loopback TLS relay, mock OIDC, real tunn mcp stdio echo publisher',
               'expiry_method':'expire fixture grant; Python also advances its cached token expiry',
               'callback_delivery':'Chromium intercepts registered callback before network; validates state and issuer'}
    try:
        run.login_and_publish()
        results['clients'] = [run.sdk('typescript',['node',str(HERE/'typescript.cjs')],evidence),
                              run.sdk('python',[sys.executable,str(HERE/'python.py')],evidence)]
        results['callbacks'] = [run.replay(callback,i,evidence) for i,callback in enumerate([
            'https://claude.ai/api/mcp/auth_callback','https://claude.com/api/mcp/auth_callback',
            'https://chatgpt.com/connector_platform_oauth_redirect'])]
        results['source'] = 'https://developers.openai.com/plugins/build/auth'
        (evidence/'clients.json').write_text(json.dumps(results,indent=2)+'\n')
        print('PASS official TypeScript and Python OAuth, 390px consent, tools/list, tools/call, expired access and rotating refresh')
        print('PASS three hosted callback replays, deleted registrations and wrong-resource/PKCE/reused-code controls')
    except Exception:
        print('Private fixture diagnostics: '+str(work),file=sys.stderr)
        raise
    finally:
        run.close(False)


if __name__ == '__main__':
    main()
