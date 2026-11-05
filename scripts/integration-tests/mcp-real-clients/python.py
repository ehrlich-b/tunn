"""Official Python SDK OAuth provider and Streamable HTTP session, no protocol substitutes."""
import asyncio
import importlib.metadata
import json
import os
import socket
import sys
import time
from urllib.parse import parse_qs, urlsplit

import httpx2
from mcp import ClientSession
from mcp.client.auth import OAuthClientProvider
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.auth import AuthorizationCodeResult, OAuthClientMetadata


def control(message):
    print(json.dumps(message), flush=True)
    return json.loads(sys.stdin.readline())


class Storage:
    tokens = None
    client = None
    registrations = 0

    async def get_tokens(self): return self.tokens
    async def set_tokens(self, value): self.tokens = value
    async def get_client_info(self): return self.client
    async def set_client_info(self, value):
        self.client = value
        self.registrations += 1


async def main():
    endpoint = sys.argv[1]
    base_host = urlsplit(endpoint).hostname.removeprefix('tools.')
    original = socket.getaddrinfo

    def loopback(host, port, *args, **kwargs):
        name = host.decode() if isinstance(host, bytes) else host
        if name not in (base_host, 'tools.' + base_host, '127.0.0.1'):
            raise RuntimeError('non-fixture DNS refused')
        return original('127.0.0.1', port, *args, **kwargs)
    socket.getaddrinfo = loopback
    storage = Storage()
    callback = None
    redirect_uri = 'http://127.0.0.1:17892/callback'
    observations = []

    async def redirect(url):
        nonlocal callback
        q = parse_qs(urlsplit(url).query)
        assert q['code_challenge_method'] == ['S256']
        assert q['resource'] == [endpoint]
        response = await asyncio.to_thread(control, {'event':'authorize','url':url,'callback':redirect_uri})
        callback = parse_qs(urlsplit(response['callback']).query)

    async def receive_callback():
        return AuthorizationCodeResult(code=callback['code'][0],state=callback['state'][0],iss=callback['iss'][0])

    async def observe(response):
        request = response.request
        form = parse_qs(request.content.decode()) if urlsplit(str(request.url)).path == '/oauth/token' else {}
        observations.append({'path':request.url.path,'status':response.status_code,'grant':form.get('grant_type',[None])[0],'resource':form.get('resource',[None])[0]})

    provider = OAuthClientProvider(endpoint, OAuthClientMetadata(
        client_name='Official Python SDK',redirect_uris=[redirect_uri],
        grant_types=['authorization_code','refresh_token'],response_types=['code'],
        token_endpoint_auth_method='none',scope='mcp'),storage,redirect,receive_callback)
    async with httpx2.AsyncClient(auth=provider,verify=os.environ['SSL_CERT_FILE'],trust_env=False,event_hooks={'response':[observe]}) as http:
        async with streamable_http_client(endpoint,http_client=http) as streams:
            async with ClientSession(streams[0],streams[1]) as session:
                await session.initialize()
                assert [t.name for t in (await session.list_tools()).tools] == ['echo']
                result = await session.call_tool('echo',{'message':'python-before-refresh'})
                assert result.content[0].text == 'python-before-refresh'
                old = storage.tokens.model_copy()
                await asyncio.to_thread(control, {'event':'expire','access':old.access_token})
                # Advance only the SDK's cached expiry, matching the expired fixture grant.
                provider.context.token_expiry_time = time.time() - 1
                assert [t.name for t in (await session.list_tools()).tools] == ['echo']
                assert storage.tokens.access_token != old.access_token
                assert storage.tokens.refresh_token != old.refresh_token
                result = await session.call_tool('echo',{'message':'python-after-refresh'})
                assert result.content[0].text == 'python-after-refresh'
    assert storage.registrations == 1
    assert any(x['path']=='/oauth/register' and x['status']==201 for x in observations)
    assert any(x['grant']=='refresh_token' and x['status']==200 for x in observations)
    print(json.dumps({'event':'result','sdk':'mcp','version':importlib.metadata.version('mcp'),'registration':True,'pkce':True,'tools_list':True,'tools_call':True,'refresh':True,'refresh_rotated':True,'observations':observations}),flush=True)


if __name__ == '__main__':
    asyncio.run(main())
