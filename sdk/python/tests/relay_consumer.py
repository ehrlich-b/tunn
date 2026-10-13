"""Separate public-API consumer driven by the disposable Go relay contract."""
import asyncio
from dataclasses import replace
import json
import sys

from tunn import Credentials, Options, ReconnectPolicy, TLSOptions, TunnelError, publish, publish_async, publish_handler, publish_handler_async


def emit(value):
    print(json.dumps(value), flush=True)


cancelled_handlers = 0


async def app(scope, receive, send):
    global cancelled_handlers
    if scope['type'] == 'websocket':
        await receive()
        await send({'type':'websocket.accept'})
        while True:
            event = await receive()
            if event['type'] == 'websocket.disconnect': return
            if event.get('text') is not None:
                await send({'type':'websocket.send', 'text':event['text']})
            elif event.get('bytes') is not None:
                await send({'type':'websocket.send', 'bytes':event['bytes']})
    elif scope['path'] == '/stream':
        await send({'type':'http.response.start','status':200,'headers':[(b'content-type',b'text/event-stream')]})
        await send({'type':'http.response.body','body':b'data: prefix\n\n','more_body':True})
        try:
            while (await receive())['type'] != 'http.disconnect': pass
        finally:
            cancelled_handlers += 1
    else:
        body = bytearray()
        while True:
            event = await receive()
            body.extend(event.get('body', b''))
            if not event.get('more_body'): break
        headers = {k.decode():v.decode() for k,v in scope['headers']}
        result = {'path':scope['path'], 'query':scope['query_string'].decode(), 'body':body.decode(),
                  'auth':headers.get('authorization',''), 'tunnAuth':headers.get('tunn-authorization',''),
                  'host':headers.get('host',''), 'proto':headers.get('x-forwarded-proto','')}
        await send({'type':'http.response.start','status':200,'headers':[
            (b'content-type',b'application/json'),(b'set-cookie',b'one=one; Path=/'),(b'set-cookie',b'two=two; Path=/')]})
        await send({'type':'http.response.body','body':json.dumps(result).encode()})


def wsgi(environ, start_response):
    body = environ['wsgi.input'].read(int(environ.get('CONTENT_LENGTH') or 0)).decode()
    result = {'path':environ['PATH_INFO'], 'query':environ['QUERY_STRING'], 'body':body,
              'auth':environ.get('HTTP_AUTHORIZATION',''),'tunnAuth':environ.get('HTTP_TUNN_AUTHORIZATION',''),
              'host':environ.get('HTTP_HOST',''),'proto':environ.get('HTTP_X_FORWARDED_PROTO','')}
    start_response('200 OK', [('Content-Type','application/json'),('Set-Cookie','one=one; Path=/'),('Set-Cookie','two=two; Path=/')])
    return [json.dumps(result).encode()]


def options(config):
    return Options(origin=config.get('origin',''), name='websocket-fixture',
        server_addr=config['server_addr'], credentials=Credentials(**config['credentials']),
        public=config.get('public',False), allowed_emails=tuple(config.get('allowed_emails') or []),
        relay_tls=TLSOptions(root_ca_pem=config['ca_pem']), connect_timeout=1,
        reconnect=ReconnectPolicy(max_attempts=3,initial_delay=.01,max_delay=.04))


async def run_async(config):
    opts = options(config)
    mcp_manager = None
    if config['mode'] == 'mcp':
        from mcp.server.fastmcp import FastMCP
        from mcp.server.transport_security import TransportSecuritySettings
        mcp = FastMCP('fixture',stateless_http=True,json_response=True,
            transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=True,
                allowed_hosts=['websocket-fixture.tunn.test'], allowed_origins=['https://websocket-fixture.tunn.test']))
        @mcp.tool()
        def add(a: int, b: int) -> int:
            return a + b
        handler = mcp.streamable_http_app()
        mcp_manager = mcp.session_manager.run()
        await mcp_manager.__aenter__()
    else:
        handler = app
    tunnel = None
    try:
        if config['mode'] == 'async-origin':
            tunnel = await publish_async(opts)
        else:
            tunnel = await publish_handler_async(handler, opts)
        url = await tunnel.wait_ready(5)
        emit({'phase':'ready','url':url,'name':tunnel.name})
        while True:
            command = json.loads(await asyncio.to_thread(sys.stdin.readline))
            if command['op'] in ('close','cancel'):
                try:
                    await (tunnel.close() if command['op'] == 'close' else tunnel.cancel())
                    code = ''
                except TunnelError as e: code = e.code
                events = [e.state async for e in tunnel.events()]
                emit({'phase':'closed','code':code,'events':events,'cancelled_handlers':cancelled_handlers})
                return
            if command['op'] == 'status':
                emit({'phase':'status','state':tunnel.status.state,'url':tunnel.url})
    except TunnelError as e:
        emit({'phase':'error','code':e.code})
    finally:
        if tunnel is not None:
            try: await tunnel.close()
            except TunnelError: pass
        if mcp_manager is not None: await mcp_manager.__aexit__(None,None,None)


def run_sync(config):
    opts = options(config)
    tunnel = None
    try:
        if config['mode'] == 'sync-origin':
            tunnel = publish(opts)
        else:
            tunnel = publish_handler(wsgi if config['mode'] == 'wsgi' else app, opts,
                                     interface='wsgi' if config['mode'] == 'wsgi' else 'asgi')
        emit({'phase':'ready','url':tunnel.wait_ready(5),'name':tunnel.name})
        for line in sys.stdin:
            command = json.loads(line)
            if command['op'] in ('close','cancel'):
                try:
                    (tunnel.close() if command['op'] == 'close' else tunnel.cancel())
                    code = ''
                except TunnelError as e: code = e.code
                emit({'phase':'closed','code':code,'events':[e.state for e in tunnel.events()]})
                return
            if command['op'] == 'status':
                emit({'phase':'status','state':tunnel.status.state,'url':tunnel.url})
    except TunnelError as e:
        emit({'phase':'error','code':e.code})
    finally:
        if tunnel is not None:
            try: tunnel.close()
            except TunnelError: pass


if __name__ == '__main__':
    config = json.loads(sys.stdin.readline())
    if config['mode'] in ('sync-origin','sync-handler','wsgi'):
        run_sync(config)
    else:
        asyncio.run(run_async(config))
