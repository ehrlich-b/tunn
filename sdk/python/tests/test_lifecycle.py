import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import os
import logging
import time
from unittest.mock import patch
from concurrent.futures import Future
from pathlib import Path
import signal
import sys
import tempfile
import threading
import unittest

from tunn import Credentials, Options, ReconnectPolicy, TLSOptions, TunnelError, publish, publish_async, publish_handler_async

# A bounded process-boundary fixture: no relay claims are made by these tests.
SCRIPT = r'''
import json, sys, os
from pathlib import Path
start = json.loads(sys.stdin.readline())
name = start['options']['name'] or 'fixture'
Path(__file__).with_name('pid').write_text(str(os.getpid()))
if name == 'startup-wait':
    Path(__file__).with_name('pid').write_text(str(os.getpid()))
    sys.stdin.readline()
    sys.exit()
if name == 'bad-version':
    print(json.dumps({'kind':'started','version':2,'name':name}), flush=True)
    sys.exit()
if name == 'startup-error':
    print(json.dumps({'kind':'error','code':'invalid_options'}), flush=True)
    sys.exit()
print(json.dumps({'kind':'started','version':1,'name':name}), flush=True)
if name == 'crash':
    sys.exit()
if name == 'registration-error':
    print(json.dumps({'kind':'event','state':'failed','code':'registration_rejected'}), flush=True)
    print(json.dumps({'kind':'event','state':'closed','code':'registration_rejected'}), flush=True)
    sys.exit()
print(json.dumps({'kind':'event','state':'connecting'}), flush=True)
if name != 'no-ready':
    print(json.dumps({'kind':'event','state':'ready','url':'https://'+name+'.fixture.test'}), flush=True)
if name == 'many-events':
    for _ in range(30):
        print(json.dumps({'kind':'event','state':'reconnecting','retry_delay':.01}), flush=True)
for line in sys.stdin:
    op = json.loads(line)['op']
    event = {'kind':'event','state':'closed'}
    if op == 'cancel': event['code'] = 'cancelled'
    print(json.dumps(event), flush=True)
    break
'''


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.helper = Path(self.temp.name) / 'helper'
        self.helper.write_text('#!' + sys.executable + '\n' + SCRIPT)
        self.helper.chmod(0o700)
        self.options = Options(origin='http://127.0.0.1:8080', name='fixture')

    def tearDown(self):
        self.temp.cleanup()

    def test_validation_redaction_and_no_side_effects(self):
        secret = 'credential-sentinel-python'
        credentials = Credentials(secret, secret, 'tunn_ep_' + secret)
        self.assertNotIn(secret, repr(credentials))
        self.assertNotIn(secret, repr(Options(credentials=credentials)))
        invalid = [replace(self.options, origin='http://user:password@localhost'),
                   replace(self.options, origin='http://localhost/path'),
                   replace(self.options, name='-bad'), replace(self.options, name='BAD'),
                   replace(self.options, public=True, allowed_emails=('alice@example.com',)),
                   replace(self.options, credentials=credentials, public=True),
                   replace(self.options, connect_timeout=float('nan')),
                   replace(self.options, reconnect=ReconnectPolicy(-1)),
                   replace(self.options, server_addr='http://relay:443')]
        for options in invalid:
            with self.subTest(options=options), self.assertRaises(TunnelError) as caught:
                publish(options, helper=self.helper)
            self.assertEqual(caught.exception.code, 'invalid_options')
        with self.assertRaises(TunnelError):
            publish(self.options, helper='/nonexistent/helper')
        self.assertFalse(any(t.name == 'tunn-publisher' for t in threading.enumerate()))

    def test_sync_concurrent_close_retains_ready_and_terminal(self):
        tunnel = publish(self.options, helper=self.helper)
        self.assertEqual(tunnel.wait_ready(2), 'https://fixture.fixture.test')
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(lambda _: tunnel.close(), range(8)))
        self.assertTrue(tunnel.done)
        self.assertFalse(tunnel._thread.is_alive())
        self.assertEqual(tunnel.wait_ready(0), tunnel.url)
        tunnel.wait(0)
        events = list(tunnel.events())
        self.assertEqual([e.state for e in events], ['connecting', 'ready', 'closed'])
        self.assertEqual(list(tunnel.events()), [])

    def test_sync_cancel_event_deadline_and_failure_retention(self):
        for mode in ('event', 'deadline', 'cancel', 'registration-error', 'crash'):
            with self.subTest(mode=mode):
                event = threading.Event()
                name = mode if mode in ('registration-error', 'crash') else 'fixture'
                tunnel = publish(replace(self.options, name=name), helper=self.helper,
                    cancel_event=event if mode == 'event' else None,
                    lifetime_timeout=.05 if mode == 'deadline' else None)
                if mode == 'event': event.set()
                if mode == 'cancel':
                    with self.assertRaises(TunnelError): tunnel.cancel()
                with self.assertRaises(TunnelError) as caught: tunnel.wait(3)
                code = {'deadline':'deadline_exceeded','registration-error':'registration_rejected',
                        'crash':'protocol_violation'}.get(mode, 'cancelled')
                self.assertEqual(caught.exception.code, code)
                with self.assertRaises(TunnelError) as retained: tunnel.close()
                self.assertEqual(retained.exception.code, code)
                self.assertEqual(list(tunnel.events())[-1].state, 'closed')

    def test_interrupted_sync_startup_joins_owned_resources(self):
        for name in ('startup-wait', 'fixture'):
            with self.subTest(name=name):
                pid_file = self.helper.with_name('pid')
                pid_file.unlink(missing_ok=True)
                def interrupted(future, *args, **kwargs):
                    deadline = time.monotonic() + 2
                    while not pid_file.exists() or (name == 'fixture' and not future.done()):
                        if time.monotonic() >= deadline:
                            raise AssertionError('fixture did not reach interrupted startup')
                        time.sleep(.005)
                    raise KeyboardInterrupt
                with patch.object(Future, 'result', new=interrupted):
                    with self.assertRaises(KeyboardInterrupt):
                        publish(replace(self.options, name=name), helper=self.helper)
                self.assertFalse(any(t.name == 'tunn-publisher' for t in threading.enumerate()))
                with self.assertRaises(ProcessLookupError): os.kill(int(pid_file.read_text()), 0)

    def test_sync_wait_timeout_does_not_cancel(self):
        tunnel = publish(replace(self.options, name='no-ready'), helper=self.helper)
        try:
            with self.assertRaises(TimeoutError): tunnel.wait_ready(.02)
            with self.assertRaises(TimeoutError): tunnel.wait(.02)
            self.assertFalse(tunnel.done)
        finally:
            tunnel.close()


class AsyncFixture(Fixture, unittest.IsolatedAsyncioTestCase):
    # Reuse fixture setup, not the synchronous tests in this subclass.
    test_validation_redaction_and_no_side_effects = None
    test_sync_concurrent_close_retains_ready_and_terminal = None
    test_sync_cancel_event_deadline_and_failure_retention = None
    test_sync_wait_timeout_does_not_cancel = None
    test_interrupted_sync_startup_joins_owned_resources = None

    async def test_async_bounded_events_and_retained_results(self):
        tunnel = await publish_async(replace(self.options, name='many-events'), helper=self.helper)
        await tunnel.wait_ready(2)
        await asyncio.sleep(.05)
        await asyncio.gather(*(tunnel.close() for _ in range(8)))
        events = [e async for e in tunnel.events()]
        self.assertLessEqual(len(events), 16)
        self.assertEqual(events[-1].state, 'closed')
        self.assertEqual(sum(e.state == 'closed' for e in events), 1)
        self.assertTrue(tunnel.done)
        self.assertIsNotNone(tunnel._process.returncode)
        self.assertEqual(await tunnel.wait_ready(0), tunnel.url)
        await tunnel.wait()

    async def test_async_wait_cancellation_and_context_cleanup(self):
        tunnel = await publish_async(replace(self.options, name='no-ready'), helper=self.helper)
        waiter = asyncio.create_task(tunnel.wait_ready())
        waiter.cancel()
        with self.assertRaises(asyncio.CancelledError): await waiter
        self.assertFalse(tunnel.done)
        with self.assertRaises(asyncio.TimeoutError): await tunnel.wait_ready(.02)
        await tunnel.close()
        async with await publish_async(self.options, helper=self.helper) as owned:
            await owned.wait_ready(2)
        self.assertTrue(owned.done)

    async def test_async_startup_rejection_and_protocol_failures(self):
        for name in ('startup-error', 'bad-version'):
            with self.subTest(name=name), self.assertRaises(TunnelError) as caught:
                await publish_async(replace(self.options, name=name), helper=self.helper)
            self.assertIn(caught.exception.code, ('invalid_options', 'protocol_violation'))

    async def test_cancelled_startup_joins_process(self):
        for mode in ('task', 'event', 'deadline'):
            with self.subTest(mode=mode):
                pid_file = self.helper.with_name('pid')
                pid_file.unlink(missing_ok=True)
                event = asyncio.Event()
                startup = asyncio.create_task(publish_async(replace(self.options, name='startup-wait'), helper=self.helper,
                    cancel_event=event if mode == 'event' else None,
                    lifetime_timeout=.15 if mode == 'deadline' else None))
                async with asyncio.timeout(2):
                    while not pid_file.exists():
                        await asyncio.sleep(.005)
                pid = int(pid_file.read_text())
                if mode == 'task': startup.cancel()
                if mode == 'event': event.set()
                with self.assertRaises((asyncio.CancelledError, TunnelError)) as caught:
                    await startup
                if mode != 'task':
                    self.assertEqual(caught.exception.code, 'cancelled' if mode == 'event' else 'deadline_exceeded')
                with self.assertRaises(ProcessLookupError): os.kill(pid, 0)

    async def test_pre_cancelled_lifetime_has_no_process(self):
        event = asyncio.Event()
        event.set()
        with self.assertRaises(TunnelError) as caught:
            await publish_async(self.options, helper=self.helper, cancel_event=event)
        self.assertEqual(caught.exception.code, 'cancelled')

    async def test_real_helper_verified_tls_and_safe_connection_failure(self):
        real = os.environ['TUNN_PYTHON_HELPER']
        options = replace(self.options, server_addr='127.0.0.1:1', connect_timeout=.05,
                          reconnect=ReconnectPolicy(0), credentials=Credentials('redaction-sentinel'))
        tunnel = await publish_async(options, helper=real)
        with self.assertRaises(TunnelError) as caught: await tunnel.wait(2)
        self.assertEqual(caught.exception.code, 'connection_failed')
        self.assertNotIn('redaction-sentinel', str(caught.exception))
        with self.assertRaises(TunnelError): await tunnel.close()

    async def test_wsgi_iterable_close_workers_and_stream_cancellation(self):
        for streamed in (False, True):
            with self.subTest(streamed=streamed):
                closed = threading.Event()
                workers = set()
                def application(environ, start_response):
                    workers.add(threading.current_thread())
                    start_response('200 OK', [('Content-Type', 'text/plain')])
                    class Body:
                        def __iter__(self):
                            yield b'prefix'
                            if streamed:
                                environ['tunn.cancelled'].wait(3)
                                yield b'suffix'
                        def close(self):
                            closed.set()
                    return Body()
                tunnel = await publish_handler_async(application, Options(name='fixture'),
                    helper=self.helper, interface='wsgi')
                reader, writer = await asyncio.open_connection(*tunnel._handler_socket.getsockname())
                writer.write(b'GET / HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n')
                await writer.drain()
                if streamed:
                    self.assertIn(b'prefix', await asyncio.wait_for(reader.readuntil(b'prefix'), 2))
                else:
                    self.assertIn(b'prefix', await asyncio.wait_for(reader.read(), 2))
                await asyncio.wait_for(tunnel.close(), 4)
                self.assertTrue(closed.is_set())
                self.assertTrue(workers)
                self.assertTrue(all(not t.is_alive() for t in workers))
                writer.close()
                await writer.wait_closed()

    async def test_handler_preserves_logging_and_suppresses_only_own_access_log(self):
        logger = logging.getLogger('uvicorn.access')
        before = (list(logger.handlers), logger.propagate, logger.level)
        records = []
        class Capture(logging.Handler):
            def emit(self, record): records.append(record)
        capture = Capture()
        logger.handlers = [capture]
        logger.propagate = True
        logger.setLevel(logging.INFO)
        async def application(scope, receive, send):
            await send({'type':'http.response.start','status':200,'headers':[]})
            await send({'type':'http.response.body','body':b'ok'})
        tunnel = None
        try:
            snapshot = (list(logger.handlers), logger.propagate, logger.level)
            tunnel = await publish_handler_async(application, Options(name='fixture'), helper=self.helper)
            self.assertEqual((logger.handlers, logger.propagate, logger.level), snapshot)
            reader, writer = await asyncio.open_connection(*tunnel._handler_socket.getsockname())
            writer.write(b'GET /?access-sentinel HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n')
            await writer.drain()
            await reader.read()
            writer.close()
            await writer.wait_closed()
            await tunnel.close()
            self.assertEqual((logger.handlers, logger.propagate, logger.level), snapshot)
            self.assertEqual(records, [])
            logger.info('other-server-access-sentinel')
            self.assertEqual(len(records), 1)
        finally:
            if tunnel is not None: await tunnel.close()
            logger.handlers, logger.propagate, logger.level = before

    async def test_handler_does_not_modify_signals_or_leave_listener(self):
        async def app(scope, receive, send):
            await send({'type':'http.response.start', 'status':200, 'headers':[]})
            await send({'type':'http.response.body', 'body':b'ok'})
        before = signal.getsignal(signal.SIGINT)
        tunnel = await publish_handler_async(app, Options(name='fixture'), helper=self.helper)
        address = tunnel._handler_socket.getsockname()
        await tunnel.wait_ready(2)
        reader, writer = await asyncio.open_connection(*address)
        writer.write(b'GET / HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n')
        await writer.drain()
        self.assertIn(b'ok', await reader.read())
        writer.close()
        await writer.wait_closed()
        await tunnel.close()
        self.assertEqual(signal.getsignal(signal.SIGINT), before)
        with self.assertRaises(OSError): await asyncio.open_connection(*address)
