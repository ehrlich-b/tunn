import asyncio
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import uvicorn

from tunn import Options, ReconnectPolicy, TunnelError, publish_handler_async
from test_lifecycle import SCRIPT


class LifespanTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.helper = Path(self.temp.name) / 'helper'
        self.helper.write_text('#!' + sys.executable + '\n' + SCRIPT)
        self.helper.chmod(0o700)

    async def test_startup_precedes_ready_and_shutdown_runs_once(self):
        started = False
        shutdowns = 0

        async def app(scope, receive, send):
            nonlocal started, shutdowns
            if scope['type'] == 'lifespan':
                self.assertEqual((await receive())['type'], 'lifespan.startup')
                started = True
                scope['state']['resource'] = b'ready-resource'
                await send({'type': 'lifespan.startup.complete'})
                self.assertEqual((await receive())['type'], 'lifespan.shutdown')
                shutdowns += 1
                await send({'type': 'lifespan.shutdown.complete'})
            else:
                await send({'type': 'http.response.start', 'status': 200, 'headers': []})
                await send({'type': 'http.response.body', 'body': scope['state']['resource']})

        tunnel = await publish_handler_async(app, Options(name='fixture'), helper=self.helper, lifespan='on')
        try:
            await tunnel.wait_ready(2)
            self.assertTrue(started, 'relay readiness was published before ASGI startup')
            reader, writer = await asyncio.open_connection(*tunnel._handler_socket.getsockname())
            try:
                writer.write(b'GET / HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n')
                await writer.drain()
                self.assertIn(b'ready-resource', await asyncio.wait_for(reader.read(), 2))
            finally:
                writer.close()
                await writer.wait_closed()
            await asyncio.gather(*(tunnel.close() for _ in range(4)))
            await tunnel.close()
            self.assertEqual(shutdowns, 1)
        finally:
            await tunnel.close()

    async def test_startup_blocks_helper_publication(self):
        app = Application()
        app.release_startup.clear()
        startup = asyncio.create_task(self.publish(app))
        try:
            await asyncio.wait_for(app.entered.wait(), 2)
            self.assertFalse(startup.done())
            self.assertFalse(self.helper.with_name('pid').exists())
            app.release_startup.set()
            tunnel = await asyncio.wait_for(startup, 2)
            try:
                await tunnel.wait_ready(2)
                self.assertTrue(app.started)
            finally:
                await tunnel.close()
            self.assert_clean(app)
        finally:
            if not startup.done():
                startup.cancel()
                await asyncio.gather(startup, return_exceptions=True)

    async def publish(self, app, **kwargs):
        return await publish_handler_async(app, Options(name=kwargs.pop('name', 'fixture')),
            helper=self.helper, lifespan='on', **kwargs)

    def assert_clean(self, app, shutdowns=1):
        self.assertEqual(app.shutdowns, shutdowns)
        self.assertTrue(app.finished.is_set())
        self.assertTrue(app.task.done())
        self.assertFalse(app.resource_open)

    async def test_failed_startup_never_launches_helper(self):
        for failure in ('failed', 'exception', 'unsupported', 'no-acknowledgement'):
            with self.subTest(failure=failure):
                app = Application(failure=failure)
                with self.assertRaises(TunnelError) as caught:
                    await asyncio.wait_for(self.publish(app), 2)
                self.assertEqual(caught.exception.code, 'handler_failed')
                self.assertNotIn('application-secret', str(caught.exception))
                self.assertFalse(self.helper.with_name('pid').exists())
                self.assert_clean(app, shutdowns=0)

    async def test_cancellation_during_startup_joins_application_and_listener(self):
        for mode in ('task', 'event', 'deadline', 'startup-timeout'):
            with self.subTest(mode=mode):
                app = Application()
                app.release_startup.clear()
                event = asyncio.Event()
                kwargs = {'cancel_event': event} if mode == 'event' else {}
                if mode == 'deadline':
                    kwargs['lifetime_timeout'] = .15
                # Capture the real server/socket while still running Uvicorn.
                servers = []
                original = uvicorn.Server.serve
                async def serve(server, sockets=None):
                    servers.append((server, sockets[0]))
                    await original(server, sockets=sockets)
                with patch.object(uvicorn.Server, 'serve', serve):
                    startup = asyncio.create_task(self.publish(app, **kwargs))
                    try:
                        await asyncio.wait_for(app.entered.wait(), 2)
                        if mode == 'task':
                            startup.cancel()
                        if mode == 'event':
                            event.set()
                        with self.assertRaises((asyncio.CancelledError, TunnelError)) as caught:
                            await asyncio.wait_for(startup, 7)
                        if mode != 'task':
                            self.assertEqual(caught.exception.code, {
                                'event': 'cancelled', 'deadline': 'deadline_exceeded',
                                'startup-timeout': 'handler_failed'}[mode])
                        self.assert_clean(app, shutdowns=0)
                        self.assertFalse(self.helper.with_name('pid').exists())
                        self.assertEqual(len(servers), 1)
                        self.assertEqual(servers[0][1].fileno(), -1)
                    finally:
                        if not startup.done():
                            startup.cancel()
                            await asyncio.gather(startup, return_exceptions=True)

    async def test_cancellation_after_startup_before_listener_sends_shutdown(self):
        app = Application()
        binding = asyncio.Event()
        loop = asyncio.get_running_loop()
        async def create_server(*args, **kwargs):
            binding.set()
            await asyncio.Event().wait()
        with patch.object(loop, 'create_server', create_server):
            startup = asyncio.create_task(self.publish(app))
            try:
                await asyncio.wait_for(binding.wait(), 2)
                startup.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await asyncio.wait_for(startup, 2)
                self.assert_clean(app)
                self.assertFalse(self.helper.with_name('pid').exists())
            finally:
                if not startup.done():
                    startup.cancel()
                    await asyncio.gather(startup, return_exceptions=True)

    async def test_cancellation_during_helper_startup_joins_all_resources(self):
        for mode in ('task', 'event', 'deadline'):
            with self.subTest(mode=mode):
                pid_file = self.helper.with_name('pid')
                pid_file.unlink(missing_ok=True)
                app = Application()
                event = asyncio.Event()
                startup = asyncio.create_task(self.publish(app, name='startup-wait',
                    cancel_event=event if mode == 'event' else None,
                    lifetime_timeout=.3 if mode == 'deadline' else None))
                try:
                    async with asyncio.timeout(2):
                        while not pid_file.exists():
                            await asyncio.sleep(.005)
                    pid = int(pid_file.read_text())
                    if mode == 'task':
                        startup.cancel()
                    if mode == 'event':
                        event.set()
                    with self.assertRaises((asyncio.CancelledError, TunnelError)) as caught:
                        await asyncio.wait_for(startup, 3)
                    if mode != 'task':
                        self.assertEqual(caught.exception.code, 'cancelled' if mode == 'event' else 'deadline_exceeded')
                    self.assert_clean(app)
                    with self.assertRaises(ProcessLookupError):
                        os.kill(pid, 0)
                finally:
                    if not startup.done():
                        startup.cancel()
                        await asyncio.gather(startup, return_exceptions=True)

    async def test_helper_launch_failure_shuts_down_started_application(self):
        app = Application()
        # A file that exists but cannot be executed passes helper-path validation.
        self.helper.chmod(0o600)
        with self.assertRaises(TunnelError) as caught:
            await self.publish(app)
        self.assertEqual(caught.exception.code, 'helper_unavailable')
        self.assert_clean(app)

    async def test_real_helper_connection_failure_shuts_down_application(self):
        app = Application()
        tunnel = await publish_handler_async(app,
            Options(name='fixture', server_addr='127.0.0.1:1', connect_timeout=.05,
                    reconnect=ReconnectPolicy(0)),
            helper=os.environ['TUNN_PYTHON_HELPER'], lifespan='on')
        with self.assertRaises(TunnelError) as caught:
            await tunnel.wait(3)
        self.assertEqual(caught.exception.code, 'connection_failed')
        with self.assertRaises(TunnelError):
            await tunnel.close()
        self.assert_clean(app)
        self.assertEqual(tunnel._handler_socket.fileno(), -1)
        self.assertIsNotNone(tunnel._process.returncode)

    async def test_cancelled_lifetime_shuts_down_once_and_closes_listener(self):
        app = Application()
        tunnel = await self.publish(app)
        address = tunnel._handler_socket.getsockname()
        await tunnel.wait_ready(2)
        with self.assertRaises(TunnelError) as caught:
            await tunnel.cancel()
        self.assertEqual(caught.exception.code, 'cancelled')
        with self.assertRaises(TunnelError):
            await tunnel.close()
        self.assert_clean(app)
        self.assertTrue(tunnel._server_task.done())
        self.assertIsNotNone(tunnel._process.returncode)
        with self.assertRaises(OSError):
            await asyncio.open_connection(*address)

    async def test_cancelled_close_waits_for_shutdown_cleanup(self):
        app = Application()
        app.release_shutdown.clear()
        tunnel = await self.publish(app)
        close = asyncio.create_task(tunnel.close())
        try:
            await asyncio.wait_for(app.shutting_down.wait(), 2)
            close.cancel()
            await asyncio.sleep(0)
            self.assertFalse(close.done())
            app.release_shutdown.set()
            with self.assertRaises(asyncio.CancelledError):
                await asyncio.wait_for(close, 2)
            await tunnel.close()
            self.assert_clean(app)
            self.assertTrue(tunnel.done)
        finally:
            app.release_shutdown.set()
            await tunnel.close()
            await asyncio.gather(close, return_exceptions=True)

    async def test_default_and_explicit_off_preserve_external_ownership(self):
        for kwargs in ({}, {'lifespan': 'off'}):
            with self.subTest(kwargs=kwargs):
                app = Application()
                tunnel = await publish_handler_async(app, Options(name='fixture'), helper=self.helper, **kwargs)
                await tunnel.wait_ready(2)
                await tunnel.close()
                self.assertFalse(app.entered.is_set())
                self.assertEqual(app.shutdowns, 0)

    async def test_shutdown_joins_async_cleanup_after_acknowledgement(self):
        app = Application()
        cleaning = asyncio.Event()
        release = asyncio.Event()
        cleaned = False

        async def handler(scope, receive, send):
            nonlocal cleaned
            try:
                await app(scope, receive, send)
            finally:
                cleaning.set()
                await release.wait()
                cleaned = True

        tunnel = await self.publish(handler)
        close = asyncio.create_task(tunnel.close())
        try:
            await asyncio.wait_for(cleaning.wait(), 2)
            await asyncio.sleep(0)
            self.assertFalse(close.done())
            release.set()
            await asyncio.wait_for(close, 2)
            self.assertTrue(cleaned)
            self.assert_clean(app)
        finally:
            release.set()
            await tunnel.close()
            await asyncio.gather(close, return_exceptions=True)

    async def test_invalid_modes_and_wsgi_ownership_are_rejected(self):
        for kwargs in ({'lifespan': 'auto'}, {'lifespan': True}, {'lifespan': None},
                       {'lifespan': 'on', 'interface': 'wsgi'}):
            with self.subTest(kwargs=kwargs), self.assertRaises(TunnelError) as caught:
                await publish_handler_async(Application(), Options(name='fixture'), helper=self.helper, **kwargs)
            self.assertEqual(caught.exception.code, 'invalid_options')
        self.assertFalse(self.helper.with_name('pid').exists())


class Application:
    def __init__(self, failure=None):
        self.failure = failure
        self.entered = asyncio.Event()
        self.finished = asyncio.Event()
        self.shutting_down = asyncio.Event()
        self.release_startup = asyncio.Event()
        self.release_startup.set()
        self.release_shutdown = asyncio.Event()
        self.release_shutdown.set()
        self.task = None
        self.started = False
        self.resource_open = False
        self.shutdowns = 0

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'lifespan':
            await send({'type': 'http.response.start', 'status': 200, 'headers': []})
            await send({'type': 'http.response.body', 'body': b'ok'})
            return
        self.task = asyncio.current_task()
        self.resource_open = True
        self.entered.set()
        try:
            if self.failure == 'unsupported':
                raise NotImplementedError('application-secret')
            assert (await receive())['type'] == 'lifespan.startup'
            await self.release_startup.wait()
            if self.failure == 'no-acknowledgement':
                return
            if self.failure == 'failed':
                await send({'type': 'lifespan.startup.failed', 'message': 'application-secret'})
                return
            if self.failure == 'exception':
                raise RuntimeError('application-secret')
            self.started = True
            await send({'type': 'lifespan.startup.complete'})
            assert (await receive())['type'] == 'lifespan.shutdown'
            self.shutdowns += 1
            self.shutting_down.set()
            await self.release_shutdown.wait()
            await send({'type': 'lifespan.shutdown.complete'})
        finally:
            await asyncio.sleep(0)
            self.resource_open = False
            self.finished.set()
