import asyncio
from dataclasses import replace
from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock, patch

from tunn import Options, ReconnectPolicy, TunnelError, WebSocketOptions, publish_async, publish_handler_async


class IntLookalike(int):
    pass


class FloatLookalike(float):
    pass


class EqualToInt(type):
    def __eq__(cls, other):
        return other is int


class DeceptiveInt(int, metaclass=EqualToInt):
    pass


class NumericOptions(IsolatedAsyncioTestCase):
    async def test_numeric_matrix_before_spawn_or_listener(self):
        base = Options(origin='http://localhost:8080')
        duration = ('connect_timeout', 'http_timeout', 'initial_delay', 'max_delay',
                    'idle_timeout', 'keepalive_interval', 'lifetime_timeout')
        integers = ('max_attempts', 'max_message_size')

        def make(field, value, handler):
            options = replace(base, origin='' if handler else base.origin)
            if field in ('initial_delay', 'max_delay', 'max_attempts'):
                # Permit each delay's upper boundary independently.
                reconnect = ReconnectPolicy(initial_delay=0, max_delay=365 * 24 * 3600)
                options = replace(options, reconnect=replace(reconnect, **{field: value}))
            elif field in ('idle_timeout', 'keepalive_interval', 'max_message_size'):
                options = replace(options, websocket=replace(WebSocketOptions(), **{field: value}))
            elif field != 'lifetime_timeout':
                options = replace(options, **{field: value})
            return options, ({'lifetime_timeout': value} if field == 'lifetime_timeout' else {})

        async def run(field, value, valid, handler):
            options, kwargs = make(field, value, handler)
            async def start_factory(factory, *args):
                return await factory()

            target = 'tunn._async._open_handler' if handler else 'tunn._async._start'
            with patch('tunn._async._owned_start', side_effect=start_factory), \
                 patch(target, new_callable=AsyncMock, return_value='fake helper') as spawn, \
                 patch('tunn._async.socket.socket') as listener, \
                 patch('builtins.open') as file_open:
                call = (publish_handler_async(lambda *args: None, options, **kwargs) if handler
                        else publish_async(options, **kwargs))
                if valid:
                    self.assertEqual(await call, 'fake helper')
                    self.assertEqual(spawn.await_count, 1)
                else:
                    with self.assertRaises(TunnelError) as caught:
                        await call
                    self.assertEqual(caught.exception.code, 'invalid_options')
                    self.assertEqual(spawn.await_count, 0)
                listener.assert_not_called()
                file_open.assert_not_called()

        for field in duration + integers:
            invalid = [True, False, float('nan'), float('inf'), float('-inf'), 10**1000,
                       -1, IntLookalike(1), FloatLookalike(1), DeceptiveInt(1)]
            if field in integers:
                invalid += [-0.0, 1.0, 2**31]
                valid = [0, 1, 2**31 - 1]
                if field == 'max_message_size':
                    invalid += [0, 100 * 1024 * 1024 + 1, 2**31 - 1]
                    valid = [1, 100 * 1024 * 1024]
            else:
                invalid += [365 * 24 * 3600 + 1]
                valid = [-0.0, 0, 1, 365 * 24 * 3600]
                if field == 'lifetime_timeout':
                    invalid += [-0.0, 0]
                    valid = [0.001, 1, 365 * 24 * 3600]
            for handler in (False, True):
                for value in invalid:
                    with self.subTest(field=field, value=repr(value), handler=handler, valid=False):
                        await run(field, value, False, handler)
                for value in valid:
                    with self.subTest(field=field, value=repr(value), handler=handler, valid=True):
                        await run(field, value, True, handler)

    async def test_reconnect_inversion_before_spawn(self):
        for initial, maximum in ((2, 1), (31, 0), (365 * 24 * 3600, 1)):
            for handler in (False, True):
                options = Options(origin='' if handler else 'http://localhost:8080',
                                  reconnect=ReconnectPolicy(initial_delay=initial, max_delay=maximum))
                with self.subTest(initial=initial, maximum=maximum, handler=handler), \
                     patch('tunn._async._owned_start', new_callable=AsyncMock) as spawn, \
                     patch('tunn._async.socket.socket') as listener, patch('builtins.open') as file_open:
                    with self.assertRaises(TunnelError) as caught:
                        if handler:
                            await publish_handler_async(lambda *args: None, options)
                        else:
                            await publish_async(options)
                    self.assertEqual(caught.exception.code, 'invalid_options')
                    spawn.assert_not_awaited()
                    listener.assert_not_called()
                    file_open.assert_not_called()
