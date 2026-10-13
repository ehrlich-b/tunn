"""Managed WSGI adapter with cooperative request cancellation and ownership."""
import asyncio
import threading

from ._async_helpers import joined


class ManagedWSGI:
    def __init__(self, application):
        from a2wsgi import WSGIMiddleware
        self.application = application
        self.middleware = WSGIMiddleware(self._application, workers=4, send_queue_size=4)
        self._requests = set()

    def _application(self, environ, start_response):
        cancelled = environ['asgi.scope']['tunn.cancelled']
        # WSGI applications may check this event while doing cooperative work.
        environ['tunn.cancelled'] = cancelled
        iterable = self.application(environ, start_response)
        try:
            for chunk in iterable:
                if cancelled.is_set():
                    break
                yield chunk
        finally:
            close = getattr(iterable, 'close', None)
            if close is not None:
                close()

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            await self.middleware(scope, receive, send)
            return
        cancelled = threading.Event()
        stopped = asyncio.Event()
        scope = dict(scope, **{'tunn.cancelled': cancelled})

        def stop():
            cancelled.set()
            stopped.set()

        async def receiving():
            if stopped.is_set():
                return {'type': 'http.disconnect'}
            incoming = asyncio.create_task(receive())
            stopping = asyncio.create_task(stopped.wait())
            try:
                complete, _ = await asyncio.wait([incoming, stopping], return_when=asyncio.FIRST_COMPLETED)
                if incoming in complete:
                    message = incoming.result()
                    if message['type'] == 'http.disconnect':
                        stop()
                    return message
                return {'type': 'http.disconnect'}
            finally:
                incoming.cancel()
                stopping.cancel()
                await asyncio.gather(incoming, stopping, return_exceptions=True)

        failure = None

        async def sending(message):
            nonlocal failure
            if failure is not None:
                return
            try:
                await send(message)
            except (OSError, RuntimeError) as exc:
                # Keep draining the middleware queue so a worker cannot become
                # stranded in its bounded send queue after network closure.
                failure = exc
                stop()

        task = asyncio.create_task(self.middleware(scope, receiving, sending))
        self._requests.add(task)
        try:
            try:
                await asyncio.shield(task)
            except asyncio.CancelledError:
                stop()
                # Shield the sender until the cooperative WSGI worker returns.
                # Its response iterable is then closed before executor teardown.
                try:
                    await joined(task)
                except asyncio.CancelledError:
                    pass  # joined completed the cooperative worker first
                return
            if failure is not None:
                raise failure
        finally:
            self._requests.discard(task)

    async def close(self):
        if self._requests:
            await asyncio.gather(*self._requests, return_exceptions=True)
        await asyncio.to_thread(self.middleware.executor.shutdown, wait=True, cancel_futures=True)
