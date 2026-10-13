"""Thread-safe synchronous facade; each tunnel owns one background loop."""
import asyncio
from collections import deque
from concurrent.futures import Future, CancelledError
import threading
import time

from ._async import publish_async, publish_handler_async
from ._async_helpers import joined
from ._options import TunnelError


class Tunnel:
    """Sync publisher. Construct with publish or publish_handler."""

    def __init__(self, factory, options, kwargs):
        self._condition = threading.Condition()
        self._events = deque(maxlen=16)
        self._finished = threading.Event()
        self._startup = Future()
        self._inner = None
        self._loop = None
        self._owner_task = None
        self._startup_interrupted = threading.Event()
        self._thread = threading.Thread(target=self._run, args=(factory, options, kwargs),
                                        name="tunn-publisher", daemon=True)
        self._thread.start()
        try:
            self._startup.result()
        except BaseException:
            self._startup_interrupted.set()
            if self._loop is not None:
                try:
                    self._loop.call_soon_threadsafe(self._interrupt_startup)
                except RuntimeError:
                    pass  # the thread has already finished its loop
            self._thread.join()
            raise

    def _interrupt_startup(self):
        if self._owner_task is not None:
            self._owner_task.cancel()

    def _notify(self, event):
        with self._condition:
            self._events.append(event)
            self._condition.notify_all()

    def _run(self, factory, options, kwargs):
        async def run():
            self._loop = asyncio.get_running_loop()
            self._owner_task = asyncio.current_task()
            if self._startup_interrupted.is_set():
                raise asyncio.CancelledError
            cancel_event = kwargs.pop("cancel_event", None)
            inner_kwargs = dict(kwargs)
            if cancel_event is not None:
                inner_kwargs["cancel_event"] = asyncio.Event()
                if cancel_event.is_set():
                    inner_kwargs["cancel_event"].set()
                async def relay_cancel():
                    while not cancel_event.is_set():
                        await asyncio.sleep(0.025)
                    inner_kwargs["cancel_event"].set()
                cancel_watch = asyncio.create_task(relay_cancel())
            else:
                cancel_watch = None
            try:
                self._inner = await factory(options, **inner_kwargs)
                with self._condition:
                    while not self._inner._queue.empty():
                        self._events.append(self._inner._queue.get_nowait())
                    self._inner._sync_notify = self._notify
                self._startup.set_result(None)
                if cancel_watch is not None:
                    if not self._inner.done:
                        self._inner._watchers.append(cancel_watch)
                    else:
                        cancel_watch.cancel()
                await self._inner._done.wait()
            finally:
                if self._inner is not None:
                    try:
                        await joined(asyncio.create_task(self._inner.close()))
                    except TunnelError:
                        pass  # the retained result belongs to wait/close callers
        try:
            asyncio.run(run())
        except BaseException as exc:
            if not self._startup.done():
                self._startup.set_exception(exc)
        finally:
            self._finished.set()
            with self._condition:
                self._condition.notify_all()

    @property
    def name(self):
        return self._inner.name

    @property
    def url(self):
        return self._inner.url

    @property
    def status(self):
        return self._inner.status

    @property
    def done(self):
        return self._finished.is_set()

    def wait_ready(self, timeout=None):
        deadline = None if timeout is None else time.monotonic() + timeout
        with self._condition:
            while not self._inner._ready_url and not self.done:
                remaining = None if deadline is None else deadline - time.monotonic()
                if remaining is not None and remaining <= 0:
                    raise TimeoutError
                self._condition.wait(remaining)
        if self._inner._ready_url:
            return self._inner._ready_url
        if self._inner._result:
            raise self._inner._result
        raise TunnelError("cancelled")

    def wait(self, timeout=None):
        if not self._finished.wait(timeout):
            raise TimeoutError
        self._thread.join()
        if self._inner._result:
            raise self._inner._result

    def events(self):
        """Single-consumer iterator. Slow readers retain the last 16 events."""
        while True:
            with self._condition:
                while not self._events and not self.done:
                    self._condition.wait()
                if not self._events:
                    return
                event = self._events.popleft()
            yield event
            if event.state == "closed":
                return

    def _stop(self, op):
        if threading.current_thread() is self._thread:
            raise RuntimeError("tunn: blocking close cannot run on the publisher loop")
        with self._condition:
            if not self._inner.done:
                future = asyncio.run_coroutine_threadsafe(self._inner._request_stop(op), self._loop)
            else:
                future = None
        if future is not None:
            # Completion of the publisher may stop its loop before this small
            # submission finishes. Joining the thread is the ownership barrier.
            try:
                future.result(timeout=6)
            except (TimeoutError, CancelledError):
                pass
        self.wait()

    def close(self):
        self._stop("close")

    def cancel(self):
        self._stop("cancel")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            self.close()
        except TunnelError:
            if exc is None:
                raise


def _sync_args(kwargs):
    cancel_event = kwargs.get("cancel_event")
    if cancel_event is not None and not isinstance(cancel_event, threading.Event):
        raise TunnelError("invalid_options")


def publish(options, *, helper=None, cancel_event=None, lifetime_timeout=None):
    """Return after local validation; use wait_ready before announcing the URL."""
    kwargs = dict(helper=helper, cancel_event=cancel_event, lifetime_timeout=lifetime_timeout)
    _sync_args(kwargs)
    return Tunnel(publish_async, options, kwargs)


def publish_handler(handler, options, *, interface="asgi", helper=None, cancel_event=None, lifetime_timeout=None):
    """Run an ASGI or WSGI callable on a loopback socket owned by this tunnel."""
    kwargs = dict(interface=interface, helper=helper, cancel_event=cancel_event, lifetime_timeout=lifetime_timeout)
    _sync_args(kwargs)
    async def start(opts, **args):
        return await publish_handler_async(handler, opts, **args)
    return Tunnel(start, options, kwargs)
