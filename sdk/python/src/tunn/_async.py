"""Async publisher lifecycle over a revision-matched local helper."""
import asyncio
from contextlib import contextmanager
from dataclasses import asdict, dataclass, replace
import json
import os
from pathlib import Path
import socket

from ._options import Options, TunnelError, validate, _duration
from ._async_helpers import joined as _joined


@dataclass(frozen=True)
class Event:
    state: str
    url: str = ""
    error: TunnelError | None = None
    retry_delay: float = 0.0


def _helper_path(helper):
    if helper is not None:
        path = Path(helper).expanduser().absolute()
    elif os.environ.get("TUNN_PYTHON_HELPER"):
        path = Path(os.environ["TUNN_PYTHON_HELPER"]).expanduser().absolute()
    else:
        # A wheel contains the helper; an editable source tree uses make's bin/.
        package = Path(__file__).resolve().parent
        path = package / "_bin" / ("tunn-python-bridge.exe" if os.name == "nt" else "tunn-python-bridge")
        if not path.is_file():
            if len(package.parents) < 4:
                raise TunnelError("helper_unavailable")
            path = package.parents[3] / "bin" / path.name
    if not path.is_file():
        raise TunnelError("helper_unavailable")
    return str(path)


class AsyncTunnel:
    """One loop-owned publisher. Use publish_async to create it."""

    def __init__(self, process, server=None, server_task=None, handler_socket=None):
        self._process = process
        self._server = server
        self._server_task = server_task
        self._handler_socket = handler_socket
        self.name = ""
        self.url = ""
        self.status = Event("connecting")
        self._queue = asyncio.Queue(maxsize=16)
        self._ready_or_done = asyncio.Event()
        self._ready_url = ""
        self._done = asyncio.Event()
        self._started = asyncio.get_running_loop().create_future()
        self._result = None
        self._stop_requested = None
        self._deadline_expired = False
        self._handler_failed = False
        self._stop_timer = None
        self._sync_notify = None
        self._watchers = []
        self._runner = asyncio.create_task(self._run())

    @property
    def done(self):
        return self._done.is_set()

    def _emit(self, event):
        self.status = event
        if event.state == "ready":
            self.url = event.url
            if not self._ready_url:
                self._ready_url = event.url
                self._ready_or_done.set()
        if self._queue.full():
            self._queue.get_nowait()
        self._queue.put_nowait(event)
        if self._sync_notify is not None:
            self._sync_notify(event)

    async def _run(self):
        terminal = None
        try:
            while raw := await self._process.stdout.readline():
                data = json.loads(raw)
                if not isinstance(data, dict):
                    raise ValueError
                kind = data.get("kind")
                if kind == "started" and not self._started.done() and data.get("version") == 1:
                    if not isinstance(data.get("name"), str) or not data["name"]:
                        raise ValueError
                    self.name = data["name"]
                    self._started.set_result(None)
                elif kind == "error" and not self._started.done():
                    self._result = TunnelError(data.get("code"))
                    break
                elif kind == "event" and self._started.done():
                    state = data.get("state")
                    if state not in ("connecting", "ready", "reconnecting", "failed", "closed"):
                        raise ValueError
                    error = TunnelError(data["code"]) if data.get("code") else None
                    event = Event(state, data.get("url", ""), error, float(data.get("retry_delay", 0)))
                    if state == "closed":
                        terminal = event
                        self._result = (TunnelError("handler_failed") if self._handler_failed else
                                        TunnelError("deadline_exceeded") if self._deadline_expired and error and error.code == "cancelled" else error)
                        break
                    self._emit(event)
                else:
                    raise ValueError
            if terminal is None and self._result is None:
                self._result = TunnelError("protocol_violation")
        except (ValueError, KeyError, TypeError, OSError):
            self._result = TunnelError("protocol_violation")
        finally:
            if not self._started.done():
                self._started.set_result(None)
            self._process.stdin.close()
            try:
                await asyncio.wait_for(self._process.wait(), 5)
            except asyncio.TimeoutError:
                self._process.kill()
                await self._process.wait()
                if self._result is None:
                    self._result = TunnelError("connection_failed")
            if self._stop_timer is not None:
                self._stop_timer.cancel()
            for task in self._watchers:
                task.cancel()
            if self._watchers:
                await asyncio.gather(*self._watchers, return_exceptions=True)
            if self._server is not None:
                self._server.should_exit = True
                # The adapter cancels its ASGI requests after one second.
                await asyncio.gather(self._server_task, return_exceptions=True)
                requests = list(self._server.server_state.tasks)
                for request in requests:
                    request.cancel()
                if requests:
                    await asyncio.gather(*requests, return_exceptions=True)
                self._handler_socket.close()
                adapter = getattr(self._server, "_tunn_wsgi", None)
                if adapter is not None:
                    await adapter.close()
            if self._result and self.status.state != "failed" and self._result.code not in ("cancelled", "deadline_exceeded"):
                self._emit(Event("failed", error=self._result))
            self._emit(Event("closed", error=self._result))
            self._ready_or_done.set()
            self._done.set()

    async def wait_ready(self, timeout=None):
        """Wait for first registration; this wait's cancellation leaves the tunnel alive."""
        if not self._ready_or_done.is_set():
            await asyncio.wait_for(self._ready_or_done.wait(), timeout)
        if self._ready_url:
            return self._ready_url
        if self._result:
            raise self._result
        raise TunnelError("cancelled")

    async def wait(self, timeout=None):
        if not self._done.is_set():
            await asyncio.wait_for(self._done.wait(), timeout)
        if self._result:
            raise self._result

    async def events(self):
        """Single-consumer stream, 16 retained events; closed is delivered last."""
        while not (self.done and self._queue.empty()):
            event = await self._queue.get()
            yield event
            if event.state == "closed":
                return

    async def _request_stop(self, op):
        if self._stop_requested is None and not self.done:
            self._stop_requested = op
            def enforce_stop():
                if self._process.returncode is None:
                    self._process.kill()
            self._stop_timer = asyncio.get_running_loop().call_later(5, enforce_stop)
            try:
                self._process.stdin.write((json.dumps({"op": op}) + "\n").encode())
                await self._process.stdin.drain()
            except (BrokenPipeError, ConnectionResetError, RuntimeError):
                pass

    async def close(self):
        """Stop and join owned resources. Safe for repeated/concurrent calls."""
        await self._request_stop("close")
        await _joined(asyncio.create_task(self.wait()))

    async def cancel(self):
        """Cancel the lifetime; wait/close retain a cancelled terminal error."""
        await self._request_stop("cancel")
        await _joined(asyncio.create_task(self.wait()))

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        try:
            await self.close()
        except TunnelError:
            if exc is None:
                raise


async def _start(options, helper, server=None, server_task=None, handler_socket=None):
    process = None
    tunnel = None
    try:
        process = await asyncio.create_subprocess_exec(_helper_path(helper), stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL, limit=65536)
        tunnel = AsyncTunnel(process, server, server_task, handler_socket)
        process.stdin.write((json.dumps({"op": "start", "version": 1, "options": asdict(options)}) + "\n").encode())
        await process.stdin.drain()
        await asyncio.wait_for(asyncio.shield(tunnel._started), 5)
        if not tunnel.name:
            await tunnel.wait()
            raise TunnelError("protocol_violation")
        return tunnel
    except BaseException as exc:
        if tunnel is not None:
            await tunnel._request_stop("close")
            await _joined(asyncio.create_task(tunnel._done.wait()))
        elif server is not None:
            server.should_exit = True
            await _joined(server_task)
            handler_socket.close()
            adapter = getattr(server, "_tunn_wsgi", None)
            if adapter is not None:
                await adapter.close()
        if isinstance(exc, (OSError, asyncio.TimeoutError)):
            raise TunnelError("helper_unavailable") from None
        raise


def _watch_lifetime(tunnel, cancel_event, lifetime_timeout):
    if tunnel.done:
        return
    async def watch():
        if cancel_event is not None:
            await cancel_event.wait()
        else:
            await asyncio.sleep(lifetime_timeout)
        # Do not join here: the runner cancels and joins watchers during cleanup.
        await tunnel._request_stop("cancel")
    if cancel_event is not None:
        tunnel._watchers.append(asyncio.create_task(watch()))
    if lifetime_timeout is not None:
        async def deadline():
            await asyncio.sleep(lifetime_timeout)
            # The bridge treats cancel as caller cancellation; retain the deadline category.
            if tunnel._stop_requested is None:
                tunnel._deadline_expired = True
                await tunnel._request_stop("cancel")
        tunnel._watchers.append(asyncio.create_task(deadline()))


async def _owned_start(factory, cancel_event, lifetime_timeout):
    loop = asyncio.get_running_loop()
    began = loop.time()
    if cancel_event is not None and cancel_event.is_set():
        raise TunnelError("cancelled")
    startup = asyncio.create_task(factory())
    guards = []
    if cancel_event is not None:
        guards.append(asyncio.create_task(cancel_event.wait()))
    if lifetime_timeout is not None:
        guards.append(asyncio.create_task(asyncio.sleep(lifetime_timeout)))
    try:
        try:
            if guards:
                completed, _ = await asyncio.wait([startup, *guards], return_when=asyncio.FIRST_COMPLETED)
                if startup not in completed:
                    code = "cancelled" if cancel_event is not None and cancel_event.is_set() else "deadline_exceeded"
                    raise TunnelError(code)
            tunnel = await asyncio.shield(startup)
        finally:
            for guard in guards:
                guard.cancel()
            await _joined(asyncio.gather(*guards, return_exceptions=True))
    except BaseException:
        startup.cancel()
        try:
            value = await _joined(startup)
        except BaseException:
            pass
        else:
            # Cancellation may race the factory returning its owned tunnel.
            try:
                await _joined(asyncio.create_task(value.close()))
            except TunnelError:
                pass
        raise
    remaining = None if lifetime_timeout is None else max(0, lifetime_timeout - (loop.time() - began))
    _watch_lifetime(tunnel, cancel_event, remaining)
    return tunnel


async def publish_async(options: Options, *, helper=None, cancel_event=None, lifetime_timeout=None):
    """Start an origin publisher; wait_ready confirms relay registration."""
    validate(options)
    if lifetime_timeout is not None and not _duration(lifetime_timeout, zero=False):
        raise TunnelError("invalid_options")
    if cancel_event is not None and not isinstance(cancel_event, asyncio.Event):
        raise TunnelError("invalid_options")
    return await _owned_start(lambda: _start(options, helper), cancel_event, lifetime_timeout)


async def publish_handler_async(handler, options: Options, *, interface="asgi", lifespan="off", helper=None, cancel_event=None, lifetime_timeout=None):
    """Publish a loopback handler; lifespan='on' also owns ASGI startup/shutdown."""
    validate(options, handler=True)
    if (not callable(handler) or interface not in ("asgi", "wsgi") or
            lifespan not in ("off", "on") or (interface == "wsgi" and lifespan != "off")):
        raise TunnelError("invalid_options")
    if lifetime_timeout is not None and not _duration(lifetime_timeout, zero=False):
        raise TunnelError("invalid_options")
    if cancel_event is not None and not isinstance(cancel_event, asyncio.Event):
        raise TunnelError("invalid_options")
    return await _owned_start(lambda: _open_handler(handler, options, interface, helper, lifespan), cancel_event, lifetime_timeout)


async def _open_handler(handler, options, interface, helper, lifespan="off"):
    _helper_path(helper)
    try:
        import uvicorn
    except ImportError:
        raise TunnelError("handler_failed") from None

    from uvicorn.protocols.http.h11_impl import H11Protocol
    from uvicorn.lifespan.on import LifespanOn

    class OwnedLifespan(LifespanOn):
        task = None
        startup_complete = False
        shutdown_requested = False

        async def send(self, message):
            await super().send(message)
            if message["type"] == "lifespan.startup.complete":
                self.startup_complete = True

        async def startup(self):
            # Retain the task before it starts so cancellation can always join it.
            self.task = asyncio.create_task(self.main())
            await self.receive_queue.put({"type": "lifespan.startup"})
            await self.startup_event.wait()
            if not self.startup_complete or self.startup_failed or self.error_occurred:
                # Some Uvicorn versions exit the process on startup failure.
                raise TunnelError("handler_failed")

        async def shutdown(self):
            self.shutdown_requested = True
            await super().shutdown()

        async def close(self):
            if self.task is None:
                return
            try:
                # Startup can finish just as the caller cancels, before the
                # listener starts. Such an application still needs shutdown.
                if (not self.task.done() and self.startup_complete and
                        not self.error_occurred and
                        not self.shutdown_requested):
                    await self.shutdown()
            finally:
                if not self.startup_event.is_set():
                    self.task.cancel()
                await asyncio.gather(self.task, return_exceptions=True)

    class Config(uvicorn.Config):
        def load(self):
            super().load()
            if lifespan == "on":
                self.lifespan_class = OwnedLifespan

        def configure_logging(self):
            # Uvicorn's access_log=False mutates its process-wide logger even
            # when log_config=None. Suppress output only on our own protocols.
            pass

    class HTTPProtocol(H11Protocol):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.access_log = False

    class Server(uvicorn.Server):
        async def serve(self, sockets=None):
            try:
                await super().serve(sockets=sockets)
            finally:
                if lifespan == "on":
                    for listener in getattr(self, "servers", []):
                        listener.close()
                    owned = getattr(self, "lifespan", None)
                    if owned is not None:
                        await owned.close()

        @contextmanager
        def capture_signals(self):
            # The application owns all process signal handlers.
            yield

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        sock.listen(128)
        sock.setblocking(False)
    except OSError:
        sock.close()
        raise TunnelError("handler_failed") from None
    adapter = None
    if interface == "wsgi":
        try:
            from ._wsgi import ManagedWSGI
            adapter = ManagedWSGI(handler)
        except ImportError:
            sock.close()
            raise TunnelError("handler_failed") from None
        handler = adapter
    config = Config(handler, interface="asgi3", http=HTTPProtocol, host="127.0.0.1", log_config=None,
        access_log=False, proxy_headers=False, server_header=False, lifespan=lifespan,
        limit_concurrency=32, timeout_graceful_shutdown=1)
    server = Server(config)
    server._tunn_wsgi = adapter
    task = asyncio.create_task(server.serve(sockets=[sock]))
    try:
        async with asyncio.timeout(5):
            while not server.started:
                if task.done():
                    raise TunnelError("handler_failed")
                await asyncio.sleep(0.01)
    except BaseException as exc:
        server.should_exit = True
        if not server.started:
            # should_exit alone cannot interrupt a blocked lifespan startup.
            task.cancel()
        try:
            await _joined(asyncio.gather(task, return_exceptions=True))
        finally:
            sock.close()
            if adapter is not None:
                await adapter.close()
        if isinstance(exc, (OSError, asyncio.TimeoutError)):
            raise TunnelError("handler_failed") from None
        raise
    origin = f"http://127.0.0.1:{sock.getsockname()[1]}"
    tunnel = await _start(replace(options, origin=origin), helper, server, task, sock)
    async def handler_stopped():
        await asyncio.shield(task)
        if not tunnel.done and tunnel._stop_requested is None:
            tunnel._handler_failed = True
            await tunnel._request_stop("cancel")
    if not tunnel.done:
        tunnel._watchers.append(asyncio.create_task(handler_stopped()))
    return tunnel
