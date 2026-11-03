"""Explicit publisher values; no login, environment credential lookup or cache."""
from dataclasses import asdict, dataclass, field
import math
import re
from urllib.parse import urlsplit


class TunnelError(Exception):
    """Stable safe error category. Remote error text is never included."""

    _MESSAGES = {
        "invalid_options": "invalid publisher options",
        "connection_failed": "relay connection failed",
        "registration_rejected": "registration rejected by relay",
        "protocol_violation": "publisher protocol violation",
        "helper_unavailable": "build or configure the revision-matched Python helper",
        "handler_failed": "application server failed",
        "cancelled": "publisher cancelled",
        "deadline_exceeded": "publisher lifetime expired",
    }

    def __init__(self, code: str):
        self.code = code if code in self._MESSAGES else "protocol_violation"
        super().__init__("tunn: " + self._MESSAGES[self.code])


@dataclass(frozen=True, repr=False)
class Credentials:
    auth_token: str = ""
    tunnel_key: str = ""
    endpoint_token: str = ""

    def __repr__(self):
        return "Credentials([redacted])"


@dataclass(frozen=True)
class ReconnectPolicy:
    max_attempts: int = 5
    initial_delay: float = 1.0
    max_delay: float = 30.0


@dataclass(frozen=True)
class TLSOptions:
    """Verified TLS. Supply a PEM CA certificate, never a private key."""
    root_ca_pem: str = field(default="", repr=False)
    server_name: str = ""


@dataclass(frozen=True)
class WebSocketOptions:
    idle_timeout: float = 300.0
    keepalive_interval: float = 30.0
    max_message_size: int = 8 * 1024 * 1024


@dataclass(frozen=True, repr=False)
class Options:
    origin: str = ""
    name: str = ""
    server_addr: str = "tunn.to:443"
    credentials: Credentials = field(default_factory=Credentials)
    public: bool = False
    allowed_emails: tuple[str, ...] = ()
    relay_tls: TLSOptions | None = None
    origin_tls: TLSOptions | None = None
    connect_timeout: float = 10.0
    http_timeout: float = 30.0
    reconnect: ReconnectPolicy = field(default_factory=ReconnectPolicy)
    websocket: WebSocketOptions = field(default_factory=WebSocketOptions)
    require_upstream_auth: bool = False

    def __repr__(self):
        return "Options([redacted])"


def _duration(value, *, zero=True):
    return (type(value) in (int, float)
            and (value >= 0 if zero else value > 0)
            and value <= 365 * 24 * 3600 and math.isfinite(value))


def validate(options: Options, *, handler=False):
    """Fail before spawning a helper or binding an application socket."""
    try:
        if not isinstance(options, Options) or not isinstance(options.credentials, Credentials):
            raise ValueError
        if not all(isinstance(x, str) for x in asdict(options.credentials).values()):
            raise ValueError
        if not isinstance(options.origin, str) or not isinstance(options.name, str):
            raise ValueError
        if handler:
            if options.origin:
                raise ValueError
        else:
            u = urlsplit(options.origin)
            if (u.scheme not in ("http", "https") or not u.hostname or u.username is not None
                    or u.password is not None or u.path not in ("", "/") or u.query or u.fragment
                    or any(c.isspace() for c in options.origin)):
                raise ValueError
            if u.port is not None and not 1 <= u.port <= 65535:
                raise ValueError
        if options.name and not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", options.name):
            raise ValueError
        addr = urlsplit("//" + options.server_addr)
        if (not addr.hostname or addr.port is None or not 1 <= addr.port <= 65535
                or addr.username is not None or addr.path or addr.query or addr.fragment
                or any(c.isspace() for c in options.server_addr)):
            raise ValueError
        if not isinstance(options.public, bool) or not isinstance(options.require_upstream_auth, bool):
            raise ValueError
        if not isinstance(options.allowed_emails, (tuple, list)) or not all(isinstance(x, str) for x in options.allowed_emails):
            raise ValueError
        if options.public and (options.allowed_emails or options.credentials.endpoint_token):
            raise ValueError
        if options.credentials.endpoint_token and not options.credentials.endpoint_token.startswith("tunn_ep_"):
            raise ValueError
        if not _duration(options.connect_timeout) or not _duration(options.http_timeout):
            raise ValueError
        r = options.reconnect
        if (not isinstance(r, ReconnectPolicy) or type(r.max_attempts) is not int or not 0 <= r.max_attempts <= 2**31 - 1
                or not _duration(r.initial_delay) or not _duration(r.max_delay)
                or (r.initial_delay or 1) > (r.max_delay or 30)):
            raise ValueError
        w = options.websocket
        if (not isinstance(w, WebSocketOptions) or not _duration(w.idle_timeout) or not _duration(w.keepalive_interval)
                or type(w.max_message_size) is not int or not 0 <= w.max_message_size <= 2**31 - 1):
            raise ValueError
        for tls in (options.relay_tls, options.origin_tls):
            if tls is not None and (not isinstance(tls, TLSOptions) or not isinstance(tls.root_ca_pem, str) or not isinstance(tls.server_name, str)):
                raise ValueError
        # Keep the helper's input record within its fixed one MiB limit.
        import json
        if len(json.dumps(asdict(options)).encode()) > 512 * 1024:
            raise ValueError
    except (ValueError, TypeError, AttributeError, OverflowError):
        raise TunnelError("invalid_options") from None
