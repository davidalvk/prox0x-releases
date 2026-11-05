"""Motor de ejecución concurrente de prox0x (Plan.md §7.2).

Punto de entrada estable para Repeater, Intruder y el Proxy:

    engine = RequestEngine(max_concurrency=8)
    attempt = await engine.send(request, service)
    attempts = await engine.send_requests(requests, service, concurrency=4)
"""

from .client import ClientResult, send_once
from .engine import Attempt, AttemptStatus, RequestEngine, build_redirect
from .errors import (
    ConfigurationError,
    EngineError,
    EngineTimeout,
    ProtocolError,
    TransportError,
)
from .options import ExecutionStats, HttpMode, RedirectMode, RequestOptions

__all__ = [
    "Attempt",
    "AttemptStatus",
    "ClientResult",
    "ConfigurationError",
    "EngineError",
    "EngineTimeout",
    "ExecutionStats",
    "HttpMode",
    "ProtocolError",
    "RedirectMode",
    "RequestEngine",
    "RequestOptions",
    "TransportError",
    "build_redirect",
    "send_once",
]
