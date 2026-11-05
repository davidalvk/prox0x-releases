"""Conexiones, TLS y serialización HTTP/1.1 (``h11``) de prox0x (Plan.md §7.2).

Lo comparten el Proxy (entrada) y el motor de ejecución (salida). El pool con
reutilización y HTTP/2 llegan en F3/F4; el *shim* ``proxy.h11io`` mantiene los
imports de F1.
"""

from __future__ import annotations

from .h11io import (
    HOP_BY_HOP,
    IncompleteMessage,
    parse_authority,
    read_body,
    read_event,
    request_from_event,
    response_from_event,
    service_from_connect,
    service_from_request,
)
from .wire import parse_request, split_head_body

__all__ = [
    "HOP_BY_HOP",
    "IncompleteMessage",
    "parse_authority",
    "parse_request",
    "read_body",
    "read_event",
    "request_from_event",
    "response_from_event",
    "service_from_connect",
    "service_from_request",
    "split_head_body",
]
