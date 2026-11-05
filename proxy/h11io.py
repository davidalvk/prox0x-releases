"""Compatibilidad: el puente ``h11`` vive ahora en :mod:`core.net.h11io`.

Se mantiene este módulo para no romper imports de F1 (``proxy.server`` y los
tests usan ``proxy.h11io``). Código nuevo debe importar de ``core.net``.
"""

from __future__ import annotations

from core.net.h11io import (
    HOP_BY_HOP,
    MAX_BODY_BYTES,
    IncompleteMessage,
    parse_authority,
    read_body,
    read_event,
    request_from_event,
    response_from_event,
    service_from_connect,
    service_from_request,
)

__all__ = [
    "HOP_BY_HOP",
    "MAX_BODY_BYTES",
    "IncompleteMessage",
    "parse_authority",
    "read_body",
    "read_event",
    "request_from_event",
    "response_from_event",
    "service_from_connect",
    "service_from_request",
]
