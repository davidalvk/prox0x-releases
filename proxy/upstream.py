"""Adaptador del Proxy sobre el motor compartido (``core.engine``).

F1 tenía aquí su propio cliente HTTP/1.1. En F2 el envío vive en
``core.engine.client`` para que Repeater e Intruder usen exactamente el mismo
transporte. Este módulo conserva la API que consume ``proxy.server`` y traduce
los errores del motor a ``UpstreamError``.
"""

from __future__ import annotations

from dataclasses import dataclass

from core.engine import EngineError, RequestOptions
from core.engine.client import send_once
from core.net.h2client import H2Pool
from core.model import HttpService, Request, Response


class UpstreamError(RuntimeError):
    """Fallo de transporte o de protocolo contra el origen."""


@dataclass(frozen=True, slots=True)
class UpstreamResult:
    """Respuesta del origen + metadatos de la conexión saliente."""

    response: Response
    peer_ip: str
    complete: bool  # False si el origen cerró sin EndOfMessage


async def send_request(
    request: Request,
    service: HttpService,
    *,
    verify: bool = True,
    timeout: float = 60.0,
    alpn: tuple[str, ...] = ("h2", "http/1.1"),
    pool: H2Pool | None = None,
) -> UpstreamResult:
    """Envía ``request`` al ``service`` y devuelve la respuesta completa."""
    try:
        result = await send_once(
            request,
            service,
            options=RequestOptions(
                verify_upstream=verify,
                timeout_ms=timeout * 1000,
            ),
            alpn=alpn,
            h2_pool=pool,
        )
    except EngineError as exc:
        raise UpstreamError(str(exc)) from exc
    return UpstreamResult(
        response=result.response,
        peer_ip=result.peer_ip,
        complete=result.complete,
    )
