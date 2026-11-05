"""Entrada de historial: el par request/response con su contexto (Plan.md §7.3).

Conserva request original **y** final, respuesta original **y** final, timing y
anotaciones: es la base del historial del Proxy y del diff del Repeater
(Plan.md §3.3, `ProxyHttpRequestResponse`).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from .message import Message, Request, Response
from .mime import MimeType
from .service import HttpService
from .timing import Timing
from .websocket import WebSocketFrame


@dataclass(frozen=True, slots=True, kw_only=True)
class Flow:
    """Flujo HTTP completo interceptado o ejecutado.

    Campos del contrato (Plan.md §7.3). ``response`` / ``original_response``
    quedan en ``None`` mientras el intercambio está en vuelo; el resto de
    campos son obligatorios para que el historial sea trazable.
    """

    id: int
    service: HttpService
    listener_port: int
    received_at: datetime
    request: Message  # tal como llegó
    final_request: Message  # tal como salió
    response: Message | None = None
    original_response: Message | None = None
    edited: bool = False
    modified_by_rule: bool = False
    mime: MimeType = MimeType.NONE
    timing: Timing | None = None
    source_ip: str = ""
    dest_ip: str = ""
    websocket_frames: tuple[WebSocketFrame, ...] = ()
    dropped: bool = False
    drop_reason: str | None = None
    in_scope: bool = True
    # Los flujos sintéticos del Full Site Scan no son tráfico navegado por el
    # usuario y se ocultan de Interceptación por defecto.
    is_scan_flow: bool = False

    def __post_init__(self) -> None:
        if self.id < 0:
            raise ValueError(f"id de flow negativo: {self.id}")
        if not 0 < self.listener_port < 65_536:
            raise ValueError(f"listener_port fuera de rango: {self.listener_port}")
        if self.received_at.tzinfo is None:
            raise ValueError("received_at debe ser consciente de zona (tz-aware)")

    def summary(self) -> str:
        """Línea compacta para logs: `#12 GET https://h/x -> 200`."""
        method = target = ""
        if isinstance(self.request, Request):
            method = self.request.method
            target = str(self.request.http_service or "") + self.request.path
        status = f" {self.response.status_code}" if isinstance(self.response, Response) else ""
        edited = " (edited)" if self.edited else ""
        return f"#{self.id} {method} {target}{status}{edited}".rstrip()
