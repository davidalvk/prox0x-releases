"""Dataclasses inmutables del contrato de datos de prox0x (Plan.md §7.3).

Toda mutación devuelve un objeto nuevo (`with_*`); nada se modifica en sitio.
Ese diseño permite versionar, comparar y reenviar mensajes sin efectos
colaterales, y es lo que necesita el Repeater (Plan.md §3.5).
"""

from .annotations import Annotations, Color
from .flow import Flow
from .headers import Header
from .message import (
    Message,
    Range,
    Request,
    Response,
    serialize_body,
    serialize_head,
)
from .mime import MimeType
from .params import Param, ParamType
from .service import HttpService
from .timing import Timing
from .websocket import WebSocketDirection, WebSocketFrame

__all__ = [
    "Annotations",
    "Color",
    "Flow",
    "Header",
    "HttpService",
    "Message",
    "MimeType",
    "Param",
    "ParamType",
    "Range",
    "Request",
    "Response",
    "Timing",
    "WebSocketDirection",
    "WebSocketFrame",
    "serialize_body",
    "serialize_head",
]
