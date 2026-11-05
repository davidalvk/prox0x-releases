"""Puente entre ``h11`` y el modelo inmutable de prox0x (transporte, §7.2).

Vive en ``core/net`` porque lo comparten el Proxy (entrada) y el motor de
ejecución (salida); ``proxy/h11io`` se conserva como *shim* de compatibilidad.

El parseo es estricto (máquina de estados de h11): evita *request smuggling*
accidental y valida ``Content-Length`` vs ``Transfer-Encoding`` (Plan.md §3.4.2).

Fidelidad: el ``raw`` del modelo se reconstruye desde los eventos de h11
conservando orden y caja de cabeceras; la única normalización es el espaciado
tras los dos puntos (`Name: value`), que h11 ya ha separado.
"""

from __future__ import annotations

import asyncio
from urllib.parse import urlsplit

import h11

from core.model import Header, HttpService, Request, Response, serialize_body, serialize_head

_READ_SIZE = 65_536
MAX_BODY_BYTES = 32 * 1024 * 1024

# Cabeceras *hop-by-hop* (RFC 9110 §7.6.1): nunca se reenvían al origen.
HOP_BY_HOP = frozenset(
    {
        "connection",
        "proxy-connection",
        "keep-alive",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "proxy-authenticate",
        "proxy-authorization",
    }
)


class IncompleteMessage(Exception):
    """El peer cerró a mitad de un mensaje."""


async def read_event(conn: h11.Connection, reader: asyncio.StreamReader) -> h11.Event | None:
    """Siguiente evento h11 leyendo del socket bajo demanda; ``None`` = fin limpio."""
    while True:
        event = conn.next_event()
        if event is h11.NEED_DATA:
            data = await reader.read(_READ_SIZE)
            if not data:
                # EOF: h11 decide si era un cierre limpio o un corte a mitad.
                conn.receive_data(b"")
                final = conn.next_event()
                if final is h11.NEED_DATA:
                    raise IncompleteMessage("conexión cerrada a mitad de mensaje")
                return final
            conn.receive_data(data)
            continue
        if event is h11.PAUSED:
            return None
        return event


async def read_body(
    conn: h11.Connection,
    reader: asyncio.StreamReader,
    *,
    max_bytes: int = MAX_BODY_BYTES,
) -> bytes:
    """Lee el cuerpo hasta ``EndOfMessage`` (h11 decodifica chunked)."""
    body = bytearray()
    while True:
        event = await read_event(conn, reader)
        if isinstance(event, h11.Data):
            if len(body) + len(event.data) > max_bytes:
                raise IncompleteMessage(
                    f"cuerpo excede el límite de {max_bytes} bytes"
                )
            body += event.data
        elif isinstance(event, h11.EndOfMessage):
            return bytes(body)
        elif isinstance(event, (h11.ConnectionClosed, type(None))) or event is None:
            raise IncompleteMessage("cuerpo incompleto")


def parse_authority(authority: str, *, default_port: int, secure: bool) -> HttpService:
    """Parsea ``host``, ``host:puerto`` o ``[IPv6]:puerto``."""
    value = authority.strip()
    if not value:
        raise ValueError("autoridad vacía")
    if value.startswith("["):
        close = value.find("]")
        if close == -1:
            raise ValueError(f"autoridad IPv6 malformada: {authority!r}")
        host = value[1:close]
        rest = value[close + 1 :]
        port = int(rest[1:]) if rest.startswith(":") else default_port
    else:
        host, sep, port_text = value.rpartition(":")
        if not sep or not host:
            host, port = value, default_port
        else:
            port = int(port_text)
    return HttpService(host=host, port=port, secure=secure)


def service_from_connect(target: str) -> HttpService:
    """Servicio de un ``CONNECT host:puerto`` (authority-form, TLS por defecto)."""
    return parse_authority(target, default_port=443, secure=True)


def service_from_request(event: h11.Request) -> HttpService:
    """Servicio de una petición en forma absoluta o de origen."""
    target = event.target.decode("latin-1")
    if target.startswith(("http://", "https://", "ws://", "wss://")):
        parts = urlsplit(target)
        if not parts.hostname:
            raise ValueError(f"URI absoluta sin host: {target!r}")
        secure = parts.scheme in ("https", "wss")
        port = parts.port or (443 if secure else 80)
        return HttpService(host=parts.hostname, port=port, secure=secure)
    # Forma de origen: el host viene en la cabecera Host (obligatoria en 1.1).
    host_header = None
    for name, value in event.headers:
        if name.lower() == b"host":
            host_header = value.decode("latin-1")
            break
    if host_header is None:
        raise ValueError("petición sin cabecera Host")
    return parse_authority(host_header, default_port=80, secure=False)


def _headers_from_event(event: h11.Request | h11.Response) -> tuple[Header, ...]:
    return tuple(
        Header(name.decode("latin-1"), value.decode("latin-1")) for name, value in event.headers
    )


def _assemble(
    start_line: bytes, headers: tuple[Header, ...], body: bytes
) -> tuple[bytes, int]:
    """``raw`` y ``body_offset`` coherentes con la serialización del modelo."""
    head = start_line + serialize_head(headers)
    return head + serialize_body(headers, body), len(head)


def _normalize_version(raw_version: bytes) -> bytes:
    """h11 guarda la versión **sin** el prefijo ``HTTP/`` (p. ej. ``b"1.1"``).

    El modelo de prox0x usa la forma completa (``"HTTP/1.1"``); aquí se
    normaliza para que la línea de inicio reconstruida y el campo ``version``
    sean coherentes con lo que vio la red.
    """
    return raw_version if raw_version.startswith(b"HTTP/") else b"HTTP/" + raw_version


def request_from_event(event: h11.Request, body: bytes) -> Request:
    """Construye el ``Request`` modelo (tal como llegó) desde el evento h11."""
    headers = _headers_from_event(event)
    version = _normalize_version(event.http_version)
    raw, body_offset = _assemble(
        b" ".join((event.method, event.target, version)) + b"\r\n", headers, body
    )
    return Request(
        raw=raw,
        headers=headers,
        body=body,
        body_offset=body_offset,
        version=version.decode("latin-1"),
        method=event.method.decode("latin-1"),
        target=event.target.decode("latin-1"),
    )


def response_from_event(event: h11.Response, body: bytes) -> Response:
    """Construye el ``Response`` modelo (tal como llegó) desde el evento h11."""
    headers = _headers_from_event(event)
    version = _normalize_version(event.http_version)
    start_line = (
        b" ".join(
            (
                version,
                str(event.status_code).encode("ascii"),
                event.reason or b"",
            )
        )
        + b"\r\n"
    )
    raw, body_offset = _assemble(start_line, headers, body)
    return Response(
        raw=raw,
        headers=headers,
        body=body,
        body_offset=body_offset,
        version=version.decode("latin-1"),
        status_code=event.status_code,
        reason=(event.reason or b"").decode("latin-1"),
    )
