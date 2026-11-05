"""Handshake y relay opaco de WebSocket (Plan.md §3.4.4).

El Proxy detecta ``Upgrade: websocket``, reenvía el handshake al origen **sin
filtrar** las cabeceras hop-by-hop (son necesarias para el 101), y a partir de
ahí copia bytes en ambas direcciones. Los frames se parsean solo para el
historial: el payload no se toca.
"""

from __future__ import annotations

import asyncio
import ssl
from dataclasses import dataclass
from collections.abc import Awaitable, Callable

from core.model import (
    Header,
    HttpService,
    Request,
    Response,
    WebSocketDirection,
)
from core.net.tls import client_context
from core.net.websocket import (
    FrameInfo,
    RawFrame,
    RawFrameParser,
    build_frame,
)

_READ_SIZE = 65_536
_HEAD_LIMIT = 65_536

FrameInterceptor = Callable[
    [WebSocketDirection, RawFrame], Awaitable[bytes | None]
]


class WebSocketError(Exception):
    """Fallo en el handshake o en el relay WebSocket."""


def is_upgrade(request: Request) -> bool:
    """True si la petición pide cambiar a WebSocket."""
    upgrade = request.header("Upgrade")
    connection = request.header("Connection")
    return (
        upgrade is not None
        and "websocket" in upgrade.lower()
        and connection is not None
        and "upgrade" in connection.lower()
    )


def _origin_target(request: Request) -> bytes:
    if request.target == "*":
        return b"*"
    path = request.path or "/"
    query = request.query
    return (f"{path}?{query}" if query else path).encode("latin-1")


def _handshake_bytes(request: Request, service: HttpService) -> bytes:
    """Petición de handshake en forma de origen, preservando Upgrade/Connection."""
    method = request.method
    version = request.version if request.version.startswith("HTTP/1.") else "HTTP/1.1"
    lines: list[bytes] = [
        f"{method} {_origin_target(request).decode('latin-1')} {version}".encode(
            "latin-1"
        )
    ]
    has_host = False
    for header in request.headers:
        if header.lowercase_name in {"proxy-connection", "proxy-authorization"}:
            continue
        if header.lowercase_name == "host":
            has_host = True
        lines.append(header.to_bytes().rstrip(b"\r\n"))
    if not has_host:
        lines.append(f"Host: {service.authority}".encode("latin-1"))
    return b"\r\n".join(lines) + b"\r\n\r\n" + request.body


def _response_from_head(head: bytes) -> Response:
    lines = head[:-4].split(b"\r\n")
    if not lines or not lines[0]:
        raise WebSocketError("respuesta de handshake vacía")
    parts = lines[0].split(b" ", 2)
    if len(parts) < 2:
        raise WebSocketError(f"línea de estado inválida: {lines[0]!r}")
    version = parts[0].decode("latin-1")
    try:
        status = int(parts[1])
    except ValueError as exc:
        raise WebSocketError(f"código de estado inválido: {parts[1]!r}") from exc
    reason = parts[2].decode("latin-1") if len(parts) > 2 else ""
    headers: list[Header] = []
    for line in lines[1:]:
        name, separator, value = line.partition(b":")
        if not separator:
            continue
        headers.append(
            Header(name.decode("latin-1").strip(), value.decode("latin-1").strip())
        )
    return Response(
        raw=head,
        headers=tuple(headers),
        body=b"",
        body_offset=len(head),
        version=version,
        status_code=status,
        reason=reason,
    )


@dataclass(slots=True)
class UpstreamHandshake:
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    response: Response
    raw_head: bytes
    peer_ip: str


async def open_upstream(
    request: Request,
    service: HttpService,
    *,
    verify: bool,
    timeout: float,
) -> UpstreamHandshake:
    """Conecta al origen y ejecuta el handshake WebSocket."""
    context = client_context(service, verify, ("http/1.1",))
    try:
        async with asyncio.timeout(timeout):
            reader, writer = await asyncio.open_connection(
                service.host,
                service.port,
                ssl=context,
                server_hostname=service.effective_sni if context else None,
            )
    except TimeoutError as exc:
        raise WebSocketError(f"timeout conectando a {service}") from exc
    except (OSError, ssl.SSLError) as exc:
        raise WebSocketError(f"no se pudo conectar a {service}: {exc}") from exc

    peer = writer.get_extra_info("peername")
    peer_ip = peer[0] if peer else ""
    try:
        writer.write(_handshake_bytes(request, service))
        await writer.drain()
        async with asyncio.timeout(timeout):
            head = await reader.readuntil(b"\r\n\r\n")
    except TimeoutError as exc:
        writer.close()
        raise WebSocketError(f"timeout en el handshake con {service}") from exc
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError) as exc:
        writer.close()
        raise WebSocketError(f"handshake incompleto con {service}") from exc
    except (OSError, ssl.SSLError) as exc:
        writer.close()
        raise WebSocketError(f"fallo de transporte en el handshake: {exc}") from exc

    if len(head) > _HEAD_LIMIT:
        writer.close()
        raise WebSocketError("cabeceras de handshake demasiado grandes")
    try:
        response = _response_from_head(head)
    except (ValueError, WebSocketError):
        writer.close()
        raise
    return UpstreamHandshake(
        reader=reader,
        writer=writer,
        response=response,
        raw_head=head,
        peer_ip=peer_ip,
    )


async def relay(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    upstream_reader: asyncio.StreamReader,
    upstream_writer: asyncio.StreamWriter,
    on_frame: Callable[[WebSocketDirection, FrameInfo], None],
    *,
    intercept_frame: FrameInterceptor | None = None,
) -> None:
    """Copia frames en ambas direcciones y permite interceptar/modificar."""

    async def pump(
        source: asyncio.StreamReader,
        destination: asyncio.StreamWriter,
        direction: WebSocketDirection,
    ) -> None:
        parser = RawFrameParser()
        while True:
            data = await source.read(_READ_SIZE)
            if not data:
                return
            for frame in parser.feed(data):
                forwarded: bytes | None = frame.raw
                if (
                    intercept_frame is not None
                    and frame.info.opcode in (0x1, 0x2)
                ):
                    forwarded = await intercept_frame(direction, frame)
                on_frame(direction, frame.info)
                if forwarded is None:
                    continue
                destination.write(forwarded)
                await destination.drain()

    tasks = [
        asyncio.create_task(
            pump(client_reader, upstream_writer, WebSocketDirection.CLIENT_TO_SERVER)
        ),
        asyncio.create_task(
            pump(upstream_reader, client_writer, WebSocketDirection.SERVER_TO_CLIENT)
        ),
    ]
    try:
        _done, pending = await asyncio.wait(
            tasks, return_when=asyncio.FIRST_COMPLETED
        )
        for task in pending:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
