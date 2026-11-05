"""Cliente HTTP/1.1 de bajo nivel: un envío, una respuesta, tres marcas.

Es la pieza de transporte que comparten Proxy, Repeater e Intruder (Plan.md
§4.5: el Repeater no tiene cliente propio). Abre una conexión nueva por envío
con ``Connection: close``; el pool con reutilización llega con F3/F4.

``Timing`` mide desde que la petición termina de enviarse (``drain``) hasta el
primer byte leído y hasta ``EndOfMessage``. El tiempo de conexión/TLS queda
fuera de ``Timing`` pero dentro de ``Attempt.latency_ms``.
"""

from __future__ import annotations

import asyncio
import ssl
from dataclasses import dataclass, replace
from datetime import datetime, timezone

import h11

from core.logging import get_logger
from core.model import HttpService, Request, Response, Timing
from core.net.h11io import HOP_BY_HOP, response_from_event
from core.net.h2client import (
    AlpnMismatch,
    H2Client,
    H2Error,
    H2Pool,
    H2ProtocolError,
    H2Result,
    H2Timeout,
    H2TransportError,
)
from core.net.tls import client_context

from .errors import EngineTimeout, ProtocolError, TransportError
from .options import HttpMode, RequestOptions

_log = get_logger("prox0x.engine.client")

_READ_SIZE = 65_536
MAX_BODY_BYTES = 32 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class ClientResult:
    """Respuesta del origen + metadatos del intercambio."""

    response: Response
    peer_ip: str
    complete: bool  # False si el origen cerró sin EndOfMessage
    timing: Timing


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _from_h2(result: H2Result) -> ClientResult:
    return ClientResult(
        response=result.response,
        peer_ip=result.peer_ip,
        complete=result.complete,
        timing=result.timing,
    )


def _h2_error(exc: H2Error, service: HttpService) -> Exception:
    if isinstance(exc, H2Timeout):
        return EngineTimeout(str(exc))
    if isinstance(exc, H2TransportError):
        return TransportError(f"fallo de transporte HTTP/2 con {service}: {exc}")
    if isinstance(exc, H2ProtocolError):
        return ProtocolError(f"error de protocolo HTTP/2 con {service}: {exc}")
    return ProtocolError(f"error HTTP/2 con {service}: {exc}")


def origin_target(request: Request) -> bytes:
    """Request-target en forma de origen para el servidor (RFC 9112 §3.2)."""
    if request.method.upper() == "CONNECT":
        raise ProtocolError("CONNECT no se reenvía como petición HTTP")
    if request.target == "*":
        return b"*"
    path = request.path or "/"
    query = request.query
    return (f"{path}?{query}" if query else path).encode("latin-1")


def upstream_headers(
    request: Request, service: HttpService
) -> list[tuple[bytes, bytes]]:
    """Cabeceras para el origen: sin hop-by-hop y con ``Content-Length`` real."""
    headers: list[tuple[bytes, bytes]] = []
    for header in request.headers:
        if header.lowercase_name in HOP_BY_HOP:
            continue
        if header.lowercase_name == "content-length":
            continue  # se recalcula abajo con el cuerpo decodificado
        headers.append(
            (
                header.name.encode("latin-1", errors="replace"),
                header.value.encode("latin-1", errors="replace"),
            )
        )
    if not any(name.lower() == b"host" for name, _ in headers):
        headers.append(
            (b"Host", service.authority.encode("latin-1", errors="replace"))
        )
    # Cuerpo decodificado => marcamos la longitud real (incluso CL: 0 si había framing).
    if request.body or request.has_header("Content-Length") or request.is_chunked:
        headers.append((b"Content-Length", str(len(request.body)).encode("ascii")))
    return headers


async def send_once(
    request: Request,
    service: HttpService,
    *,
    options: RequestOptions,
    alpn: tuple[str, ...] | None = None,
    h2_pool: H2Pool | None = None,
) -> ClientResult:
    """Envía una petición eligiendo HTTP/2 o HTTP/1.1 según ``http_mode``.

    - ``AUTO``: ofrece ``h2,http/1.1``; usa h2 si el origen lo negocia y
      degrada a HTTP/1.1 si no.
    - ``HTTP_1``: fuerza HTTP/1.1.
    - ``HTTP_2``: exige h2 (error si el origen no lo negocia).
    - ``HTTP_2_IGNORE_ALPN``: habla h2 aunque el ALPN no lo confirme.
    """
    mode = options.http_mode
    if mode in (HttpMode.HTTP_2, HttpMode.HTTP_2_IGNORE_ALPN) and not service.secure:
        raise ProtocolError("HTTP/2 requiere TLS en prox0x (h2c no soportado todavía)")

    if mode is HttpMode.HTTP_1 or not service.secure:
        return await _send_h1(
            request,
            service,
            options=options,
            alpn=alpn or ("http/1.1",),
        )

    target_service = replace(service, sni=options.sni) if options.sni else service

    if mode is HttpMode.HTTP_2_IGNORE_ALPN:
        try:
            client = await H2Client.connect(
                target_service,
                verify=options.verify_upstream,
                timeout_s=options.timeout_s,
                alpn=("h2",),
                require_h2=False,
            )
        except H2Error as exc:
            raise _h2_error(exc, service) from exc
        try:
            result = await client.request(request, options)
        except H2Error as exc:
            raise _h2_error(exc, service) from exc
        finally:
            await client.aclose()
        return _from_h2(result)

    own_pool = h2_pool is None
    pool = h2_pool or H2Pool()
    try:
        try:
            client = await pool.get(
                target_service,
                verify=options.verify_upstream,
                timeout_s=options.timeout_s,
                alpn=("h2", "http/1.1"),
                require_h2=True,
            )
        except AlpnMismatch as exc:
            if mode is HttpMode.HTTP_2:
                raise ProtocolError(
                    f"el origen {service} no negocia HTTP/2: {exc}"
                ) from exc
            return await _send_h1(
                request,
                service,
                options=options,
                alpn=("http/1.1",),
            )
        except H2Error as exc:
            raise _h2_error(exc, service) from exc

        try:
            result = await client.request(request, options)
        except H2Error as exc:
            raise _h2_error(exc, service) from exc
        return _from_h2(result)
    finally:
        if own_pool:
            await pool.aclose()


async def _send_h1(
    request: Request,
    service: HttpService,
    *,
    options: RequestOptions,
    alpn: tuple[str, ...] = ("http/1.1",),
) -> ClientResult:
    """Envía ``request`` al ``service`` por HTTP/1.1 y devuelve la respuesta."""
    target_service = replace(service, sni=options.sni) if options.sni else service
    ssl_context = client_context(target_service, options.verify_upstream, alpn)
    timeout = options.timeout_s

    try:
        async with asyncio.timeout(timeout):
            reader, writer = await asyncio.open_connection(
                target_service.host,
                target_service.port,
                ssl=ssl_context,
                server_hostname=target_service.effective_sni if ssl_context else None,
            )
    except TimeoutError as exc:
        raise EngineTimeout(f"timeout conectando a {target_service}") from exc
    except (OSError, ssl.SSLError) as exc:
        raise TransportError(f"no se pudo conectar a {target_service}: {exc}") from exc

    peer = writer.get_extra_info("peername")
    peer_ip = peer[0] if peer else ""
    # Se inicializa antes de construir/enviar la petición: los ``except`` de
    # protocolo consultan esta variable incluso si h11 falla al serializarla.
    first_byte = False

    try:
        conn = h11.Connection(h11.CLIENT)
        writer.write(
            conn.send(
                h11.Request(
                    method=request.method.encode("latin-1"),
                    target=origin_target(request),
                    headers=upstream_headers(request, target_service),
                )
            )
        )
        if request.body:
            writer.write(conn.send(h11.Data(data=request.body)))
        writer.write(conn.send(h11.EndOfMessage()))
        try:
            async with asyncio.timeout(timeout):
                await writer.drain()
        except TimeoutError as exc:
            raise EngineTimeout(f"timeout enviando a {target_service}") from exc

        timing = Timing.start()
        response_event: h11.Response | None = None
        body = bytearray()
        complete = False
        while True:
            event = conn.next_event()
            if event is h11.NEED_DATA:
                try:
                    async with asyncio.timeout(timeout):
                        data = await reader.read(_READ_SIZE)
                except TimeoutError as exc:
                    raise EngineTimeout(
                        f"timeout esperando respuesta de {target_service}"
                    ) from exc
                if data and not first_byte:
                    timing = timing.with_first_byte(_now())
                    first_byte = True
                if not data:
                    conn.receive_data(b"")  # EOF: h11 cierra el mensaje si puede
                else:
                    conn.receive_data(data)
                continue
            if isinstance(event, h11.InformationalResponse):
                _log.debug(
                    "upstream_1xx", status=event.status_code, service=str(target_service)
                )
                continue
            if isinstance(event, h11.Response):
                response_event = event
                continue
            if isinstance(event, h11.Data):
                if len(body) + len(event.data) > MAX_BODY_BYTES:
                    raise ProtocolError(
                        f"cuerpo de respuesta de {target_service} excede el límite de {MAX_BODY_BYTES} bytes"
                    )
                body += event.data
                continue
            if isinstance(event, h11.EndOfMessage):
                complete = True
                break
            if isinstance(event, h11.ConnectionClosed):
                break
            if event is h11.PAUSED:
                complete = True
                break

        if response_event is None:
            if not first_byte:
                # Cierre sin un solo byte: fallo de transporte (reintentable).
                raise TransportError(f"el origen {target_service} cerró sin responder")
            raise ProtocolError(f"el origen {target_service} cerró sin responder")
        if not complete:
            _log.warning(
                "upstream_truncated",
                service=str(target_service),
                body_bytes=len(body),
            )
        timing = timing.with_completed(_now())
        return ClientResult(
            response=response_from_event(response_event, bytes(body)),
            peer_ip=peer_ip,
            complete=complete,
            timing=timing,
        )
    except (h11.RemoteProtocolError, h11.LocalProtocolError) as exc:
        if not first_byte:
            # Cierre del peer antes de enviar un solo byte: fallo reintentable.
            raise TransportError(
                f"el origen {target_service} cerró sin responder: {exc}"
            ) from exc
        raise ProtocolError(f"error de protocolo con {target_service}: {exc}") from exc
    except (OSError, ssl.SSLError) as exc:
        raise TransportError(f"fallo de transporte con {target_service}: {exc}") from exc
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, ssl.SSLError):  # el origen puede cortar sin cierre limpio
            pass
